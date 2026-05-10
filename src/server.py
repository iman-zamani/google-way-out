#!/usr/bin/env python3
import asyncio
import base64
import json
import logging
import sys
import time
from typing import Dict, List, Optional
from aiohttp import web

BIND_HOST       = "0.0.0.0"
BIND_PORT       = 8080
AUTH_TOKEN      = "" 

CONNECT_TIMEOUT = 8.0
SESSION_TTL     = 120
GC_INTERVAL     = 30

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SERVER] %(message)s")
log = logging.getLogger("tunnel.server")

class ConnState:
    __slots__ = ("reader", "writer", "ready", "failed", "pending_data", "outbound_buf", "remote_eof", "read_task")
    def __init__(self):
        self.reader = None
        self.writer = None
        self.ready = False
        self.failed = False
        # Remote-to-Client background buffer (The "Sponge")
        self.pending_data = bytearray()
        # Client-to-Remote buffer (used only while TCP handshake is pending)
        self.outbound_buf = bytearray()
        self.remote_eof = False
        self.read_task = None

class SessionState:
    def __init__(self):
        self.conns: Dict[int, ConnState] = {}
        self.error_queue: List[dict] = []
        self.lock = asyncio.Lock()
        self.last_active = time.monotonic()

sessions: Dict[str, SessionState] = {}
_sess_lock = asyncio.Lock()

async def _get_session(sid: str) -> SessionState:
    async with _sess_lock:
        if sid not in sessions: sessions[sid] = SessionState()
        s = sessions[sid]
        s.last_active = time.monotonic()
    return s

async def _background_reader(sess: SessionState, cid: int, cs: ConnState):
    """Continuously reads from the remote socket and buffers it in user-space."""
    try:
        while True:
            # Hard Cap: Pause reading if buffer exceeds 5MB to prevent memory exhaustion
            if len(cs.pending_data) > 5242880:
                await asyncio.sleep(0.1)
                continue

            chunk = await cs.reader.read(65536)
            if not chunk:
                break # EOF reached

            async with sess.lock:
                cs.pending_data.extend(chunk)
    except Exception:
        pass
    finally:
        async with sess.lock:
            cs.remote_eof = True

async def _connect_task(sess: SessionState, cid: int, host: str, port: int):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT)
    except Exception as e:
        async with sess.lock:
            if sess.conns.pop(cid, None): sess.error_queue.append({"t": "error", "id": cid, "msg": str(e)})
        return

    pending = b""
    async with sess.lock:
        cs = sess.conns.get(cid)
        if not cs: 
            w.close()
            return
            
        cs.reader, cs.writer, cs.ready = r, w, True
        
        # Grab any data the client sent while we were connecting
        if cs.outbound_buf:
            pending = bytes(cs.outbound_buf)
            cs.outbound_buf.clear()
            
        # Spawn the continuous background reader
        cs.read_task = asyncio.create_task(_background_reader(sess, cid, cs))

    # Flush pending client outbound data
    if pending:
        try:
            w.write(pending)
            await w.drain()
        except: pass

async def handle_tunnel(req: web.Request) -> web.Response:
    try: body = await req.json()
    except: return web.Response(status=400)

    sid, frames = body.get("sid", "__anon__"), body.get("frames", [])
    
    if frames:
        log.info(f"Received request with {len(frames)} frames for session [{sid[:8]}]")

    sess = await _get_session(sid)
    new_connects, writes_todo = [], []

    response = web.StreamResponse()
    response.content_type = 'application/jsonl'
    await response.prepare(req)

    # 1. Process Incoming Client Data & Commands
    async with sess.lock:
        for f in sess.error_queue:
            await response.write((json.dumps(f) + "\n").encode())
        sess.error_queue.clear()
        
        for f in frames:
            ft, cid = f.get("t"), f.get("id")
            if ft == "open":
                sess.conns[cid] = ConnState()
                new_connects.append((cid, f.get("h", ""), int(f.get("p", 0))))
            elif ft == "data":
                cs = sess.conns.get(cid)
                if cs:
                    raw = base64.b64decode(f["d"])
                    if cs.ready: writes_todo.append((cs.writer, raw))
                    elif not cs.failed: cs.outbound_buf.extend(raw)
            elif ft == "close":
                cs = sess.conns.pop(cid, None)
                if cs:
                    if cs.read_task: cs.read_task.cancel()
                    if cs.writer:
                        try: cs.writer.close()
                        except: pass

    # 2. Execute Connections & Writes
    for cid, host, port in new_connects: 
        asyncio.create_task(_connect_task(sess, cid, host, port))
    
    for writer, raw in writes_todo:
        try:
            writer.write(raw)
            await writer.drain()
        except: pass

    # 3. Slice up to 3MB directly from the Background Sponge Buffer
    extracts = []
    async with sess.lock:
        for cid, cs in list(sess.conns.items()):
            if not cs.ready: continue
            
            # Slice up to 3145728 bytes (3MB) instantly
            extract_len = min(len(cs.pending_data), 3145728)
            data = None
            if extract_len > 0:
                data = bytes(cs.pending_data[:extract_len])
                del cs.pending_data[:extract_len]
            
            # If the remote closed the connection AND our sponge is fully drained
            eof_close = (cs.remote_eof and len(cs.pending_data) == 0)
            if eof_close:
                if cs.writer:
                    try: cs.writer.close()
                    except: pass
                sess.conns.pop(cid, None)
                
            if data or eof_close:
                extracts.append((cid, data, eof_close))

    # 4. Stream Results Back via JSONL
    for cid, data, eof_close in extracts:
        if data:
            out_f = {"t": "data", "id": cid, "d": base64.b64encode(data).decode()}
            await response.write((json.dumps(out_f) + "\n").encode())
        if eof_close:
            await response.write((json.dumps({"t": "close", "id": cid}) + "\n").encode())

    await response.write_eof()
    return response

async def _gc_loop():
    while True:
        await asyncio.sleep(GC_INTERVAL)
        now = time.monotonic()
        to_del = []
        async with _sess_lock:
            for sid, sess in sessions.items():
                if now - sess.last_active > SESSION_TTL: to_del.append(sid)
        for sid in to_del:
            async with _sess_lock: sess = sessions.pop(sid, None)
            if sess:
                async with sess.lock:
                    for cs in sess.conns.values():
                        if cs.read_task: cs.read_task.cancel()
                        if cs.writer:
                            try: cs.writer.close()
                            except: pass

async def create_app() -> web.Application:
    app = web.Application(client_max_size=512 * 1024 * 1024)
    app.router.add_post("/tunnel", handle_tunnel)
    async def _startup(a): asyncio.create_task(_gc_loop())
    app.on_startup.append(_startup)
    return app

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else BIND_PORT
    web.run_app(create_app(), host=BIND_HOST, port=port, access_log=None)
