#!/usr/bin/env python3
import asyncio
import base64
import json
import logging
import sys
import time
import zlib
from typing import Dict, List, Optional
from aiohttp import web

BIND_HOST       = "0.0.0.0"
BIND_PORT       = 8080
AUTH_TOKEN      = "" 

CONNECT_TIMEOUT = 8.0
COLLECT_WAIT    = 0.05
READ_CHUNK      = 1048576 
MAX_READ_CAP    = 3145728 
READ_TIMEOUT    = 0.02
SESSION_TTL     = 120
GC_INTERVAL     = 30

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SERVER] %(message)s")
log = logging.getLogger("tunnel.server")

class ConnState:
    __slots__ = ("reader", "writer", "ready", "failed", "pending_data")
    def __init__(self):
        self.reader = None
        self.writer = None
        self.ready = False
        self.failed = False
        self.pending_data = bytearray()

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
        if not cs: return w.close()
        cs.reader, cs.writer, cs.ready = r, w, True
        if cs.pending_data:
            pending = bytes(cs.pending_data)
            cs.pending_data.clear()

    if pending:
        try:
            w.write(pending)
            await w.drain()
        except: pass

async def _drain_remote(reader: asyncio.StreamReader, budget: float = COLLECT_WAIT) -> bytes:
    buf = bytearray()
    deadline = asyncio.get_event_loop().time() + budget
    while True:
        rem = deadline - asyncio.get_event_loop().time()
        if rem <= 0: break
        try:
            chunk = await asyncio.wait_for(reader.read(READ_CHUNK), timeout=min(rem, READ_TIMEOUT))
            if not chunk: break
            buf.extend(chunk)
            if len(chunk) < READ_CHUNK: break
            if len(buf) >= MAX_READ_CAP: break
        except: break
    return bytes(buf)

async def handle_tunnel(req: web.Request) -> web.Response:
    try: body = await req.json()
    except: return web.Response(status=400)

    sid, frames = body.get("sid", "__anon__"), body.get("frames", [])
    
    # Adding a helpful log so you know data is actively reaching your VPS
    if frames:
        log.info(f"Received request with {len(frames)} frames for session [{sid[:8]}]")

    sess = await _get_session(sid)
    new_connects, writes_todo = [], []

    response = web.StreamResponse()
    response.content_type = 'application/jsonl'
    await response.prepare(req)

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
                    try: raw = zlib.decompress(raw)
                    except Exception: pass

                    if cs.ready: writes_todo.append((cs.writer, raw))
                    elif not cs.failed: cs.pending_data.extend(raw)
            elif ft == "close":
                cs = sess.conns.pop(cid, None)
                if cs and cs.writer:
                    try: cs.writer.close()
                    except: pass

    for cid, host, port in new_connects: 
        asyncio.create_task(_connect_task(sess, cid, host, port))
    
    for writer, raw in writes_todo:
        try:
            writer.write(raw)
            await writer.drain()
        except: pass

    async with sess.lock:
        ready = [(cid, cs.reader) for cid, cs in sess.conns.items() if cs.ready and cs.reader]

    if ready:
        async def read_one(c_id, r): return c_id, await _drain_remote(r), r.at_eof()
        tasks = [asyncio.create_task(read_one(cid, r)) for cid, r in ready]
        
        for task in asyncio.as_completed(tasks):
            try:
                cid, data, eof = await task
                if data:
                    comp = zlib.compress(data, level=6)
                    out_f = {"t": "data", "id": cid, "d": base64.b64encode(comp).decode()}
                    await response.write((json.dumps(out_f) + "\n").encode())
                if eof:
                    async with sess.lock:
                        cs = sess.conns.pop(cid, None)
                        if cs and cs.writer:
                            try: cs.writer.close()
                            except: pass
                    await response.write((json.dumps({"t": "close", "id": cid}) + "\n").encode())
            except Exception: pass

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
