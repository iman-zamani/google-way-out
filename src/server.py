#!/usr/bin/env python3
import asyncio
import base64
import logging
import sys
import time
from typing import Dict, List, Optional
from aiohttp import web

BIND_HOST       = "0.0.0.0"
BIND_PORT       = 8080
AUTH_TOKEN      = "" 

CONNECT_TIMEOUT = 8.0
# Drastically reduced wait times to prevent lag buildup
COLLECT_WAIT    = 0.02
READ_CHUNK      = 65536
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
            if len(chunk) < READ_CHUNK: break # Break instantly if we read partial chunk
        except: break
    return bytes(buf)

async def handle_tunnel(req: web.Request) -> web.Response:
    try: body = await req.json()
    except: return web.Response(status=400)

    sid, frames = body.get("sid", "__anon__"), body.get("frames", [])
    sess = await _get_session(sid)
    out_frames, new_connects, writes_todo = [], [], []

    async with sess.lock:
        out_frames.extend(sess.error_queue)
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
                    elif not cs.failed: cs.pending_data.extend(raw)
            elif ft == "close":
                cs = sess.conns.pop(cid, None)
                if cs and cs.writer:
                    try: cs.writer.close()
                    except: pass

    for cid, host, port in new_connects: asyncio.create_task(_connect_task(sess, cid, host, port))
    
    for writer, raw in writes_todo:
        try:
            writer.write(raw)
            await writer.drain()
        except: pass

    async with sess.lock:
        ready = [(cid, cs.reader) for cid, cs in sess.conns.items() if cs.ready and cs.reader]

    if ready:
        async def read_one(cid, reader): return cid, await _drain_remote(reader), reader.at_eof()
        results = await asyncio.gather(*[read_one(cid, r) for cid, r in ready], return_exceptions=True)

        async with sess.lock:
            for item in results:
                if isinstance(item, Exception): continue
                cid, data, eof = item
                if data: out_frames.append({"t": "data", "id": cid, "d": base64.b64encode(data).decode()})
                if eof:
                    cs = sess.conns.pop(cid, None)
                    if cs and cs.writer:
                        try: cs.writer.close()
                        except: pass
                    out_frames.append({"t": "close", "id": cid})

    return web.json_response({"frames": out_frames})

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
    async def _startup(app): asyncio.create_task(_gc_loop())
    app.on_startup.append(_startup)
    return app

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else BIND_PORT
    web.run_app(create_app(), host=BIND_HOST, port=port, access_log=None)
