#!/usr/bin/env python3
"""
POST Tunnel Server
==================
Receives multiplexed SOCKS5 frames from the client (via Google Apps Script),
opens real TCP connections to each target, and relays data back.

Usage:
    pip install aiohttp
    python server.py 8080
"""

import asyncio
import base64
import logging
import sys
import time
from typing import Dict, List, Optional
from aiohttp import web

BIND_HOST       = "0.0.0.0"
BIND_PORT       = 8080
AUTH_TOKEN      = ""        # must match client AUTH_TOKEN if set

CONNECT_TIMEOUT = 8.0
COLLECT_WAIT    = 0.15
READ_CHUNK      = 65536
READ_TIMEOUT    = 0.05
SESSION_TTL     = 120
GC_INTERVAL     = 30

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(levelname)-5s %(message)s"
)
log = logging.getLogger("tunnel.server")


# ── per-connection state ───────────────────────────────────────────────────────

class ConnState:
    __slots__ = ("reader", "writer", "ready", "failed", "pending_data")

    def __init__(self):
        self.reader:       Optional[asyncio.StreamReader] = None
        self.writer:       Optional[asyncio.StreamWriter] = None
        self.ready:        bool      = False
        self.failed:       bool      = False
        self.pending_data: bytearray = bytearray()


class SessionState:
    def __init__(self):
        self.conns:       Dict[int, ConnState] = {}
        self.error_queue: List[dict]           = []
        self.lock                              = asyncio.Lock()
        self.last_active: float                = time.monotonic()


sessions: Dict[str, SessionState] = {}
_sess_lock = asyncio.Lock()


async def _get_session(sid: str) -> SessionState:
    async with _sess_lock:
        if sid not in sessions:
            sessions[sid] = SessionState()
            log.info(f"New session {sid[:12]}…")
        s = sessions[sid]
        s.last_active = time.monotonic()
    return s


# ── background connect task ────────────────────────────────────────────────────

async def _connect_task(sess: SessionState, cid: int, host: str, port: int):
    log.info(f"[{cid}] connecting → {host}:{port}")
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=CONNECT_TIMEOUT,
        )
    except Exception as e:
        log.warning(f"[{cid}] connect failed: {e}")
        async with sess.lock:
            if sess.conns.pop(cid, None) is not None:
                sess.error_queue.append({"t": "error", "id": cid, "msg": str(e)})
        return

    pending = b""
    async with sess.lock:
        cs = sess.conns.get(cid)
        if cs is None:
            w.close()
            return
        cs.reader = r
        cs.writer = w
        cs.ready  = True
        if cs.pending_data:
            pending = bytes(cs.pending_data)
            cs.pending_data.clear()

    if pending:
        try:
            w.write(pending)
            await w.drain()
        except Exception as e:
            log.warning(f"[{cid}] flush pending failed: {e}")

    log.info(f"[{cid}] connected → {host}:{port}")


# ── remote drain ──────────────────────────────────────────────────────────────

async def _drain_remote(reader: asyncio.StreamReader,
                        budget: float = COLLECT_WAIT) -> bytes:
    buf      = bytearray()
    deadline = asyncio.get_event_loop().time() + budget

    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            break
        try:
            chunk = await asyncio.wait_for(
                reader.read(READ_CHUNK),
                timeout=min(remaining, READ_TIMEOUT),
            )
            if not chunk:
                break
            buf.extend(chunk)
            if len(chunk) < READ_CHUNK:
                break
        except (asyncio.TimeoutError, Exception):
            break

    return bytes(buf)


# ── request handler ────────────────────────────────────────────────────────────

async def handle_tunnel(req: web.Request) -> web.Response:
    # auth check
    if AUTH_TOKEN and req.headers.get("X-Tunnel-Token", "") != AUTH_TOKEN:
        log.warning(f"Rejected {req.remote}: bad token")
        return web.Response(status=401, text="Unauthorized")

    try:
        body = await req.json()
    except Exception:
        return web.Response(status=400, text="Bad JSON")

    sid    = body.get("sid", "__anon__")
    frames = body.get("frames", [])
    sess   = await _get_session(sid)

    out_frames:   list = []
    new_connects: list = []
    writes_todo:  list = []
    has_sent_data       = False

    async with sess.lock:
        out_frames.extend(sess.error_queue)
        sess.error_queue.clear()

        for f in frames:
            ft  = f.get("t")
            cid = f.get("id")

            if ft == "open":
                cs = ConnState()
                sess.conns[cid] = cs
                new_connects.append((cid, f.get("h", ""), int(f.get("p", 0))))

            elif ft == "data":
                cs = sess.conns.get(cid)
                if cs:
                    raw = base64.b64decode(f["d"])
                    if cs.ready:
                        writes_todo.append((cs.writer, raw))
                        has_sent_data = True
                    elif not cs.failed:
                        cs.pending_data.extend(raw)

            elif ft == "close":
                cs = sess.conns.pop(cid, None)
                if cs and cs.writer:
                    try:
                        cs.writer.close()
                    except Exception:
                        pass
                log.info(f"[{sid[:8]}][{cid}] closed by client")

    # spawn connects outside lock
    for cid, host, port in new_connects:
        asyncio.create_task(_connect_task(sess, cid, host, port))

    # forward data outside lock
    for writer, raw in writes_todo:
        try:
            writer.write(raw)
            await writer.drain()
        except Exception as e:
            log.warning(f"remote write error: {e}")

    if has_sent_data:
        await asyncio.sleep(COLLECT_WAIT)

    # read responses
    async with sess.lock:
        ready = [
            (cid, cs.reader)
            for cid, cs in sess.conns.items()
            if cs.ready and cs.reader is not None
        ]

    if ready:
        async def read_one(cid, reader):
            data = await _drain_remote(reader)
            return cid, data, reader.at_eof()

        results = await asyncio.gather(
            *[read_one(cid, r) for cid, r in ready],
            return_exceptions=True,
        )

        async with sess.lock:
            for item in results:
                if isinstance(item, Exception):
                    continue
                cid, data, eof = item
                if data:
                    out_frames.append({
                        "t": "data", "id": cid,
                        "d": base64.b64encode(data).decode(),
                    })
                if eof:
                    log.info(f"[{sid[:8]}][{cid}] remote EOF")
                    cs = sess.conns.pop(cid, None)
                    if cs and cs.writer:
                        try:
                            cs.writer.close()
                        except Exception:
                            pass
                    out_frames.append({"t": "close", "id": cid})

    return web.json_response({"frames": out_frames})


# ── session GC ────────────────────────────────────────────────────────────────

async def _gc_loop():
    while True:
        await asyncio.sleep(GC_INTERVAL)
        now = time.monotonic()
        to_del = []
        async with _sess_lock:
            for sid, sess in sessions.items():
                if now - sess.last_active > SESSION_TTL:
                    to_del.append(sid)
        for sid in to_del:
            async with _sess_lock:
                sess = sessions.pop(sid, None)
            if sess:
                async with sess.lock:
                    n = len(sess.conns)
                    for cs in sess.conns.values():
                        if cs.writer:
                            try:
                                cs.writer.close()
                            except Exception:
                                pass
                log.info(f"GC removed session {sid[:12]}… ({n} conns closed)")


# ── app factory ────────────────────────────────────────────────────────────────

async def create_app() -> web.Application:
    app = web.Application(client_max_size=512 * 1024 * 1024)
    app.router.add_post("/tunnel", handle_tunnel)

    # IMPORTANT: startup hook must be async and return None (not a Task)
    # so aiohttp doesn't await the infinite gc loop before binding the port.
    async def _startup(app):
        asyncio.create_task(_gc_loop())

    app.on_startup.append(_startup)
    return app


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else BIND_PORT
    log.info(f"Starting tunnel server on {BIND_HOST}:{port}")
    log.info(f"Auth: {'enabled' if AUTH_TOKEN else 'DISABLED'}")
    web.run_app(create_app(), host=BIND_HOST, port=port, access_log=None)
