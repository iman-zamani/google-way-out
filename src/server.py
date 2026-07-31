#!/usr/bin/env python3
import asyncio
import base64
import json
import logging
import sys
import time
from typing import Dict, List
from aiohttp import web

BIND_HOST       = "127.0.0.1"
BIND_PORT       = 8080
AUTH_TOKEN      = ""

CONNECT_TIMEOUT = 8.0
SESSION_TTL     = 120
GC_INTERVAL     = 30
TUNNEL_MAX_WAIT = 0.1
BIG = 50000  # payloads larger than this go to the thread pool

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SERVER] %(message)s")
log = logging.getLogger("tunnel.server")

def _b64e(d): return base64.b64encode(d).decode()

class ConnState:
    __slots__ = ("reader", "writer", "ready", "failed", "pending_data",
                 "outbound_buf", "remote_eof", "read_task", "tx_seq",
                 "rx_seq", "rx_buffer", "closed_sent")
    def __init__(self):
        self.reader = None; self.writer = None
        self.ready = False; self.failed = False
        self.pending_data = bytearray(); self.outbound_buf = bytearray()
        self.remote_eof = False; self.read_task = None
        self.tx_seq = 0; self.rx_seq = 0; self.rx_buffer = {}; self.closed_sent = False

class SessionState:
    def __init__(self):
        self.conns: Dict[int, ConnState] = {}
        self.error_queue: List[dict] = []
        self.lock = asyncio.Lock()
        self.last_active = time.monotonic()
        self.data_event = asyncio.Event()

sessions: Dict[str, SessionState] = {}
_sess_lock = asyncio.Lock()

async def _get_session(sid: str) -> SessionState:
    async with _sess_lock:
        if sid not in sessions: sessions[sid] = SessionState()
        s = sessions[sid]; s.last_active = time.monotonic()
    return s

async def _background_reader(sess, cid, cs):
    try:
        while True:
            if len(cs.pending_data) > 5242880:
                await asyncio.sleep(0.1); continue
            chunk = await cs.reader.read(65536)
            if not chunk: break
            async with sess.lock:
                cs.pending_data.extend(chunk)
                sess.data_event.set()
    except Exception:
        pass
    finally:
        async with sess.lock:
            cs.remote_eof = True
            sess.data_event.set()

async def _safe_write(writer, raw):
    try:
        writer.write(raw)
        await asyncio.wait_for(writer.drain(), timeout=0.5)
    except Exception:
        pass

async def _connect_task(sess, cid, host, port):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT)
    except Exception as e:
        async with sess.lock:
            if sess.conns.pop(cid, None):
                sess.error_queue.append({"t": "error", "id": cid, "msg": str(e)})
        return
    pending = b""
    async with sess.lock:
        cs = sess.conns.get(cid)
        if not cs:
            w.close(); return
        cs.reader, cs.writer, cs.ready = r, w, True
        if cs.outbound_buf:
            pending = bytes(cs.outbound_buf); cs.outbound_buf.clear()
        cs.read_task = asyncio.create_task(_background_reader(sess, cid, cs))
    if pending:
        asyncio.create_task(_safe_write(w, pending))

def _process_frame_server(sess, cid, cs, f, new_connects, writes_todo):
    ft = f.get("t")
    if ft == "open":
        if "_raw" in f:
            cs.outbound_buf.extend(f["_raw"])
        new_connects.append((cid, f.get("h", ""), int(f.get("p", 0))))
    elif ft == "data":
        raw = f.get("_raw", b"")
        if cs.ready:
            writes_todo.append((cs.writer, raw))
        elif not cs.failed:
            cs.outbound_buf.extend(raw)
    elif ft == "close":
        if cs.read_task: cs.read_task.cancel()
        if cs.writer:
            try: cs.writer.close()
            except: pass

async def handle_tunnel(req: web.Request) -> web.Response:
    start_time = time.monotonic()
    try: body = await req.json()
    except: return web.Response(status=400)

    sid, frames = body.get("sid", "__anon__"), body.get("frames", [])
    sess = await _get_session(sid)
    loop = asyncio.get_running_loop()
    new_connects, writes_todo = [], []

    response = web.StreamResponse()
    response.content_type = 'application/jsonl'
    await response.prepare(req)

    # 1a. Decode inbound payloads OFF the lock (and off the event loop for big
    #     ones) so a single fat upload frame can't stall every other connection.
    for f in frames:
        if f.get("t") in ("open", "data") and "d" in f:
            d = f["d"]
            f["_raw"] = (await loop.run_in_executor(None, base64.b64decode, d)
                         if len(d) > BIG else base64.b64decode(d))

    # 1b. Process inbound under the lock — pure CPU now, no awaits, no I/O.
    err_frames = []
    async with sess.lock:
        if sess.error_queue:
            err_frames = sess.error_queue; sess.error_queue = []
        for f in frames:
            cid, seq, ft = f.get("id"), f.get("seq"), f.get("t")
            if cid is None: continue
            if seq is not None:
                if ft == "open" and cid not in sess.conns:
                    sess.conns[cid] = ConnState()
                cs = sess.conns.get(cid)
                if cs:
                    if seq < cs.rx_seq: continue
                    cs.rx_buffer[seq] = f
                    while cs.rx_seq in cs.rx_buffer:
                        curr_f = cs.rx_buffer.pop(cs.rx_seq)
                        _process_frame_server(sess, cid, cs, curr_f, new_connects, writes_todo)
                        cs.rx_seq += 1
            else:
                if ft == "open" and cid not in sess.conns:
                    sess.conns[cid] = ConnState()
                cs = sess.conns.get(cid)
                if cs: _process_frame_server(sess, cid, cs, f, new_connects, writes_todo)

    # write queued errors AFTER releasing the lock
    if err_frames:
        await response.write(("\n".join(json.dumps(f) for f in err_frames) + "\n").encode())

    # 2. Execute connections & batch writes
    for cid, host, port in new_connects:
        asyncio.create_task(_connect_task(sess, cid, host, port))
    drains_todo = []
    for writer, raw in writes_todo:
        try:
            writer.write(raw); drains_todo.append(writer)
        except Exception:
            pass
    if drains_todo:
        async def drain_all():
            for w in drains_todo:
                try: await w.drain()
                except Exception: pass
        asyncio.create_task(drain_all())

    # 3. Smart wait
    try:
        await asyncio.wait_for(sess.data_event.wait(), timeout=TUNNEL_MAX_WAIT)
        sess.data_event.clear()
    except asyncio.TimeoutError:
        pass

    # 4. Max-min fair extraction (lock held, sync only)
    extracts = []
    global_budget = 3145728
    async with sess.lock:
        active = [(cid, cs) for cid, cs in sess.conns.items()
                  if cs.ready and (len(cs.pending_data) > 0 or (cs.remote_eof and not cs.closed_sent))]
        active.sort(key=lambda x: len(x[1].pending_data))
        for i, (cid, cs) in enumerate(active):
            fair = global_budget // (len(active) - i)
            n = min(len(cs.pending_data), fair)
            data = None
            if n > 0:
                data = bytes(cs.pending_data[:n])
                cs.pending_data = cs.pending_data[n:]
                global_budget -= n
            eof_close = (cs.remote_eof and len(cs.pending_data) == 0 and not cs.closed_sent)
            if data:
                extracts.append((cid, data, False, cs.tx_seq)); cs.tx_seq += 1
            if eof_close:
                cs.closed_sent = True
                extracts.append((cid, None, True, cs.tx_seq)); cs.tx_seq += 1
                if cs.writer:
                    try: cs.writer.close()
                    except: pass
                sess.conns.pop(cid, None)

    # 5. Encode OFF the lock, batch into a single write
    out_lines = []
    for cid, data, eof_close, seq in extracts:
        if data:
            b64 = (await loop.run_in_executor(None, _b64e, data)) if len(data) > BIG else _b64e(data)
            out_lines.append(json.dumps({"t": "data", "id": cid, "seq": seq, "d": b64}))
        elif eof_close:
            out_lines.append(json.dumps({"t": "close", "id": cid, "seq": seq}))
    if out_lines:
        await response.write(("\n".join(out_lines) + "\n").encode())

    await response.write_eof()
    log.info(f"POST {time.monotonic()-start_time:.3f}s | New TCP: {len(new_connects)} | Out: {len(extracts)}")
    return response

async def _gc_loop():
    while True:
        await asyncio.sleep(GC_INTERVAL)
        now = time.monotonic(); to_del = []
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
