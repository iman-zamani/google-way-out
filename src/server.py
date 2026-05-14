#!/usr/bin/env python3
import asyncio
import base64
import json
import logging
import sys
import time
import random  # BUG 1 FIX: Imported random for connection shuffling
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
    __slots__ = ("reader", "writer", "ready", "failed", "pending_data", 
                 "outbound_buf", "remote_eof", "read_task", "tx_seq", 
                 "rx_seq", "rx_buffer", "closed_sent")
    def __init__(self):
        self.reader = None
        self.writer = None
        self.ready = False
        self.failed = False
        self.pending_data = bytearray()
        self.outbound_buf = bytearray()
        self.remote_eof = False
        self.read_task = None
        
        self.tx_seq = 0
        self.rx_seq = 0
        self.rx_buffer = {}
        self.closed_sent = False

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
    try:
        while True:
            if len(cs.pending_data) > 5242880:
                await asyncio.sleep(0.1)
                continue

            chunk = await cs.reader.read(65536)
            if not chunk:
                break

            async with sess.lock:
                cs.pending_data.extend(chunk)
    except Exception:
        pass
    finally:
        async with sess.lock:
            cs.remote_eof = True

async def _safe_write(writer, raw):
    try:
        writer.write(raw)
        await asyncio.wait_for(writer.drain(), timeout=0.5)
    except Exception: 
        pass

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
        
        if cs.outbound_buf:
            pending = bytes(cs.outbound_buf)
            cs.outbound_buf.clear()
            
        cs.read_task = asyncio.create_task(_background_reader(sess, cid, cs))

    if pending:
        asyncio.create_task(_safe_write(w, pending))

def _process_frame_server(sess, cid, cs, f, new_connects, writes_todo):
    ft = f.get("t")
    if ft == "open":
        if "d" in f:
            cs.outbound_buf.extend(base64.b64decode(f["d"]))
        new_connects.append((cid, f.get("h", ""), int(f.get("p", 0))))
    elif ft == "data":
        raw = base64.b64decode(f["d"])
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
    try: body = await req.json()
    except: return web.Response(status=400)

    sid, frames = body.get("sid", "__anon__"), body.get("frames", [])
    sess = await _get_session(sid)
    new_connects, writes_todo = [], []

    response = web.StreamResponse()
    response.content_type = 'application/jsonl'
    await response.prepare(req)

    # 1. Process Incoming Client Data with Reassembly Buffering
    async with sess.lock:
        for f in sess.error_queue:
            await response.write((json.dumps(f) + "\n").encode())
        sess.error_queue.clear()
        
        for f in frames:
            cid = f.get("id")
            seq = f.get("seq")
            ft  = f.get("t")
            
            if cid is None: continue

            if seq is not None:
                if ft == "open" and cid not in sess.conns:
                    sess.conns[cid] = ConnState()
                cs = sess.conns.get(cid)
                if cs:
                    # BUG 3 FIX: Drop duplicate/old sequences to prevent memory leak
                    if seq < cs.rx_seq:
                        continue

                    cs.rx_buffer[seq] = f
                    # Strict In-Order Processing
                    while cs.rx_seq in cs.rx_buffer:
                        curr_f = cs.rx_buffer.pop(cs.rx_seq)
                        _process_frame_server(sess, cid, cs, curr_f, new_connects, writes_todo)
                        cs.rx_seq += 1
            else:
                # Handle unsequenced backwards compatibility gracefully
                if ft == "open" and cid not in sess.conns:
                    sess.conns[cid] = ConnState()
                cs = sess.conns.get(cid)
                if cs: _process_frame_server(sess, cid, cs, f, new_connects, writes_todo)

    # 2. Execute Connections & Writes
    for cid, host, port in new_connects: 
        asyncio.create_task(_connect_task(sess, cid, host, port))
    
    for writer, raw in writes_todo:
        asyncio.create_task(_safe_write(writer, raw))

    await asyncio.sleep(0.05)


    # 3. Slice globally using Max-Min Fair Allocation (Smallest buffers first)
    extracts = []
    global_budget = 3145728 
    
    async with sess.lock:
        # Get all ready connections that have data or need to send an EOF
        active_conns = [
            (cid, cs) for cid, cs in sess.conns.items() 
            if cs.ready and (len(cs.pending_data) > 0 or (cs.remote_eof and not cs.closed_sent))
        ]
        
        # Sort ascending by amount of pending data. 
        # Smallest (interactive) traffic goes first, heavy downloads go last.
        active_conns.sort(key=lambda x: len(x[1].pending_data))
        
        for i, (cid, cs) in enumerate(active_conns):
            # Calculate fair share: divide the remaining budget by the remaining connections
            remaining_conns = len(active_conns) - i
            fair_share = global_budget // remaining_conns
            
            extract_len = min(len(cs.pending_data), fair_share)
            data = None
            
            if extract_len > 0:
                data = bytes(cs.pending_data[:extract_len])
                del cs.pending_data[:extract_len]
                global_budget -= extract_len
            
            eof_close = (cs.remote_eof and len(cs.pending_data) == 0 and not cs.closed_sent)
            
            if data or eof_close:
                if data:
                    extracts.append((cid, data, False, cs.tx_seq))
                    cs.tx_seq += 1
                if eof_close:
                    cs.closed_sent = True
                    extracts.append((cid, None, True, cs.tx_seq))
                    cs.tx_seq += 1
            
            if eof_close:
                if cs.writer:
                    try: cs.writer.close()
                    except: pass
                sess.conns.pop(cid, None)

    # 4. Stream Sequenced Results Back
    for cid, data, eof_close, seq in extracts:
        if data:
            out_f = {"t": "data", "id": cid, "seq": seq, "d": base64.b64encode(data).decode()}
            await response.write((json.dumps(out_f) + "\n").encode())
        elif eof_close:
            out_f = {"t": "close", "id": cid, "seq": seq}
            await response.write((json.dumps(out_f) + "\n").encode())

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
