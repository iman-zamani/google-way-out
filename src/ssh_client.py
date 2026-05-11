#!/usr/bin/env python3
import asyncio
import base64
import json
import logging
import ssl
import sys
import time
import uuid
import os
import datetime
from urllib.parse import urlparse
from typing import Dict, Optional, Tuple

# ── configuration ──────────────────────────────────────────────────────────────
# COPY THESE FROM YOUR client.py
SERVER_URL    = "https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec" # <-- change this 
VPS_URL       = "http://YOUR_VPS_IP:8080/tunnel"                         # <-- change this 
AUTH_TOKEN    = ""

# ── SSH PORT FORWARDING CONFIG ─────────────────────────────────────────────────
LOCAL_PORT    = 2222
TARGET_HOST   = "127.0.0.1"  # Target the SSH daemon running on the VPS itself
TARGET_PORT   = 22           # Default SSH port

# ── AGGRESSIVE POLLING FOR TERMINAL RESPONSIVENESS ─────────────────────────────
# This will burn quota faster, but it makes the terminal actually usable.
# Close this script when you are done with your SSH session!
FORCE_MIN_DELAY = 0.05  
MAX_IDLE_DELAY  = 1.0   
# ───────────────────────────────────────────────────────────────────────────────

GOOGLE_IPS = ["216.239.38.120", "216.239.32.21", "216.239.34.21", "216.239.36.21", "142.250.181.206", "172.217.16.206"]
SNI_HOST      = "www.google.com"
POST_TIMEOUT  = 35
CHUNK_SIZE    = 1048576 
SESSION_ID    = str(uuid.uuid4())

logging.basicConfig(level=logging.INFO, format="%(asctime)s [SSH-CLIENT] %(levelname)-5s %(message)s")
log = logging.getLogger("tunnel.ssh")

class Conn:
    __slots__ = ("cid", "reader", "writer", "host", "port", "outbuf", "want_open", "local_eof")
    def __init__(self, cid, reader, writer, host, port):
        self.cid, self.reader, self.writer = cid, reader, writer
        self.host, self.port = host, port
        self.outbuf = bytearray()
        self.want_open, self.local_eof = True, False

# [Keep _read_response_headers, _read_chunked, _read_content_length, _read_until_eof exactly the same]
async def _read_response_headers(reader, timeout):
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = await asyncio.wait_for(reader.read(8192), timeout)
        if not chunk: break
        buf.extend(chunk)
    if b"\r\n\r\n" not in buf: return 0, {}, b""
    idx = buf.index(b"\r\n\r\n")
    lines = buf[:idx].split(b"\r\n")
    try: status = int(lines[0].decode(errors="ignore").split()[1])
    except: return 0, {}, b""
    headers = {ln.partition(b":")[0].strip().lower().decode(errors="ignore"): ln.partition(b":")[2].strip().decode(errors="ignore") for ln in lines[1:] if b":" in ln}
    return status, headers, bytes(buf[idx + 4:])

async def _read_chunked(reader, rest, timeout):
    cbuf = rest
    while True:
        while b"\r\n" not in cbuf:
            c = await asyncio.wait_for(reader.read(8192), timeout)
            if not c: return
            cbuf += c
        idx = cbuf.index(b"\r\n")
        try: size = int(cbuf[:idx].decode(errors="ignore").split(";")[0].strip(), 16)
        except: break
        cbuf = cbuf[idx + 2:]
        if size == 0: break
        while len(cbuf) < size + 2:
            c = await asyncio.wait_for(reader.read(8192), timeout)
            if not c: return
            cbuf += c
        yield cbuf[:size]
        cbuf = cbuf[size + 2:]

async def _read_content_length(reader, rest, length, timeout):
    if rest: yield rest[:length]
    read_so_far = min(len(rest), length)
    while read_so_far < length:
        c = await asyncio.wait_for(reader.read(8192), timeout)
        if not c: break
        read_so_far += len(c)
        yield c

async def _read_until_eof(reader, rest, timeout):
    if rest: yield rest
    while True:
        try:
            c = await asyncio.wait_for(reader.read(8192), timeout=2.0)
            if not c: break
            yield c
        except asyncio.TimeoutError: break

class KeepAliveClient:
    def __init__(self):
        self.reader, self.writer = None, None
        self.lock = asyncio.Lock()
        self.ip_index = 0

    async def _connect(self):
        ip = GOOGLE_IPS[self.ip_index]
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        try: self.reader, self.writer = await asyncio.wait_for(asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=SNI_HOST), timeout=15.0)
        except Exception as e:
            self.ip_index = (self.ip_index + 1) % len(GOOGLE_IPS)
            raise e

    def _close(self):
        if self.writer:
            try: self.writer.close()
            except: pass
        self.writer, self.reader = None, None

    async def stream_post(self, url: str, payload: dict, timeout: float):
        parsed = urlparse(url)
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        body_bytes = json.dumps(payload).encode()

        async with self.lock:
            for attempt in range(2):
                try:
                    if not self.writer: await self._connect()
                    req = (f"POST {path} HTTP/1.1\r\nHost: {parsed.netloc}\r\nContent-Type: application/json\r\nContent-Length: {len(body_bytes)}\r\nConnection: keep-alive\r\n\r\n").encode() + body_bytes
                    self.writer.write(req)
                    await self.writer.drain()

                    status, headers, rest = await _read_response_headers(self.reader, timeout)
                    closed_by_server = headers.get("connection", "").lower() == "close"
                    
                    for _ in range(3):
                        if status not in (301, 302, 303, 307, 308): break
                        loc = headers.get("location", "")
                        if not loc: break
                        if "chunked" in headers.get("transfer-encoding", ""):
                            async for _ in _read_chunked(self.reader, rest, timeout): pass
                        elif int(headers.get("content-length", "-1")) >= 0:
                            async for _ in _read_content_length(self.reader, rest, int(headers.get("content-length", "-1")), timeout): pass

                        p = urlparse(loc)
                        self.writer.write((f"GET {p.path + ('?'+p.query if p.query else '')} HTTP/1.1\r\nHost: {p.netloc}\r\nConnection: keep-alive\r\n\r\n").encode())
                        await self.writer.drain()
                        status, headers, rest = await _read_response_headers(self.reader, timeout)
                        if headers.get("connection", "").lower() == "close": closed_by_server = True

                    if status == 0 or closed_by_server: self._close()
                    if status == 0 and attempt == 0: continue 
                    if status != 200: raise Exception(f"HTTP {status}")

                    line_buf = bytearray()
                    async def fill_buffer():
                        if "chunked" in headers.get("transfer-encoding", ""):
                            async for c in _read_chunked(self.reader, rest, timeout): yield c
                        elif int(headers.get("content-length", "-1")) >= 0:
                            async for c in _read_content_length(self.reader, rest, int(headers.get("content-length", "-1")), timeout): yield c
                        else:
                            async for c in _read_until_eof(self.reader, rest, timeout): yield c

                    async for chunk in fill_buffer():
                        line_buf.extend(chunk)
                        while b"\n" in line_buf:
                            line, line_buf = line_buf.split(b"\n", 1)
                            if line.strip(): yield json.loads(line.strip())
                    if line_buf.strip(): yield json.loads(line_buf.strip())
                    return
                except Exception as e:
                    self._close()
                    if attempt == 1: raise e

class SSHTunnelClient:
    def __init__(self):
        self.conns: Dict[int, Conn] = {}
        self._nid, self._lock, self.http, self.wakeup_event = 0, asyncio.Lock(), KeepAliveClient(), asyncio.Event()
        self.requests_today = 0 # Intentionally not saving to JSON to avoid IO bottlenecks during fast polling

    async def _handle_local(self, reader, writer):
        # BYPASS SOCKS5 ENTIRELY - Directly map to target
        async with self._lock:
            self._nid += 1
            cid = self._nid
            conn = Conn(cid, reader, writer, TARGET_HOST, TARGET_PORT)
            self.conns[cid] = conn

        log.info(f"New SSH Local connection mapped to {TARGET_HOST}:{TARGET_PORT} (ID: {cid})")
        self.wakeup_event.set()
        await self._drain_local(conn)
        try: writer.close()
        except: pass

    async def _drain_local(self, conn: Conn):
        try:
            while True:
                data = await conn.reader.read(CHUNK_SIZE)
                if not data:
                    conn.local_eof = True
                    self.wakeup_event.set()
                    break
                async with self._lock: conn.outbuf.extend(data)
                self.wakeup_event.set()
        except Exception:
            conn.local_eof = True
            self.wakeup_event.set()

    async def _poll_loop(self):
        current_delay = FORCE_MIN_DELAY
        last_poll_end = 0.0

        while True:
            self.wakeup_event.clear()
            now = time.monotonic()
            if (now - last_poll_end) < FORCE_MIN_DELAY: await asyncio.sleep(FORCE_MIN_DELAY - (now - last_poll_end))

            sent, rcvd = False, False
            try: sent, rcvd = await self._poll()
            except Exception as e:
                log.error(f"Poll Error: {e}")
                await asyncio.sleep(1.0) 

            last_poll_end = time.monotonic()
            
            # Tighter scaling for SSH
            if sent or rcvd: current_delay = FORCE_MIN_DELAY
            else: current_delay = min(MAX_IDLE_DELAY, current_delay + 0.1)

            time_to_sleep = current_delay - (time.monotonic() - last_poll_end)
            if time_to_sleep > 0:
                try: await asyncio.wait_for(self.wakeup_event.wait(), timeout=time_to_sleep)
                except asyncio.TimeoutError: pass

    async def _poll(self) -> Tuple[bool, bool]:
        frames, to_close, opened_cids, saved_data = [], [], [], {}

        async with self._lock:
            for cid, c in list(self.conns.items()):
                if c.want_open:
                    frame = {"t": "open", "id": cid, "h": c.host, "p": c.port}
                    if c.outbuf:
                        frame["d"] = base64.b64encode(bytes(c.outbuf)).decode()
                        saved_data[cid] = bytes(c.outbuf)
                        c.outbuf.clear()
                    frames.append(frame)
                    opened_cids.append(cid)
                elif c.outbuf:
                    frames.append({"t": "data", "id": cid, "d": base64.b64encode(bytes(c.outbuf)).decode()})
                    saved_data[cid] = bytes(c.outbuf)
                    c.outbuf.clear()
                if c.local_eof and not c.want_open:
                    frames.append({"t": "close", "id": cid})
                    to_close.append(cid)
            for cid in to_close: self.conns.pop(cid, None)

        if not frames and not self.conns: return False, False

        rcvd_something = False
        try:
            async for f in self.http.stream_post(SERVER_URL, {"target": VPS_URL, "token": AUTH_TOKEN, "body": {"sid": SESSION_ID, "frames": frames}}, POST_TIMEOUT):
                rcvd_something = True
                ft, cid = f.get("t"), f.get("id")
                async with self._lock: c = self.conns.get(cid)
                if ft == "data" and c:
                    try:
                        c.writer.write(base64.b64decode(f["d"]))
                        await c.writer.drain()
                    except: pass
                elif ft in ("error", "close"):
                    async with self._lock: c = self.conns.pop(cid, None)
                    if c:
                        try: c.writer.close()
                        except: pass
        except Exception as e:
            async with self._lock:
                for cid, data in saved_data.items():
                    if cid in self.conns: self.conns[cid].outbuf[0:0] = data
            raise e

        self.requests_today += 1
        async with self._lock:
            for cid in opened_cids:
                if cid in self.conns: self.conns[cid].want_open = False

        return len(frames) > 0, rcvd_something

    async def run(self):
        server = await asyncio.start_server(self._handle_local, "127.0.0.1", LOCAL_PORT)
        log.info(f"SSH Fast Tunnel mapping 127.0.0.1:{LOCAL_PORT} -> {TARGET_HOST}:{TARGET_PORT}")
        asyncio.create_task(self._poll_loop())
        async with server: await server.serve_forever()

if __name__ == "__main__":
    try: asyncio.run(SSHTunnelClient().run())
    except KeyboardInterrupt: log.info("Stopped.")
