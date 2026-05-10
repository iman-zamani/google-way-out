#!/usr/bin/env python3
import asyncio
import base64
import json
import logging
import ssl
import struct
import sys
import time
import uuid
import os
import datetime
import zlib
from urllib.parse import urlparse
from typing import Dict, Optional, Tuple

# ── configuration ──────────────────────────────────────────────────────────────

SERVER_URL    = "https://script.google.com/macros/s/your-GAS-path/exec" # <--- change this 
VPS_URL       = "http://VPS_IP/tunnel"                                  # <--- change this 

GOOGLE_IP     = "216.239.38.120"
SNI_HOST      = "www.google.com"

SOCKS5_HOST   = "127.0.0.1"
SOCKS5_PORT   = 1080

FORCE_MIN_DELAY = 0.3  
MAX_IDLE_DELAY  = 4.5  

BYPASS_EXACT_DOMAINS = {"mail.google.com", "www.google.com", "google.com"}
BYPASS_SUFFIXES = (".ir",)

POST_TIMEOUT  = 35
# OPTIMIZATION 1: Allow massive client-side reads
CHUNK_SIZE    = 1048576 
SESSION_ID    = str(uuid.uuid4())
AUTH_TOKEN    = ""

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CLIENT] %(levelname)-5s %(message)s")
log = logging.getLogger("tunnel.client")

# ── per-connection state ───────────────────────────────────────────────────────

class Conn:
    __slots__ = ("cid", "reader", "writer", "host", "port", "outbuf", "want_open", "local_eof")
    def __init__(self, cid, reader, writer, host, port):
        self.cid        = cid
        self.reader     = reader
        self.writer     = writer
        self.host       = host
        self.port       = port
        self.outbuf     = bytearray()
        self.want_open  = True
        self.local_eof  = False

# ── HTTP Stream Readers ────────────────────────────────────────────────────────

async def _read_response_headers(reader, timeout):
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = await asyncio.wait_for(reader.read(8192), timeout)
        if not chunk: break
        buf.extend(chunk)
    if b"\r\n\r\n" not in buf: return 0, {}, b""
    
    idx = buf.index(b"\r\n\r\n")
    header_raw = buf[:idx]
    rest = buf[idx + 4:]
    
    lines = header_raw.split(b"\r\n")
    try: status = int(lines[0].decode(errors="ignore").split()[1])
    except (IndexError, ValueError): return 0, {}, b""
        
    headers = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, _, v = ln.partition(b":")
            headers[k.strip().lower().decode(errors="ignore")] = v.strip().decode(errors="ignore")
    return status, headers, bytes(rest)

async def _read_chunked(reader, rest, timeout):
    cbuf = rest
    while True:
        while b"\r\n" not in cbuf:
            c = await asyncio.wait_for(reader.read(8192), timeout)
            if not c: return
            cbuf += c
        
        idx = cbuf.index(b"\r\n")
        size_hex = cbuf[:idx].decode(errors="ignore").split(";")[0].strip()
        cbuf = cbuf[idx + 2:]
        
        try: size = int(size_hex, 16)
        except ValueError: break
        
        if size == 0:
            while b"\r\n" not in cbuf:
                c = await asyncio.wait_for(reader.read(8192), timeout)
                if not c: break
                cbuf += c
            break
            
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
        self.reader = None
        self.writer = None
        self.lock = asyncio.Lock()

    async def _connect(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(GOOGLE_IP, 443, ssl=ctx, server_hostname=SNI_HOST), timeout=15.0
        )

    def _close(self):
        if self.writer:
            try: self.writer.close()
            except: pass
        self.writer, self.reader = None, None

    # OPTIMIZATION 3: Return an asynchronous generator to yield frames line-by-line
    async def stream_post(self, url: str, payload: dict, timeout: float):
        parsed = urlparse(url)
        path = parsed.path + ("?" + parsed.query if parsed.query else "")
        body_bytes = json.dumps(payload).encode()

        async with self.lock:
            for attempt in range(2):
                try:
                    if not self.writer: await self._connect()

                    req = (
                        f"POST {path} HTTP/1.1\r\n"
                        f"Host: {parsed.netloc}\r\n"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: {len(body_bytes)}\r\n"
                        f"Connection: keep-alive\r\n"
                        f"\r\n"
                    ).encode() + body_bytes

                    self.writer.write(req)
                    await self.writer.drain()

                    status, headers, rest = await _read_response_headers(self.reader, timeout)
                    closed_by_server = headers.get("connection", "").lower() == "close"

                    # Handle 302 Redirects
                    for _ in range(3):
                        if status not in (301, 302, 303, 307, 308): break
                        loc = headers.get("location", "")
                        if not loc: break

                        chunked = "chunked" in headers.get("transfer-encoding", "")
                        clen = int(headers.get("content-length", "-1"))
                        if chunked:
                            async for _ in _read_chunked(self.reader, rest, timeout): pass
                        elif clen >= 0:
                            async for _ in _read_content_length(self.reader, rest, clen, timeout): pass

                        p = urlparse(loc)
                        npath = p.path + ("?" + p.query if p.query else "")
                        follow_req = (f"GET {npath} HTTP/1.1\r\nHost: {p.netloc}\r\nConnection: keep-alive\r\n\r\n").encode()

                        self.writer.write(follow_req)
                        await self.writer.drain()
                        status, headers, rest = await _read_response_headers(self.reader, timeout)
                        if headers.get("connection", "").lower() == "close": closed_by_server = True

                    if status == 0 or closed_by_server: self._close()
                    if status == 0 and attempt == 0: continue 

                    if status != 200:
                        err = b""
                        async for c in _read_until_eof(self.reader, rest, timeout): err += c
                        raise Exception(f"HTTP {status} from relay: {err[:100].decode(errors='ignore')}")

                    chunked = "chunked" in headers.get("transfer-encoding", "")
                    content_len = int(headers.get("content-length", "-1"))

                    line_buf = bytearray()
                    async def fill_buffer():
                        if chunked:
                            async for c in _read_chunked(self.reader, rest, timeout): yield c
                        elif content_len >= 0:
                            async for c in _read_content_length(self.reader, rest, content_len, timeout): yield c
                        else:
                            async for c in _read_until_eof(self.reader, rest, timeout): yield c

                    # Parse frames on-the-fly and yield instantly
                    async for chunk in fill_buffer():
                        line_buf.extend(chunk)
                        while b"\n" in line_buf:
                            line, line_buf = line_buf.split(b"\n", 1)
                            line = line.strip()
                            if line: yield json.loads(line)
                                
                    if line_buf.strip(): yield json.loads(line_buf.strip())
                    return

                except Exception as e:
                    self._close()
                    if attempt == 1: raise e


# ── tunnel client ──────────────────────────────────────────────────────────────

class TunnelClient:
    def __init__(self, server_url: str, socks_host: str, socks_port: int):
        self.url        = server_url
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.conns: Dict[int, Conn] = {}
        self._nid       = 0
        self._lock      = asyncio.Lock()
        self.http       = KeepAliveClient()
        self.wakeup_event = asyncio.Event()  
        
        self.quota_file = "gas_quota.json"
        self.requests_today = self._load_quota()
        self.last_100_time = time.monotonic() 

    def _load_quota(self) -> int:
        try:
            if os.path.exists(self.quota_file):
                with open(self.quota_file, "r") as f:
                    data = json.load(f)
                    if data.get("date") == datetime.date.today().isoformat():
                        return data.get("count", 0)
        except Exception: pass
        return 0

    def _save_quota(self):
        try:
            with open(self.quota_file, "w") as f:
                json.dump({"date": datetime.date.today().isoformat(), "count": self.requests_today}, f)
        except Exception: pass

    def _next_id(self) -> int:
        self._nid += 1
        return self._nid

    def _should_bypass(self, host: str) -> bool:
        if host in BYPASS_EXACT_DOMAINS: return True
        if host.endswith(BYPASS_SUFFIXES): return True
        return False

    async def _socks5(self, reader, writer) -> Optional[tuple]:
        try:
            hdr = await asyncio.wait_for(reader.readexactly(2), 15)
            if hdr[0] != 5: return None
            await reader.readexactly(hdr[1])
            writer.write(b"\x05\x00")
            await writer.drain()

            hdr = await reader.readexactly(4)
            if hdr[0] != 5 or hdr[1] != 1:
                writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return None

            atyp = hdr[3]
            if atyp == 1: host = ".".join(map(str, await reader.readexactly(4)))
            elif atyp == 3:
                n = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(n)).decode()
            elif atyp == 4:
                import socket as _socket
                host = _socket.inet_ntop(_socket.AF_INET6, await reader.readexactly(16))
            else: return None
            
            port = struct.unpack("!H", await reader.readexactly(2))[0]
            return host, port
        except Exception: return None

    async def _handle_local(self, reader, writer):
        should_close = True
        try:
            result = await self._socks5(reader, writer)
            if not result: return
            host, port = result

            if self._should_bypass(host):
                log.info(f"DIRECT ROUTE (Bypassing proxy) -> {host}:{port}")
                try: remote_reader, remote_writer = await asyncio.open_connection(host, port)
                except Exception as e:
                    log.error(f"Direct connection failed to {host}:{port}: {e}")
                    return

                writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                should_close = False 

                async def relay(src, dst):
                    try:
                        while True:
                            data = await src.read(CHUNK_SIZE)
                            if not data: break
                            dst.write(data)
                            await dst.drain()
                    except Exception: pass
                    finally:
                        try: dst.close()
                        except Exception: pass

                asyncio.create_task(relay(reader, remote_writer))
                asyncio.create_task(relay(remote_reader, writer))
                return

            cid = self._next_id()
            conn = Conn(cid, reader, writer, host, port)

            async with self._lock: self.conns[cid] = conn

            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            
            self.wakeup_event.set()
            await self._drain_local(conn)
            
        except Exception: pass
        finally:
            if should_close:
                try: writer.close()
                except Exception: pass

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
            time_since_last = now - last_poll_end
            if time_since_last < FORCE_MIN_DELAY: await asyncio.sleep(FORCE_MIN_DELAY - time_since_last)

            sent_something, rcvd_something = False, False
            try:
                sent_something, rcvd_something = await self._poll()
            except Exception as e:
                log.error(f"poll exception: {e}")
                await asyncio.sleep(1.0) 

            last_poll_end = time.monotonic()

            if sent_something or rcvd_something: current_delay = FORCE_MIN_DELAY
            else: current_delay = min(MAX_IDLE_DELAY, current_delay + 0.2)

            now = time.monotonic()
            time_to_sleep = current_delay - (now - last_poll_end)
            
            if time_to_sleep > 0:
                try: await asyncio.wait_for(self.wakeup_event.wait(), timeout=time_to_sleep)
                except asyncio.TimeoutError: pass

    async def _poll(self) -> Tuple[bool, bool]:
        frames, to_close, opened_cids, saved_data = [], [], [], {}

        async with self._lock:
            for cid, c in list(self.conns.items()):
                if c.want_open:
                    frames.append({"t": "open", "id": cid, "h": c.host, "p": c.port})
                    opened_cids.append(cid)
                if c.outbuf:
                    snapshot = bytes(c.outbuf)
                    # OPTIMIZATION 2: Zlib Compression
                    comp = zlib.compress(snapshot, level=6)
                    frames.append({"t": "data", "id": cid, "d": base64.b64encode(comp).decode()})
                    saved_data[cid] = snapshot
                    c.outbuf.clear()
                if c.local_eof and not c.want_open:
                    frames.append({"t": "close", "id": cid})
                    to_close.append(cid)
            for cid in to_close:
                self.conns.pop(cid, None)

        if not frames and not self.conns:
            return False, False

        proxy_payload = {
            "target": VPS_URL, "token": AUTH_TOKEN,
            "body": {"sid": SESSION_ID, "frames": frames},
        }

        rcvd_something = False

        try:
            # OPTIMIZATION 3: Process JSONL stream as it arrives
            async for f in self.http.stream_post(self.url, proxy_payload, POST_TIMEOUT):
                rcvd_something = True
                ft, cid = f.get("t"), f.get("id")
                async with self._lock: c = self.conns.get(cid)

                if ft == "data" and c:
                    try:
                        raw = base64.b64decode(f["d"])
                        # OPTIMIZATION 2: Decompression with fallback
                        try: raw = zlib.decompress(raw)
                        except Exception: pass
                        c.writer.write(raw)
                        await c.writer.drain()
                    except Exception: pass
                elif ft in ("error", "close"):
                    async with self._lock: c = self.conns.pop(cid, None)
                    if c:
                        try: c.writer.close()
                        except Exception: pass

        except Exception as e:
            async with self._lock:
                for cid, data in saved_data.items():
                    if cid in self.conns: self.conns[cid].outbuf[0:0] = data
            raise e

        # Quota Logic mapped to a successful invocation
        self.requests_today += 1
        if self.requests_today % 100 == 0:
            self._save_quota() 
            remaining = max(0, 20000 - self.requests_today)
            now = time.monotonic()
            avg_time = (now - self.last_100_time) / 100.0
            self.last_100_time = now
            log.info(f"📊 QUOTA: {self.requests_today}/20000 (~{remaining} left). Avg gap: {avg_time:.2f}s/req")

        async with self._lock:
            for cid in opened_cids:
                if cid in self.conns: self.conns[cid].want_open = False

        return len(frames) > 0, rcvd_something

    async def run(self):
        server = await asyncio.start_server(self._handle_local, self.socks_host, self.socks_port)
        log.info(f"SOCKS5     → {self.socks_host}:{self.socks_port}")
        log.info(f"Speed Limit Check: FORCE_MIN_DELAY is set to {FORCE_MIN_DELAY}s")
        log.info(f"Starting Session... Today's Request Count: {self.requests_today}")
        
        asyncio.create_task(self._poll_loop())
        async with server: await server.serve_forever()

if __name__ == "__main__":
    try: asyncio.run(TunnelClient(SERVER_URL, SOCKS5_HOST, SOCKS5_PORT).run())
    except KeyboardInterrupt: log.info("Stopped.")
