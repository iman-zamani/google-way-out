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
from urllib.parse import urlparse
from typing import Dict, Optional, Tuple

# ── configuration ──────────────────────────────────────────────────────────────
# Replace with your list of Google Apps Script deployment URLs
SERVER_URLS = [
    "https://script.google.com/macros/s/your-GAS-path-1/exec",     # <-- change this 
    "https://script.google.com/macros/s/your-GAS-path-2/exec",     # <-- change this 
]
VPS_URL       = "http://VPS_IP/tunnel"                             # <-- change this                                                
GOOGLE_IPS = [
    "216.239.38.120", 
    "216.239.32.21",  
    "216.239.34.21",  
    "216.239.36.21",  
    "142.250.181.206",
    "172.217.16.206"
]
SNI_HOST      = "www.google.com"

SOCKS5_HOST   = "0.0.0.0"
SOCKS5_PORT   = 1080

FORCE_MIN_DELAY = 1.5  
MAX_IDLE_DELAY  = 4.5  
CONCURRENT_POSTS = 5

BYPASS_EXACT_DOMAINS = {"mail.google.com", "www.google.com", "google.com"}
BYPASS_SUFFIXES = (".ir",)

POST_TIMEOUT  = 35
CHUNK_SIZE    = 1048576 
SESSION_ID    = str(uuid.uuid4())
AUTH_TOKEN    = ""

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CLIENT] %(levelname)-5s %(message)s")
log = logging.getLogger("tunnel.client")

class Conn:
    __slots__ = ("cid", "reader", "writer", "host", "port", "outbuf", 
                 "want_open", "local_eof", "tx_seq", "rx_seq", "rx_buffer", "closed_sent")
    def __init__(self, cid, reader, writer, host, port):
        self.cid        = cid
        self.reader     = reader
        self.writer     = writer
        self.host       = host
        self.port       = port
        self.outbuf     = bytearray()
        self.want_open  = True
        self.local_eof  = False
        
        self.tx_seq     = 0
        self.rx_seq     = 0
        self.rx_buffer  = {}
        self.closed_sent = False

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
        self.reader = None
        self.writer = None
        self.lock = asyncio.Lock()
        self.ip_index = 0

    async def _connect(self):
        ip = GOOGLE_IPS[self.ip_index]
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ctx, server_hostname=SNI_HOST), timeout=15.0
            )
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
        loop = asyncio.get_running_loop()
        
        # OFF-LOAD: Avoid blocking on huge JSON payloads serialization
        body_bytes = await loop.run_in_executor(None, lambda: json.dumps(payload).encode())

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

                    async for chunk in fill_buffer():
                        line_buf.extend(chunk)
                        while b"\n" in line_buf:
                            line, line_buf = line_buf.split(b"\n", 1)
                            line = line.strip()
                            if line: 
                                # OFF-LOAD: JSON Loads logic
                                if len(line) > 50000:
                                    yield await loop.run_in_executor(None, json.loads, line)
                                else:
                                    yield json.loads(line)
                                
                    if line_buf.strip():
                        last_line = line_buf.strip()
                        if len(last_line) > 50000:
                            yield await loop.run_in_executor(None, json.loads, last_line)
                        else:
                            yield json.loads(last_line)
                    return

                except Exception as e:
                    self._close()
                    if attempt == 1: raise e

class KeepAlivePool:
    def __init__(self, size: int):
        self.queue = asyncio.Queue()
        for _ in range(size):
            self.queue.put_nowait(KeepAliveClient())

class TunnelClient:
    def __init__(self, server_urls: list, socks_host: str, socks_port: int):
        self.urls       = server_urls
        self.active_urls = list(server_urls)
        self.url_idx    = 0
        self.url_lock   = asyncio.Lock()
        
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.conns: Dict[int, Conn] = {}
        self._nid       = 0
        self._lock      = asyncio.Lock()
        
        self.http_pool  = KeepAlivePool(size=CONCURRENT_POSTS)
        self.wakeup_event = asyncio.Event()  
        
        self.quota_file = "gas_quota.json"
        self.requests_today = self._load_quota()
        self.last_100_time = time.monotonic() 
        self.last_activity = time.monotonic()

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

    async def _get_next_url(self) -> str:
        async with self.url_lock:
            if not self.active_urls:
                raise Exception("All Google Apps Script URLs have been exhausted!")
            url = self.active_urls[self.url_idx % len(self.active_urls)]
            self.url_idx += 1
            return url

    async def _ban_url(self, url: str):
        async with self.url_lock:
            if url in self.active_urls:
                self.active_urls.remove(url)
                log.warning(f"Circuit Breaker triggered: Banned URL {url}. {len(self.active_urls)} active URLs remaining.")

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
                            if dst.is_closing(): break 
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

            try:
                early_data = await asyncio.wait_for(reader.read(CHUNK_SIZE), timeout=0.05)
                if early_data:
                    async with self._lock:
                        conn.outbuf.extend(early_data)
                else:
                    conn.local_eof = True
            except asyncio.TimeoutError:
                pass 

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

    async def _gather_frames(self) -> list:
        frames = []
        loop = asyncio.get_running_loop()
        
        async with self._lock:
            for cid, c in list(self.conns.items()):
                if c.want_open:
                    frame = {"t": "open", "id": cid, "h": c.host, "p": c.port, "seq": c.tx_seq}
                    if c.outbuf:
                        # OFF-LOAD: Base64 Encoding
                        raw_buf = bytes(c.outbuf)
                        if len(raw_buf) > 50000:
                            frame["d"] = await loop.run_in_executor(None, lambda b: base64.b64encode(b).decode(), raw_buf)
                        else:
                            frame["d"] = base64.b64encode(raw_buf).decode()
                        c.outbuf.clear()
                    frames.append(frame)
                    c.tx_seq += 1
                    c.want_open = False
                elif c.outbuf:
                    raw_buf = bytes(c.outbuf)
                    if len(raw_buf) > 50000:
                        encoded = await loop.run_in_executor(None, lambda b: base64.b64encode(b).decode(), raw_buf)
                    else:
                        encoded = base64.b64encode(raw_buf).decode()
                    frames.append({"t": "data", "id": cid, "seq": c.tx_seq, "d": encoded})
                    c.tx_seq += 1
                    c.outbuf.clear()
                
                if c.local_eof and not c.closed_sent and not c.want_open:
                    frames.append({"t": "close", "id": cid, "seq": c.tx_seq})
                    c.tx_seq += 1
                    c.closed_sent = True
                    
        return frames

    async def _process_rx_frame(self, c: Conn, f: dict):
        ft = f.get("t")
        if ft == "data" and "d" in f:
            # 1. STOP writing if the local socket is already closed
            if c.writer.is_closing():
                return
                
            try:
                # OFF-LOAD: Base64 Decoding
                raw_b64 = f["d"]
                if len(raw_b64) > 50000:
                    loop = asyncio.get_running_loop()
                    decoded_data = await loop.run_in_executor(None, base64.b64decode, raw_b64)
                else:
                    decoded_data = base64.b64decode(raw_b64)
                
                c.writer.write(decoded_data)
                await c.writer.drain()
                
            except Exception: 
                # 2. Local connection broke (e.g., user canceled download).
                c.local_eof = True
                try: c.writer.close()
                except Exception: pass
                # 3. Wake up the poller immediately to send {"t": "close"} to the server
                self.wakeup_event.set()
                
        elif ft in ("close", "error"):
            c.local_eof = True
            try: c.writer.close()
            except Exception: pass
            self.conns.pop(c.cid, None)

    async def _handle_rx_frame(self, f: dict):
        self.last_activity = time.monotonic()
        cid = f.get("id")
        seq = f.get("seq")
        
        async with self._lock:
            c = self.conns.get(cid)
            if not c: return
            
            if seq is not None:
                if seq < c.rx_seq:
                    return

                c.rx_buffer[seq] = f
                while c.rx_seq in c.rx_buffer:
                    curr_f = c.rx_buffer.pop(c.rx_seq)
                    await self._process_rx_frame(c, curr_f)
                    c.rx_seq += 1
            else:
                await self._process_rx_frame(c, f)

    async def _do_post(self, frames: list):
        self.requests_today += 1
        if self.requests_today % 100 == 0:
            self._save_quota() 
            now = time.monotonic()
            avg_time = (now - self.last_100_time) / 100.0
            self.last_100_time = now
            log.info(f"📊 Global Activity: {self.requests_today} requests sent today across all URLs. Avg gap: {avg_time:.2f}s/req")

        payload = {
            "target": VPS_URL, "token": AUTH_TOKEN,
            "body": {"sid": SESSION_ID, "frames": frames},
        }

        while True:
            try:
                target_url = await self._get_next_url()
            except Exception as e:
                log.critical(f"FATAL: {e}")
                os._exit(1)

            http_client = await self.http_pool.queue.get()
            success = False
            
            try:
                async for f in http_client.stream_post(target_url, payload, POST_TIMEOUT):
                    asyncio.create_task(self._handle_rx_frame(f))
                success = True
            except Exception as e:
                log.error(f"POST Error on {target_url}: {e}")
                await self._ban_url(target_url)
                async with self._lock:
                    for failed_frame in frames:
                        fcid = failed_frame.get("id")
                        if fcid in self.conns:
                            fc = self.conns[fcid]
                            try: fc.writer.close()
                            except Exception: pass
                            self.conns.pop(fcid, None)
                break
            finally:
                self.http_pool.queue.put_nowait(http_client)
            
            if success:
                break

    async def _poll_loop(self):
        current_delay = FORCE_MIN_DELAY
        last_post_time = 0.0

        while True:
            self.wakeup_event.clear()
            now = time.monotonic()
            
            if (now - self.last_activity) < 5.0:
                current_delay = FORCE_MIN_DELAY
            else:
                current_delay = min(MAX_IDLE_DELAY, current_delay + 0.5)

            time_since_last_post = now - last_post_time
            time_to_wait = max(0, current_delay - time_since_last_post)

            if time_to_wait > 0:
                try:
                    await asyncio.wait_for(self.wakeup_event.wait(), timeout=time_to_wait)
                except asyncio.TimeoutError:
                    pass
            
            now = time.monotonic()
            if now - last_post_time < FORCE_MIN_DELAY:
                await asyncio.sleep(FORCE_MIN_DELAY - (now - last_post_time))

            frames = await self._gather_frames()
            
            if frames or (time.monotonic() - last_post_time) >= current_delay:
                asyncio.create_task(self._do_post(frames))
                last_post_time = time.monotonic()

    async def run(self):
        server = await asyncio.start_server(self._handle_local, self.socks_host, self.socks_port)
        log.info(f"SOCKS5      → {self.socks_host}:{self.socks_port}")
        log.info(f"Active Polling Delay: {FORCE_MIN_DELAY}s (Concurrent Enabled)")
        log.info(f"Starting Session... Load balancing across {len(self.urls)} Google Accounts.")
        
        asyncio.create_task(self._poll_loop())
        async with server: await server.serve_forever()

if __name__ == "__main__":
    try: asyncio.run(TunnelClient(SERVER_URLS, SOCKS5_HOST, SOCKS5_PORT).run())
    except KeyboardInterrupt: log.info("Stopped.")
