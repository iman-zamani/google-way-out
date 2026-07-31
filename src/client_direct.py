#!/usr/bin/env python3
import asyncio
import base64
import json
import logging
import struct
import sys
import time
import uuid
import resource
import socket
from urllib.parse import urlparse
from typing import Dict, Optional, List
from curl_cffi import requests

# ── Automatically raise the maximum open file limit on macOS/Linux ─────────────
try:
    soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
    target_limit = 65536 if hard_limit == resource.RLIM_INFINITY else hard_limit
    
    if soft_limit < target_limit:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target_limit, hard_limit))
        print(f"[INIT] Raised open file limit from {soft_limit} to {target_limit}")
except Exception as e:
    print(f"[INIT] Warning: Could not raise open file limit automatically: {e}")
# ───────────────────────────────────────────────────────────────────────────────

# ── configuration ──────────────────────────────────────────────────────────────
VPS_URLS = [
    "https://domain1.com/tunnel",
    "https://domain2.com/tunnel",
    "https://domain3.com/tunnel",
    "https://domain4.com/tunnel" 
]

SOCKS5_HOST   = "127.0.0.1"
SOCKS5_PORT   = 1080

# --- DPI Evasion & SNI Fragmentation Settings ---
CF_RESOLVE_HOST      = "domain1.com" 
FRAGMENT_PROXY_PORT  = 10080
FRAGMENT_CHUNK_SIZE  = 10     
FRAGMENT_DELAY       = 0.005  
# ------------------------------------------------

# --- Connection Lifecycle ---
SESSION_ROTATION_INTERVAL = 85  # Seconds before seamlessly switching TLS connection to bypass timeouts
# ------------------------------------------------

FORCE_MIN_DELAY = 0.1  
MAX_IDLE_DELAY  = 1.0  

POST_TIMEOUT  = 35
CHUNK_SIZE    = 65536
SESSION_ID    = str(uuid.uuid4())

BYPASS_EXACT_DOMAINS = {"localhost", "127.0.0.1"} #"connectivitycheck.gstatic.com", "minecraft.nitem.org" }
BYPASS_SUFFIXES = (".local", ".ir") #, "speedtest.net")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CLIENT] %(levelname)-5s %(message)s")
log = logging.getLogger("tunnel.client")

# ── Internal TCP Fragmenting Proxy ─────────────────────────────────────────────
class FragmentingProxy:
    def __init__(self, listen_port, target_hostname, chunk_size, delay):
        self.listen_port = listen_port
        self.target_hostname = target_hostname
        self.chunk_size = chunk_size
        self.delay = delay
        self.target_ip = None
        self._proxy_tasks = set()

    def _resolve_target(self):
        try:
            self.target_ip = socket.gethostbyname(self.target_hostname)
            log.info(f"[PROXY] Domain Fronting -> {self.target_hostname} resolved to {self.target_ip}")
        except Exception as e:
            log.error(f"[PROXY] Failed to resolve {self.target_hostname}: {e}")

    async def handle_client(self, reader, writer):
        try:
            req = await reader.readuntil(b'\r\n\r\n')
            if b"CONNECT" not in req:
                writer.close()
                return
            
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            if not self.target_ip:
                self._resolve_target()
            if not self.target_ip:
                writer.close()
                return

            target_reader, target_writer = await asyncio.open_connection(self.target_ip, 443)
                
            sock = target_writer.get_extra_info('socket')
            if sock is not None:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            async def pump(src, dst, is_hello=False):
                try:
                    if is_hello:
                        first_chunk = await src.read(8192)
                        if first_chunk:
                            for i in range(0, len(first_chunk), self.chunk_size):
                                dst.write(first_chunk[i:i+self.chunk_size])
                                await dst.drain()
                                if self.delay > 0:
                                    await asyncio.sleep(self.delay)
                    while True:
                        data = await src.read(8192)
                        if not data:
                            break
                        dst.write(data)
                        await dst.drain()
                except Exception:
                    pass
                finally:
                    try: dst.write_eof()
                    except: pass
                    try: dst.close()
                    except: pass

            t1 = asyncio.create_task(pump(reader, target_writer, is_hello=True))
            t2 = asyncio.create_task(pump(target_reader, writer, is_hello=False))
            
            self._proxy_tasks.add(t1)
            self._proxy_tasks.add(t2)
            t1.add_done_callback(self._proxy_tasks.discard)
            t2.add_done_callback(self._proxy_tasks.discard)

        except Exception:
            try: writer.close()
            except: pass

    async def start(self):
        self._resolve_target()
        server = await asyncio.start_server(self.handle_client, '127.0.0.1', self.listen_port)
        log.info(f"[PROXY] Internal DPI Evasion Proxy bound to 127.0.0.1:{self.listen_port}")
        async with server:
            await server.serve_forever()

# ── Core Tunnel Logic ──────────────────────────────────────────────────────────
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

class TunnelClient:
    def __init__(self, vps_urls: List[str], socks_host: str, socks_port: int):
        self.vps_urls   = vps_urls if vps_urls else ["http://127.0.0.1"]
        self.url_idx    = 0
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.conns: Dict[int, Conn] = {}
        self._nid       = 0
        self._lock      = asyncio.Lock()
        
        self.session_lock = asyncio.Lock()
        self.session = self._create_session()
        self.current_url = self.vps_urls[self.url_idx]
        self.session_time = time.monotonic()
        
        self.wakeup_event = asyncio.Event()  
        self._direct_tasks = set()
        self.last_activity = time.monotonic()
        
        self.pending_force_closes = set() # Graveyard for server-notification

    def _create_session(self):
        proxy_url = f"http://127.0.0.1:{FRAGMENT_PROXY_PORT}"
        return requests.AsyncSession(
            impersonate="chrome", 
            verify=False,
            proxies={"https": proxy_url, "http": proxy_url}
        )

    async def _seamless_handover(self):
        next_idx = (self.url_idx + 1) % len(self.vps_urls)
        next_url = self.vps_urls[next_idx]
        
        new_session = self._create_session()
        
        try:
            # TRUE PRE-WARMING
            await new_session.post(next_url, json={"sid": "warmup", "frames": []}, timeout=10)
        except Exception:
            pass
        
        async with self.session_lock:
            if time.monotonic() - self.session_time < 5.0:
                return 
            
            old_session = self.session
            self.session = new_session
            self.current_url = next_url
            self.url_idx = next_idx
            self.session_time = time.monotonic()
        
        log.info(f"🔄 Seamless Handover -> Pre-warmed & routed to {urlparse(next_url).hostname}")
        
        await asyncio.sleep(45.0) 
        try:
            close_task = old_session.close()
            if asyncio.iscoroutine(close_task):
                await close_task
        except Exception: 
            pass

    async def _session_recycler(self):
        while True:
            await asyncio.sleep(SESSION_ROTATION_INTERVAL)
            await self._seamless_handover()

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

                t1 = asyncio.create_task(relay(reader, remote_writer))
                t2 = asyncio.create_task(relay(remote_reader, writer))
                self._direct_tasks.add(t1)
                self._direct_tasks.add(t2)
                t1.add_done_callback(self._direct_tasks.discard)
                t2.add_done_callback(self._direct_tasks.discard)
                return

            cid = self._next_id()
            conn = Conn(cid, reader, writer, host, port)
            async with self._lock: self.conns[cid] = conn

            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            try:
                early_data = await asyncio.wait_for(reader.read(CHUNK_SIZE), timeout=0.2)
                if early_data:
                    async with self._lock:
                        conn.outbuf.extend(early_data)
                else:
                    conn.local_eof = True
            except asyncio.TimeoutError:
                pass 

            self.wakeup_event.set()
            should_close = False
            await self._drain_local(conn)
            
        except Exception: pass
        finally:
            if should_close:
                try: writer.close()
                except Exception: pass

    async def _drain_local(self, conn: Conn):
        try:
            while True:
                # BACKPRESSURE: If outbuf is larger than ~4MB, wait before reading more.
                # This prevents the OOM Killer if the VPS connection stalls.
                while len(conn.outbuf) > 4194304:
                    await asyncio.sleep(0.1)
                    if conn.local_eof: return # Exit if closed while sleeping

                data = await conn.reader.read(CHUNK_SIZE)
                if not data:
                    conn.local_eof = True
                    self.wakeup_event.set()
                    break
                
                async with self._lock: 
                    conn.outbuf.extend(data)
                self.wakeup_event.set()
        except Exception:
            conn.local_eof = True
            self.wakeup_event.set()
    async def _gather_frames(self) -> list:
        frames = []
        loop = asyncio.get_running_loop()
        
        async with self._lock:
            # POST-MORTEM GRAVEYARD: Send explicit closes to server for connections that failed POSTs
            for fcid in self.pending_force_closes:
                frames.append({"t": "close", "id": fcid, "seq": 0})
            self.pending_force_closes.clear()

            for cid, c in list(self.conns.items()):
                if c.want_open:
                    frame = {"t": "open", "id": cid, "h": c.host, "p": c.port, "seq": c.tx_seq}
                    if c.outbuf:
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
            if c.writer.is_closing(): return
            try:
                raw_b64 = f["d"]
                if len(raw_b64) > 50000:
                    loop = asyncio.get_running_loop()
                    decoded_data = await loop.run_in_executor(None, base64.b64decode, raw_b64)
                else:
                    decoded_data = base64.b64decode(raw_b64)
                
                c.writer.write(decoded_data)
                await c.writer.drain()
            except Exception: 
                c.local_eof = True
                try: c.writer.close()
                except Exception: pass
                self.wakeup_event.set()
                
        elif ft in ("close", "error"):
            c.local_eof = True
            try: c.writer.close()
            except Exception: pass
            self.conns.pop(c.cid, None)

    async def _handle_rx_frame(self, f: dict):
        cid = f.get("id")
        seq = f.get("seq")
        
        # Immediate teardown overrides sequencing
        if f.get("t") in ("close", "error"):
            async with self._lock:
                c = self.conns.pop(cid, None)
                if c:
                    c.local_eof = True
                    try: c.writer.close()
                    except Exception: pass
            return

        async with self._lock:
            c = self.conns.get(cid)
            if not c: return
            
            if seq is not None:
                if seq < c.rx_seq: return
                c.rx_buffer[seq] = f
                
                # DEADLOCK PREVENTION
                if len(c.rx_buffer) > 64:
                    c.local_eof = True
                    try: c.writer.close()
                    except Exception: pass
                    self.conns.pop(cid, None)
                    return

                while c.rx_seq in c.rx_buffer:
                    curr_f = c.rx_buffer.pop(c.rx_seq)
                    await self._process_rx_frame(c, curr_f)
                    c.rx_seq += 1
            else:
                await self._process_rx_frame(c, f)

    async def _do_post(self, frames: list):
        payload = {"sid": SESSION_ID, "frames": frames}

        async with self.session_lock:
            active_session = self.session
            active_url = self.current_url

        success = False
        for attempt in range(2):
            try:
                response = await active_session.post(
                    active_url, 
                    json=payload, 
                    timeout=POST_TIMEOUT
                )
                
                if response.status_code != 200:
                    raise Exception(f"HTTP {response.status_code}: {response.text}")

                lines = response.content.split(b"\n")
                for line in lines:
                    line = line.strip()
                    if line:
                        try:
                            frame = json.loads(line)
                            asyncio.create_task(self._handle_rx_frame(frame))
                        except json.JSONDecodeError:
                            log.error("Received malformed JSON/HTML from server (likely Cloudflare intercept).")
                            continue # Skip
                success = True
                break 
                
            except Exception as e:
                err_str = str(e)
                
                if "55" not in err_str and "35" not in err_str and "SessionClosed" not in err_str and "HTTP 0" not in err_str: 
                    log.error(f"POST Error (Attempt {attempt+1}): {type(e).__name__} - {err_str}")
                
                if "28" in err_str or "Timeout" in err_str or "time" in err_str.lower() or "55" in err_str or "35" in err_str or "SessionClosed" in err_str or "HTTP 0" in err_str:
                    await self._seamless_handover()
                    async with self.session_lock:
                        active_session = self.session
                        active_url = self.current_url
                else:
                    await asyncio.sleep(0.5)
        
        # PROPER CLEANUP: Ensure the server gets notified of lost connections
        if not success and frames:
            async with self._lock:
                for failed_frame in frames:
                    fcid = failed_frame.get("id")
                    if fcid in self.conns:
                        fc = self.conns[fcid]
                        try: fc.writer.close()
                        except Exception: pass
                        self.conns.pop(fcid, None)
                        self.pending_force_closes.add(fcid)

    async def _poll_loop(self):
        current_delay = FORCE_MIN_DELAY
        last_post_time = 0.0

        while True:
            self.wakeup_event.clear()
            is_active = len(self.conns) > 0
            
            if is_active:
                if (time.monotonic() - self.last_activity) < 5.0:
                    current_delay = FORCE_MIN_DELAY
                else:
                    current_delay = min(MAX_IDLE_DELAY, current_delay + 0.5)
            else:
                current_delay = 20.0

            time_since_last_post = time.monotonic() - last_post_time
            time_to_wait = max(0, current_delay - time_since_last_post)

            if time_to_wait > 0:
                try:
                    await asyncio.wait_for(self.wakeup_event.wait(), timeout=time_to_wait)
                except asyncio.TimeoutError:
                    pass
            
            if (time.monotonic() - last_post_time) < FORCE_MIN_DELAY:
                await asyncio.sleep(FORCE_MIN_DELAY - (time.monotonic() - last_post_time))

            frames = await self._gather_frames()
            
            if frames or (time.monotonic() - last_post_time) >= current_delay:
                asyncio.create_task(self._do_post(frames))
                last_post_time = time.monotonic()

    async def run(self):
        proxy = FragmentingProxy(FRAGMENT_PROXY_PORT, CF_RESOLVE_HOST, FRAGMENT_CHUNK_SIZE, FRAGMENT_DELAY)
        asyncio.create_task(proxy.start())
        await asyncio.sleep(0.5) 

        server = await asyncio.start_server(self._handle_local, self.socks_host, self.socks_port)
        log.info(f"SOCKS5      → {self.socks_host}:{self.socks_port}")
        log.info(f"Targeting {len(self.vps_urls)} VPS endpoint(s).")
        log.info(f"Active Polling Delay: {FORCE_MIN_DELAY}s")
        log.info(f"Rotation Interval: Every {SESSION_ROTATION_INTERVAL}s")
        log.info("Impersonating Chromium TLS fingerprint to bypass DPI.")
        
        asyncio.create_task(self._session_recycler())
        asyncio.create_task(self._poll_loop())
        async with server: 
            await server.serve_forever()

if __name__ == "__main__":
    try: 
        asyncio.run(TunnelClient(VPS_URLS, SOCKS5_HOST, SOCKS5_PORT).run())
    except KeyboardInterrupt: 
        log.info("Stopped.")

