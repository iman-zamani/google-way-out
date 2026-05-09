#!/usr/bin/env python3
"""
POST Tunnel Client - v3 add google as the middle man 
===================================
1. Opens a SOCKS5 proxy on localhost:1080
2. Collects all traffic into frames, POSTs them every 0.8s
3. Uses Domain Fronting: connects to GOOGLE_IP with SNI=www.google.com
   but sends Host: script.google.com — bypasses Iran's SNI filter
4. Google Apps Script relays the payload to your VPS and returns the response
"""

import asyncio
import base64
import json
import logging
import ssl
import struct
import sys
import time
import uuid
from urllib.parse import urlparse
from typing import Dict, Optional, Tuple

# ── configuration ──────────────────────────────────────────────────────────────

SERVER_URL    = "https://script.google.com/macros/s/your-GAS-path/exec" # <--- change this 
VPS_URL       = "http://VPS_IP/tunnel"                                  # <--- change this 

GOOGLE_IP     = "216.239.38.120"   # Google edge IP — shared by script.google.com
SNI_HOST      = "www.google.com"   # SNI shown to Iran's firewall

SOCKS5_HOST   = "127.0.0.1"
SOCKS5_PORT   = 1080
POLL_INTERVAL = 0.8
POST_TIMEOUT  = 35
CHUNK_SIZE    = 65536
SESSION_ID    = str(uuid.uuid4())
AUTH_TOKEN    = ""

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLIENT] %(levelname)-5s %(message)s"
)
log = logging.getLogger("tunnel.client")


# ── per-connection state ───────────────────────────────────────────────────────

class Conn:
    __slots__ = ("cid", "reader", "writer", "host", "port",
                 "outbuf", "want_open", "local_eof")

    def __init__(self, cid, reader, writer, host, port):
        self.cid       = cid
        self.reader    = reader
        self.writer    = writer
        self.host      = host
        self.port      = port
        self.outbuf    = bytearray()
        self.want_open = True
        self.local_eof = False


# ── HTTP response reader ───────────────────────────────────────────────────────

async def _read_response(reader: asyncio.StreamReader,
                         read_timeout: float = 20.0) -> Tuple[int, dict, bytes]:
    """
    Parse one HTTP/1.1 response from `reader`.
    Uses per-chunk timeouts so it never hangs indefinitely.
    Safe to call multiple times on the same keep-alive connection.
    """
    # ── read headers ──────────────────────────────────────────────
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=read_timeout)
        except asyncio.TimeoutError:
            raise TimeoutError("Timed out waiting for response headers")
        if not chunk:
            break
        buf += chunk

    if b"\r\n\r\n" not in buf:
        return 0, {}, b""

    header_raw, rest = buf.split(b"\r\n\r\n", 1)
    lines = header_raw.split(b"\r\n")

    # status line
    try:
        status = int(lines[0].decode(errors="ignore").split()[1])
    except (IndexError, ValueError):
        return 0, {}, b""

    # header dict
    headers: dict = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, _, v = ln.partition(b":")
            headers[k.strip().lower().decode(errors="ignore")] = \
                v.strip().decode(errors="ignore")

    chunked       = "chunked" in headers.get("transfer-encoding", "")
    raw_cl        = headers.get("content-length", "")
    try:
        content_len = int(raw_cl)
    except (ValueError, TypeError):
        content_len = -1   # unknown

    # ── read body ─────────────────────────────────────────────────
    if chunked:
        body = b""
        cbuf = rest
        while True:
            # read until we have a chunk-size line
            while b"\r\n" not in cbuf:
                try:
                    c = await asyncio.wait_for(reader.read(8192), timeout=read_timeout)
                except asyncio.TimeoutError:
                    return status, headers, body
                if not c:
                    return status, headers, body
                cbuf += c

            idx = cbuf.index(b"\r\n")
            size_hex = cbuf[:idx].decode(errors="ignore").split(";")[0].strip()
            cbuf = cbuf[idx + 2:]

            try:
                size = int(size_hex, 16)
            except ValueError:
                break
            if size == 0:
                break

            # read chunk data
            while len(cbuf) < size + 2:
                try:
                    c = await asyncio.wait_for(reader.read(8192), timeout=read_timeout)
                except asyncio.TimeoutError:
                    return status, headers, body + cbuf[:size]
                if not c:
                    return status, headers, body + cbuf[:size]
                cbuf += c

            body += cbuf[:size]
            cbuf  = cbuf[size + 2:]   # skip trailing \r\n

        return status, headers, body

    elif content_len >= 0:
        # exact length known
        body = rest
        while len(body) < content_len:
            try:
                c = await asyncio.wait_for(reader.read(8192), timeout=read_timeout)
            except asyncio.TimeoutError:
                break
            if not c:
                break
            body += c
        return status, headers, body[:content_len]

    else:
        # No framing info (common on short redirect responses).
        # Read with a short timeout until silence — safe for keep-alive
        # because redirect bodies are tiny and end quickly.
        body = rest
        while True:
            try:
                c = await asyncio.wait_for(reader.read(8192), timeout=2.0)
            except asyncio.TimeoutError:
                break
            if not c:
                break
            body += c
        return status, headers, body


# ── domain-fronted POST ────────────────────────────────────────────────────────

async def _fronted_post(url: str, payload: dict, timeout: float) -> dict:
    """
    POST `payload` as JSON using domain fronting:
      - TCP  → GOOGLE_IP:443
      - SNI  → www.google.com  (what Iran's firewall sees)
      - Host → script.google.com  (what Google's edge routes)

    Follows the 302 redirect from Apps Script on the SAME socket
    so no new TLS handshake ever exposes the blocked SNI.
    """
    parsed = urlparse(url)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(GOOGLE_IP, 443, ssl=ctx, server_hostname=SNI_HOST),
        timeout=timeout,
    )

    try:
        body_bytes = json.dumps(payload).encode()
        path       = parsed.path + ("?" + parsed.query if parsed.query else "")

        # Initial POST
        req = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode() + body_bytes

        writer.write(req)
        await writer.drain()

        status, resp_headers, resp_body = await _read_response(reader, timeout)

        # Follow up to 3 redirects on the SAME socket
        for _ in range(3):
            if status not in (301, 302, 303, 307, 308):
                break
            location = resp_headers.get("location", "")
            if not location:
                break

            p = urlparse(location)
            new_path = p.path + ("?" + p.query if p.query else "")

            # 302/303 → GET; 307/308 → keep original method (POST), but
            # GAS always 302s to a GET-able result URL, so GET is correct.
            follow_req = (
                f"GET {new_path} HTTP/1.1\r\n"
                f"Host: {p.netloc}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            ).encode()

            writer.write(follow_req)
            await writer.drain()

            status, resp_headers, resp_body = await _read_response(reader, timeout)

        if status != 200:
            preview = resp_body[:200].decode(errors="ignore")
            raise Exception(f"HTTP {status} from relay:\n{preview}")

        if not resp_body:
            raise Exception("Empty response body from relay")

        try:
            return json.loads(resp_body.decode())
        except json.JSONDecodeError:
            preview = resp_body[:300].decode(errors="ignore")
            raise Exception(f"Relay returned non-JSON:\n{preview}")

    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ── tunnel client ──────────────────────────────────────────────────────────────

class TunnelClient:

    def __init__(self, server_url: str, socks_host: str, socks_port: int):
        self.url        = server_url
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.conns: Dict[int, Conn] = {}
        self._nid  = 0
        self._lock = asyncio.Lock()

    def _next_id(self) -> int:
        self._nid += 1
        return self._nid

    # ── SOCKS5 handshake ───────────────────────────────────────────────────────

    async def _socks5(self, reader, writer) -> Optional[tuple]:
        try:
            hdr = await asyncio.wait_for(reader.readexactly(2), 15)
        except Exception:
            return None

        ver, nmethods = hdr[0], hdr[1]
        if ver != 5:
            return None

        await reader.readexactly(nmethods)
        writer.write(b"\x05\x00")
        await writer.drain()

        try:
            hdr = await reader.readexactly(4)
        except Exception:
            return None

        ver, cmd, _, atyp = hdr
        if ver != 5 or cmd != 1:
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return None

        try:
            if atyp == 1:
                raw  = await reader.readexactly(4)
                host = ".".join(map(str, raw))
            elif atyp == 3:
                n    = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(n)).decode()
            elif atyp == 4:
                import socket as _socket
                raw  = await reader.readexactly(16)
                host = _socket.inet_ntop(_socket.AF_INET6, raw)
            else:
                return None
            port = struct.unpack("!H", await reader.readexactly(2))[0]
        except Exception:
            return None

        return host, port

    async def _handle_local(self, reader, writer):
        try:
            result = await self._socks5(reader, writer)
            if result is None:
                writer.close()
                return

            host, port = result
            cid  = self._next_id()
            conn = Conn(cid, reader, writer, host, port)

            async with self._lock:
                self.conns[cid] = conn

            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            log.info(f"[{cid}] CONNECT {host}:{port}")

            await self._drain_local(conn)
        except Exception as e:
            log.debug(f"handle_local error: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _drain_local(self, conn: Conn):
        try:
            while True:
                data = await conn.reader.read(CHUNK_SIZE)
                if not data:
                    conn.local_eof = True
                    break
                async with self._lock:
                    conn.outbuf.extend(data)
        except Exception:
            conn.local_eof = True

    # ── poll loop ──────────────────────────────────────────────────────────────

    async def _poll_loop(self):
        while True:
            t0 = time.monotonic()
            try:
                await self._poll()
            except Exception as e:
                log.error(f"poll exception: {e}")
            elapsed = time.monotonic() - t0
            await asyncio.sleep(max(0.0, POLL_INTERVAL - elapsed))

    async def _poll(self):
        frames: list     = []
        to_close: list   = []
        opened_cids: list = []
        saved_data: dict  = {}

        async with self._lock:
            for cid, c in list(self.conns.items()):
                if c.want_open:
                    frames.append({"t": "open", "id": cid,
                                   "h": c.host, "p": c.port})
                    opened_cids.append(cid)

                if c.outbuf:
                    snapshot = bytes(c.outbuf)
                    frames.append({"t": "data", "id": cid,
                                   "d": base64.b64encode(snapshot).decode()})
                    saved_data[cid] = snapshot
                    c.outbuf.clear()

                if c.local_eof and not c.want_open:
                    frames.append({"t": "close", "id": cid})
                    to_close.append(cid)

            for cid in to_close:
                self.conns.pop(cid, None)

        if not frames and not self.conns:
            return

        proxy_payload = {
            "target": VPS_URL,
            "token":  AUTH_TOKEN,
            "body":   {"sid": SESSION_ID, "frames": frames},
        }

        try:
            reply = await asyncio.wait_for(
                _fronted_post(self.url, proxy_payload, POST_TIMEOUT),
                timeout=POST_TIMEOUT + 5,
            )

            if "error" in reply and "frames" not in reply:
                log.warning(f"Relay error: {reply['error']}")
                return

        except Exception as e:
            log.warning(f"POST failed ({type(e).__name__}): {e}")
            # put data back so it's retried next poll
            async with self._lock:
                for cid, data in saved_data.items():
                    if cid in self.conns:
                        self.conns[cid].outbuf[0:0] = data
            return

        # commit state: mark opened connections as no longer needing open frame
        async with self._lock:
            for cid in opened_cids:
                if cid in self.conns:
                    self.conns[cid].want_open = False

        # deliver server→client frames
        for f in reply.get("frames", []):
            ft  = f.get("t")
            cid = f.get("id")

            async with self._lock:
                c = self.conns.get(cid)

            if ft == "data" and c:
                try:
                    c.writer.write(base64.b64decode(f["d"]))
                    await c.writer.drain()
                except Exception:
                    pass

            elif ft in ("error", "close"):
                if ft == "error":
                    log.warning(f"[{cid}] remote error: {f.get('msg', '?')}")
                async with self._lock:
                    c = self.conns.pop(cid, None)
                if c:
                    try:
                        c.writer.close()
                    except Exception:
                        pass

    # ── entry point ────────────────────────────────────────────────────────────

    async def run(self):
        server = await asyncio.start_server(
            self._handle_local, self.socks_host, self.socks_port
        )
        log.info(f"SOCKS5     → {self.socks_host}:{self.socks_port}")
        log.info(f"Front IP   → {GOOGLE_IP}  SNI: {SNI_HOST}")
        log.info(f"GAS URL    → {self.url}")
        log.info(f"VPS URL    → {VPS_URL}")
        log.info(f"Session    → {SESSION_ID}")

        asyncio.create_task(self._poll_loop())
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    url  = sys.argv[1] if len(sys.argv) > 1 else SERVER_URL
    port = int(sys.argv[2]) if len(sys.argv) > 2 else SOCKS5_PORT
    try:
        asyncio.run(TunnelClient(url, SOCKS5_HOST, port).run())
    except KeyboardInterrupt:
        log.info("Stopped.")
