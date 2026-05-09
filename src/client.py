#!/usr/bin/env python3
"""
POST Tunnel Client v2
=====================
Key fixes over v1:
  - POST timeout raised to 30 s (server now responds in < 0.5 s normally)
  - Data is requeued (prepended back to buffer) on POST failure
  - "want_open" flag is only cleared AFTER a successful POST, so a timed-out
    open frame is automatically retried on the next poll

Usage:
    pip install aiohttp
    python client.py [server_url] [local_socks5_port]

    Default: python client.py http://localhost:8080/tunnel 1080

Point your browser / app at SOCKS5 proxy 127.0.0.1:1080
"""

import asyncio
import aiohttp
import base64
import logging
import struct
import sys
import time
import uuid
from typing import Dict, Optional

# ── configuration ─────────────────────────────────────────────────────────────
SERVER_URL    = "http://localhost:8080/tunnel"
SOCKS5_HOST   = "127.0.0.1"
SOCKS5_PORT   = 1080
POLL_INTERVAL = 0.8        # seconds — do NOT lower this
POST_TIMEOUT  = 30           # generous ceiling; server replies in ~0.3 s normally
CHUNK_SIZE    = 65536
SESSION_ID    = str(uuid.uuid4())

# Optional shared secret — must match server's AUTH_TOKEN ("" to disable)
AUTH_TOKEN    = ""

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CLIENT] %(levelname)-5s %(message)s"
)
log = logging.getLogger("tunnel.client")


# ── per-connection state ───────────────────────────────────────────────────────

class Conn:
    """State for one proxied TCP stream from the local SOCKS5 client."""
    __slots__ = ("cid", "reader", "writer", "host", "port",
                 "outbuf", "want_open", "local_eof")

    def __init__(self, cid: int, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter, host: str, port: int):
        self.cid       = cid
        self.reader    = reader
        self.writer    = writer
        self.host      = host
        self.port      = port
        self.outbuf    = bytearray()   # local → remote pending bytes
        self.want_open = True          # first successful poll must include "open"
        self.local_eof = False         # set when local app closes its side


# ── tunnel client ─────────────────────────────────────────────────────────────

class TunnelClient:

    def __init__(self, server_url: str, socks_host: str, socks_port: int):
        self.url        = server_url
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.conns      : Dict[int, Conn] = {}
        self._nid       = 0
        self._lock      = asyncio.Lock()
        self._http      : Optional[aiohttp.ClientSession] = None

    def _next_id(self) -> int:
        self._nid += 1
        return self._nid

    # ── SOCKS5 handshake ──────────────────────────────────────────────────────

    async def _socks5(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> Optional[tuple]:
        """Return (host, port) on success, None on failure."""
        try:
            hdr = await asyncio.wait_for(reader.readexactly(2), 15)
        except Exception:
            return None

        ver, nmethods = hdr[0], hdr[1]
        if ver != 5:
            return None

        await reader.readexactly(nmethods)    # discard method list
        writer.write(b"\x05\x00")            # select NO-AUTH
        await writer.drain()

        try:
            hdr = await reader.readexactly(4)
        except Exception:
            return None

        ver, cmd, _, atyp = hdr
        if ver != 5 or cmd != 1:             # CONNECT only
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return None

        try:
            if atyp == 1:                    # IPv4
                raw  = await reader.readexactly(4)
                host = ".".join(map(str, raw))
            elif atyp == 3:                  # domain
                n    = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(n)).decode()
            elif atyp == 4:                  # IPv6
                import socket
                raw  = await reader.readexactly(16)
                host = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                return None
            port = struct.unpack("!H", await reader.readexactly(2))[0]
        except Exception:
            return None

        return host, port

    # ── handle incoming local SOCKS5 connection ───────────────────────────────

    async def _handle_local(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername", ("?", 0))
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

            # Optimistic SOCKS5 success reply — tunnel reports real errors later
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            log.info(f"[{cid}] CONNECT {host}:{port} from {peer[0]}:{peer[1]}")

            # Block here (in this task) reading local data into outbuf until EOF
            await self._drain_local(conn)

        except Exception as e:
            log.debug(f"handle_local: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _drain_local(self, conn: Conn):
        """Read from local socket into conn.outbuf until EOF or error."""
        try:
            while True:
                data = await conn.reader.read(CHUNK_SIZE)
                if not data:
                    conn.local_eof = True
                    break
                async with self._lock:
                    conn.outbuf.extend(data)
        except Exception as e:
            log.debug(f"[{conn.cid}] drain_local: {e}")
            conn.local_eof = True

    # ── poll loop ─────────────────────────────────────────────────────────────

    async def _poll_loop(self):
        """Fire one POST every POLL_INTERVAL seconds, wall-clock aligned."""
        while True:
            t0 = time.monotonic()
            try:
                await self._poll()
            except Exception as e:
                log.error(f"poll exception: {e}")
            elapsed = time.monotonic() - t0
            await asyncio.sleep(max(0.0, POLL_INTERVAL - elapsed))

    async def _poll(self):
        """
        Snapshot all pending frames, POST them, deliver server frames back.

        On POST failure: data is prepended back to outbuf (not lost).
        want_open is cleared only after a confirmed successful POST.
        """
        frames       : list            = []
        to_close     : list            = []
        opened_cids  : list            = []           # reset want_open on success
        saved_data   : Dict[int, bytes] = {}          # for requeue on failure

        async with self._lock:
            for cid, c in list(self.conns.items()):

                if c.want_open:
                    frames.append({"t": "open", "id": cid,
                                   "h": c.host, "p": c.port})
                    opened_cids.append(cid)
                    # Do NOT reset want_open yet — wait for confirmed POST

                if c.outbuf:
                    snapshot = bytes(c.outbuf)
                    frames.append({"t": "data", "id": cid,
                                   "d": base64.b64encode(snapshot).decode()})
                    saved_data[cid] = snapshot
                    c.outbuf.clear()

                # Send close only after the open has been confirmed (want_open=False)
                if c.local_eof and not c.want_open:
                    frames.append({"t": "close", "id": cid})
                    to_close.append(cid)

            for cid in to_close:
                self.conns.pop(cid, None)

        # Nothing to do and no live connections
        if not frames and not self.conns:
            return

        headers = {"X-Tunnel-Token": AUTH_TOKEN} if AUTH_TOKEN else {}
        body    = {"sid": SESSION_ID, "frames": frames}

        # ── POST ──────────────────────────────────────────────────────────────
        try:
            timeout = aiohttp.ClientTimeout(total=POST_TIMEOUT)
            async with self._http.post(
                self.url, json=body, headers=headers, timeout=timeout
            ) as resp:
                if resp.status == 401:
                    log.error("Auth token rejected by server")
                    return
                if resp.status != 200:
                    log.warning(f"Server returned HTTP {resp.status}")
                    return
                reply = await resp.json()

        except Exception as e:
            log.warning(f"POST failed ({e.__class__.__name__}): {e}")
            # Requeue data so it is not lost on transient failures
            async with self._lock:
                for cid, data in saved_data.items():
                    if cid in self.conns:
                        self.conns[cid].outbuf[0:0] = data   # prepend
                # want_open was never cleared, so open frames auto-retry
            return

        # ── POST succeeded: commit state changes ──────────────────────────────
        async with self._lock:
            for cid in opened_cids:
                if cid in self.conns:
                    self.conns[cid].want_open = False

        # ── deliver server→client frames ──────────────────────────────────────
        for f in reply.get("frames", []):
            ft  = f.get("t")
            cid = f.get("id")

            async with self._lock:
                c = self.conns.get(cid)

            if ft == "data" and c:
                try:
                    c.writer.write(base64.b64decode(f["d"]))
                    await c.writer.drain()
                except Exception as e:
                    log.debug(f"[{cid}] write-to-local: {e}")

            elif ft == "error":
                log.warning(f"[{cid}] remote error: {f.get('msg', '?')}")
                async with self._lock:
                    c = self.conns.pop(cid, None)
                if c:
                    try:
                        c.writer.close()
                    except Exception:
                        pass

            elif ft == "close":
                log.debug(f"[{cid}] server closed stream")
                async with self._lock:
                    c = self.conns.pop(cid, None)
                if c:
                    try:
                        c.writer.close()
                    except Exception:
                        pass

    # ── entry point ───────────────────────────────────────────────────────────

    async def run(self):
        connector  = aiohttp.TCPConnector(limit=16)
        self._http = aiohttp.ClientSession(connector=connector)

        server = await asyncio.start_server(
            self._handle_local, self.socks_host, self.socks_port
        )

        log.info(f"SOCKS5 on  {self.socks_host}:{self.socks_port}")
        log.info(f"Tunnel →   {self.url}")
        log.info(f"Session    {SESSION_ID}")
        log.info(f"Interval   {POLL_INTERVAL} s  |  POST timeout {POST_TIMEOUT} s")

        asyncio.create_task(self._poll_loop())

        try:
            async with server:
                await server.serve_forever()
        finally:
            await self._http.close()


# ── main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    url  = sys.argv[1] if len(sys.argv) > 1 else SERVER_URL
    port = int(sys.argv[2]) if len(sys.argv) > 2 else SOCKS5_PORT

    client = TunnelClient(url, SOCKS5_HOST, port)
    try:
        asyncio.run(client.run())
    except KeyboardInterrupt:
        log.info("Stopped.")
