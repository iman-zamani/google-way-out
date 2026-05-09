[فارسی](README.fa.md)

# google-way-out

A SOCKS5 tunnel that proxies traffic through Google Apps Script, using domain fronting to route connections via Google's infrastructure. Performance is not ideal, but it allows free browsing where direct access is blocked.

---

## How It Works

The system has three components:

1. **Client (`client.py`)** — Runs locally. Exposes a SOCKS5 proxy on `127.0.0.1:1080`. When your browser or application connects through it, the client batches the connection frames and POSTs them to your Google Apps Script deployment. The connection goes out over TLS to a hardcoded Google IP (`216.239.38.120`) with SNI set to `www.google.com`, which means the request looks like ordinary Google traffic from the outside. A smart polling loop with a hard minimum delay between requests ensures you do not exhaust Google's daily URL Fetch quota (20,000 requests/day).

2. **Google Apps Script (`google-script.gs`)** — Acts as a relay. It receives the POST from the client, extracts the target VPS URL and payload, and forwards the request to your VPS using `UrlFetchApp`. It returns whatever the VPS responds with back to the client.

3. **Server (`server.py`)** — Runs on your VPS. Receives tunneled frames from the script relay, opens the actual TCP connections to the requested hosts on behalf of the client, and streams data back through the same channel.

The data flow is:

```
Your App -> SOCKS5 (localhost:1080) -> client.py -> Google Apps Script -> server.py (VPS) -> Internet
```

---

## Requirements

- A VPS with a public IP address
- A Google account to deploy a Google Apps Script
- Python 3.8 or later on the client machine
- `aiohttp` installed on the VPS (`pip install aiohttp`)

---

## Setup

### 1. Deploy the Google Apps Script

1. Go to [https://script.google.com](https://script.google.com) and create a new project.
2. Paste the contents of `src/google-script.gs` into the editor.
3. Click **Deploy > New deployment**.
4. Set the type to **Web app**.
5. Set **Execute as** to your account and **Who has access** to **Anyone**.
6. Click **Deploy** and copy the deployment URL. It will look like:
   `https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec`

### 2. Set Up the VPS Server

Copy `src/server.py` to your VPS and install the dependency:

```bash
pip install aiohttp
```

Run the server. By default it binds to port `8080`:

```bash
python3 server.py
```

To use a different port:

```bash
python3 server.py 9000
```

Make sure the port is open in your firewall. The server exposes one endpoint: `POST /tunnel`.

Optionally, set `AUTH_TOKEN` in `server.py` to a secret string to prevent unauthorized use of your relay.

### 3. Configure and Run the Client

Open `src/client.py` and update the two required values near the top of the file:

```python
SERVER_URL = "https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec"
VPS_URL    = "http://YOUR_VPS_IP:8080/tunnel"
```

If you set an `AUTH_TOKEN` on the server, set the same value in `AUTH_TOKEN` in the client.

Install no additional dependencies are needed for the client. Run it:

```bash
python3 client.py
```

### 4. Configure Your Application

Point your browser or application to use a SOCKS5 proxy at `127.0.0.1:1080`. In most browsers this is found under network or proxy settings.

---

## Advantages Over Similar Tools

- **Streaming connections supported** — unlike pure HTTP relay tools, this implementation keeps connections alive across polls, so chatbots and streaming APIs work correctly.
- **Quota protection** — a hard minimum delay between requests and an adaptive backoff algorithm prevent you from burning through Google's 20,000 daily URL Fetch quota under normal use. Usage is tracked in `gas_quota.json`.
- **No certificate trust required** — you do not need to install or trust any custom certificate on your machine.
- **No elevated privileges required** — no `sudo`, `root`, or administrator access is needed on either the client or the server.

---

## Limitations

This setup will not give you fast or consistent performance. Latency is inherently high because every request must round-trip through Google's script infrastructure. It is suitable for browsing and light API usage, not for high-throughput or latency-sensitive applications.

---

## Credits

This project is written from scratch but the original concept comes from:

[https://github.com/masterking32/MasterHttpRelayVPN](https://github.com/masterking32/MasterHttpRelayVPN)

---

## License

[MIT](LICENSE)
