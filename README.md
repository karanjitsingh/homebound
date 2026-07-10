# Homebound

A simple, fast, and gorgeous Python-based dashboard that scans local listening TCP sockets on your machine, determines if they host HTTP or HTTPS services, and provides a centralized index page for quick access and redirection.

## Features

- **Port Auto-Discovery**: Reads from `/proc/net/tcp` (and `/proc/net/tcp6`) or falls back to system `ss -tln` command to get active sockets in milliseconds.
- **Concurrent HTTP/HTTPS Verification**: Uses Python's `ThreadPoolExecutor` to probe active ports in parallel for fast loading without slowing down system performance.
- **Root Port 80 Fallback**: Default binds to HTTP port `80`. If run without privileges, it will gracefully warn you and fall back to port `8080`.
- **Premium Glassmorphic UI**: Dashboard uses a beautiful CSS glassmorphic dark-mode interface with Outfit and Plus Jakarta Sans typography, micro-animations, search filter, active scan state indicators, and a one-click "Rescan" trigger.
- **Zero Dependencies**: Built entirely using Python 3 standard library modules (`http.server`, `socket`, `ssl`, `json`, `threading`, etc.). No `pip install` required!

## Installation & Running

Navigate to the project folder and run:

```bash
python3 server.py
```

### Bind to Port 80 (Requires Root/Sudo)

To bind to the standard HTTP port 80:

```bash
sudo python3 server.py --port 80
```

If run without `sudo`, the server will log a permission error and automatically start on port **`8080`**.

### Custom Host, Port, or Scan Interval

You can configure options using arguments:

```bash
python3 server.py --host 127.0.0.1 --port 8000 --interval 60
```

- `--host`: Bind address (default: `0.0.0.0`)
- `--port`: Dashboard server port (default: `80`, fallback: `8080`)
- `--interval`: Background socket auto-rescan interval in seconds (default: `30`)

## How it works

1. **Active Sockets Detection**: The server checks `/proc/net/tcp` & `/proc/net/tcp6` or runs `ss -tln` to quickly fetch all ports that are currently listening for TCP connections on the machine.
2. **Web Verification**: It issues concurrent `GET` / `HEAD` HTTP requests. Sockets that return a response starting with `HTTP/` (under plaintext or TLS/SSL) are verified as active web servers.
3. **Metadata Gathering**: It extracts the `Server:` response header and the page HTML `<title>` tag to list services by name.
4. **Redirection Route**: The dashboard links redirect users through a proxy handler `/redirect/<port>` which automatically resolves to the host domain accessing the dashboard (e.g. localhost, local LAN IP, or Tailscale IP).
