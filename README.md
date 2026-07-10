# Homebound

A simple Python-based dashboard that scans local listening TCP sockets, determines if they host HTTP or HTTPS services, and provides a centralized index page for quick access.

## Running the Server

Start the dashboard using Python:

```bash
python3 server.py
```

### Options

* `--host`: Bind address (default: `0.0.0.0`)
* `--port`: Port to run the dashboard on (default: `80`, fallback: `8080` if not run as root)
* `--interval`: Scanning cooldown interval in seconds (default: `60`)

Example:
```bash
python3 server.py --port 8000 --interval 60
```
