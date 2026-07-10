# Homebound

A simple Python-based dashboard that scans local listening TCP sockets, determines if they host HTTP or HTTPS services, and provides a centralized index page for quick access.

## Running the Server

To run the dashboard on port 80, use `sudo` since binding to ports below 1024 requires root privileges:

```bash
sudo python3 server.py
```

If run without root privileges, the server will automatically fall back to port `8080`.

### Options

* `--host`: Bind address (default: `0.0.0.0`)
* `--port`: Port to run the dashboard on (default: `80`, fallback: `8080` if not run as root)
* `--interval`: Scanning cooldown interval in seconds (default: `60`)

Example to run on a custom port:
```bash
python3 server.py --port 8000 --interval 60
```
