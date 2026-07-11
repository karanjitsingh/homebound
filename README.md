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
* `--public`: Disable private restriction and allow connections from any IP address (by default, connections are restricted to localhost, local LAN, and Tailscale networks)

Example to run on a custom port:
```bash
python3 server.py --port 8000 --interval 60
```

## Tailscale HTTPS Support

Homebound can automatically run with HTTPS (TLS) using certificates generated from Tailscale.

### 1. Generate the Certificates
Run the Tailscale cert command to generate your free Let's Encrypt certificates:
```bash
tailscale cert your-tailscale-domain.ts.net
```
This generates two files in your current directory:
* `your-tailscale-domain.ts.net.crt`
* `your-tailscale-domain.ts.net.key`

### 2. Set Up the Directory
Create a directory named `tailscale` under your home directory:
```bash
mkdir -p ~/tailscale
```

Move the generated `.crt` and `.key` files into `~/tailscale/`.

### 3. Create the Domain File
Write your exact Tailscale domain name into a file named `domain` inside `~/tailscale/`:
```bash
echo "your-tailscale-domain.ts.net" > ~/tailscale/domain
```

### 4. Run the Server
When you run the server, it will automatically detect these files, switch its default port to `443` (HTTPS), and start securely. 
* To bind to `443` directly, run the server using `sudo`:
  ```bash
  sudo python3 server.py
  ```
  Access it at `https://your-tailscale-domain.ts.net/`.
* Running without root privileges will fall back to port `8443`. Access it at `https://your-tailscale-domain.ts.net:8443/`.
