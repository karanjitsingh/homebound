#!/usr/bin/env python3
import os
import sys
import json
import socket
import ssl
import time
import re
import threading
import argparse
import subprocess
import http.server
from concurrent.futures import ThreadPoolExecutor
import ipaddress

# File to store user customizations
CUSTOMIZATIONS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "customizations.json")

# Global server state
class ServerState:
    def __init__(self, host="0.0.0.0", port=80, scan_interval=60):
        self.host = host
        self.port = port
        self.scan_interval = scan_interval
        self.discovered_servers = []
        self.is_scanning = False
        self.last_scan_time = 0
        self.needs_refresh_scan = False
        self.lock = threading.Lock()

server_state = None

def hex_to_ip(hex_str):
    """Converts hex representations from /proc/net/tcp into standard IP strings."""
    if len(hex_str) == 8:
        # IPv4 representation
        try:
            addr = [int(hex_str[i:i+2], 16) for i in range(0, 8, 2)]
            addr.reverse()  # Little-endian swap
            return ".".join(map(str, addr))
        except Exception:
            return "127.0.0.1"
    elif len(hex_str) == 32:
        # IPv6 representation
        if hex_str == "00000000000000000000000000000001":
            return "::1"
        elif hex_str == "00000000000000000000000000000000":
            return "::"
        # Return fallback IPv6 loopback
        return "::1"
    return "127.0.0.1"

def load_customizations():
    """Loads custom titles and images from customizations.json."""
    if os.path.exists(CUSTOMIZATIONS_FILE):
        try:
            with open(CUSTOMIZATIONS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_customizations(data):
    """Saves user customizations to customizations.json."""
    try:
        with open(CUSTOMIZATIONS_FILE, "w") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"[Homebound] Error saving customizations: {e}")

def update_customization(port, title, image, ignored=None):
    """Updates customization fields for a specific port."""
    customs = load_customizations()
    port_str = str(port)
    if port_str not in customs:
        customs[port_str] = {}
    
    if title is not None:
        customs[port_str]["title"] = title.strip()
    if image is not None:
        customs[port_str]["image"] = image.strip()
    if ignored is not None:
        customs[port_str]["ignored"] = bool(ignored)
        
    save_customizations(customs)

def get_listening_sockets_proc():
    """Gets list of all listening TCP sockets as (ip, port) tuples from /proc/net/tcp & tcp6."""
    sockets = []
    for filepath in ['/proc/net/tcp', '/proc/net/tcp6']:
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()
            for line in lines[1:]:  # Skip header
                parts = line.strip().split()
                if len(parts) >= 4:
                    state = parts[3]
                    if state == '0A':  # TCP_LISTEN
                        local_addr = parts[1]
                        ip_hex, port_hex = local_addr.split(':')
                        port = int(port_hex, 16)
                        ip = hex_to_ip(ip_hex)
                        
                        # Normalize 0.0.0.0 or :: to loopbacks for connection testing
                        if ip == "0.0.0.0":
                            ip = "127.0.0.1"
                        elif ip == "::":
                            ip = "::1"
                        sockets.append((ip, port))
        except Exception:
            pass
    return sockets

def get_listening_sockets_ss():
    """Gets list of listening TCP sockets as (ip, port) tuples from 'ss -tln'."""
    sockets = []
    try:
        result = subprocess.run(['ss', '-tln'], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            for line in result.stdout.splitlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 4:
                    addr = parts[3]
                    port_match = re.search(r':(\d+)$', addr)
                    if port_match:
                        port = int(port_match.group(1))
                        ip = addr[:port_match.start()]
                        
                        # Normalize formats
                        if ip == "*" or ip == "0.0.0.0":
                            ip = "127.0.0.1"
                        elif ip == "[::]" or ip == "::":
                            ip = "::1"
                        elif ip.startswith("[") and ip.endswith("]"):
                            ip = ip[1:-1]
                        sockets.append((ip, port))
    except Exception:
        pass
    return sockets

def resolve_relative_path(href, request_path):
    if href.startswith("http://") or href.startswith("https://") or href.startswith("//"):
        return href
    if href.startswith("/"):
        return href
    
    if href.startswith("./"):
        href = href[2:]
        
    if request_path.endswith("/"):
        base_dir = request_path
    else:
        parts = request_path.split("/")
        if len(parts) > 1:
            base_dir = "/".join(parts[:-1]) + "/"
        else:
            base_dir = "/"
            
    resolved = base_dir + href
    resolved = re.sub(r'/+', '/', resolved)
    return resolved

def parse_http_response(data, port, protocol, latency, host, request_path="/"):
    """Parses initial HTTP response chunk to extract status code, server type, and HTML title/favicon."""
    decoded = data.decode("utf-8", errors="ignore")
    lines = decoded.split("\r\n")
    
    # Parse status code
    status_code = 200
    if lines:
        status_match = re.match(r"^HTTP/\d+\.\d+\s+(\d+)", lines[0])
        if status_match:
            status_code = int(status_match.group(1))
            
    headers = {}
    body = ""
    in_body = False
    
    for line in lines:
        if in_body:
            body += line + "\n"
        elif line == "":
            in_body = True
        else:
            parts = line.split(":", 1)
            if len(parts) == 2:
                headers[parts[0].strip().lower()] = parts[1].strip()
                
    server = headers.get("server", "Unknown")
    
    # Extract HTML title
    title = "HTTP Service"
    title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if title_match:
        title = title_match.group(1).strip()
    else:
        # Check standard defaults or signatures
        if port == 9091:
            title = "Transmission Web Control"
            server = "Transmission"
        elif port == 2019:
            title = "Caddy Admin API"
            server = "Caddy"
        elif port == 631:
            title = "CUPS Dashboard"
            server = "CUPS"
        else:
            title = f"Port {port} Service"

    # Extract favicon path
    favicon_path = None
    link_tags = re.findall(r'<link\s+[^>]*>', body, re.IGNORECASE)
    for tag in link_tags:
        if re.search(r'rel\s*=\s*["\']([^"\']*icon[^"\']*)["\']', tag, re.IGNORECASE):
            href_match = re.search(r'href\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
            if href_match:
                favicon_path = href_match.group(1).strip()
                break

    if favicon_path:
        favicon = resolve_relative_path(favicon_path, request_path)
    else:
        favicon = "/favicon.ico"

    # Extract metadata tags
    app_name = None
    description = None
    meta_tags = re.findall(r'<meta\s+[^>]*>', body, re.IGNORECASE)
    for tag in meta_tags:
        name_match = re.search(r'(?:name|property)\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
        content_match = re.search(r'content\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
        if name_match and content_match:
            name_val = name_match.group(1).lower()
            content_val = content_match.group(1).strip()
            if name_val in ("application-name", "apple-mobile-web-app-title", "og:site_name"):
                if not app_name:
                    app_name = content_val
            elif name_val in ("description", "og:description"):
                if not description:
                    description = content_val

    return {
        "port": port,
        "protocol": protocol,
        "server": server,
        "title": title,
        "app_name": app_name or title,
        "description": description,
        "latency_ms": latency,
        "status_code": status_code,
        "is_http": True,
        "ip": host,
        "favicon": favicon
    }

def check_http_port(host, port, timeout=0.4):
    """Probes a specific port on host to check if it's running HTTP or HTTPS, following local redirects."""
    start_time = time.time()
    family = socket.AF_INET
    if ":" in host:
        family = socket.AF_INET6

    # 1. Probe HTTP (plain TCP first)
    current_path = "/web/index.html" if port == 32400 else "/"
    for redirect_depth in range(3):
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            req = f"GET {current_path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
            sock.sendall(req.encode())
            data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
            latency = int((time.time() - start_time) * 1000)
            sock.close()
            
            if data.startswith(b"HTTP/"):
                res = parse_http_response(data, port, "http", latency, host, current_path)
                if res["status_code"] in (301, 302, 303, 307, 308):
                    decoded = data.decode("utf-8", errors="ignore")
                    loc_match = re.search(r"(?i)^Location:\s*([^\r\n]+)", decoded, re.MULTILINE)
                    if loc_match:
                        loc = loc_match.group(1).strip()
                        if loc.startswith("http://") or loc.startswith("https://"):
                            from urllib.parse import urlparse
                            parsed = urlparse(loc)
                            if parsed.netloc and parsed.netloc != f"{host}:{port}" and parsed.netloc != host:
                                return res  # External redirect, don't follow
                            current_path = parsed.path or "/"
                            if parsed.query:
                                current_path += "?" + parsed.query
                        elif loc.startswith("/"):
                            current_path = loc
                        else:
                            if current_path.endswith("/"):
                                base_dir = current_path
                            else:
                                parts = current_path.split("/")
                                if len(parts) > 1:
                                    base_dir = "/".join(parts[:-1]) + "/"
                                else:
                                    base_dir = "/"
                            current_path = base_dir + loc
                            current_path = re.sub(r'/+', '/', current_path)
                        continue  # Follow redirect
                return res
        except Exception:
            pass
        break

    # 2. Probe HTTPS (TLS wrapping)
    current_path = "/web/index.html" if port == 32400 else "/"
    for redirect_depth in range(3):
        try:
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            ssl_sock.connect((host, port))
            
            req = f"GET {current_path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
            ssl_sock.sendall(req.encode())
            data = b""
            while True:
                chunk = ssl_sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
            latency = int((time.time() - start_time) * 1000)
            ssl_sock.close()
            
            if data.startswith(b"HTTP/"):
                res = parse_http_response(data, port, "https", latency, host, current_path)
                if res["status_code"] in (301, 302, 303, 307, 308):
                    decoded = data.decode("utf-8", errors="ignore")
                    loc_match = re.search(r"(?i)^Location:\s*([^\r\n]+)", decoded, re.MULTILINE)
                    if loc_match:
                        loc = loc_match.group(1).strip()
                        if loc.startswith("http://") or loc.startswith("https://"):
                            from urllib.parse import urlparse
                            parsed = urlparse(loc)
                            if parsed.netloc and parsed.netloc != f"{host}:{port}" and parsed.netloc != host:
                                return res  # External redirect, don't follow
                            current_path = parsed.path or "/"
                            if parsed.query:
                                current_path += "?" + parsed.query
                        elif loc.startswith("/"):
                            current_path = loc
                        else:
                            if current_path.endswith("/"):
                                base_dir = current_path
                            else:
                                parts = current_path.split("/")
                                if len(parts) > 1:
                                    base_dir = "/".join(parts[:-1]) + "/"
                                else:
                                    base_dir = "/"
                            current_path = base_dir + loc
                            current_path = re.sub(r'/+', '/', current_path)
                        continue  # Follow redirect
                return res
        except Exception:
            pass
        break

    return None

def scan_ports_parallel(sockets):
    """Scans list of (ip, port) sockets concurrently using thread pool."""
    discovered = []
    # Deduplicate sockets
    unique_sockets = list(set(sockets))
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(check_http_port, ip, port): (ip, port) for ip, port in unique_sockets}
        for future in futures:
            ip, port = futures[future]
            try:
                res = future.result()
                if res:
                    discovered.append(res)
                else:
                    # Generic TCP listener
                    server_name = "TCP Listener"
                    if port == 22:
                        server_name = "SSH Server"
                    elif port == 6379:
                        server_name = "Redis Database"
                    elif port == 3306:
                        server_name = "MySQL Database"
                    elif port == 5432:
                        server_name = "PostgreSQL Database"
                    elif port == 27017:
                        server_name = "MongoDB Database"

                    discovered.append({
                        "port": port,
                        "protocol": "tcp",
                        "server": server_name,
                        "title": f"Port {port} Connection",
                        "app_name": f"Port {port} Connection",
                        "description": None,
                        "latency_ms": 0,
                        "status_code": 0,
                        "is_http": False,
                        "ip": ip
                    })
            except Exception:
                pass
    # Deduplicate results by port
    deduplicated = {}
    for item in discovered:
        port = item["port"]
        if port not in deduplicated:
            deduplicated[port] = item
        else:
            existing = deduplicated[port]
            # Preference 1: Keep HTTP service over generic TCP
            if item.get("is_http", False) and not existing.get("is_http", False):
                deduplicated[port] = item
            # Preference 2: If both are same protocol type, prefer IPv4 (127.0.0.1) over IPv6 (::1)
            elif item.get("is_http", False) == existing.get("is_http", False):
                if item["ip"] == "127.0.0.1" or ":" not in item["ip"]:
                    deduplicated[port] = item
                    
    return sorted(deduplicated.values(), key=lambda x: x["port"])

def run_scan():
    """Fetches listening ports, runs verification scanning, and applies user customizations."""
    global server_state
    with server_state.lock:
        if server_state.is_scanning:
            return
        server_state.is_scanning = True
        
    try:
        print("[Homebound] Scanning local listening ports...")
        start_time = time.time()
        
        sockets = get_listening_sockets_proc()
        if not sockets:
            sockets = get_listening_sockets_ss()
        
        # Filter out the server's own port
        sockets = [s for s in sockets if s[1] != server_state.port]

        if not sockets:
            print("[Homebound] No active ports found. Using defaults list on 127.0.0.1.")
            default_ports = [22, 80, 443, 631, 2019, 3000, 3001, 4000, 5000, 5001, 8000, 8080, 8081, 8888, 9000, 9090, 9091, 9999]
            sockets = [("127.0.0.1", p) for p in default_ports if p != server_state.port]
            
        results = scan_ports_parallel(sockets)
        
        # Apply name/image customizations
        customs = load_customizations()
        for s in results:
            port_str = str(s["port"])
            if port_str in customs:
                if customs[port_str].get("title"):
                    s["title"] = customs[port_str]["title"]
                if customs[port_str].get("image"):
                    s["image"] = customs[port_str]["image"]
                else:
                    s["image"] = ""
                s["ignored"] = customs[port_str].get("ignored", False)
            else:
                s["image"] = ""
                s["ignored"] = False
        
        with server_state.lock:
            server_state.discovered_servers = results
            server_state.last_scan_time = time.time()
            
        duration = time.time() - start_time
        print(f"[Homebound] Scan completed in {duration:.2f}s. Found {len(results)} active sockets.")
    except Exception as e:
        print(f"[Homebound] Error during scan: {e}")
    finally:
        with server_state.lock:
            server_state.is_scanning = False



class HomeboundHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        if len(args) >= 3:
            print(f"[{self.log_date_time_string()}] {args[0]} {args[1]} -> {args[2]}")
        else:
            try:
                formatted = format % args
            except Exception:
                formatted = " ".join(str(x) for x in args)
            print(f"[{self.log_date_time_string()}] {formatted}")

    def do_GET(self):
        global server_state
        host_header = self.headers.get("Host", "localhost")
        hostname = host_header.split(":")[0]

        if self.path == "/" or self.path == "/index.html":
            with server_state.lock:
                server_state.needs_refresh_scan = True
            
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            
            dir_path = os.path.dirname(os.path.abspath(__file__))
            index_path = os.path.join(dir_path, "index.html")
            try:
                with open(index_path, "rb") as f:
                    self.wfile.write(f.read())
            except Exception as e:
                self.wfile.write(f"Error loading index.html: {e}".encode())
                
        elif self.path == "/api/servers":
            current_time = time.time()
            should_scan = False
            with server_state.lock:
                if server_state.needs_refresh_scan or (current_time - server_state.last_scan_time > server_state.scan_interval):
                    should_scan = True
                    server_state.needs_refresh_scan = False
            
            if should_scan:
                run_scan()
                
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            
            with server_state.lock:
                data = {
                    "servers": server_state.discovered_servers,
                    "is_scanning": server_state.is_scanning,
                    "last_scan": server_state.last_scan_time
                }
            self.wfile.write(json.dumps(data).encode())
            
        elif self.path == "/api/scan":
            run_scan()
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            
            with server_state.lock:
                data = {
                    "servers": server_state.discovered_servers,
                    "is_scanning": server_state.is_scanning,
                    "last_scan": server_state.last_scan_time
                }
            self.wfile.write(json.dumps(data).encode())
            
        elif self.path.startswith("/redirect/"):
            try:
                port_str = self.path.split("/")[-1]
                port = int(port_str)
                
                protocol = "http"
                with server_state.lock:
                    for s in server_state.discovered_servers:
                        if s["port"] == port:
                            protocol = s["protocol"]
                            break
                            
                target_url = f"{protocol}://{hostname}:{port}"
                self.send_response(302)
                self.send_header("Location", target_url)
                self.end_headers()
            except Exception as e:
                self.send_error(400, f"Invalid port redirection parameters: {e}")
        else:
            self.send_error(404, "Route Not Found")

    def do_POST(self):
        global server_state
        if self.path == "/api/customize":
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            try:
                params = json.loads(post_data.decode('utf-8'))
                port = int(params.get("port"))
                custom_title = params.get("title")
                custom_image = params.get("image")
                custom_ignored = params.get("ignored")
                
                update_customization(port, custom_title, custom_image, custom_ignored)
                run_scan()
                
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                
                with server_state.lock:
                    data = {
                        "servers": server_state.discovered_servers,
                        "is_scanning": server_state.is_scanning,
                        "last_scan": server_state.last_scan_time
                    }
                self.wfile.write(json.dumps(data).encode())
            except Exception as e:
                self.send_error(400, f"Error processing customization request: {e}")
        else:
            self.send_error(404, "Route Not Found")

class RestrictedHTTPServer(http.server.ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, restrict_access=True):
        self.restrict_access = restrict_access
        super().__init__(server_address, RequestHandlerClass)

    def verify_request(self, request, client_address):
        if not self.restrict_access:
            return True
        
        client_ip = client_address[0]
        if '%' in client_ip:
            client_ip = client_ip.split('%')[0]
        
        try:
            ip = ipaddress.ip_address(client_ip)
            # Allowed subnets:
            # 1. Loopback (localhost): 127.0.0.0/8, ::1/128
            # 2. Tailscale: 100.64.0.0/10, fd7a:115c:a1e0::/48
            # 3. Private LAN: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fe80::/10 (link-local)
            allowed_networks = [
                ipaddress.ip_network("127.0.0.0/8"),
                ipaddress.ip_network("::1/128"),
                ipaddress.ip_network("100.64.0.0/10"),
                ipaddress.ip_network("fd7a:115c:a1e0::/48"),
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
                ipaddress.ip_network("fe80::/10"),
            ]
            if any(ip in net for net in allowed_networks):
                return True
        except ValueError:
            pass
        
        print(f"[Homebound] Blocked unauthorized connection attempt from: {client_ip}")
        return False

def main():
    global server_state
    
    parser = argparse.ArgumentParser(description="Homebound HTTP Server")
    parser.add_argument("--host", default="0.0.0.0", help="Hostname/IP to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=80, help="Port to run index server on (default: 80)")
    parser.add_argument("--interval", type=int, default=60, help="Scan interval in seconds (default: 60)")
    parser.add_argument("--public", action="store_true", help="Allow connections from any IP address (publicly accessible)")
    args = parser.parse_args()

    server_state = ServerState(host=args.host, port=args.port, scan_interval=args.interval)

    # Perform initial scan in main thread to ensure cache is ready on server start
    print("[Homebound] Performing initial startup socket scan...")
    run_scan()

    # Try binding to server port
    try:
        server = RestrictedHTTPServer((args.host, args.port), HomeboundHandler, restrict_access=not args.public)
        print(f"\n=======================================================")
        print(f"🚀 Homebound Dashboard successfully started!")
        print(f"👉 Open in browser: http://localhost:{args.port}/")
        print(f"👉 Binding Address: {args.host}:{args.port}")
        if not args.public:
            print(f"🔒 Access restricted to localhost, local LAN, and Tailscale networks")
        print(f"=======================================================\n")
    except PermissionError:
        print(f"\n❌ Error: Permission denied for port {args.port}.")
        print(f"ℹ️  Ports below 1024 (like 80) require root/administrator privileges.")
        print(f"ℹ️  To run on port 80, try: sudo python3 {sys.argv[0]} --port 80")
        print(f"⚠️  Falling back to port 8080 instead...\n")
        
        server_state.port = 8080
        # Re-run initial scan using the correct fallback port excluded
        run_scan()
        try:
            server = RestrictedHTTPServer((args.host, 8080), HomeboundHandler, restrict_access=not args.public)
            print(f"=======================================================")
            print(f"🚀 Homebound Dashboard successfully started (Fallback)!")
            print(f"👉 Open in browser: http://localhost:8080/")
            print(f"👉 Binding Address: {args.host}:8080")
            if not args.public:
                print(f"🔒 Access restricted to localhost, local LAN, and Tailscale networks")
            print(f"=======================================================\n")
        except Exception as fallback_err:
            print(f"❌ Fallback port 8080 binding failed: {fallback_err}")
            sys.exit(1)
    except Exception as e:
        print(f"❌ Server binding failed: {e}")
        sys.exit(1)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user request. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
