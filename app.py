from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
import nmap
import socket
import threading
import time
import os

app = Flask(__name__, static_folder="static")
CORS(app)

scan_state = {
    "running": False,
    "progress": 0,
    "message": "Ready",
    "results": None,
}
scan_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def ip_to_subnet(ip):
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def get_docker_info():
    """Return list of running containers with their host-port bindings."""
    try:
        import docker as docker_sdk
        client = docker_sdk.from_env()
        result = []
        for container in client.containers.list():
            port_bindings = {}
            for container_port, bindings in (container.ports or {}).items():
                if bindings:
                    for b in bindings:
                        try:
                            host_port = int(b["HostPort"])
                            port_bindings[host_port] = {
                                "container_port": container_port,
                                "host_ip": b.get("HostIp", "0.0.0.0"),
                            }
                        except (KeyError, ValueError):
                            pass
            result.append({
                "id": container.short_id,
                "name": container.name,
                "image": (container.image.tags or [container.image.short_id])[0],
                "status": container.status,
                "ports": port_bindings,
            })
        return result
    except Exception as e:
        return []


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def run_scan(subnet: str):
    global scan_state

    with scan_lock:
        scan_state["running"] = True
        scan_state["progress"] = 5
        scan_state["message"] = "Discovering hosts…"
        scan_state["results"] = None

    local_ip = get_local_ip()
    docker_containers = get_docker_info()

    # Build a quick lookup: host_port -> container info (for the local machine)
    docker_port_map: dict[int, dict] = {}
    for c in docker_containers:
        for host_port, info in c["ports"].items():
            docker_port_map[host_port] = {
                "container": c["name"],
                "image": c["image"],
                "container_port": info["container_port"],
            }

    nm_discover = nmap.PortScanner()
    try:
        nm_discover.scan(hosts=subnet, arguments="-sn -T4 --min-rate=2000")
        hosts = [h for h in nm_discover.all_hosts() if nm_discover[h].state() == "up"]
    except Exception as e:
        with scan_lock:
            scan_state["running"] = False
            scan_state["message"] = f"Discovery failed: {e}"
        return

    with scan_lock:
        scan_state["progress"] = 20
        scan_state["message"] = f"Found {len(hosts)} host(s). Scanning ports…"
        scan_state["results"] = {
            "devices": [],
            "subnet": subnet,
            "local_ip": local_ip,
            "docker_containers": docker_containers,
            "timestamp": time.time(),
            "scanning": True,
        }

    devices = []

    for idx, host in enumerate(hosts):
        nm_ports = nmap.PortScanner()
        try:
            nm_ports.scan(hosts=host, arguments="--top-ports 200 -T4 --open")
        except Exception:
            pass

        open_ports = []
        if host in nm_ports.all_hosts():
            for proto in nm_ports[host].all_protocols():
                for port in sorted(nm_ports[host][proto].keys()):
                    pdata = nm_ports[host][proto][port]
                    is_docker_port = host == local_ip and port in docker_port_map
                    open_ports.append({
                        "port": port,
                        "protocol": proto,
                        "state": pdata["state"],
                        "service": pdata.get("name", ""),
                        "docker": docker_port_map[port] if is_docker_port else None,
                    })

        # For local machine add docker ports that nmap might have missed
        if host == local_ip:
            known = {p["port"] for p in open_ports}
            for hp, dinfo in docker_port_map.items():
                if hp not in known:
                    open_ports.append({
                        "port": hp,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "",
                        "docker": dinfo,
                    })
            open_ports.sort(key=lambda p: p["port"])

        # MAC / vendor from discovery scan
        mac = vendor = ""
        if host in nm_discover.all_hosts():
            addrs = nm_discover[host].get("addresses", {})
            mac = addrs.get("mac", "")
            if mac:
                vendor = nm_discover[host].get("vendor", {}).get(mac, "")

        device = {
            "ip": host,
            "hostname": resolve_hostname(host),
            "mac": mac,
            "vendor": vendor,
            "ports": open_ports,
            "is_local": host == local_ip,
            "is_gateway": host.endswith(".1") or host.endswith(".254"),
        }
        devices.append(device)

        progress = 20 + int(75 * (idx + 1) / max(len(hosts), 1))
        with scan_lock:
            scan_state["results"]["devices"] = list(devices)
            scan_state["progress"] = progress
            scan_state["message"] = f"Scanned {idx + 1} / {len(hosts)} host(s)…"

    with scan_lock:
        scan_state["results"]["scanning"] = False
        scan_state["progress"] = 100
        scan_state["message"] = f"Done. {len(devices)} device(s) found."
        scan_state["running"] = False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.route("/api/status")
def api_status():
    with scan_lock:
        return jsonify({
            "running": scan_state["running"],
            "progress": scan_state["progress"],
            "message": scan_state["message"],
            "has_results": scan_state["results"] is not None,
        })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    with scan_lock:
        if scan_state["running"]:
            return jsonify({"error": "Scan already in progress"}), 409

    data = request.get_json(silent=True) or {}
    subnet = data.get("subnet") or os.environ.get("SUBNET", "")
    if not subnet:
        subnet = ip_to_subnet(get_local_ip())

    thread = threading.Thread(target=run_scan, args=(subnet,), daemon=True)
    thread.start()
    return jsonify({"status": "started", "subnet": subnet})


@app.route("/api/results")
def api_results():
    with scan_lock:
        if scan_state["results"] is None:
            return jsonify({"error": "No results yet"}), 404
        return jsonify(scan_state["results"])


@app.route("/api/docker")
def api_docker():
    return jsonify(get_docker_info())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
