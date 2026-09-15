from flask import Flask, render_template, jsonify
import os
import psutil
import platform
import datetime
import time
import socket
import ssl
import concurrent.futures
import docker
from cryptography import x509

app = Flask(__name__)


def _get_container_stats():
    try:
        client = docker.from_env()
        containers = client.containers.list(all=True)
        counts = {"running": 0, "exited": 0, "other": 0}
        items = []
        for c in containers:
            if c.status == "running":
                counts["running"] += 1
            elif c.status in ("exited", "stopped"):
                counts["exited"] += 1
            else:
                counts["other"] += 1
            items.append({"name": c.name, "status": c.status})
        items.sort(key=lambda x: (x["status"] != "running", x["name"]))
        return {"total": len(containers), "counts": counts, "containers": items}
    except Exception:
        return None


def _get_host_hostname():
    try:
        with open("/etc/host_hostname") as f:
            return f.read().strip()
    except OSError:
        return os.environ.get("HOST_HOSTNAME", platform.node())


BACKUP_ROOT = os.environ.get("BACKUP_ROOT", "/mnt/docker-backups")
BACKUP_CACHE_TTL = 300  # NFS reads are slow; the page polls every 5s
_backup_cache = {"at": 0.0, "data": None}


def _dated_dirs(path):
    """Date-shaped subdirs only, sorted. Mirrors qb-backup's own prune() glob."""
    try:
        return sorted(e.name for e in os.scandir(path)
                      if e.is_dir() and e.name[:1].isdigit())
    except OSError:
        return []


def _read_backup_status():
    daily_dir = os.path.join(BACKUP_ROOT, "daily")
    dailies = _dated_dirs(daily_dir)
    weeklies = _dated_dirs(os.path.join(BACKUP_ROOT, "weekly"))
    if not dailies:
        return {"state": "unknown",
                "message": f"{BACKUP_ROOT} is unreadable or empty"}

    latest = dailies[-1]
    latest_path = os.path.join(daily_dir, latest)
    success = os.path.exists(os.path.join(latest_path, "SUCCESS"))

    last_run, age_hours = None, None
    try:
        with open(os.path.join(daily_dir, "last-run")) as f:
            last_run = f.read().strip()
        ts = datetime.datetime.fromisoformat(last_run)
        age_hours = (datetime.datetime.now(ts.tzinfo) - ts).total_seconds() / 3600
    except (OSError, ValueError):
        pass

    size = 0
    try:
        for e in os.scandir(latest_path):
            if e.is_file():
                size += e.stat().st_size
    except OSError:
        pass

    share = None
    statvfs = getattr(os, "statvfs", None)  # absent on Windows
    try:
        v = statvfs(BACKUP_ROOT) if statvfs else None
        total = v.f_blocks * v.f_frsize if v else 0
        free = v.f_bavail * v.f_frsize if v else 0
        if total:
            share = {"total_gb": round(total / 1024**3, 1),
                     "used_gb": round((total - free) / 1024**3, 1),
                     "percent": round((total - free) / total * 100, 1)}
    except OSError:
        pass

    # Cron is 02:30 nightly, so a healthy last-run is under ~26h old.
    if not success:
        state = "fail"
        message = f"Run {latest} never finished — no SUCCESS marker"
    elif age_hours is None:
        state = "warn"
        message = f"Latest backup {latest}, run time unknown"
    elif age_hours >= 54:
        state = "fail"
        message = f"No backup in {int(age_hours)}h"
    elif age_hours >= 30:
        state = "warn"
        message = f"Last backup {int(age_hours)}h ago — a night was missed"
    else:
        state = "ok"
        message = f"{latest} completed successfully"

    return {
        "state": state,
        "message": message,
        "last_run": last_run,
        "age_hours": round(age_hours, 1) if age_hours is not None else None,
        "latest_daily": latest,
        "latest_size_gb": round(size / 1024**3, 2),
        "daily_count": len(dailies),
        "weekly_count": len(weeklies),
        "latest_weekly": weeklies[-1] if weeklies else None,
        "share": share,
    }


def _get_backup_status():
    now = time.monotonic()
    if _backup_cache["data"] is None or now - _backup_cache["at"] > BACKUP_CACHE_TTL:
        try:
            _backup_cache["data"] = _read_backup_status()
        except Exception:
            _backup_cache["data"] = {"state": "unknown",
                                     "message": "backup check failed"}
        _backup_cache["at"] = now
    return _backup_cache["data"]


# "Label=host:port", comma separated. Home Assistant and Grafana are plain HTTP
# and have no cert to read. step-ca is deliberately absent: it re-issues its own
# leaf every 24h, so it would sit permanently in "expires today".
# The UDM must be probed by its id.ui.direct name - the bare IP answers with the
# self-signed unifi.local cert instead of the Let's Encrypt one.
CERT_TARGETS = os.environ.get("CERT_TARGETS", ",".join([
    "NAS (DSM)=ls-nas.limestone.pvt:5001",
    "Portainer=portainer.limestone.pvt:9443",
    "Cockpit=192.168.10.250:9090",
    "Pi-hole=192.168.10.250:7301",  # 7300 is the plain-HTTP port
    "Wazuh dashboard=192.168.10.250:8443",
    "UDM-Pro=d8b3701b063d0765131707bf639f064171940.id.ui.direct:443",
]))
CERT_CACHE_TTL = 3600  # certs move monthly at most; the page polls every 5s
CERT_WARN_DAYS = 30
CERT_TIMEOUT = 4
_cert_cache = {"at": 0.0, "data": None}
_CERT_SEVERITY = {"ok": 0, "unknown": 1, "warn": 2, "fail": 3}


def _parse_cert_targets(raw):
    targets = []
    for item in raw.split(","):
        label, _, addr = item.strip().rpartition("=")
        host, _, port = addr.rpartition(":")
        if not host:
            continue
        try:
            targets.append((label or addr, host, int(port)))
        except ValueError:
            continue
    return targets


def _common_name(name):
    cn = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return cn[0].value if cn else name.rfc4514_string()


def _probe_cert(label, host, port):
    # CERT_NONE on purpose. An expiring cert still has to be reported when it is
    # untrusted or already expired, which is exactly when validation would fail.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    row = {"label": label, "target": f"{host}:{port}"}
    try:
        with socket.create_connection((host, port), timeout=CERT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(der)
    except (OSError, ValueError) as e:
        return {**row, "state": "unknown", "message": type(e).__name__}

    expires = cert.not_valid_after_utc
    days = (expires - datetime.datetime.now(datetime.timezone.utc)).days
    if days < 0:
        state = "fail"
    elif days <= CERT_WARN_DAYS:
        state = "warn"
    else:
        state = "ok"
    return {**row, "state": state, "days_left": days,
            "expires": expires.date().isoformat(),
            "subject": _common_name(cert.subject),
            "issuer": _common_name(cert.issuer)}


def _read_cert_status():
    targets = _parse_cert_targets(CERT_TARGETS)
    if not targets:
        return {"state": "unknown", "message": "No targets configured", "certs": []}

    # Probed in parallel so one dead host cannot stall the whole refresh.
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        certs = list(pool.map(lambda t: _probe_cert(*t), targets))
    certs.sort(key=lambda c: (c.get("days_left") is None, c.get("days_left", 0)))

    state = max(certs, key=lambda c: _CERT_SEVERITY[c["state"]])["state"]
    expired = [c for c in certs if c["state"] == "fail"]
    expiring = [c for c in certs if c["state"] == "warn"]
    unreachable = [c for c in certs if c["state"] == "unknown"]
    soonest = next((c for c in certs if "days_left" in c), None)

    if expired:
        message = f"{expired[0]['label']} has EXPIRED"
    elif expiring:
        message = f"{expiring[0]['label']} expires in {expiring[0]['days_left']} days"
    elif unreachable:
        message = f"{unreachable[0]['label']} unreachable ({unreachable[0]['message']})"
    elif soonest:
        message = (f"All {len(certs)} valid — next is {soonest['label']}, "
                   f"{soonest['days_left']} days")
    else:
        message = "No certificates read"

    return {"state": state, "message": message, "certs": certs}


def _get_cert_status():
    now = time.monotonic()
    if _cert_cache["data"] is None or now - _cert_cache["at"] > CERT_CACHE_TTL:
        try:
            _cert_cache["data"] = _read_cert_status()
        except Exception:
            _cert_cache["data"] = {"state": "unknown",
                                   "message": "cert check failed", "certs": []}
        _cert_cache["at"] = now
    return _cert_cache["data"]


def get_system_stats():
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.datetime.now() - boot_time
    hours, remainder = divmod(int(uptime.total_seconds()), 3600)
    minutes, seconds = divmod(remainder, 60)

    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    return {
        "time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "os": f"{platform.system()} {platform.release()}",
        "hostname": _get_host_hostname(),
        "uptime": f"{hours}h {minutes}m {seconds}s",
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "cpu_count": psutil.cpu_count(),
        "mem_total_gb": round(mem.total / 1024**3, 1),
        "mem_used_gb": round(mem.used / 1024**3, 1),
        "mem_percent": mem.percent,
        "disk_total_gb": round(disk.total / 1024**3, 1),
        "disk_used_gb": round(disk.used / 1024**3, 1),
        "disk_percent": disk.percent,
        "docker": _get_container_stats(),
        "backup": _get_backup_status(),
        "certs": _get_cert_status(),
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    return jsonify(get_system_stats())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8085, debug=False)
