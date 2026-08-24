from flask import Flask, render_template, jsonify
import os
import psutil
import platform
import datetime
import time
import docker

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
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    return jsonify(get_system_stats())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8085, debug=False)
