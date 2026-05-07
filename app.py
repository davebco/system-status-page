from flask import Flask, render_template, jsonify
import os
import psutil
import platform
import datetime
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
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    return jsonify(get_system_stats())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8085, debug=False)
