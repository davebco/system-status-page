from flask import Flask, render_template, jsonify
import psutil
import platform
import datetime

app = Flask(__name__)


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
        "hostname": platform.node(),
        "uptime": f"{hours}h {minutes}m {seconds}s",
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "cpu_count": psutil.cpu_count(),
        "mem_total_gb": round(mem.total / 1024**3, 1),
        "mem_used_gb": round(mem.used / 1024**3, 1),
        "mem_percent": mem.percent,
        "disk_total_gb": round(disk.total / 1024**3, 1),
        "disk_used_gb": round(disk.used / 1024**3, 1),
        "disk_percent": disk.percent,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    return jsonify(get_system_stats())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8085, debug=False)
