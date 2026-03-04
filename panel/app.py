"""
DNSTT SSH User Management Panel
Dashboard with server stats, menu, tunnel user management.
"""

import os
import re
import sqlite3
import subprocess
import secrets
import hashlib
import time
from functools import wraps
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify

try:
    import psutil
except ImportError:
    psutil = None

BASE_DIR = Path(os.environ.get("DNSTT_PANEL_BASE", "/opt/dnstt-panel"))
CONFIG_DIR = Path(os.environ.get("DNSTT_CONFIG_DIR", "/etc/dnstt"))
DB_PATH = CONFIG_DIR / "panel.db"
CONFIG_ENV_PATH = CONFIG_DIR / "panel.env"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# Track network bytes for rate (per interface, then sum)
_net_last = None
_net_last_time = None


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_config(key, default=None):
    with get_db() as conn:
        row = conn.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_config(key, value):
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, value)
        )
        conn.commit()


def init_db_if_needed():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tunnel_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("panel_logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password, stored_hash):
    return hash_password(password) == stored_hash


def safe_username(name):
    return re.match(r"^[a-zA-Z][a-zA-Z0-9_]{2,31}$", name) is not None


def system_user_add(username, password):
    if not safe_username(username):
        return False, "Username must be 3–32 chars, start with letter, only letters, numbers, underscore."
    try:
        subprocess.run(
            ["useradd", "-m", "-s", "/bin/bash", "-c", "DNSTT tunnel user", username],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        if "already exists" in (e.stderr or "").lower() or e.returncode == 9:
            return False, "User already exists."
        return False, (e.stderr or str(e)).strip() or "useradd failed."
    try:
        p = subprocess.Popen(
            ["chpasswd"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        _, err = p.communicate(input=f"{username}:{password}\n", timeout=5)
        if p.returncode != 0:
            subprocess.run(["userdel", "-r", username], capture_output=True)
            return False, (err or "chpasswd failed").strip()
    except Exception as e:
        subprocess.run(["userdel", "-r", username], capture_output=True)
        return False, str(e)
    return True, None


def system_user_delete(username):
    if not safe_username(username):
        return False, "Invalid username."
    try:
        subprocess.run(["userdel", "-r", username], check=True, capture_output=True, text=True)
        return True, None
    except subprocess.CalledProcessError as e:
        return False, (e.stderr or str(e)).strip() or "userdel failed."


def system_user_change_password(username, password):
    if not safe_username(username):
        return False, "Invalid username."
    try:
        p = subprocess.Popen(
            ["chpasswd"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        _, err = p.communicate(input=f"{username}:{password}\n", timeout=5)
        if p.returncode != 0:
            return False, (err or "chpasswd failed").strip()
        return True, None
    except Exception as e:
        return False, str(e)


def get_server_stats():
    """Return dict of server stats for dashboard (works without psutil with minimal data)."""
    global _net_last, _net_last_time
    out = {
        "cpu_percent": 0,
        "memory_percent": 0,
        "memory_used_mb": 0,
        "memory_total_mb": 0,
        "disk_percent": 0,
        "disk_used_gb": 0,
        "disk_total_gb": 0,
        "load_1": 0,
        "load_5": 0,
        "load_15": 0,
        "uptime_seconds": 0,
        "uptime_text": "",
        "net_sent_kbps": 0,
        "net_recv_kbps": 0,
    }
    if psutil:
        try:
            out["cpu_percent"] = round(psutil.cpu_percent(interval=0.1), 1)
            mem = psutil.virtual_memory()
            out["memory_percent"] = round(mem.percent, 1)
            out["memory_used_mb"] = round(mem.used / (1024 * 1024), 0)
            out["memory_total_mb"] = round(mem.total / (1024 * 1024), 0)
            disk = psutil.disk_usage("/")
            out["disk_percent"] = round(disk.percent, 1)
            out["disk_used_gb"] = round(disk.used / (1024 ** 3), 2)
            out["disk_total_gb"] = round(disk.total / (1024 ** 3), 2)
            load = os.getloadavg() if hasattr(os, "getloadavg") else (0, 0, 0)
            out["load_1"], out["load_5"], out["load_15"] = round(load[0], 2), round(load[1], 2), round(load[2], 2)
            out["uptime_seconds"] = int(time.time() - psutil.boot_time())
            sec = out["uptime_seconds"]
            d, r = divmod(sec, 86400)
            h, r = divmod(r, 3600)
            m, s = divmod(r, 60)
            if d > 0:
                out["uptime_text"] = f"{int(d)}d {int(h)}h {int(m)}m"
            elif h > 0:
                out["uptime_text"] = f"{int(h)}h {int(m)}m {int(s)}s"
            else:
                out["uptime_text"] = f"{int(m)}m {int(s)}s"
            net = psutil.net_io_counters()
            now = time.time()
            if _net_last is not None and _net_last_time is not None and (now - _net_last_time) > 0:
                dt = now - _net_last_time
                out["net_sent_kbps"] = round((net.bytes_sent - _net_last[0]) / 1024 / dt, 1)
                out["net_recv_kbps"] = round((net.bytes_recv - _net_last[1]) / 1024 / dt, 1)
            _net_last = (net.bytes_sent, net.bytes_recv)
            _net_last_time = now
        except Exception:
            pass
    return out


# Fix global for net rate
def _update_net_global():
    global _net_last, _net_last_time
    if psutil:
        try:
            net = psutil.net_io_counters()
            now = time.time()
            if _net_last is None:
                _net_last = (net.bytes_sent, net.bytes_recv)
                _net_last_time = now
            elif (now - _net_last_time) > 0:
                _net_last = (net.bytes_sent, net.bytes_recv)
                _net_last_time = now
        except Exception:
            pass


@app.route("/api/stats")
@login_required
def api_stats():
    _update_net_global()
    return jsonify(get_server_stats())


@app.route("/login", methods=["GET", "POST"])
def login():
    init_db_if_needed()
    admin_user = get_config("admin_username")
    if not admin_user:
        return "Panel not initialized. Run init_panel.py first.", 500
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        stored_hash = get_config("admin_password_hash")
        if not stored_hash:
            flash("Panel not configured.", "error")
            return redirect(url_for("login"))
        if username == admin_user and verify_password(password, stored_hash):
            session["panel_logged_in"] = True
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("panel_logged_in", None)
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/users")
@login_required
def users():
    init_db_if_needed()
    with get_db() as conn:
        users_list = conn.execute(
            "SELECT id, username, created_at FROM tunnel_users ORDER BY created_at DESC"
        ).fetchall()
    return render_template("users.html", users=users_list)


@app.route("/user/add", methods=["POST"])
@login_required
def user_add():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if not username:
        flash("Username is required.", "error")
        return redirect(url_for("users"))
    if len(password) < 6:
        flash("Password must be at least 6 characters.", "error")
        return redirect(url_for("users"))
    ok, err = system_user_add(username, password)
    if not ok:
        flash(err, "error")
        return redirect(url_for("users"))
    with get_db() as conn:
        conn.execute("INSERT INTO tunnel_users (username) VALUES (?)", (username,))
        conn.commit()
    flash(f"User '{username}' created. They can connect via SSH with this username and password.", "success")
    return redirect(url_for("users"))


@app.route("/user/<username>/delete", methods=["POST"])
@login_required
def user_delete(username):
    ok, err = system_user_delete(username)
    if not ok:
        flash(err, "error")
        return redirect(url_for("users"))
    with get_db() as conn:
        conn.execute("DELETE FROM tunnel_users WHERE username = ?", (username,))
        conn.commit()
    flash(f"User '{username}' removed.", "success")
    return redirect(url_for("users"))


@app.route("/user/<username>/password", methods=["POST"])
@login_required
def user_password(username):
    password = request.form.get("password") or ""
    if len(password) < 6:
        flash("Password must be at least 6 characters.", "error")
        return redirect(url_for("users"))
    with get_db() as conn:
        exists = conn.execute("SELECT 1 FROM tunnel_users WHERE username = ?", (username,)).fetchone()
    if not exists:
        flash("User not found.", "error")
        return redirect(url_for("users"))
    ok, err = system_user_change_password(username, password)
    if not ok:
        flash(err, "error")
    else:
        flash(f"Password updated for '{username}'.", "success")
    return redirect(url_for("users"))


def main():
    init_db_if_needed()
    port = int(os.environ.get("PANEL_PORT", get_config("panel_port", "5847")))
    host = os.environ.get("PANEL_HOST", "0.0.0.0")
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
