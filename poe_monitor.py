#!/usr/bin/env python3
"""PoE Monitor - multi-switch Flask application for Linux/Proxmox."""
from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import secrets
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps

from flask import (
    Flask, abort, flash, redirect, render_template, request, session, url_for
)

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "cameras.db"
ENV_FILE = BASE_DIR / "poe-monitor.env"
LOG = logging.getLogger("poe-monitor")

# Values from the supplied original project. Used only to migrate its old
# single-switch configuration into the new switches table.
LEGACY_SWITCH_IP = "10.10.5.168"
LEGACY_COMMUNITY = "public"

def load_env_file():
    if not ENV_FILE.exists():
        return
    for raw in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)

load_env_file()

WEB_USER = os.environ.get("POE_WEB_USER", "")
WEB_PASSWORD = os.environ.get("POE_WEB_PASSWORD", "")
SECRET_KEY = os.environ.get("POE_SECRET_KEY") or secrets.token_hex(32)
HOST = os.environ.get("POE_WEB_HOST", "0.0.0.0")
PORT = int(os.environ.get("POE_WEB_PORT", "5000"))

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# Prevent simultaneous manual/automatic cycles on the same switch port.
_port_locks: dict[tuple[int, int], threading.Lock] = {}
_port_locks_guard = threading.Lock()
_worker_started = False
_worker_guard = threading.Lock()

def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def db():
    conn = sqlite3.connect(DB_FILE, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS switches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ip TEXT NOT NULL UNIQUE,
            community TEXT NOT NULL,
            version TEXT NOT NULL DEFAULT '2c',
            created_at TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cameras (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            port_index INTEGER NOT NULL,
            fail_count INTEGER NOT NULL DEFAULT 0
        )
    """)
    columns = {r["name"] for r in cur.execute("PRAGMA table_info(cameras)")}
    if "switch_id" not in columns:
        cur.execute("ALTER TABLE cameras ADD COLUMN switch_id INTEGER")
    if "enabled" not in columns:
        cur.execute("ALTER TABLE cameras ADD COLUMN enabled INTEGER NOT NULL DEFAULT 0")
    if "last_status" not in columns:
        cur.execute("ALTER TABLE cameras ADD COLUMN last_status TEXT NOT NULL DEFAULT 'Nieznany'")
    if "last_restart" not in columns:
        cur.execute("ALTER TABLE cameras ADD COLUMN last_restart REAL")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY CHECK (id=1),
            ping_interval INTEGER NOT NULL DEFAULT 30,
            fail_threshold INTEGER NOT NULL DEFAULT 5,
            poe_off_time INTEGER NOT NULL DEFAULT 10,
            cooldown INTEGER NOT NULL DEFAULT 300,
            max_restarts_hour INTEGER NOT NULL DEFAULT 2
        )
    """)
    cur.execute("""
        INSERT OR IGNORE INTO settings
        (id, ping_interval, fail_threshold, poe_off_time, cooldown, max_restarts_hour)
        VALUES (1, 30, 5, 10, 300, 2)
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            camera_id INTEGER,
            switch_id INTEGER,
            port_index INTEGER,
            event_type TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    # Migrate the old single-switch settings from the original source file.
    if cur.execute("SELECT COUNT(*) FROM switches").fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO switches(name, ip, community, version, created_at) VALUES (?, ?, ?, '2c', ?)",
            ("HP 2620 (przeniesiony ze starej konfiguracji)", LEGACY_SWITCH_IP, LEGACY_COMMUNITY, utc_now())
        )
        legacy_id = cur.lastrowid
        cur.execute(
            "UPDATE cameras SET switch_id=?, enabled=0 WHERE switch_id IS NULL",
            (legacy_id,)
        )
    else:
        # Any orphaned old rows remain disabled until explicitly assigned.
        cur.execute("UPDATE cameras SET enabled=0 WHERE switch_id IS NULL")
    conn.commit()
    conn.close()

def get_settings(conn=None):
    own = conn is None
    conn = conn or db()
    row = conn.execute("SELECT * FROM settings WHERE id=1").fetchone()
    if own:
        conn.close()
    return dict(row)

def record_event(camera_id, switch_id, port, event_type, message):
    conn = db()
    conn.execute(
        "INSERT INTO events(camera_id, switch_id, port_index, event_type, message, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (camera_id, switch_id, port, event_type, message, utc_now())
    )
    conn.commit()
    conn.close()

def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        raise ValueError("Nieprawidłowy adres IP.")

def validate_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("Numer portu musi być liczbą.")
    if not 1 <= port <= 48:
        raise ValueError("Dla HP 2620-48-PoEP numer portu musi być w zakresie 1–48.")
    return port

def snmp_command(binary, switch, oid, value=None, timeout=5):
    if binary not in ("snmpget", "snmpset"):
        raise ValueError("Niedozwolone polecenie SNMP.")
    cmd = [
        binary, "-v" + switch["version"], "-c", switch["community"],
        "-t", "2", "-r", "1", "-Oqv", switch["ip"], oid
    ]
    if binary == "snmpset":
        cmd.extend(["i", str(int(value))])
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        raise RuntimeError("Nie znaleziono snmpget/snmpset. Zainstaluj pakiet Debian: snmp.")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Przekroczono czas oczekiwania na odpowiedź SNMP.")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "brak szczegółów").strip()
        raise RuntimeError(f"SNMP {binary} nie powiodło się: {detail}")
    return (result.stdout or "").strip()

def poe_admin_oid(port):
    # Confirmed on the user's HP 2620: pethPsePortAdminEnable, PSE 1, port index.
    return f"1.3.6.1.2.1.105.1.1.1.3.1.{port}"

def snmp_test(switch):
    descr = snmp_command("snmpget", switch, "1.3.6.1.2.1.1.1.0")
    return descr or "SNMP OK"

def ping_host(ip):
    try:
        result = subprocess.run(
            ["ping", "-n", "-c", "1", "-W", "2", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=3, check=False
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def port_lock(switch_id, port):
    key = (switch_id, port)
    with _port_locks_guard:
        return _port_locks.setdefault(key, threading.Lock())

def power_cycle(switch, port, off_time, camera_id=None):
    lock = port_lock(switch["id"], port)
    if not lock.acquire(blocking=False):
        raise RuntimeError("Power cycle tego portu już trwa.")
    try:
        oid = poe_admin_oid(port)
        # Read current administrative state first. Expected values: 1=on, 2=off.
        before = snmp_command("snmpget", switch, oid)
        snmp_command("snmpset", switch, oid, 2)
        time.sleep(off_time)
        snmp_command("snmpset", switch, oid, 1)
        after = snmp_command("snmpget", switch, oid)
        if after.strip() != "1":
            raise RuntimeError(f"Po włączeniu SNMP zwróciło stan {after!r}, oczekiwano 1.")
        record_event(camera_id, switch["id"], port, "restart",
                     f"Power cycle wykonany. Stan przed: {before}; po: {after}.")
    except Exception as exc:
        record_event(camera_id, switch["id"], port, "error", str(exc))
        raise
    finally:
        lock.release()

def restart_allowed(camera):
    now = time.time()
    settings = get_settings()
    if camera["last_restart"] and now - camera["last_restart"] < settings["cooldown"]:
        return False, "Aktywny cooldown po poprzednim restarcie."
    conn = db()
    since = datetime.fromtimestamp(now - 3600, timezone.utc).isoformat(timespec="seconds")
    count = conn.execute(
        "SELECT COUNT(*) FROM events WHERE camera_id=? AND event_type='restart' AND created_at>=?",
        (camera["id"], since)
    ).fetchone()[0]
    conn.close()
    if count >= settings["max_restarts_hour"]:
        return False, "Osiągnięto limit restartów tego urządzenia na godzinę."
    return True, ""

def monitor_once():
    settings = get_settings()
    conn = db()
    cameras = conn.execute("""
        SELECT c.*, s.name AS switch_name, s.ip AS switch_ip,
               s.community AS switch_community, s.version AS switch_version
        FROM cameras c JOIN switches s ON s.id=c.switch_id
        WHERE c.enabled=1
    """).fetchall()
    conn.close()

    for camera in cameras:
        ok = ping_host(camera["target_ip"])
        conn = db()
        if ok:
            conn.execute("UPDATE cameras SET fail_count=0, last_status='OK' WHERE id=?", (camera["id"],))
            conn.commit()
            conn.close()
            continue

        fail_count = camera["fail_count"] + 1
        conn.execute(
            "UPDATE cameras SET fail_count=?, last_status=? WHERE id=?",
            (fail_count, f"Brak odpowiedzi ({fail_count}/{settings['fail_threshold']})", camera["id"])
        )
        conn.commit()
        conn.close()

        if fail_count < settings["fail_threshold"]:
            continue

        switch = {
            "id": camera["switch_id"], "ip": camera["switch_ip"],
            "community": camera["switch_community"], "version": camera["switch_version"]
        }
        allowed, reason = restart_allowed(camera)
        if not allowed:
            record_event(camera["id"], switch["id"], camera["port_index"], "blocked", reason)
            conn = db()
            conn.execute("UPDATE cameras SET fail_count=0, last_status=? WHERE id=?",
                         (reason, camera["id"]))
            conn.commit()
            conn.close()
            continue
        try:
            power_cycle(switch, camera["port_index"], settings["poe_off_time"], camera["id"])
            conn = db()
            conn.execute(
                "UPDATE cameras SET fail_count=0, last_restart=?, last_status='Restart PoE wykonany' WHERE id=?",
                (time.time(), camera["id"])
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            LOG.exception("Power cycle failed for camera id=%s", camera["id"])
            conn = db()
            conn.execute("UPDATE cameras SET fail_count=0, last_status=? WHERE id=?",
                         (f"Błąd SNMP: {exc}"[:250], camera["id"]))
            conn.commit()
            conn.close()

def monitor_worker():
    LOG.info("Monitor thread started.")
    while True:
        try:
            monitor_once()
        except Exception:
            LOG.exception("Monitoring iteration failed")
        time.sleep(get_settings()["ping_interval"])

def start_worker():
    global _worker_started
    with _worker_guard:
        if not _worker_started:
            thread = threading.Thread(target=monitor_worker, name="poe-monitor", daemon=True)
            thread.start()
            _worker_started = True

def require_auth():
    if not WEB_USER or not WEB_PASSWORD or WEB_PASSWORD in ("CHANGE_ME_TO_A_LONG_RANDOM_PASSWORD", "CHANGE_ME"):
        raise RuntimeError(
            "Brak konfiguracji logowania. Ustaw POE_WEB_USER i POE_WEB_PASSWORD w pliku "
            f"{ENV_FILE} (hasło nie może pozostać przykładowe)."
        )

@app.before_request
def protect_and_csrf():
    require_auth()
    auth = request.authorization
    if not auth or not hmac.compare_digest(auth.username or "", WEB_USER) or not hmac.compare_digest(auth.password or "", WEB_PASSWORD):
        return ("Wymagane logowanie.", 401, {"WWW-Authenticate": 'Basic realm="PoE Monitor"'})
    if request.method == "POST":
        token = request.form.get("_csrf", "")
        if not token or not hmac.compare_digest(token, session.get("_csrf", "")):
            abort(400, "Nieprawidłowy token formularza.")

@app.context_processor
def inject_csrf():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["_csrf"]}

@app.route("/")
def index():
    conn = db()
    switches = conn.execute("SELECT id, name, ip, version FROM switches ORDER BY name").fetchall()
    cameras = conn.execute("""
        SELECT c.*, s.name AS switch_name, s.ip AS switch_ip
        FROM cameras c LEFT JOIN switches s ON s.id=c.switch_id
        ORDER BY c.id
    """).fetchall()
    events = conn.execute("""
        SELECT e.*, c.name AS camera_name, s.name AS switch_name
        FROM events e
        LEFT JOIN cameras c ON c.id=e.camera_id
        LEFT JOIN switches s ON s.id=e.switch_id
        ORDER BY e.id DESC LIMIT 20
    """).fetchall()
    settings = get_settings(conn)
    conn.close()
    return render_template("index.html", switches=switches, cameras=cameras,
                           events=events, settings=settings)

@app.post("/switch/add")
def add_switch():
    name = request.form.get("name", "").strip()
    ip = valid_ip(request.form.get("ip", ""))
    community = request.form.get("community", "")
    version = request.form.get("version", "2c")
    if not name or not community:
        flash("Nazwa i community są wymagane.", "error")
        return redirect(url_for("index"))
    if version not in ("1", "2c"):
        flash("Ta wersja obsługuje SNMP v1 lub v2c.", "error")
        return redirect(url_for("index"))
    conn = db()
    try:
        conn.execute(
            "INSERT INTO switches(name,ip,community,version,created_at) VALUES(?,?,?,?,?)",
            (name, ip, community, version, utc_now())
        )
        conn.commit()
        flash("Switch dodany.", "success")
    except sqlite3.IntegrityError:
        flash("Switch z takim adresem IP już istnieje.", "error")
    finally:
        conn.close()
    return redirect(url_for("index"))

@app.post("/switch/<int:switch_id>/test")
def test_switch(switch_id):
    conn = db()
    switch = conn.execute("SELECT * FROM switches WHERE id=?", (switch_id,)).fetchone()
    conn.close()
    if not switch:
        abort(404)
    try:
        result = snmp_test(dict(switch))
        flash(f"SNMP działa: {result[:180]}", "success")
    except Exception as exc:
        flash(str(exc), "error")
    return redirect(url_for("index"))

@app.post("/switch/<int:switch_id>/edit")
def edit_switch(switch_id):
    name = request.form.get("name", "").strip()
    ip = valid_ip(request.form.get("ip", ""))
    community = request.form.get("community", "")
    version = request.form.get("version", "2c")
    if not name:
        raise ValueError("Nazwa switcha jest wymagana.")
    if version not in ("1", "2c"):
        raise ValueError("Ta wersja obsługuje SNMP v1 lub v2c.")
    conn = db()
    old = conn.execute("SELECT community FROM switches WHERE id=?", (switch_id,)).fetchone()
    if not old:
        conn.close()
        abort(404)
    # Blank password field means retain the currently stored community.
    if not community:
        community = old["community"]
    try:
        conn.execute(
            "UPDATE switches SET name=?, ip=?, community=?, version=? WHERE id=?",
            (name, ip, community, version, switch_id)
        )
        conn.commit()
        flash("Konfiguracja switcha zaktualizowana.", "success")
    except sqlite3.IntegrityError:
        flash("Inny switch ma już taki adres IP.", "error")
    finally:
        conn.close()
    return redirect(url_for("index"))

@app.post("/switch/<int:switch_id>/delete")
def delete_switch(switch_id):
    conn = db()
    used = conn.execute("SELECT COUNT(*) FROM cameras WHERE switch_id=?", (switch_id,)).fetchone()[0]
    if used:
        conn.close()
        flash("Nie można usunąć switcha: najpierw usuń lub przepnij przypisane urządzenia.", "error")
    else:
        conn.execute("DELETE FROM switches WHERE id=?", (switch_id,))
        conn.commit()
        conn.close()
        flash("Switch usunięty.", "success")
    return redirect(url_for("index"))

@app.post("/camera/add")
def add_camera():
    name = request.form.get("name", "").strip()
    ip = valid_ip(request.form.get("target_ip", ""))
    port = validate_port(request.form.get("port_index", ""))
    try:
        switch_id = int(request.form.get("switch_id", ""))
    except ValueError:
        raise ValueError("Wybierz switch.")
    if not name:
        raise ValueError("Nazwa urządzenia jest wymagana.")
    conn = db()
    exists = conn.execute("SELECT 1 FROM switches WHERE id=?", (switch_id,)).fetchone()
    if not exists:
        conn.close()
        raise ValueError("Wybrany switch nie istnieje.")
    conn.execute(
        "INSERT INTO cameras(name,target_ip,port_index,fail_count,switch_id,enabled,last_status) VALUES(?,?,?,0,?,1,'Oczekuje na ping')",
        (name, ip, port, switch_id)
    )
    conn.commit()
    conn.close()
    flash("Urządzenie dodane i monitoring włączony.", "success")
    return redirect(url_for("index"))

@app.post("/camera/<int:camera_id>/toggle")
def toggle_camera(camera_id):
    conn = db()
    row = conn.execute("SELECT enabled FROM cameras WHERE id=?", (camera_id,)).fetchone()
    if not row:
        conn.close()
        abort(404)
    new_value = 0 if row["enabled"] else 1
    conn.execute("UPDATE cameras SET enabled=?, fail_count=0 WHERE id=?", (new_value, camera_id))
    conn.commit()
    conn.close()
    flash("Monitoring urządzenia " + ("włączony." if new_value else "wyłączony."), "success")
    return redirect(url_for("index"))

@app.post("/camera/<int:camera_id>/cycle")
def manual_cycle(camera_id):
    conn = db()
    camera = conn.execute("""
        SELECT c.*, s.name AS switch_name, s.ip AS switch_ip,
               s.community AS switch_community, s.version AS switch_version
        FROM cameras c JOIN switches s ON s.id=c.switch_id WHERE c.id=?
    """, (camera_id,)).fetchone()
    conn.close()
    if not camera:
        abort(404)
    switch = {"id": camera["switch_id"], "ip": camera["switch_ip"],
              "community": camera["switch_community"], "version": camera["switch_version"]}
    try:
        off_time = get_settings()["poe_off_time"]
        power_cycle(switch, camera["port_index"], off_time, camera_id)
        conn = db()
        conn.execute("UPDATE cameras SET last_restart=?, fail_count=0, last_status='Ręczny restart PoE' WHERE id=?",
                     (time.time(), camera_id))
        conn.commit()
        conn.close()
        flash(f"Power cycle portu {camera['port_index']} wykonany.", "success")
    except Exception as exc:
        flash(f"Nie udało się zrestartować PoE: {exc}", "error")
    return redirect(url_for("index"))

@app.post("/camera/<int:camera_id>/delete")
def delete_camera(camera_id):
    conn = db()
    conn.execute("DELETE FROM cameras WHERE id=?", (camera_id,))
    conn.commit()
    conn.close()
    flash("Urządzenie usunięte.", "success")
    return redirect(url_for("index"))

@app.post("/settings")
def save_settings():
    def bounded(field, low, high):
        try:
            value = int(request.form[field])
        except (KeyError, ValueError):
            raise ValueError(f"Nieprawidłowa wartość pola {field}.")
        if not low <= value <= high:
            raise ValueError(f"Pole {field}: dozwolony zakres {low}–{high}.")
        return value
    values = (
        bounded("ping_interval", 5, 3600),
        bounded("fail_threshold", 1, 20),
        bounded("poe_off_time", 3, 120),
        bounded("cooldown", 60, 86400),
        bounded("max_restarts_hour", 1, 10)
    )
    conn = db()
    conn.execute("""
        UPDATE settings SET ping_interval=?, fail_threshold=?, poe_off_time=?,
        cooldown=?, max_restarts_hour=? WHERE id=1
    """, values)
    conn.commit()
    conn.close()
    flash("Ustawienia zapisane.", "success")
    return redirect(url_for("index"))

@app.errorhandler(ValueError)
def handle_value_error(exc):
    flash(str(exc), "error")
    return redirect(url_for("index"))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    require_auth()
    init_db()
    start_worker()
    app.run(host=HOST, port=PORT, threaded=True, use_reloader=False)
