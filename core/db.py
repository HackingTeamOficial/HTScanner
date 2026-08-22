#!/usr/bin/env python3
"""core/db.py - persistencia SQLite (comparar escaneos entre si).

Guarda:
  scans(id, target, fecha, modo, riesgo, estado)
  findings(scan_id, severidad, modulo, detalle, evidencia_json)
  techs(scan_id, nombre, version)
  apis(scan_id, endpoint)

Permite comparar escaneos (estado, riesgo, nuevo vs viejo).
"""
import os
import sqlite3
import json
import datetime
import threading

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ht_scanner.db")

_db_local = threading.local()


def _get_conn():
    """Conexion thread-local (evita cross-thread sqlite errors)."""
    conn = getattr(_db_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        _init(conn)
        _db_local.conn = conn
    return conn


def get_db():
    """Conexion SQLite thread-local para uso interno."""
    return _get_conn()


def get_conn(path=None):
    conn = sqlite3.connect(path or DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    _init(conn)
    return conn


def _init(conn):
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        target TEXT,
        fecha TEXT,
        modo TEXT,
        riesgo TEXT,
        estado TEXT,
        duracion REAL
    );
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT,
        severidad TEXT,
        modulo TEXT,
        detalle TEXT,
        evidencia TEXT,
        confidence TEXT
    );
    CREATE TABLE IF NOT EXISTS techs (
        scan_id TEXT,
        nombre TEXT,
        version TEXT
    );
    CREATE TABLE IF NOT EXISTS apis (
        scan_id TEXT,
        endpoint TEXT
    );
    """)
    # migracion: anadir columna duracion si falta (versiones previas)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(scans)")]
    if "duracion" not in cols:
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN duracion REAL")
        except Exception:
            pass
    # migracion findings.confidence
    fcols = [r[1] for r in conn.execute("PRAGMA table_info(findings)")]
    if "confidence" not in fcols:
        try:
            conn.execute("ALTER TABLE findings ADD COLUMN confidence TEXT")
        except Exception:
            pass
    conn.commit()


def save_scan(scan_id, target, modo, riesgo, findings, techs=None, apis=None,
              fecha=None, estado="completado", duracion=None):
    conn = get_conn()
    try:
        fecha = fecha or datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        conn.execute("INSERT OR REPLACE INTO scans (id, target, fecha, modo, riesgo, estado, duracion) "
                     "VALUES (?,?,?,?,?,?,?)",
                     (scan_id, target, fecha, modo, riesgo, estado, duracion))
        conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM techs WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM apis WHERE scan_id=?", (scan_id,))
        for f in findings:
            conn.execute(
                "INSERT INTO findings (scan_id, severidad, modulo, detalle, evidencia, confidence) "
                "VALUES (?,?,?,?,?,?)",
                (scan_id, f.get("severidad", "low"), f.get("modulo", ""),
                 f.get("detalle", ""), json.dumps(f.get("evidencia", {}), ensure_ascii=False),
                 f.get("confidence", "confirmed")))
        for t in (techs or []):
            conn.execute("INSERT INTO techs (scan_id, nombre, version) VALUES (?,?,?)",
                         (scan_id, t.get("nombre", ""), t.get("version", "")))
        for a in (apis or []):
            conn.execute("INSERT INTO apis (scan_id, endpoint) VALUES (?,?)", (scan_id, a))
        conn.commit()
    finally:
        conn.close()


def get_scans():
    conn = get_conn()
    try:
        rows = conn.execute("SELECT id, target, fecha, riesgo, estado, duracion FROM scans "
                           "ORDER BY fecha DESC").fetchall()
        return [{"id": r[0], "target": r[1], "fecha": r[2], "riesgo": r[3],
                 "estado": r[4], "duracion": r[5]} for r in rows]
    finally:
        conn.close()


def get_scan(scan_id):
    conn = get_conn()
    try:
        s = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not s:
            return None
        findings = conn.execute("SELECT severidad, modulo, detalle, evidencia, confidence FROM findings "
                                "WHERE scan_id=?", (scan_id,)).fetchall()
        techs = conn.execute("SELECT nombre, version FROM techs WHERE scan_id=?", (scan_id,)).fetchall()
        apis = conn.execute("SELECT endpoint FROM apis WHERE scan_id=?", (scan_id,)).fetchall()
        return {
            "id": s[0], "target": s[1], "fecha": s[2], "modo": s[3], "riesgo": s[4],
            "estado": s[5],
            "duracion": s[6] if len(s) > 6 else None,
            "findings": [{"severidad": f[0], "modulo": f[1], "detalle": f[2],
                          "evidencia": json.loads(f[3] or "{}"),
                          "confidence": f[4] or "confirmed"} for f in findings],
            "apis": [a[0] for a in apis],
        }
    finally:
        conn.close()


def compare_scans(id_a, id_b):
    """Devuelve diferencias de hallazgos entre dos escaneos."""
    a, b = get_scan(id_a), get_scan(id_b)
    if not a or not b:
        return None
    ka = {(f["modulo"], f["detalle"]) for f in a["findings"]}
    kb = {(f["modulo"], f["detalle"]) for f in b["findings"]}
    return {
        "a": id_a, "b": id_b,
        "nuevos_en_b": [f for f in b["findings"] if (f["modulo"], f["detalle"]) not in ka],
        "ya_no_en_b": [f for f in a["findings"] if (f["modulo"], f["detalle"]) not in kb],
    }


def previous_scan(target):
    """Devuelve el scan previo (anterior en fecha) del mismo objetivo, o None."""
    conn = get_conn()
    try:
        row = conn.execute("SELECT id FROM scans WHERE target=? ORDER BY fecha DESC LIMIT 1 OFFSET 1",
                           (target,)).fetchone()
        if not row:
            return None
        return get_scan(row[0])
    finally:
        conn.close()


def diff_with_previous(scan_id):
    """Compara el scan con el previo del MISMO objetivo y devuelve el diff."""
    cur = get_scan(scan_id)
    if not cur:
        return None
    prev = previous_scan(cur["target"])
    if not prev:
        return {"previo": None, "mensaje": "Primer escaneo de este objetivo"}
    ka = {(f["modulo"], f["detalle"]) for f in prev["findings"]}
    kb = {(f["modulo"], f["detalle"]) for f in cur["findings"]}
    return {
        "previo": prev["id"],
        "fecha_previo": prev["fecha"],
        "riesgo_anterior": prev["riesgo"],
        "riesgo_actual": cur["riesgo"],
        "nuevos": [f for f in cur["findings"] if (f["modulo"], f["detalle"]) not in ka],
        "resueltos": [f for f in prev["findings"] if (f["modulo"], f["detalle"]) not in kb],
    }
