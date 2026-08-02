"""
IP Watch Agent - Full Edition
Versión avanzada con SQLite, scheduler, webhooks, speedtest y más.
Uso: python agent.py
Config: ip_watch_config.json (se crea automáticamente)
"""

import json, re, time, threading, platform, subprocess, socket, os, sqlite3, hashlib, hmac, secrets
from dataclasses import dataclass, asdict, field
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, urlencode, quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from datetime import datetime, timezone
from typing import Optional

VERSION = "2.5.0"
HOST = "127.0.0.1"
PORT = 8790
IP_CHECK_SECONDS = 120
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) IPWatch-Agent/2.0"
STATE_FILE = "ip_watch_state.json"
CONFIG_FILE = "ip_watch_config.json"
DB_FILE = "ip_watch.db"

# =========================================================
# CONFIG — se lee/guarda en ip_watch_config.json
# =========================================================
DEFAULT_CONFIG = {
    "abuseipdb_api_key": "",
    "ipqualityscore_api_key": "",
    "ipqualityscore_strictness": 1,
    "scamalytics_user": "",
    "scamalytics_api_key": "",
    "scamalytics_api_host": "https://api11.scamalytics.com/v3",
    "starvpn_email": "",
    "starvpn_token": "",
    "webhooks": [],          # lista de URLs a las que se hace POST al cambiar IP
    "auto_tz": False,        # cambiar zona horaria de Windows automáticamente
    "script_on_ip_change": "",  # ruta a script .bat/.py a ejecutar al cambiar IP
    "scheduler": [],         # lista de tareas programadas
    "notify_on_fraud_above": 40,  # notificar si fraud score supera este umbral
    "check_interval_seconds": 120,
    "local_auth_token": "",  # token local para extensión/agente
    "safe_export": True,
    "tunnel_watch_enabled": True,   # vigilar la caída/cambio del túnel (kill-switch informativo)
    "tunnel_expected": {},          # estado "bueno" fijado por el usuario: {ip, country_code, asn, nature}
    "expected_country": "",         # país real esperado (ISO-2) para el score de riesgo bancario; vacío = auto
    "using_tunnel": True,           # el usuario navega vía WireGuard/VPN (los bancos penalizan cualquier túnel)
}

config = dict(DEFAULT_CONFIG)

def load_config():
    global config
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        config = {**DEFAULT_CONFIG, **loaded}
        if not config.get("local_auth_token"):
            config["local_auth_token"] = secrets.token_urlsafe(32)
            save_config()
    except FileNotFoundError:
        config["local_auth_token"] = secrets.token_urlsafe(32)
        save_config()
    except Exception as e:
        print(f"[Config] Error cargando config: {e}")

def save_config():
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

# =========================================================
# BASE DE DATOS SQLite
# =========================================================
_db_lock = threading.Lock()

def db_connect():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def db_init():
    with _db_lock:
        conn = db_connect()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS ip_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                ip TEXT NOT NULL,
                city TEXT,
                region TEXT,
                country TEXT,
                country_code TEXT,
                org TEXT,
                asn TEXT,
                timezone TEXT,
                fraud_score INTEGER,
                fraud_risk TEXT,
                is_blacklisted INTEGER,
                abuseipdb_score INTEGER,
                proxy_enabled INTEGER,
                anonymizer_likely INTEGER,
                ai_friendly_score INTEGER,
                ai_friendly_label TEXT,
                dns TEXT,
                hostname TEXT,
                egress_source TEXT,
                nature_type TEXT
            );
            CREATE TABLE IF NOT EXISTS webhook_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                url TEXT NOT NULL,
                event_type TEXT,
                status_code INTEGER,
                success INTEGER,
                error TEXT
            );
            CREATE TABLE IF NOT EXISTS scheduler_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                task_name TEXT,
                action TEXT,
                result TEXT,
                success INTEGER
            );
            CREATE TABLE IF NOT EXISTS speedtest_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                ping REAL,
                download REAL,
                upload REAL,
                server TEXT,
                ip TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_ip_history_ts ON ip_history(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_ip_history_ip ON ip_history(ip);
        """)
        # Migración suave para BDs existentes creadas antes de la columna nature_type.
        cols = [r[1] for r in conn.execute("PRAGMA table_info(ip_history)").fetchall()]
        if "nature_type" not in cols:
            conn.execute("ALTER TABLE ip_history ADD COLUMN nature_type TEXT")
        conn.commit()
        conn.close()

def db_insert_ip_history(record: dict):
    with _db_lock:
        conn = db_connect()
        conn.execute("""
            INSERT INTO ip_history
            (ts, ip, city, region, country, country_code, org, asn, timezone,
             fraud_score, fraud_risk, is_blacklisted, abuseipdb_score,
             proxy_enabled, anonymizer_likely, ai_friendly_score, ai_friendly_label,
             dns, hostname, egress_source, nature_type)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            record.get("ts", int(time.time())),
            record.get("ip",""),
            record.get("city"), record.get("region"), record.get("country"),
            record.get("country_code"), record.get("org"), record.get("asn"),
            record.get("timezone"),
            record.get("fraud_score"), record.get("fraud_risk"),
            1 if record.get("is_blacklisted") else 0,
            record.get("abuseipdb_score"),
            1 if record.get("proxy_enabled") else 0,
            1 if record.get("anonymizer_likely") else 0,
            record.get("ai_friendly_score"), record.get("ai_friendly_label"),
            json.dumps(record.get("dns", [])),
            record.get("hostname",""),
            record.get("egress_source",""),
            record.get("nature_type")
        ))
        conn.commit()
        conn.close()

def db_get_ip_history(limit=50, offset=0, ip_filter=None):
    with _db_lock:
        conn = db_connect()
        if ip_filter:
            rows = conn.execute(
                "SELECT * FROM ip_history WHERE ip=? ORDER BY ts DESC LIMIT ? OFFSET ?",
                (ip_filter, limit, offset)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ip_history ORDER BY ts DESC LIMIT ? OFFSET ?",
                (limit, offset)
            ).fetchall()
        result = [dict(r) for r in rows]
        conn.close()
        return result

def db_get_fraud_trend(days=7):
    """Retorna evolución del fraud score de los últimos N días."""
    since = int(time.time()) - days * 86400
    with _db_lock:
        conn = db_connect()
        rows = conn.execute(
            "SELECT ts, ip, fraud_score, fraud_risk FROM ip_history WHERE ts >= ? ORDER BY ts ASC",
            (since,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

def db_log_webhook(url, event_type, status_code, success, error=None):
    with _db_lock:
        conn = db_connect()
        conn.execute(
            "INSERT INTO webhook_log (ts, url, event_type, status_code, success, error) VALUES (?,?,?,?,?,?)",
            (int(time.time()), url, event_type, status_code, 1 if success else 0, error)
        )
        conn.commit()
        conn.close()

def db_log_scheduler(task_name, action, result, success):
    with _db_lock:
        conn = db_connect()
        conn.execute(
            "INSERT INTO scheduler_log (ts, task_name, action, result, success) VALUES (?,?,?,?,?)",
            (int(time.time()), task_name, action, result, 1 if success else 0)
        )
        conn.commit()
        conn.close()

def db_insert_speedtest(record: dict):
    with _db_lock:
        conn = db_connect()
        conn.execute(
            "INSERT INTO speedtest_history (ts, ping, download, upload, server, ip) VALUES (?,?,?,?,?,?)",
            (int(time.time()), record.get("ping"), record.get("download"),
             record.get("upload"), record.get("server",""), record.get("ip",""))
        )
        conn.commit()
        conn.close()

def db_get_speedtest_history(limit=20):
    with _db_lock:
        conn = db_connect()
        rows = conn.execute(
            "SELECT * FROM speedtest_history ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

# =========================================================
# HTTP helpers
# =========================================================
def http_get_json(url: str, timeout: int = 10, headers: dict = None) -> dict:
    req = Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="ignore"))

def http_get_text(url: str, timeout: int = 15) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")

def http_post_json(url: str, payload: dict, timeout: int = 10, headers: dict = None) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = Request(url, data=body, method="POST",
                  headers={"Content-Type": "application/json", "User-Agent": USER_AGENT, **(headers or {})})
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="ignore"))

# =========================================================
# IP / Geolocation
# =========================================================
def get_public_ip_info() -> dict:
    for getter in [_ip_cloudflare, _ip_ipify, _ip_api]:
        try:
            result = getter()
            if result.get("ip"):
                return result
        except Exception:
            pass
    return {"ip": "", "ts": int(time.time()), "source": "none"}

def _ip_cloudflare():
    txt = http_get_text("https://www.cloudflare.com/cdn-cgi/trace", timeout=8)
    out = dict(line.split("=", 1) for line in txt.splitlines() if "=" in line)
    ip = out.get("ip", "")
    if ip and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return {"ip": ip, "colo": out.get("colo",""), "ts": int(time.time()), "source": "cloudflare"}
    raise ValueError("No IPv4")

def _ip_ipify():
    data = http_get_json("https://api.ipify.org?format=json", timeout=8)
    return {"ip": data["ip"], "ts": int(time.time()), "source": "ipify"}

def _ip_api():
    data = http_get_json("http://ip-api.com/json/?fields=query", timeout=8)
    return {"ip": data["query"], "ts": int(time.time()), "source": "ip-api"}

def get_ip_profile(ip: str) -> dict:
    for getter in [lambda: _profile_ipapi(ip), lambda: _profile_ipapi_com(ip), lambda: _profile_ipinfo(ip)]:
        try:
            result = getter()
            if result.get("city") or result.get("country"):
                return result
        except Exception:
            pass
    return {"ip": ip, "source": "none"}

def _profile_ipapi(ip):
    data = http_get_json(f"https://ipapi.co/{ip}/json/")
    if data.get("error"): raise ValueError(data.get("reason"))
    return {"ip": ip, "city": data.get("city"), "region": data.get("region"),
            "country": data.get("country_name"), "country_code": data.get("country_code"),
            "org": data.get("org"), "asn": data.get("asn"), "timezone": data.get("timezone"),
            "latitude": data.get("latitude"), "longitude": data.get("longitude"),
            "source": "ipapi.co"}

def _profile_ipapi_com(ip):
    data = http_get_json(f"http://ip-api.com/json/{ip}?fields=status,city,region,country,countryCode,org,as,timezone,lat,lon")
    if data.get("status") != "success": raise ValueError("fail")
    return {"ip": ip, "city": data.get("city"), "region": data.get("region"),
            "country": data.get("country"), "country_code": data.get("countryCode"),
            "org": data.get("org"), "asn": data.get("as"), "timezone": data.get("timezone"),
            "latitude": data.get("lat"), "longitude": data.get("lon"),
            "source": "ip-api.com"}

def _profile_ipinfo(ip):
    data = http_get_json(f"https://ipinfo.io/{ip}/json")
    lat, lon = None, None
    if data.get("loc"):
        parts = data["loc"].split(",")
        if len(parts) == 2:
            lat, lon = float(parts[0]), float(parts[1])
    return {"ip": ip, "city": data.get("city"), "region": data.get("region"),
            "country": data.get("country"), "country_code": data.get("country"),
            "org": data.get("org"), "timezone": data.get("timezone"),
            "latitude": lat, "longitude": lon, "source": "ipinfo.io"}

# =========================================================
# Fraud / Privacy checks
# =========================================================
def _looks_like_cloudflare_or_captcha(text: str) -> bool:
    """Detecta respuestas HTML de Cloudflare/CAPTCHA para no tratarlas como datos válidos."""
    if not text:
        return False
    t = text[:5000].lower()
    markers = [
        "cloudflare", "cf-chl", "cf_clearance", "captcha",
        "just a moment", "checking your browser", "challenge-platform",
        "turnstile", "ray id", "attention required"
    ]
    return any(m in t for m in markers)


def _normalize_scamalytics_api_response(data: dict, ip: str) -> dict:
    """
    Normaliza la respuesta real de Scamalytics.

    Soporta estas variantes:
    1) Respuesta pública/ejemplo:
       {"ip":"x.x.x.x", "score":"13", "risk":"low", "is_blacklisted_external": false}

    2) Respuesta API v3 real vista en integraciones:
       {"scamalytics": {"scamalytics_score": 13, "scamalytics_risk": "low", ...}, ...}
    """
    default_url = f"https://scamalytics.com/ip/{ip}"
    if not isinstance(data, dict):
        return {"fraud_score": None, "risk": None, "is_blacklisted_external": None,
                "scamalytics_url": default_url, "source": "scamalytics_api_invalid",
                "error": "Respuesta API no es JSON object"}

    # La API v3 puede venir anidada dentro de data["scamalytics"].
    payload = data.get("scamalytics") if isinstance(data.get("scamalytics"), dict) else data

    score = None
    for key in ("score", "fraud_score", "fraudScore", "scamalytics_score", "scamalyticsScore"):
        if key in payload and payload.get(key) not in (None, ""):
            try:
                score = int(float(payload.get(key)))
                break
            except Exception:
                pass

    risk = str(
        payload.get("risk")
        or payload.get("risk_level")
        or payload.get("scamalytics_risk")
        or payload.get("scamalyticsRisk")
        or ""
    ).strip().lower()
    risk = risk.replace(" risk", "")

    if score is None and risk:
        score = 75 if risk == "high" else 30 if risk == "medium" else 5 if risk == "low" else None
    if not risk and score is not None:
        risk = "high" if score >= 40 else "medium" if score >= 20 else "low"

    bl = payload.get("is_blacklisted_external")
    if bl is None:
        bl = data.get("is_blacklisted_external")
    if bl is None:
        bl = payload.get("is_blacklisted")
    if isinstance(bl, str):
        bl = bl.strip().lower() in ("true", "1", "yes", "y")

    scam_url = payload.get("scamalytics_url") or data.get("scamalytics_url") or default_url

    api_error = None
    status_value = str(payload.get("status") or data.get("status") or "").lower()
    if status_value in ("error", "fail", "failed"):
        api_error = payload.get("error") or data.get("error") or payload.get("message") or data.get("message") or "Scamalytics API devolvió error"

    source = "scamalytics_api_v3_nested" if payload is not data else "scamalytics_api"
    return {"fraud_score": score, "risk": risk or None, "is_blacklisted_external": bl,
            "scamalytics_url": scam_url, "source": source,
            "error": api_error, "raw": data}

def _build_scamalytics_api_urls(user: str, api_key: str, ip: str) -> list:
    """
    Scamalytics es sensible al slash final en algunas cuentas/planes.
    El build anterior usaba /v3/{user}?key=... y en varios casos eso cae en HTML/Cloudflare.
    Probamos primero el formato clásico usado por la extensión original:
      https://api11.scamalytics.com/v3/{username}/?key=...&ip=...
    y luego variantes seguras antes de declarar fallo.
    """
    host = (config.get("scamalytics_api_host") or "https://api11.scamalytics.com/v3").strip().rstrip("/")
    u = quote(user.strip('/'))
    q = urlencode({'key': api_key, 'ip': ip})
    return [
        f"{host}/{u}/?{q}",      # formato clásico correcto para muchas cuentas
        f"{host}/{u}?{q}",       # variante sin slash
    ]


def _fetch_one_url(url: str, api_key: str) -> dict:
    safe_url = url.replace(api_key, "***API_KEY***")
    req = Request(url, headers={
        "User-Agent": "IPWatch-Agent/2.1.3 (+local)",
        "Accept": "application/json, text/plain;q=0.9, */*;q=0.5",
        "Cache-Control": "no-cache"
    })
    with urlopen(req, timeout=12) as r:
        body = r.read().decode("utf-8", errors="ignore")
        content_type = (r.headers.get("Content-Type") or "").lower()
        http_status = getattr(r, "status", 200)
    return {"ok": True, "url": safe_url, "body": body, "content_type": content_type, "http_status": http_status}


def _extract_scamalytics_from_text(body: str, ip: str) -> dict | None:
    """Extrae score/risk aunque la respuesta llegue como HTML con un bloque JSON visible."""
    if not body:
        return None
    # 1) Intentar JSON completo
    try:
        data = json.loads(body)
        if isinstance(data, dict):
            return _normalize_scamalytics_api_response(data, ip)
    except Exception:
        pass
    # 2) Buscar campos JSON incrustados: "score":"13", "risk":"low"
    m_score = re.search(r'"(?:score|fraud_score|scamalytics_score)"\s*:\s*"?(\d{1,3})"?', body, re.I)
    if not m_score:
        m_score = re.search(r'Fraud\s*Score[^0-9]{0,80}(\d{1,3})', body, re.I | re.S)
    if not m_score:
        return None
    score = int(m_score.group(1))
    m_risk = re.search(r'"(?:risk|risk_level|scamalytics_risk)"\s*:\s*"?([a-zA-Z]+)"?', body, re.I)
    risk = (m_risk.group(1).lower() if m_risk else ("high" if score >= 40 else "medium" if score >= 20 else "low"))
    m_bl = re.search(r'"is_blacklisted_external"\s*:\s*(true|false)', body, re.I)
    bl = None if not m_bl else (m_bl.group(1).lower() == "true")
    return {
        "fraud_score": score,
        "risk": risk,
        "is_blacklisted_external": bl,
        "scamalytics_url": f"https://scamalytics.com/ip/{ip}",
        "source": "scamalytics_text_extracted",
        "error": None,
    }


def _fetch_scamalytics_raw(ip: str) -> dict:
    load_config()
    user = config.get("scamalytics_user", "").strip()
    api_key = config.get("scamalytics_api_key", "").strip()
    if not user or not api_key:
        return {"ok": False, "error": "Scamalytics API no configurada", "source": "scamalytics_not_configured"}

    last_error = None
    attempts = []
    for api_url in _build_scamalytics_api_urls(user, api_key, ip):
        safe_url = api_url.replace(api_key, "***API_KEY***")
        try:
            raw = _fetch_one_url(api_url, api_key)
            raw["attempts"] = attempts + [{"url": safe_url, "ok": True, "http_status": raw.get("http_status"), "content_type": raw.get("content_type")} ]
            return raw
        except HTTPError as e:
            try:
                err_body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                err_body = ""
            last_error = f"HTTP {e.code}: {err_body[:220]}"
            attempts.append({"url": safe_url, "ok": False, "error": last_error})
        except Exception as e:
            last_error = str(e)
            attempts.append({"url": safe_url, "ok": False, "error": last_error})
    return {"ok": False, "error": last_error or "Scamalytics API no disponible", "source": "scamalytics_all_urls_failed", "attempts": attempts}


def get_scamalytics_score(ip: str) -> dict:
    """
    Hotfix v2.1.3:
    - Usa endpoint API v3 directo con el formato sin slash antes del ?.
    - Parsea score/risk top-level y también respuesta anidada data["scamalytics"].
    - Detecta HTML/Cloudflare/CAPTCHA y no lo guarda como resultado válido.
    """
    scam_url = f"https://scamalytics.com/ip/{ip}"

    try:
        raw = _fetch_scamalytics_raw(ip)
        if not raw.get("ok"):
            return {"fraud_score": None, "risk": None, "is_blacklisted_external": None,
                    "scamalytics_url": scam_url, "source": raw.get("source", "scamalytics_error"),
                    "error": raw.get("error", "Scamalytics API no disponible")}

        body = raw.get("body", "")
        content_type = raw.get("content_type", "")

        # Primero intenta extraer JSON/score real. Algunas respuestas llegan como HTML
        # pero contienen el bloque JSON {"ip":"...","score":"13","risk":"low"}.
        extracted = _extract_scamalytics_from_text(body, ip)
        if extracted and extracted.get("fraud_score") is not None:
            return extracted

        if _looks_like_cloudflare_or_captcha(body) or ("text/html" in content_type and body.lstrip().startswith("<")):
            status.add_note("Scamalytics: Cloudflare/CAPTCHA detectado; no hay score parseable.")
            return {"fraud_score": None, "risk": None, "is_blacklisted_external": None,
                    "scamalytics_url": scam_url, "source": "scamalytics_cloudflare_block",
                    "error": "Cloudflare/CAPTCHA detectado en respuesta de Scamalytics"}

        try:
            data = json.loads(body)
        except Exception:
            snippet = re.sub(r"\s+", " ", body[:220]).strip()
            return {"fraud_score": None, "risk": None, "is_blacklisted_external": None,
                    "scamalytics_url": scam_url, "source": "scamalytics_non_json",
                    "error": f"Respuesta no JSON de Scamalytics: {snippet}"}

        result = _normalize_scamalytics_api_response(data, ip)
        if result.get("fraud_score") is None:
            status.add_note(f"Scamalytics parse sin score. Keys raíz: {list(data.keys())[:8]}")
        return result

    except HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="ignore")
        except Exception:
            err_body = ""
        if _looks_like_cloudflare_or_captcha(err_body):
            source = "scamalytics_cloudflare_block"
            msg = f"Cloudflare/CAPTCHA detectado HTTP {e.code}"
        else:
            source = "scamalytics_http_error"
            msg = f"HTTP {e.code}: {err_body[:180]}"
        status.add_note(f"Scamalytics: {msg}; se usa fallback si está disponible.")
        return {"fraud_score": None, "risk": None, "is_blacklisted_external": None,
                "scamalytics_url": scam_url, "source": source, "error": msg}
    except Exception as e:
        status.add_note(f"Scamalytics API no disponible: {e}; se usa fallback si está disponible.")
        return {"fraud_score": None, "risk": None, "is_blacklisted_external": None,
                "scamalytics_url": scam_url, "source": "scamalytics_error", "error": str(e)}


FALLBACK_ABUSEIPDB_KEY = ""

def get_abuseipdb_score(ip: str) -> dict:
    load_config()  # Recargar por si se actualizó
    # Usar key del config, o la key de la instalación previa como fallback
    api_key = config.get("abuseipdb_api_key","").strip() or FALLBACK_ABUSEIPDB_KEY
    if not api_key:
        return {"error": "no_api_key"}
    try:
        req = Request(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": api_key, "User-Agent": USER_AGENT, "Accept": "application/json"}
        )
        with urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
            d = data["data"]
            return {
                "score": d["abuseConfidenceScore"],
                "country_code": d.get("countryCode"),
                "isp": d.get("isp"),
                "domain": d.get("domain"),
                "total_reports": d.get("totalReports"),
                "last_reported": d.get("lastReportedAt"),
                "source": "abuseipdb"
            }
    except Exception as e:
        return {"error": str(e)}


def get_ipqualityscore_score(ip: str) -> dict:
    """Consulta IPQualityScore Proxy/VPN Detection API y normaliza el resultado."""
    load_config()
    api_key = config.get("ipqualityscore_api_key", "").strip()
    if not api_key:
        return {"error": "no_api_key", "source": "ipqualityscore"}
    try:
        strictness = int(config.get("ipqualityscore_strictness", 1) or 1)
        strictness = max(0, min(3, strictness))
    except Exception:
        strictness = 1

    params = urlencode({
        "strictness": strictness,
        "allow_public_access_points": "true",
        "fast": "true",
        "mobile": "true"
    })
    url = f"https://ipqualityscore.com/api/json/ip/{quote(api_key)}/{quote(ip)}?{params}"
    safe_url = url.replace(api_key, "***API_KEY***")
    try:
        req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        with urlopen(req, timeout=12) as r:
            data = json.loads(r.read().decode("utf-8", errors="ignore"))
        if data.get("success") is False:
            return {
                "error": data.get("message") or "IPQualityScore API devolvió error",
                "source": "ipqualityscore",
                "request_id": data.get("request_id"),
            }
        fraud_score = data.get("fraud_score")
        try:
            fraud_score = int(float(fraud_score)) if fraud_score not in (None, "") else None
        except Exception:
            fraud_score = None
        risk = "high" if isinstance(fraud_score, int) and fraud_score >= 85 else "medium" if isinstance(fraud_score, int) and fraud_score >= 40 else "low" if isinstance(fraud_score, int) else None
        return {
            "score": fraud_score,
            "risk": risk,
            "proxy": data.get("proxy"),
            "vpn": data.get("vpn"),
            "tor": data.get("tor"),
            "bot_status": data.get("bot_status"),
            "recent_abuse": data.get("recent_abuse"),
            "crawler": data.get("crawler"),
            "active_vpn": data.get("active_vpn"),
            "active_tor": data.get("active_tor"),
            "connection_type": data.get("connection_type"),
            "isp": data.get("ISP") or data.get("isp"),
            "organization": data.get("organization"),
            "asn": data.get("ASN") or data.get("asn"),
            "country_code": data.get("country_code"),
            "city": data.get("city"),
            "region": data.get("region"),
            "timezone": data.get("timezone"),
            "request_id": data.get("request_id"),
            "source": "ipqualityscore",
            "lookup_url": f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}",
        }
    except HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="ignore")[:220]
        except Exception:
            body = ""
        return {"error": f"HTTP {e.code}: {body}", "source": "ipqualityscore", "url": safe_url}
    except Exception as e:
        return {"error": str(e), "source": "ipqualityscore"}

IS_WINDOWS = platform.system().lower().startswith("win")
IS_MAC = platform.system().lower() == "darwin"
IS_LINUX = platform.system().lower() == "linux"


def get_dns_servers() -> list:
    """DNS resolvers configurados, según el sistema operativo."""
    if IS_WINDOWS:
        return get_windows_dns_servers()
    if IS_MAC:
        return _dns_macos()
    return _dns_linux()


def _dns_linux() -> list:
    dns = []
    # systemd-resolved
    try:
        out = subprocess.check_output(["resolvectl", "status"], text=True, errors="ignore", timeout=8)
        for m in re.finditer(r"DNS Servers?:\s*(.+)", out):
            dns += m.group(1).split()
    except Exception:
        pass
    # /etc/resolv.conf como fallback
    if not dns:
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            dns.append(parts[1])
        except Exception:
            pass
    seen = set()
    return [x for x in dns if re.match(r"^[0-9a-fA-F.:]+$", x) and not (x in seen or seen.add(x))][:6]


def _dns_macos() -> list:
    dns = []
    try:
        out = subprocess.check_output(["scutil", "--dns"], text=True, errors="ignore", timeout=8)
        for m in re.finditer(r"nameserver\[[0-9]+\]\s*:\s*([0-9a-fA-F.:]+)", out):
            dns.append(m.group(1))
    except Exception:
        pass
    seen = set()
    return [x for x in dns if not (x in seen or seen.add(x))][:6]


def get_system_proxy() -> dict:
    """Proxy del sistema, según SO."""
    if IS_WINDOWS:
        return get_winhttp_proxy()
    # macOS/Linux: variables de entorno estándar
    for var in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        val = os.environ.get(var)
        if val:
            return {"enabled": True, "value": val, "source": f"env:{var}"}
    return {"enabled": False, "value": None, "source": "env"}


def get_system_timezone() -> str:
    """Zona horaria local del sistema (IANA cuando es posible)."""
    try:
        tz = datetime.now().astimezone().tzinfo
        key = getattr(tz, "key", None)  # zoneinfo expone .key
        if key:
            return key
    except Exception:
        pass
    try:
        if IS_LINUX and os.path.islink("/etc/localtime"):
            target = os.readlink("/etc/localtime")
            if "zoneinfo/" in target:
                return target.split("zoneinfo/", 1)[1]
    except Exception:
        pass
    try:
        return time.tzname[0]
    except Exception:
        return ""


def get_windows_dns_servers() -> list:
    try:
        out = subprocess.check_output(["ipconfig", "/all"], text=True, errors="ignore", timeout=10)
    except Exception:
        return []
    dns = []; capture = False
    for line in out.splitlines():
        if "DNS Servers" in line or "Servidores DNS" in line:
            capture = True
            parts = line.split(":")
            if len(parts) >= 2:
                val = parts[-1].strip()
                if val and re.match(r"^[0-9a-fA-F.:]+$", val): dns.append(val)
            continue
        if capture:
            if line.startswith((" ", "\t")):
                val = line.strip()
                if val and re.match(r"^[0-9a-fA-F.:]+$", val): dns.append(val)
            else:
                capture = False
    seen = set()
    return [x for x in dns if not (x in seen or seen.add(x))][:6]

def get_winhttp_proxy() -> dict:
    try:
        out = subprocess.check_output(["netsh", "winhttp", "show", "proxy"], text=True, errors="ignore", timeout=10)
        low = out.lower()
        if "direct access" in low or "sin servidor proxy" in low:
            return {"enabled": False, "value": None, "source": "winhttp"}
        m = re.search(r"proxy server\(s\)\s*:\s*(.+)", out, flags=re.IGNORECASE)
        val = m.group(1).strip() if m else out.strip()
        return {"enabled": True, "value": val, "source": "winhttp"}
    except Exception:
        return {"enabled": None, "value": None, "source": "winhttp"}

def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

# =========================================================
# Clasificador residencial vs datacenter/VPN
# =========================================================
DATACENTER_KW = [
    "hosting", "datacenter", "data center", "data-center", "colo", "colocation",
    "server", "dedicated", "vps", "cloud", "amazon", "aws", "google", "gcp",
    "microsoft", "azure", "ovh", "digitalocean", "linode", "hetzner", "vultr",
    "leaseweb", "contabo", "scaleway", "oracle", "cloudflare", "akamai", "m247",
    "choopa", "quadranet", "psychz", "datapacket", "packet", "gcore",
]
VPN_KW = [
    "vpn", "nordvpn", "expressvpn", "surfshark", "protonvpn", "mullvad",
    "cyberghost", "private internet access", "pia", "ipvanish", "windscribe",
    "tunnelbear", "hidemyass", "vyprvpn", "torguard", "purevpn", "starvpn",
]
MOBILE_KW = [
    "mobile", "cellular", "wireless", "lte", "gsm", "movistar", "vodafone",
    "orange", "t-mobile", "at&t", "verizon", "telcel", "claro", "digicel",
]
RESIDENTIAL_KW = [
    "telecom", "cable", "fiber", "fibra", "broadband", "isp", "communications",
    "telefonica", "comcast", "spectrum", "cox", "charter", "att internet",
    "residential", "dsl", "adsl",
]


def classify_ip_nature(profile: dict, fraud: dict = None, ipqs: dict = None) -> dict:
    """
    Clasifica la naturaleza de la IP tal como la ven los anti-fraude (Whoer/Scamalytics):
    residential / datacenter / vpn / tor / mobile / unknown.

    Es la señal que de verdad decide si un servicio de IA te trata como usuario
    legítimo o te bloquea por parecer VPN/hosting.
    """
    profile = profile or {}
    ipqs = ipqs or {}
    fraud = fraud or {}

    org = (profile.get("org") or "").lower()
    asn = (profile.get("asn") or "").lower()
    hostname = (profile.get("hostname") or "").lower()
    blob = " ".join([org, asn, hostname])

    signals = []
    nature = None
    confidence = 40

    # 1) IPQualityScore es la fuente más fiable cuando está configurada.
    conn = (ipqs.get("connection_type") or "").lower()
    if ipqs.get("tor") is True or ipqs.get("active_tor") is True:
        nature = "tor"; confidence = 95; signals.append("IPQS: Tor")
    elif ipqs.get("vpn") is True or ipqs.get("active_vpn") is True:
        nature = "vpn"; confidence = 92; signals.append("IPQS: VPN")
    elif ipqs.get("proxy") is True:
        nature = "vpn"; confidence = 80; signals.append("IPQS: proxy")
    elif "data center" in conn or "datacenter" in conn or "hosting" in conn:
        nature = "datacenter"; confidence = 90; signals.append(f"IPQS: {conn}")
    elif "mobile" in conn or "cellular" in conn:
        nature = "mobile"; confidence = 88; signals.append(f"IPQS: {conn}")
    elif "residential" in conn:
        nature = "residential"; confidence = 90; signals.append(f"IPQS: {conn}")
    elif "corporate" in conn:
        nature = "residential"; confidence = 70; signals.append("IPQS: corporate")

    # 2) Palabras clave del ASN/org/hostname (funciona sin IPQS).
    if any(k in blob for k in VPN_KW):
        signals.append("ASN/org sugiere VPN")
        if nature is None:
            nature = "vpn"; confidence = 75
    if any(k in blob for k in DATACENTER_KW):
        signals.append("ASN/org de datacenter/hosting")
        if nature in (None, "residential") and not (ipqs.get("connection_type")):
            nature = "datacenter"; confidence = max(confidence, 72)
    if any(k in blob for k in MOBILE_KW) and nature is None:
        nature = "mobile"; confidence = 65; signals.append("ASN/org móvil")
    if any(k in blob for k in RESIDENTIAL_KW) and nature is None:
        nature = "residential"; confidence = 68; signals.append("ASN/org de ISP residencial")

    if fraud.get("is_blacklisted_external") is True:
        signals.append("En lista negra")

    if nature is None:
        nature = "unknown"; confidence = 30
        signals.append("Sin señales claras")

    ai_friendly_nature = nature in ("residential", "mobile")
    labels = {
        "residential": "Residencial", "mobile": "Móvil", "datacenter": "Datacenter/Hosting",
        "vpn": "VPN/Proxy", "tor": "Tor", "unknown": "Desconocida",
    }
    return {
        "type": nature,
        "label": labels.get(nature, nature),
        "ai_friendly": ai_friendly_nature,
        "confidence": confidence,
        "signals": signals[:6],
    }


# =========================================================
# AI Friendly Score (accionable)
# =========================================================
def compute_ai_friendly(profile, fraud, privacy, abuseipdb=None, ipqualityscore=None, nature=None) -> dict:
    score = 100; reasons = []; recommendations = []
    fraud_score = fraud.get("fraud_score") if fraud else None
    black = fraud.get("is_blacklisted_external") if fraud else None
    org = (profile.get("org") or "").lower() if profile else ""
    proxy_enabled = None
    if isinstance(privacy.get("proxy"), dict):
        proxy_enabled = privacy["proxy"].get("enabled")
    anonymizer_likely = privacy.get("anonymizer_likely")
    abuse_score = abuseipdb.get("score") if abuseipdb else None
    ipqs_score = ipqualityscore.get("score") if ipqualityscore else None

    # La naturaleza de la IP es lo que más pesa para un servicio de IA.
    if nature:
        nt = nature.get("type")
        if nt == "residential":
            reasons.append("IP residencial ✓")
        elif nt == "mobile":
            reasons.append("IP móvil ✓")
        elif nt == "datacenter":
            score -= 45; reasons.append("IP de datacenter/hosting ✗")
            recommendations.append("Tu exit luce datacenter/hosting: usa un exit residencial/móvil si quieres pasar como usuario nativo ante servicios de IA.")
        elif nt == "vpn":
            score -= 40; reasons.append("Detectada como VPN/proxy ✗")
            recommendations.append("La IP está catalogada como VPN/proxy: cambia a un exit residencial o rota a una IP no marcada.")
        elif nt == "tor":
            score -= 70; reasons.append("Salida Tor ✗")
            recommendations.append("Salida Tor detectada: casi todos los servicios de IA la bloquean.")
        else:
            score -= 8; reasons.append("Naturaleza de IP desconocida")

    if black is True:
        score -= 60; reasons.append("En lista negra ✗")
        recommendations.append("La IP está en lista negra: rota a otra IP; esta ya está quemada.")
    elif black is False:
        reasons.append("No está en lista negra ✓")

    if isinstance(fraud_score, int):
        if fraud_score >= 40:
            score -= 35; reasons.append(f"Fraude alto ({fraud_score}) ✗")
            recommendations.append(f"Scamalytics marca fraude {fraud_score}/100: rota a una IP más limpia.")
        elif fraud_score >= 20:
            score -= 15; reasons.append(f"Fraude medio ({fraud_score})")
        else:
            reasons.append(f"Fraude bajo ({fraud_score}) ✓")
    else:
        score -= 8; reasons.append("Fraude desconocido")

    if isinstance(abuse_score, int):
        if abuse_score >= 50:
            score -= 25; reasons.append(f"AbuseIPDB alto ({abuse_score}) ✗")
            recommendations.append(f"AbuseIPDB {abuse_score}/100: IP con reportes de abuso, conviene rotar.")
        elif abuse_score >= 25:
            score -= 10; reasons.append(f"AbuseIPDB medio ({abuse_score})")
        else:
            reasons.append(f"AbuseIPDB limpio ({abuse_score}) ✓")

    if isinstance(ipqs_score, int):
        if ipqs_score >= 85: score -= 35; reasons.append(f"IPQS alto ({ipqs_score}) ✗")
        elif ipqs_score >= 40: score -= 15; reasons.append(f"IPQS medio ({ipqs_score})")
        else: reasons.append(f"IPQS limpio ({ipqs_score}) ✓")
    if ipqualityscore:
        flags = []
        if ipqualityscore.get("recent_abuse") is True: flags.append("recent abuse")
        if ipqualityscore.get("bot_status") is True: flags.append("bot")
        if flags:
            score -= 15
            reasons.append("IPQS flags: " + ", ".join(flags[:4]))

    if proxy_enabled is True:
        score -= 10; reasons.append("Proxy del sistema activo")
        recommendations.append("Hay un proxy configurado en el sistema; verifica que sea intencional.")

    score = max(0, min(100, score))
    label = "YES" if score >= 75 else "MAYBE" if score >= 50 else "NO"
    if label == "YES" and not recommendations:
        recommendations.append("IP en buen estado: limpia y con aspecto nativo.")
    return {"label": label, "score": score, "reasons": reasons[:10], "recommendations": recommendations[:6]}


# =========================================================
# Coherencia (timezone / geo)
# =========================================================
# Idioma(s) principal(es) que se esperarían para cada país (ISO-2). Heurística ligera:
# solo penalizamos cuando conocemos el país y ninguno de sus idiomas encaja con el del navegador.
LANG_BY_COUNTRY = {
    "US": ["en"], "GB": ["en"], "CA": ["en", "fr"], "AU": ["en"], "NZ": ["en"], "IE": ["en"],
    "ES": ["es"], "MX": ["es"], "AR": ["es"], "CO": ["es"], "CL": ["es"], "PE": ["es"],
    "VE": ["es"], "EC": ["es"], "GT": ["es"], "CU": ["es"], "BO": ["es"], "DO": ["es"],
    "HN": ["es"], "PY": ["es"], "SV": ["es"], "NI": ["es"], "CR": ["es"], "PA": ["es"], "UY": ["es"],
    "BR": ["pt"], "PT": ["pt"], "FR": ["fr"], "BE": ["nl", "fr"], "DE": ["de"], "AT": ["de"],
    "CH": ["de", "fr", "it"], "IT": ["it"], "NL": ["nl"], "SE": ["sv"], "NO": ["no", "nb"],
    "DK": ["da"], "FI": ["fi"], "PL": ["pl"], "RU": ["ru"], "UA": ["uk", "ru"], "JP": ["ja"],
    "CN": ["zh"], "TW": ["zh"], "KR": ["ko"], "IN": ["en", "hi"], "TR": ["tr"], "GR": ["el"],
}


def compute_coherence(profile: dict, system_tz: str, client: dict = None, expected_country: str = "") -> dict:
    """Detecta incoherencias que los anti-fraude penalizan: zona horaria del sistema/navegador
    vs país de la IP, idioma del navegador vs país, y país esperado (KYC) vs país de la IP."""
    profile = profile or {}
    client = client or {}
    issues = []
    ok = True

    ip_tz = profile.get("timezone") or ""
    browser_tz = client.get("timezone") or ""
    browser_lang = (client.get("language") or "").strip()
    ip_cc = (profile.get("country_code") or "").upper()
    exp_cc = (expected_country or "").upper()

    def _region_mismatch(a: str, b: str) -> bool:
        ra, rb = a.split("/")[0].lower(), b.split("/")[0].lower()
        return bool(ra and rb and ra != rb)

    # 1) Timezone del sistema vs IP (heurística por región continental).
    if ip_tz and system_tz and ip_tz != system_tz and _region_mismatch(ip_tz, system_tz):
        ok = False
        issues.append(f"Zona horaria del sistema ({system_tz}) no coincide con la de la IP ({ip_tz}).")

    # 2) Timezone del navegador vs IP (lo que ve realmente un sitio web).
    if ip_tz and browser_tz and ip_tz != browser_tz and _region_mismatch(ip_tz, browser_tz):
        ok = False
        issues.append(f"Zona horaria del navegador ({browser_tz}) no coincide con la de la IP ({ip_tz}).")

    # 3) Idioma del navegador vs país de la IP.
    lang_ok = None
    if browser_lang and ip_cc and ip_cc in LANG_BY_COUNTRY:
        primary = browser_lang.split("-")[0].lower()
        expected_langs = LANG_BY_COUNTRY[ip_cc]
        lang_ok = primary in expected_langs
        if not lang_ok:
            ok = False
            issues.append(
                f"Idioma del navegador ({browser_lang}) no es típico del país de la IP "
                f"({ip_cc}: {', '.join(expected_langs)})."
            )

    # 4) País esperado (KYC) vs país de la IP.
    country_match = None
    if exp_cc and ip_cc:
        country_match = exp_cc == ip_cc
        if not country_match:
            ok = False
            issues.append(f"País esperado ({exp_cc}) no coincide con el país de la IP ({ip_cc}).")

    return {
        "ok": ok,
        "ip_timezone": ip_tz,
        "system_timezone": system_tz,
        "browser_timezone": browser_tz or None,
        "browser_language": browser_lang or None,
        "ip_country": ip_cc or None,
        "expected_country": exp_cc or None,
        "language_ok": lang_ok,
        "country_match": country_match,
        "issues": issues,
    }


# =========================================================
# Score de riesgo bancario (estimado)
# =========================================================
def compute_bank_risk(profile, fraud, abuseipdb, ipqualityscore, nature, coherence,
                      client=None, dns_leak=None, privacy=None, using_tunnel=True) -> dict:
    """
    Estima cómo puntuaría un motor de riesgo bancario/fintech. A diferencia del
    AI-Friendly (que premia "residencial=limpio"), aquí una IP residencial es solo
    lo mínimo esperable: partimos de riesgo 0 y SUMAMOS puntos por cada bandera.
    Score 0-100 donde 0 = riesgo bajo, 100 = riesgo alto (escala inversa al AI-Friendly).
    La IP/red es solo una capa; pesan también coherencia, fingerprint y reputación.
    """
    client = client or {}
    dns_leak = dns_leak or {}
    privacy = privacy or {}
    risk = 0
    factors = []
    recommendations = []

    def add(layer, delta, label):
        nonlocal risk
        risk += delta
        factors.append({"layer": layer, "delta": delta, "label": label})

    # ---- Capa Red / naturaleza de la IP (una señal entre varias) ----
    nt = (nature or {}).get("type")
    if nt == "datacenter":
        add("Red", 25, "IP de datacenter/hosting")
        recommendations.append("Un banco marca datacenter/hosting como alto riesgo: usa un exit residencial.")
    elif nt == "vpn":
        add("Red", 22, "IP catalogada VPN/proxy")
        recommendations.append("La IP está catalogada como VPN/proxy: para banca conviene una residencial no marcada.")
    elif nt == "tor":
        add("Red", 45, "Salida Tor")
        recommendations.append("Tor es rechazo casi seguro en banca.")
    elif nt == "unknown":
        add("Red", 6, "Naturaleza de IP desconocida")

    # El hecho de ir por túnel penaliza aunque el exit sea residencial.
    if using_tunnel and nt not in ("vpn", "tor", "datacenter"):
        add("Red", 12, "Tráfico tunelizado (VPN/WireGuard)")
        recommendations.append("Los bancos desconfían de cualquier túnel: para trámites bancarios sensibles considera conexión directa.")

    # ---- Capa Reputación ----
    if (fraud or {}).get("is_blacklisted_external") is True:
        add("Reputación", 35, "IP en lista negra")
        recommendations.append("IP en lista negra: rota; para banca ya está quemada.")
    fs = (fraud or {}).get("fraud_score")
    if isinstance(fs, int):
        if fs >= 40: add("Reputación", 25, f"Fraude Scamalytics alto ({fs})")
        elif fs >= 20: add("Reputación", 12, f"Fraude Scamalytics medio ({fs})")
    ab = (abuseipdb or {}).get("score")
    if isinstance(ab, int):
        if ab >= 50: add("Reputación", 20, f"AbuseIPDB alto ({ab})")
        elif ab >= 25: add("Reputación", 10, f"AbuseIPDB medio ({ab})")
    iq = (ipqualityscore or {}).get("score")
    if isinstance(iq, int):
        if iq >= 85: add("Reputación", 25, f"IPQualityScore alto ({iq})")
        elif iq >= 40: add("Reputación", 12, f"IPQualityScore medio ({iq})")
    if ipqualityscore:
        if ipqualityscore.get("recent_abuse") is True:
            add("Reputación", 12, "IPQS: abuso reciente")
        if ipqualityscore.get("bot_status") is True:
            add("Reputación", 10, "IPQS: comportamiento bot")

    # ---- Capa Coherencia (geo/idioma/timezone/KYC) ----
    coh = coherence or {}
    coh_issues = coh.get("issues", []) or []
    if coh.get("country_match") is False:
        add("Coherencia", 20, "País esperado ≠ país de la IP")
        recommendations.append("El país de tu IP no coincide con tu país real: gran bandera para banca.")
    if coh.get("language_ok") is False:
        add("Coherencia", 12, "Idioma del navegador ≠ país de la IP")
    tz_issue = any("horaria" in i.lower() for i in coh_issues)
    if tz_issue:
        add("Coherencia", 12, "Zona horaria incoherente con la IP")

    # ---- Capa Fingerprint / fugas ----
    wr = client.get("webrtc") if isinstance(client, dict) else None
    if isinstance(wr, dict) and wr.get("leak") is True:
        add("Fingerprint", 12, "Fuga WebRTC (IP expuesta)")
        recommendations.append("WebRTC filtra una IP real: desactiva WebRTC o usa una extensión que lo bloquee.")
    if dns_leak.get("leak_suspected") is True:
        add("Fingerprint", 10, "Posible fuga de DNS")
    if isinstance(privacy.get("proxy"), dict) and privacy["proxy"].get("enabled") is True:
        add("Fingerprint", 8, "Proxy del sistema activo")

    risk = max(0, min(100, risk))
    if risk >= 60:
        level = "ALTO"
    elif risk >= 25:
        level = "MEDIO"
    else:
        level = "BAJO"
    if level == "BAJO" and not recommendations:
        recommendations.append("Sin banderas de red relevantes para banca. (No sustituye señales de comportamiento/KYC que solo ve el banco.)")
    return {
        "risk": risk,
        "level": level,
        "factors": factors[:12],
        "recommendations": recommendations[:6],
    }


# =========================================================
# Análisis de fuga de DNS
# =========================================================
def _is_private_ip(ip: str) -> bool:
    return bool(re.match(r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|::1|fc|fd)", ip or ""))


def analyze_dns_leak(dns_servers: list, exit_country_code: str) -> dict:
    """
    Comprueba si los resolvers DNS salen por el mismo país que el exit de la IP.
    Un resolver en un país distinto (o del ISP real) delata una fuga de DNS que
    rompe el anonimato aunque el túnel esté arriba.
    """
    exit_cc = (exit_country_code or "").upper()
    resolvers = []
    leak = False
    for ip in (dns_servers or [])[:4]:
        if _is_private_ip(ip):
            resolvers.append({"ip": ip, "scope": "local/router", "country_code": None})
            continue
        cc = ""
        org = None
        try:
            prof = get_ip_profile(ip)
            cc = (prof.get("country_code") or "").upper()
            org = prof.get("org")
        except Exception:
            pass
        mismatch = bool(exit_cc and cc and cc != exit_cc)
        if mismatch:
            leak = True
        resolvers.append({
            "ip": ip,
            "scope": "public",
            "country_code": cc or None,
            "org": org,
            "mismatch": mismatch,
        })
    return {
        "leak_suspected": leak,
        "exit_country_code": exit_cc or None,
        "resolvers": resolvers,
    }


# =========================================================
# Vigilancia del túnel (kill-switch informativo)
# =========================================================
def compute_tunnel(ip: str, profile: dict, nature: dict) -> dict:
    """
    Compara el estado actual contra el estado "bueno" que el usuario fijó
    (`tunnel_expected`). Si la IP/país/ASN/naturaleza cambian, se considera
    una posible caída o cambio de túnel y se avisa.
    """
    profile = profile or {}
    nature = nature or {}
    enabled = bool(config.get("tunnel_watch_enabled", True))
    expected = config.get("tunnel_expected") or {}
    current = {
        "ip": ip,
        "country_code": (profile.get("country_code") or "").upper() or None,
        "asn": profile.get("asn"),
        "nature": nature.get("type"),
    }
    if not expected:
        return {"enabled": enabled, "pinned": False, "ok": True, "current": current, "expected": None, "issues": []}

    issues = []
    if expected.get("ip") and expected["ip"] != current["ip"]:
        issues.append(f"IP cambió: {expected['ip']} → {current['ip']}")
    if expected.get("country_code") and current["country_code"] and expected["country_code"] != current["country_code"]:
        issues.append(f"País cambió: {expected['country_code']} → {current['country_code']}")
    if expected.get("asn") and current["asn"] and expected["asn"] != current["asn"]:
        issues.append(f"ASN cambió: {expected['asn']} → {current['asn']}")
    if expected.get("nature") and current["nature"] and expected["nature"] != current["nature"]:
        issues.append(f"Naturaleza cambió: {expected['nature']} → {current['nature']}")

    return {
        "enabled": enabled,
        "pinned": True,
        "ok": len(issues) == 0,
        "current": current,
        "expected": expected,
        "issues": issues,
    }


# =========================================================
# Timezone
# =========================================================
IANA_TO_WIN = {
    "America/New_York":"Eastern Standard Time","America/Chicago":"Central Standard Time",
    "America/Denver":"Mountain Standard Time","America/Phoenix":"US Mountain Standard Time",
    "America/Los_Angeles":"Pacific Standard Time","America/Anchorage":"Alaskan Standard Time",
    "Pacific/Honolulu":"Hawaiian Standard Time","Europe/London":"GMT Standard Time",
    "Europe/Paris":"Romance Standard Time","Europe/Berlin":"W. Europe Standard Time",
    "Europe/Madrid":"Romance Standard Time","Europe/Rome":"W. Europe Standard Time",
    "Asia/Tokyo":"Tokyo Standard Time","Asia/Shanghai":"China Standard Time",
    "Asia/Kolkata":"India Standard Time","Australia/Sydney":"AUS Eastern Standard Time",
    "America/Sao_Paulo":"E. South America Standard Time",
    "America/Mexico_City":"Central Standard Time (Mexico)",
    "America/Bogota":"SA Pacific Standard Time","America/Lima":"SA Pacific Standard Time",
    "America/Santiago":"Pacific SA Standard Time","America/Buenos_Aires":"Argentina Standard Time",
    "America/Caracas":"Venezuela Standard Time","America/Toronto":"Eastern Standard Time",
    "America/Vancouver":"Pacific Standard Time",
}

def windows_set_timezone(iana_tz: str) -> dict:
    win_tz = IANA_TO_WIN.get(iana_tz)
    if not win_tz:
        return {"ok": False, "reason": "no_mapping", "iana": iana_tz}
    try:
        subprocess.check_output(["tzutil", "/s", win_tz], text=True, errors="ignore", timeout=10)
        return {"ok": True, "iana": iana_tz, "windows": win_tz}
    except Exception as e:
        return {"ok": False, "reason": "tzutil_failed", "iana": iana_tz, "windows": win_tz, "error": str(e)}

# =========================================================
# Webhooks
# =========================================================
def fire_webhooks(event_type: str, payload: dict):
    hooks = config.get("webhooks", [])
    if not hooks:
        return
    def _send(url):
        try:
            body = json.dumps({"event": event_type, "ts": int(time.time()), "data": payload}).encode()
            req = Request(url, data=body, method="POST",
                          headers={"Content-Type":"application/json","User-Agent":USER_AGENT})
            with urlopen(req, timeout=10) as r:
                sc = r.status
            db_log_webhook(url, event_type, sc, True)
            print(f"[Webhook] {event_type} → {url} [{sc}]")
        except Exception as e:
            db_log_webhook(url, event_type, 0, False, str(e))
            print(f"[Webhook] Error {url}: {e}")
    for url in hooks:
        threading.Thread(target=_send, args=(url,), daemon=True).start()

# =========================================================
# Speedtest
# =========================================================
def run_speedtest() -> dict:
    """
    Intenta speedtest con multiples estrategias de PATH:
    1. sys.executable -m speedtest (mismo Python del agente, cubre AppData del usuario)
    2. speedtest-cli como comando directo
    3. py -m speedtest (Windows launcher)
    """
    import sys

    bps_to_mbps = lambda x: round(x / 1_000_000, 2) if x else None

    def _parse_and_save(out: str, tool: str) -> dict:
        data = json.loads(out)
        result = {
            "ok": True,
            "ping": round(data.get("ping", 0), 1),
            "download": bps_to_mbps(data.get("download")),
            "upload": bps_to_mbps(data.get("upload")),
            "server": data.get("server", {}).get("name", ""),
            "sponsor": data.get("server", {}).get("sponsor", ""),
            "url": data.get("share", ""),
            "ts": int(time.time()),
            "tool": tool
        }
        db_insert_speedtest({**result, "ip": status.ip})
        return result

    # Estrategia 1: mismo Python que ejecuta el agente (garantiza AppData user packages)
    try:
        out = subprocess.check_output(
            [sys.executable, "-m", "speedtest", "--json"],
            text=True, timeout=90, stderr=subprocess.DEVNULL
        )
        return _parse_and_save(out, "python -m speedtest")
    except Exception:
        pass

    # Estrategia 2: speedtest-cli en el PATH del sistema
    try:
        out = subprocess.check_output(
            ["speedtest-cli", "--json"],
            text=True, timeout=90, stderr=subprocess.DEVNULL
        )
        return _parse_and_save(out, "speedtest-cli")
    except FileNotFoundError:
        pass
    except Exception:
        pass

    # Estrategia 3: Windows Python launcher
    try:
        out = subprocess.check_output(
            ["py", "-m", "speedtest", "--json"],
            text=True, timeout=90, stderr=subprocess.DEVNULL
        )
        return _parse_and_save(out, "py -m speedtest")
    except Exception:
        pass

    return {"ok": False, "error": "speedtest-cli no encontrado. Ejecuta: pip install speedtest-cli"}

# =========================================================
# Scheduler
# =========================================================
class Scheduler:
    """Ejecuta tareas programadas definidas en config['scheduler'].
    Cada tarea: {"name": str, "cron_like": "every_N_minutes", "action": "rotate_ip"|"speedtest"|"webhook_ping", ...}
    """
    def __init__(self):
        self._lock = threading.Lock()
        self._last_run = {}

    def tick(self):
        tasks = config.get("scheduler", [])
        now = int(time.time())
        for task in tasks:
            name = task.get("name", "unnamed")
            every_seconds = task.get("every_seconds", 3600)
            action = task.get("action", "")
            last = self._last_run.get(name, 0)
            if now - last >= every_seconds:
                self._last_run[name] = now
                threading.Thread(target=self._run_task, args=(task,), daemon=True).start()

    def _run_task(self, task: dict):
        name = task.get("name", "unnamed")
        action = task.get("action", "")
        print(f"[Scheduler] Ejecutando tarea '{name}': {action}")
        try:
            if action == "speedtest":
                result = run_speedtest()
                db_log_scheduler(name, action, json.dumps(result), result.get("ok", False))
            elif action == "rotate_ip":
                result = _rotate_starvpn()
                db_log_scheduler(name, action, json.dumps(result), result.get("ok", False))
            elif action == "webhook_ping":
                url = task.get("url", "")
                if url:
                    fire_webhooks("SCHEDULER_PING", {"task": name, "ip": status.ip})
                db_log_scheduler(name, action, "ping_sent", True)
            elif action == "refresh_status":
                egress = get_public_ip_info()
                refresh_full(egress.get("ip",""), egress)
                db_log_scheduler(name, action, "refreshed", True)
            else:
                db_log_scheduler(name, action, f"unknown_action:{action}", False)
        except Exception as e:
            db_log_scheduler(name, action, str(e), False)

scheduler = Scheduler()

# =========================================================
# StarVPN
# =========================================================
def _rotate_starvpn() -> dict:
    # Recargar config del disco por si se actualizó después de arrancar el agente
    load_config()
    email = config.get("starvpn_email","").strip()
    token = config.get("starvpn_token","").strip()
    if not email or not token:
        return {"ok": False, "error": "StarVPN no configurado. Ve a Configuración."}
    payload = {"email": email, "auth_token": token, "custom": 1,
               "command": "ip_update_now", "port": "1", "ip_type": "Rotating IP"}
    try:
        result = http_post_json("https://api.starhome.io/rotate_starvpn", payload, timeout=30)
        if result.get("result") == "success":
            return {"ok": True, "message": "IP rotada exitosamente"}
        return {"ok": False, "error": result.get("error","Error desconocido de StarVPN")}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# =========================================================
# Status State
# =========================================================
@dataclass
class Status:
    last_updated_ts: int = 0
    ip: str = ""
    profile: dict = field(default_factory=dict)
    fraud: dict = field(default_factory=dict)
    abuseipdb: dict = field(default_factory=dict)
    ipqualityscore: dict = field(default_factory=dict)
    privacy: dict = field(default_factory=dict)
    dns: list = field(default_factory=list)
    system: dict = field(default_factory=dict)
    client: dict = field(default_factory=dict)
    location: dict = field(default_factory=dict)
    nature: dict = field(default_factory=dict)
    coherence: dict = field(default_factory=dict)
    dns_leak: dict = field(default_factory=dict)
    tunnel: dict = field(default_factory=dict)
    bank_risk: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    def add_note(self, note: str):
        self.notes.insert(0, f"[{datetime.now().strftime('%H:%M:%S')}] {note}")
        self.notes = self.notes[:200]  # mantener últimas 200

status = Status()

class EventBus:
    def __init__(self):
        self._lock = threading.Lock()
        self._events = []
        self._next_id = 1
        # Identifica este arranque del agente. La extensión usa este valor
        # para detectar que los IDs de eventos se reiniciaron.
        self.stream_id = secrets.token_hex(12)

    def publish(self, event_type: str, payload: dict):
        with self._lock:
            ev = {"id": self._next_id, "ts": int(time.time()), "type": event_type, "payload": payload}
            self._events.append(ev)
            if len(self._events) > 500:
                self._events = self._events[-500:]
            self._next_id += 1
        threading.Thread(target=fire_webhooks, args=(event_type, payload), daemon=True).start()

    def get_after(self, after_id: int):
        with self._lock:
            return [e for e in self._events if e["id"] > after_id]

bus = EventBus()

# =========================================================
# State persistence (JSON rápido para arranque)
# =========================================================
def load_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k in ["ip","profile","fraud","abuseipdb","ipqualityscore","privacy","dns","system","client","location","nature","coherence","dns_leak","tunnel","bank_risk","notes","last_updated_ts"]:
            if k in data:
                setattr(status, k, data[k])
        # El fingerprint del navegador (idioma/timezone/WebRTC) puede haber cambiado
        # entre sesiones; lo descartamos al arrancar para no calcular coherencia/riesgo
        # con datos rancios. El popup lo repone en /client al abrirse.
        if isinstance(status.client, dict):
            for volatile in ("language", "languages", "timezone", "webrtc"):
                status.client.pop(volatile, None)
    except FileNotFoundError:
        pass
    except Exception as e:
        status.add_note(f"State load error: {e}")

def save_state():
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(asdict(status), f, ensure_ascii=False, indent=2)
    except Exception as e:
        status.add_note(f"State save error: {e}")

# =========================================================
# Full Refresh
# =========================================================
def refresh_full(ip: str, egress_info: dict = None):
    if not ip:
        return
    egress_info = egress_info or {"ip": ip, "source": "manual", "ts": int(time.time())}
    status.add_note(f"Actualizando datos para IP {ip}...")

    profile = {}; fraud = {}; abuseipdb_data = {}; ipqs_data = {}

    try:
        profile = get_ip_profile(ip)
        status.add_note(f"Perfil: {profile.get('city','?')}, {profile.get('country','?')}")
    except Exception as e:
        status.add_note(f"Error perfil: {e}")

    try:
        fraud = get_scamalytics_score(ip)
        status.add_note(f"Fraud score: {fraud.get('fraud_score','?')} ({fraud.get('risk','?')})")
    except Exception as e:
        status.add_note(f"Error Scamalytics: {e}")

    try:
        abuseipdb_data = get_abuseipdb_score(ip)
        if "score" in abuseipdb_data:
            status.add_note(f"AbuseIPDB: {abuseipdb_data['score']}/100")
    except Exception as e:
        status.add_note(f"Error AbuseIPDB: {e}")

    try:
        ipqs_data = get_ipqualityscore_score(ip)
        if "score" in ipqs_data and ipqs_data.get("score") is not None:
            status.add_note(f"IPQualityScore: {ipqs_data['score']}/100 ({ipqs_data.get('risk','?')})")
        elif ipqs_data.get("error") and ipqs_data.get("error") != "no_api_key":
            status.add_note(f"IPQualityScore error: {ipqs_data.get('error')}")
    except Exception as e:
        status.add_note(f"Error IPQualityScore: {e}")

    dns = get_dns_servers()
    proxy = get_system_proxy()
    hostname = get_hostname(ip)
    if isinstance(profile, dict):
        profile["hostname"] = hostname

    # Clasificación de la naturaleza de la IP (residencial vs datacenter/VPN).
    nature = classify_ip_nature(profile, fraud, ipqs_data)
    anonymizer_likely = nature.get("type") in ("datacenter", "vpn", "tor")

    privacy = {"proxy": proxy, "anonymizer_likely": anonymizer_likely}
    ai_friendly = compute_ai_friendly(profile, fraud, privacy, abuseipdb_data, ipqs_data, nature)

    # Coherencia del sistema/navegador vs país de la IP (timezone, idioma, país esperado).
    system_tz = get_system_timezone()
    coherence = compute_coherence(profile, system_tz, status.client, config.get("expected_country", ""))
    if not coherence.get("ok"):
        status.add_note("Coherencia: " + "; ".join(coherence.get("issues", [])))

    # Fuga de DNS: resolvers en país distinto al exit.
    try:
        dns_leak = analyze_dns_leak(dns, profile.get("country_code"))
        if dns_leak.get("leak_suspected"):
            status.add_note("⚠️ Posible fuga de DNS: resolver en país distinto al de la IP.")
    except Exception as e:
        dns_leak = {"error": str(e)}

    # Estado del túnel vs el estado "bueno" fijado por el usuario.
    tunnel = compute_tunnel(ip, profile, nature)
    if tunnel.get("pinned") and not tunnel.get("ok"):
        status.add_note("⚠️ Túnel: " + "; ".join(tunnel.get("issues", [])))

    # Riesgo bancario estimado (escala inversa: 0 = riesgo bajo).
    bank_risk = compute_bank_risk(
        profile, fraud, abuseipdb_data, ipqs_data, nature, coherence,
        client=status.client, dns_leak=dns_leak, privacy=privacy,
        using_tunnel=bool(config.get("using_tunnel", True)),
    )

    status.ip = ip
    status.profile = profile
    status.fraud = fraud
    status.abuseipdb = abuseipdb_data
    status.ipqualityscore = ipqs_data
    status.privacy = privacy
    status.dns = dns
    status.nature = nature
    status.coherence = coherence
    status.dns_leak = dns_leak
    status.tunnel = tunnel
    status.bank_risk = bank_risk
    status.last_updated_ts = int(time.time())
    status.add_note(f"Naturaleza IP: {nature.get('label')} · AI-Friendly {ai_friendly.get('label')} ({ai_friendly.get('score')})")
    status.add_note(f"Riesgo bancario estimado: {bank_risk.get('level')} ({bank_risk.get('risk')}/100)")
    status.system = {
        "os": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "egress_source": egress_info,
        "ai_friendly": ai_friendly
    }

    # Guardar en SQLite
    db_insert_ip_history({
        "ts": int(time.time()),
        "ip": ip,
        "city": profile.get("city"),
        "region": profile.get("region"),
        "country": profile.get("country"),
        "country_code": profile.get("country_code"),
        "org": profile.get("org"),
        "asn": profile.get("asn"),
        "timezone": profile.get("timezone"),
        "fraud_score": fraud.get("fraud_score"),
        "fraud_risk": fraud.get("risk"),
        "is_blacklisted": fraud.get("is_blacklisted_external"),
        "abuseipdb_score": abuseipdb_data.get("score"),
        "proxy_enabled": proxy.get("enabled"),
        "anonymizer_likely": anonymizer_likely,
        "ai_friendly_score": ai_friendly.get("score"),
        "ai_friendly_label": ai_friendly.get("label"),
        "dns": dns,
        "hostname": hostname,
        "egress_source": egress_info.get("source",""),
        "nature_type": nature.get("type")
    })

    # Timezone automática (solo Windows por ahora)
    if config.get("auto_tz") and profile.get("timezone") and IS_WINDOWS:
        result = windows_set_timezone(profile["timezone"])
        status.add_note(f"Timezone: {result}")

    save_state()
    status.add_note(f"✓ Actualización completa para {ip}")

# =========================================================
# Monitor loop
# =========================================================
def monitor_loop():
    load_config()
    db_init()
    load_state()

    # Chequeo inicial
    try:
        egress = get_public_ip_info()
        current_ip = egress.get("ip","")
        if current_ip:
            refresh_full(current_ip, egress)
            bus.publish("IP_CHANGED", asdict(status))
    except Exception as e:
        status.add_note(f"Startup error: {e}")

    last_ip = status.ip

    while True:
        try:
            check_interval = config.get("check_interval_seconds", IP_CHECK_SECONDS)
            time.sleep(check_interval)
            egress = get_public_ip_info()
            current_ip = egress.get("ip","")
            if current_ip and current_ip != last_ip:
                status.add_note(f"IP cambió: {last_ip} → {current_ip}")
                refresh_full(current_ip, egress)
                bus.publish("IP_CHANGED", asdict(status))

                # Kill-switch informativo: si el estado fijado del túnel se rompió, avisar aparte.
                if config.get("tunnel_watch_enabled", True) and status.tunnel.get("pinned") and not status.tunnel.get("ok"):
                    bus.publish("TUNNEL_ALERT", {
                        "ip": current_ip,
                        "issues": status.tunnel.get("issues", []),
                        "expected": status.tunnel.get("expected"),
                        "current": status.tunnel.get("current"),
                    })

                # Script personalizado
                script = config.get("script_on_ip_change","")
                if script and os.path.exists(script):
                    try:
                        env = os.environ.copy()
                        env["IPWATCH_NEW_IP"] = current_ip
                        env["IPWATCH_OLD_IP"] = last_ip
                        subprocess.Popen([script], shell=True, env=env)
                        status.add_note(f"Script ejecutado: {script}")
                    except Exception as e:
                        status.add_note(f"Script error: {e}")

                last_ip = current_ip

            # Alerta de fraud score alto
            threshold = config.get("notify_on_fraud_above", 40)
            fs = status.fraud.get("fraud_score")
            if isinstance(fs, int) and fs >= threshold:
                bus.publish("HIGH_FRAUD_SCORE", {"ip": status.ip, "fraud_score": fs, "threshold": threshold})

            # Scheduler
            scheduler.tick()

        except Exception as e:
            status.add_note(f"Monitor loop error: {e}")


SENSITIVE_KEYS = {"abuseipdb_api_key", "ipqualityscore_api_key", "scamalytics_api_key", "starvpn_token", "local_auth_token"}


def _mask_value(value: str) -> str:
    if not value:
        return ""
    s = str(value)
    if len(s) <= 8:
        return "***"
    return s[:4] + "…" + s[-4:]


def sanitize_config(cfg: dict, include_token_hint: bool = True) -> dict:
    safe = {}
    for k, v in cfg.items():
        if k in SENSITIVE_KEYS:
            safe[k] = _mask_value(v)
            safe[k + "_set"] = bool(v)
        else:
            safe[k] = v
    if include_token_hint:
        safe["auth_enabled"] = bool(cfg.get("local_auth_token"))
    return safe


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest((a or "").encode(), (b or "").encode())


# =========================================================
# HTTP Handler
# =========================================================
class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # silenciar logs de acceso

    def log_error(self, format, *args):
        pass  # silenciar ConnectionAbortedError WinError 10053 (Chrome cierra el socket, normal)

    def handle_error(self, request, client_address):
        pass  # suprimir tracebacks de conexiones abortadas por el cliente

    def _cors(self):
        origin = self.headers.get("Origin", "")
        allowed = ""
        if origin.startswith(("chrome-extension://", "moz-extension://")) or origin in ("http://127.0.0.1:8790", "http://localhost:8790"):
            allowed = origin
        self.send_header("Access-Control-Allow-Origin", allowed or "null")
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-IPWatch-Token")

    def _authorized(self) -> bool:
        expected = config.get("local_auth_token", "")
        if not expected:
            return True
        supplied = self.headers.get("X-IPWatch-Token", "")
        return constant_time_equal(supplied, expected)

    def _require_auth(self) -> bool:
        if self._authorized():
            return True
        self._send_json({"ok": False, "error": "unauthorized", "message": "Token local inválido o ausente"}, 401)
        return False

    def _send_json(self, obj, code=200):
        try:
            body = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self._cors()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionAbortedError, BrokenPipeError, ConnectionResetError):
            pass  # Chrome cerró la conexión — ignorar

    def do_OPTIONS(self):
        self.send_response(200)
        self._cors()
        self.end_headers()

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        return json.loads(raw) if raw else {}

    # ---- POST ----
    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if not self._require_auth():
            return

        if path == "/client":
            data = self._read_body()
            client = {
                "ua": data.get("ua"),
                "browser": data.get("browser"),
                "language": data.get("language"),
                "languages": data.get("languages"),
                "timezone": data.get("timezone"),
                "ts": int(time.time()),
            }
            # WebRTC lo reporta el navegador (leak/ip/reason); conservarlo si viene.
            if isinstance(data.get("webrtc"), dict):
                client["webrtc"] = data["webrtc"]
            elif isinstance(status.client, dict) and status.client.get("webrtc"):
                client["webrtc"] = status.client["webrtc"]
            status.client = client
            save_state()
            self._send_json({"ok": True})
            return

        if path == "/config":
            data = self._read_body()
            for k in DEFAULT_CONFIG.keys():
                if k in data:
                    # No sobreescribir secretos si el UI devuelve un valor enmascarado
                    if k in SENSITIVE_KEYS and isinstance(data[k], str) and ("***" in data[k] or "…" in data[k]):
                        continue
                    config[k] = data[k]
            save_config()
            self._send_json({"ok": True, "config": sanitize_config(config)})
            return

        if path == "/star_api":
            data = self._read_body()
            try:
                url = f"https://api.starhome.io{data.get('endpoint','/')}"
                result = http_post_json(url, data.get("payload",{}), timeout=30)
                self._send_json({"ok": True, "response": result})
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)
            return

        if path == "/rotate_ip":
            result = _rotate_starvpn()
            if result.get("ok"):
                bus.publish("IP_ROTATION_REQUESTED", {"ts": int(time.time())})
            self._send_json(result)
            return

        if path == "/set_timezone":
            tz = status.profile.get("timezone") if status.profile else None
            if not tz:
                self._send_json({"ok": False, "error": "No timezone available"}, 400)
                return
            result = windows_set_timezone(tz)
            self._send_json({"ok": result["ok"], "result": result})
            return

        if path == "/refresh":
            def _bg():
                try:
                    egress = get_public_ip_info()
                    refresh_full(egress.get("ip",""), egress)
                    bus.publish("STATUS_REFRESHED", asdict(status))
                except Exception as e:
                    status.add_note(f"Manual refresh error: {e}")
            threading.Thread(target=_bg, daemon=True).start()
            self._send_json({"ok": True, "message": "Actualizando en background..."})
            return

        if path == "/webhook/test":
            data = self._read_body()
            url = data.get("url","")
            if not url:
                self._send_json({"ok": False, "error": "url requerida"}, 400)
                return
            try:
                http_post_json(url, {"event": "TEST", "ts": int(time.time()), "data": {"ip": status.ip}}, timeout=10)
                self._send_json({"ok": True})
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)})
            return

        if path == "/tunnel/pin":
            # Fija el estado actual como el estado "bueno" del túnel.
            if not status.ip:
                self._send_json({"ok": False, "error": "No hay IP actual para fijar"}, 400)
                return
            config["tunnel_expected"] = {
                "ip": status.ip,
                "country_code": (status.profile.get("country_code") or "").upper() or None,
                "asn": status.profile.get("asn"),
                "nature": (status.nature or {}).get("type"),
            }
            save_config()
            status.tunnel = compute_tunnel(status.ip, status.profile, status.nature)
            save_state()
            self._send_json({"ok": True, "tunnel": status.tunnel})
            return

        if path == "/tunnel/clear":
            config["tunnel_expected"] = {}
            save_config()
            status.tunnel = compute_tunnel(status.ip, status.profile, status.nature)
            save_state()
            self._send_json({"ok": True, "tunnel": status.tunnel})
            return

        self._send_json({"ok": False, "error": "not_found"}, 404)

    # ---- GET ----
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/status":
            self._send_json(asdict(status))
            return

        if path == "/health":
            self._send_json({"ok": True, "ts": int(time.time()), "ip": status.ip, "version": VERSION, "stream_id": bus.stream_id})
            return

        if path == "/config":
            load_config()  # Siempre leer del disco para mostrar valores actuales
            self._send_json({"ok": True, "config": sanitize_config(config)})
            return

        if path == "/events":
            after = int(qs.get("after", ["0"])[0])
            events = bus.get_after(after)
            self._send_json({
                "ok": True,
                "stream_id": bus.stream_id,
                "latest_id": bus._next_id - 1,
                "events": events
            })
            return

        if path == "/history":
            limit = int(qs.get("limit", ["50"])[0])
            offset = int(qs.get("offset", ["0"])[0])
            ip_filter = qs.get("ip", [None])[0]
            rows = db_get_ip_history(limit=limit, offset=offset, ip_filter=ip_filter)
            self._send_json({"ok": True, "history": rows, "count": len(rows)})
            return

        if path == "/history/trend":
            days = int(qs.get("days", ["7"])[0])
            trend = db_get_fraud_trend(days=days)
            self._send_json({"ok": True, "trend": trend, "days": days})
            return


        if path == "/scamalytics/test":
            if not self._require_auth():
                return
            test_ip = qs.get("ip", [status.ip or ""])[0]
            if not test_ip:
                self._send_json({"ok": False, "error": "No hay IP actual. Usa /scamalytics/test?ip=1.2.3.4"}, 400)
                return
            try:
                raw = _fetch_scamalytics_raw(test_ip)
                body = raw.get("body", "")
                parsed = None
                normalized = None
                is_cf = _looks_like_cloudflare_or_captcha(body)
                try:
                    parsed = json.loads(body)
                    normalized = _normalize_scamalytics_api_response(parsed, test_ip)
                    if isinstance(normalized, dict) and "raw" in normalized:
                        normalized.pop("raw", None)
                except Exception:
                    pass
                self._send_json({
                    "ok": raw.get("ok", False),
                    "ip": test_ip,
                    "url": raw.get("url"),
                    "http_status": raw.get("http_status"),
                    "content_type": raw.get("content_type"),
                    "cloudflare_or_captcha": is_cf,
                    "body_preview": body[:1200],
                    "parsed": parsed if isinstance(parsed, dict) else None,
                    "normalized": normalized,
                    "error": raw.get("error")
                })
            except Exception as e:
                self._send_json({"ok": False, "error": str(e)}, 500)
            return

        if path == "/ipqualityscore/test":
            if not self._require_auth():
                return
            test_ip = qs.get("ip", [status.ip or ""])[0]
            if not test_ip:
                self._send_json({"ok": False, "error": "No hay IP actual. Usa /ipqualityscore/test?ip=1.2.3.4"}, 400)
                return
            result = get_ipqualityscore_score(test_ip)
            self._send_json({"ok": not bool(result.get("error")), "ip": test_ip, "result": result})
            return

        if path == "/logs":
            limit = int(qs.get("limit", ["100"])[0])
            logs = status.notes[:limit]
            self._send_json({"ok": True, "logs": logs, "count": len(logs)})
            return

        if path == "/speedtest":
            result = run_speedtest()
            self._send_json(result)
            return

        if path == "/speedtest/history":
            rows = db_get_speedtest_history(20)
            self._send_json({"ok": True, "history": rows})
            return

        if path == "/webhook/log":
            limit = int(qs.get("limit", ["50"])[0])
            with _db_lock:
                conn = db_connect()
                rows = conn.execute(
                    "SELECT * FROM webhook_log ORDER BY ts DESC LIMIT ?", (limit,)
                ).fetchall()
                conn.close()
            self._send_json({"ok": True, "log": [dict(r) for r in rows]})
            return

        if path == "/scheduler/log":
            limit = int(qs.get("limit", ["50"])[0])
            with _db_lock:
                conn = db_connect()
                rows = conn.execute(
                    "SELECT * FROM scheduler_log ORDER BY ts DESC LIMIT ?", (limit,)
                ).fetchall()
                conn.close()
            self._send_json({"ok": True, "log": [dict(r) for r in rows]})
            return

        if path == "/stats":
            # Estadísticas generales de la BD
            with _db_lock:
                conn = db_connect()
                total = conn.execute("SELECT COUNT(*) as c FROM ip_history").fetchone()["c"]
                unique_ips = conn.execute("SELECT COUNT(DISTINCT ip) as c FROM ip_history").fetchone()["c"]
                avg_fraud = conn.execute("SELECT AVG(fraud_score) as a FROM ip_history WHERE fraud_score IS NOT NULL").fetchone()["a"]
                max_fraud = conn.execute("SELECT MAX(fraud_score) as m FROM ip_history WHERE fraud_score IS NOT NULL").fetchone()["m"]
                first_seen = conn.execute("SELECT MIN(ts) as m FROM ip_history").fetchone()["m"]
                webhook_total = conn.execute("SELECT COUNT(*) as c FROM webhook_log").fetchone()["c"]
                speedtest_total = conn.execute("SELECT COUNT(*) as c FROM speedtest_history").fetchone()["c"]
                conn.close()
            self._send_json({
                "ok": True,
                "total_records": total,
                "unique_ips": unique_ips,
                "avg_fraud_score": round(avg_fraud, 1) if avg_fraud else None,
                "max_fraud_score": max_fraud,
                "first_seen_ts": first_seen,
                "webhook_calls": webhook_total,
                "speedtests_run": speedtest_total,
                "current_ip": status.ip,
                "uptime_since": status.last_updated_ts
            })
            return

        self._send_json({"ok": False, "error": "not_found"}, 404)

# =========================================================
# Main
# =========================================================
class QuietHTTPServer(ThreadingHTTPServer):
    """HTTPServer multihilo que no imprime tracebacks de conexiones abortadas por el cliente.

    Multihilo para que una petición lenta (p.ej. /speedtest ~90 s o una API externa que
    tarda) no bloquee el /status que la extensión sondea cada 5 s.
    """
    daemon_threads = True
    def handle_error(self, request, client_address):
        import sys
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionAbortedError, BrokenPipeError, ConnectionResetError)):
            return  # WinError 10053 — Chrome cerró el socket, completamente normal
        # Para otros errores reales, sí mostrar
        super().handle_error(request, client_address)


def main():
    print("=" * 55)
    print(f"  IP Watch Agent v{VERSION}")
    print("=" * 55)
    print(f"  URL:    http://{HOST}:{PORT}")
    print(f"  Config: {CONFIG_FILE}")
    print(f"  DB:     {DB_FILE}")
    print("=" * 55)
    print("  Endpoints:")
    print("  GET  /status /health /config /events /history")
    print("  GET  /history/trend /logs /speedtest /stats")
    print("  GET  /scamalytics/test?ip=1.2.3.4 /ipqualityscore/test?ip=1.2.3.4")
    print("  GET  /speedtest/history /webhook/log /scheduler/log")
    print("  POST /config /rotate_ip /refresh /client")
    print("  POST /set_timezone /star_api /webhook/test")
    print("  POST /tunnel/pin /tunnel/clear")
    print("=" * 55)

    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    server = QuietHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Agent] Detenido.")

if __name__ == "__main__":
    main()
