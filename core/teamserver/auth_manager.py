import logging
logger = logging.getLogger(__name__)

import os, uuid, sqlite3, threading, secrets
import re
from datetime import datetime
import bcrypt

_DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt()).decode()

# where to store your DB (next to your script, or configurable)
DB_PATH = os.path.expanduser("~/.gunnerc2/operators.db")

write_lock = threading.Lock()

# Per‑thread connection storage
_thread_local = threading.local()

# Cache operators in memory to reduce read latency
cache_lock = threading.Lock()
operators_cache: dict[str, dict] = {}

def _get_conn():
    """Get or open a thread‑local SQLite3 connection, tuned for speed."""
    if not hasattr(_thread_local, "conn"):
        conn = sqlite3.connect(
            DB_PATH,
            timeout=5,
            check_same_thread=False,     # we manage thread‑safety ourselves
        )
        # WAL mode allows readers & writers to run in parallel
        conn.execute("PRAGMA journal_mode=WAL;")

        # Trade a little durability for speed
        conn.execute("PRAGMA synchronous=NORMAL;")

        conn.execute("""
        CREATE TABLE IF NOT EXISTS operators (
            id           TEXT   PRIMARY KEY,
            username     TEXT   UNIQUE COLLATE NOCASE,
            password_hash TEXT  NOT NULL,
            role         TEXT   NOT NULL,
            created_at   TEXT   NOT NULL
        )
        """)
        conn.commit()

        conn.row_factory = sqlite3.Row
        _thread_local.conn = conn

        reload_cache()

    return _thread_local.conn

def reload_cache():
    """Rebuild the in‑memory cache from disk.  Called at startup and after writes."""
    conn = _get_conn()
    rows = conn.execute("SELECT id,username,password_hash,role,created_at FROM operators").fetchall()
    with cache_lock:
        operators_cache.clear()
        for r in rows:
            # keying on lowercase username for case‑insensitive lookups
            operators_cache[r["username"].lower()] = {
                "id":            r["id"],
                "password_hash": r["password_hash"],
                "role":          r["role"],
                "created_at":    r["created_at"],
            }

def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = _get_conn()
    with write_lock:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS operators (
            id           TEXT   PRIMARY KEY,
            username     TEXT   UNIQUE COLLATE NOCASE,
            password_hash TEXT  NOT NULL,
            role         TEXT   NOT NULL,
            created_at   TEXT   NOT NULL
        )
        """)
        conn.commit()

    reload_cache()
    return True


def add_operator(username, password, role="operator"):
    # strict allow‑list: only A‑Z, a‑z, 0‑9, @ . _ -, 1–32 chars
    if not re.fullmatch(r"[A-Za-z0-9@._-]{1,32}", username):
        return "USERNAME REGEX FAIL"

    # password: 1–64 non‑whitespace chars
    if not re.fullmatch(r"\S{1,64}", password):
        return "PASSWORD REGEX FAIL"
    conn = _get_conn()
    try:
        with write_lock:
            if username.lower() in operators_cache:
                return "ALREADY EXISTS"

            oid  = str(uuid.uuid4())
            pw_h = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            now  = datetime.utcnow().isoformat()
            conn.execute(
            "INSERT INTO operators(id,username,password_hash,role,created_at) VALUES (?,?,?,?,?)",
            (oid, username, pw_h, role, now)
            )
            conn.commit()
            return oid

    except sqlite3.IntegrityError:
        return "ALREADY EXISTS"

    except sqlite3.Error:
        return False

    finally:
        reload_cache()

def query_operatordb(action, username=""):
    try:
        if action == "username":
            if not username:
                return False

            with cache_lock:
                if username.lower() in operators_cache:
                    return username.lower() in operators_cache

                else:
                    return False

    except sqlite3.Error:
        return False


def startup_useradd(password=None):
    username = "gunner"
    if password is None:
        password = secrets.token_urlsafe(16)
    role = "admin"
    now = datetime.utcnow().isoformat()
    conn = _get_conn()

    try:
        with cache_lock:
            if username.lower() in operators_cache:
                return (True, None)

        with write_lock:
            oid  = str(uuid.uuid4())
            pw_h = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            # Atomic, case‐insensitive insert if not exists:
            conn.execute("""
                INSERT OR IGNORE INTO operators(id, username, password_hash, role, created_at)
                SELECT ?, ?, ?, ?, ?
                WHERE NOT EXISTS (SELECT 1 FROM operators WHERE username = ?)""", (oid, username, pw_h, role, now, username))

            conn.commit()
            reload_cache()
            # confirm existence
            cur = conn.execute(
                "SELECT 1 FROM operators WHERE username = ? LIMIT 1",
                (username,)
            )
            if cur.fetchone() is not None:
                return (True, password)
            return False

    except sqlite3.Error as e:
        logger.debug(f"{e}")
        return False


def verify_credentials(username, password):
    with cache_lock:
        entry = operators_cache.get(username.lower())
    pw_hash = entry["password_hash"] if entry else _DUMMY_HASH
    valid = bcrypt.checkpw(password.encode(), pw_hash.encode())
    if entry and valid:
        return {"id": entry["id"], "role": entry["role"]}
    return None

def list_operators():
    # read-only: return snapshot from cache
    with cache_lock:
        return [
            {
                "id": entry["id"],
                "username": uname,
                "role": entry["role"],
                "created_at": entry["created_at"]
            }
            for uname, entry in operators_cache.items()
        ]

def verify_username(username):
    try:
        uname = username.lower().strip()
        with cache_lock:
            entry = operators_cache.get(uname)
            if entry:
                return entry["id"]
        return False

    except Exception as e:
        print(brightred + f"ERROR IN GET UUID BY USERNAME: {e}")
        return False

def delete_operator(identifier):
    """
    Delete an operator by UUID or by username (case‑insensitive).
    Returns True if an operator was removed, False otherwise.
    """
    conn = _get_conn()
    success = False
    hit_error = False
    try:
        with write_lock:
            cur = conn.execute("DELETE FROM operators WHERE id = ?", (identifier,))
            
            if cur.rowcount > 0:
                success = True
                conn.commit()
                reload_cache()
                return True

            return False

    except sqlite3.Error:
        hit_error = True
        return False

    finally:
        if success != True and hit_error:
            reload_cache()

def update_operator(identifier, new_username=None, new_password=None, new_role=None):
    """
    Update an operator's username, password, and/or role by UUID.
    Returns:
      True on success,
      False if nothing to update or operator not found,
      "USERNAME REGEX FAIL" or "PASSWORD REGEX FAIL" or "ROLE INVALID" on bad args.
    """
    fields = []
    values = []

    # -- Username
    if new_username:
        if not re.fullmatch(r"[A-Za-z0-9@._-]{1,32}", new_username):
            return "USERNAME REGEX FAIL"
        fields.append("username = ?")
        values.append(new_username)

    # -- Password
    if new_password:
        if not re.fullmatch(r"\S{1,64}", new_password):
            return "PASSWORD REGEX FAIL"
        pw_h = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        fields.append("password_hash = ?")
        values.append(pw_h)

    # -- Role
    if new_role:
        if new_role not in ("operator", "admin"):
            return "ROLE INVALID"
        fields.append("role = ?")
        values.append(new_role)

    if not fields:
        return False

    conn = _get_conn()
    try:
        with write_lock:
            sql = f"UPDATE operators SET {', '.join(fields)} WHERE id = ?"
            params = values + [identifier]
            cur = conn.execute(sql, params)
            # fallback: match by username if no row updated
            if cur.rowcount == 0:
                alt_sql = f"UPDATE operators SET {', '.join(fields)} WHERE lower(username)=lower(?)"
                cur = conn.execute(alt_sql, [*values, identifier])
            conn.commit()
            reload_cache()
        return cur.rowcount > 0
        
    except sqlite3.Error:
        reload_cache()
        return False