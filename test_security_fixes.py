#!/usr/bin/env python3
"""
Comprehensive test suite for all GunnerC2 security fixes.
Tests: JWT secret, default creds, CORS, command injection quoting,
       auth on endpoints, WebSocket auth, bcrypt migration, gunnerc2 wrapper.
"""
import os, sys, time, json, subprocess, stat, asyncio, signal

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

PASS = 0
FAIL = 0
TESTS = []

def test(name):
    def decorator(fn):
        TESTS.append((name, fn))
        return fn
    return decorator

def ok(msg):
    global PASS
    PASS += 1
    print(f"  \033[32m✓\033[0m {msg}")

def fail(msg):
    global FAIL
    FAIL += 1
    print(f"  \033[31m✗\033[0m {msg}")

def check(condition, pass_msg, fail_msg):
    if condition:
        ok(pass_msg)
    else:
        fail(fail_msg)

# ============================================================================
# PHASE 1: JWT SECRET
# ============================================================================
@test("Phase 1: Dynamic JWT Secret")
def test_jwt_secret():
    secret_path = os.path.expanduser("~/.gunnerc2/jwt_secret")

    # Clean state
    if os.path.exists(secret_path):
        os.remove(secret_path)

    # Import should generate the secret
    if "backend.config" in sys.modules:
        del sys.modules["backend.config"]

    from backend import config
    # Force regeneration by reimporting
    importlib.reload(config)

    # 1. File created
    check(os.path.isfile(secret_path),
          "jwt_secret file created on import",
          "jwt_secret file NOT created")

    # 2. File has correct permissions (0600)
    mode = oct(os.stat(secret_path).st_mode & 0o777)
    check(mode == "0o600",
          f"jwt_secret permissions are 0600 (got {mode})",
          f"jwt_secret permissions wrong: expected 0600, got {mode}")

    # 3. Secret is 64 hex chars
    secret = open(secret_path).read().strip()
    check(len(secret) == 64 and all(c in "0123456789abcdef" for c in secret),
          f"Secret is valid 64-char hex string",
          f"Secret format wrong: len={len(secret)}, value={secret[:20]}...")

    # 4. Secret persists across reimport
    importlib.reload(config)
    secret2 = config.SECRET_KEY
    check(secret == secret2,
          "Secret persists across reimport (not regenerated)",
          f"Secret changed on reimport! {secret[:10]}... vs {secret2[:10]}...")

    # 5. Not the old hardcoded value
    check(secret != "CHANGE_ME_SUPER_SECRET",
          "Secret is NOT the old hardcoded value",
          "SECRET IS STILL HARDCODED!")

    # 6. Different secrets on regeneration
    os.remove(secret_path)
    importlib.reload(config)
    secret3 = config.SECRET_KEY
    check(secret != secret3,
          "New secret generated after deletion (different from previous)",
          "Same secret regenerated — randomness issue")


# ============================================================================
# PHASE 2: BCRYPT MIGRATION (passlib removed)
# ============================================================================
@test("Phase 2: Bcrypt migration (passlib removed)")
def test_bcrypt():
    import bcrypt

    # 1. passlib not imported anywhere
    try:
        import passlib
        # It might be installed but shouldn't be used
    except ImportError:
        pass

    grep_result = subprocess.run(
        ["grep", "-r", "from passlib", "--include=*.py", PROJECT_ROOT],
        capture_output=True, text=True
    )
    passlib_imports = [l for l in grep_result.stdout.strip().split("\n")
                       if l and "__pycache__" not in l and "test_security" not in l]
    check(len(passlib_imports) == 0,
          "No passlib imports found in codebase",
          f"passlib still imported in: {passlib_imports}")

    # 2. auth_manager uses bcrypt directly
    from core.teamserver import auth_manager as auth
    auth._connect()

    # 3. Hash a password
    pw = "TestPassword123!"
    pw_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    check(pw_hash.startswith("$2b$"),
          f"bcrypt hash format correct: {pw_hash[:20]}...",
          f"Unexpected hash format: {pw_hash[:20]}...")

    # 4. Verify correct password
    check(bcrypt.checkpw(pw.encode(), pw_hash.encode()),
          "bcrypt.checkpw verifies correct password",
          "bcrypt.checkpw FAILED on correct password!")

    # 5. Reject wrong password
    check(not bcrypt.checkpw(b"WrongPassword", pw_hash.encode()),
          "bcrypt.checkpw rejects wrong password",
          "bcrypt.checkpw ACCEPTED wrong password!")

    # 6. Test actual operator creation via auth_manager
    # Clean DB first
    db_path = os.path.expanduser("~/.gunnerc2/operators.db")
    if os.path.exists(db_path):
        os.remove(db_path)
    importlib.reload(auth)
    auth._connect()

    try:
        oid = auth.add_operator("testuser", "testpass123", "operator")
        check(oid is not None,
              f"add_operator succeeded, id={oid}",
              "add_operator returned None")
    except Exception as e:
        fail(f"add_operator raised: {e}")
        return

    # 7. Verify credentials work
    result = auth.verify_credentials("testuser", "testpass123")
    check(result is not None and isinstance(result, dict),
          f"verify_credentials accepts valid creds: {result}",
          f"verify_credentials rejected valid creds: {result}")

    # 8. Verify wrong password rejected
    result_bad = auth.verify_credentials("testuser", "wrongpassword")
    check(result_bad is None or result_bad is False or (isinstance(result_bad, dict) and not result_bad),
          "verify_credentials rejects wrong password",
          f"verify_credentials ACCEPTED wrong password: {result_bad}")

    # 9. Verify non-existent user rejected
    result_nouser = auth.verify_credentials("nonexistent", "anything")
    check(result_nouser is None or result_nouser is False,
          "verify_credentials rejects non-existent user",
          f"verify_credentials found non-existent user: {result_nouser}")


# ============================================================================
# PHASE 3: DEFAULT CREDENTIALS
# ============================================================================
@test("Phase 3: No hardcoded default credentials")
def test_default_creds():
    from core.teamserver import auth_manager as auth

    # Clean DB
    db_path = os.path.expanduser("~/.gunnerc2/operators.db")
    for ext in ["", "-shm", "-wal"]:
        p = db_path + ext
        if os.path.exists(p):
            os.remove(p)
    importlib.reload(auth)
    auth._connect()

    # 1. startup_useradd generates random password
    result = auth.startup_useradd()
    check(isinstance(result, tuple) and len(result) == 2,
          f"startup_useradd returns (bool, password) tuple: {type(result)}",
          f"startup_useradd return type wrong: {type(result)} = {result}")

    if isinstance(result, tuple):
        success, password = result
        check(success is True,
              "startup_useradd succeeded",
              f"startup_useradd failed: {success}")
        check(password is not None and len(password) > 10,
              f"Generated password is long enough: {len(password)} chars",
              f"Password too short or None: {password}")
        check(password != "admin",
              "Password is NOT 'admin'",
              "PASSWORD IS STILL 'admin'!")

        # 2. Can't login with old hardcoded creds
        bad1 = auth.verify_credentials("gunner", "admin")
        check(bad1 is None or bad1 is False,
              "gunner:admin rejected (old hardcoded creds don't work)",
              f"gunner:admin ACCEPTED! {bad1}")

        # 3. Can login with generated password
        good = auth.verify_credentials("gunner", password)
        check(good is not None and isinstance(good, dict),
              f"gunner:<generated> accepted",
              f"gunner:<generated> rejected: {good}")

    # 4. Second call returns (True, None) — user already exists
    result2 = auth.startup_useradd()
    check(isinstance(result2, tuple) and result2 == (True, None),
          f"Second startup_useradd returns (True, None): {result2}",
          f"Second startup_useradd unexpected: {result2}")

    # 5. admin:admin not in DB (backend creates admin with random pw, but we test auth_manager only)
    bad2 = auth.verify_credentials("admin", "admin")
    check(bad2 is None or bad2 is False,
          "admin:admin rejected",
          f"admin:admin ACCEPTED: {bad2}")


# ============================================================================
# PHASE 4: COMMAND INJECTION QUOTING
# ============================================================================
@test("Phase 4: Shell quoting functions")
def test_quoting():
    from backend.utils import _psq, _shq

    # PowerShell quoting
    # 1. Normal path
    check(_psq("C:\\Users\\test") == "'C:\\Users\\test'",
          "psq: normal path quoted correctly",
          f"psq normal path: {_psq('C:\\Users\\test')}")

    # 2. Path with single quote (injection attempt)
    result = _psq("test'; Get-Process; echo '")
    check("''" in result and result == "'test''; Get-Process; echo '''",
          f"psq: single-quote escaped to double-quote",
          f"psq injection attempt: {result}")

    # 3. Empty string
    check(_psq("") == "''",
          "psq: empty string → ''",
          f"psq empty: {_psq('')}")

    # Shell quoting
    # 4. Normal path
    check(_shq("/tmp/test") == "'/tmp/test'",
          "shq: normal path quoted correctly",
          f"shq normal: {_shq('/tmp/test')}")

    # 5. Path with single quote (injection attempt)
    result = _shq("test'; rm -rf /; echo '")
    expected = "'test'\"'\"'; rm -rf /; echo '\"'\"''"
    check(result == expected,
          f"shq: single-quote properly escaped",
          f"shq injection: got {result}, expected {expected}")

    # 6. Path with spaces
    check(_shq("/path/with spaces/file") == "'/path/with spaces/file'",
          "shq: spaces handled correctly",
          f"shq spaces: {_shq('/path/with spaces/file')}")

    # 7. Path with backticks (shell expansion)
    result = _shq("`whoami`")
    check(result == "'`whoami`'",
          "shq: backticks safely quoted (inside single quotes)",
          f"shq backticks: {result}")

    # 8. Path with $() (command substitution)
    result = _shq("$(cat /etc/passwd)")
    check(result == "'$(cat /etc/passwd)'",
          "shq: $() safely quoted",
          f"shq command sub: {result}")

    # 9. Path with double quotes
    result = _shq('path"with"quotes')
    check(result == "'path\"with\"quotes'",
          "shq: double quotes pass through (safe inside single quotes)",
          f"shq double quotes: {result}")

    # 10. Path with semicolons
    result = _shq("file; cat /etc/shadow")
    check(result == "'file; cat /etc/shadow'",
          "shq: semicolons safely quoted",
          f"shq semicolons: {result}")

    # 11. Path with newlines
    result = _shq("file\ninjected")
    check(result == "'file\ninjected'",
          "shq: newlines safely quoted inside single quotes",
          f"shq newlines: {result}")

    # 12. Verify files.py actually uses quoting
    files_py = open(os.path.join(PROJECT_ROOT, "backend", "files.py")).read()
    raw_path_interpolations = []
    for i, line in enumerate(files_py.split("\n"), 1):
        if "'{path}'" in line or "'{b64}'" in line:
            raw_path_interpolations.append(f"  line {i}: {line.strip()}")
    check(len(raw_path_interpolations) == 0,
          "files.py has no unquoted path/b64 interpolations",
          f"files.py still has raw interpolations:\n" + "\n".join(raw_path_interpolations))

    # 13. Verify files.py imports from utils
    check("from .utils import _psq, _shq" in files_py,
          "files.py imports _psq, _shq from utils",
          "files.py missing utils import")

    # 14. Verify websocket_files.py uses shared utils
    ws_files_py = open(os.path.join(PROJECT_ROOT, "backend", "websocket_files.py")).read()
    check("from .utils import _psq, _shq" in ws_files_py,
          "websocket_files.py imports from shared utils",
          "websocket_files.py not using shared utils")

    # 15. Verify websocket_files.py doesn't define its own _psq/_shq
    local_def_count = ws_files_py.count("def _psq(") + ws_files_py.count("def _shq(")
    check(local_def_count == 0,
          "websocket_files.py has no local _psq/_shq definitions",
          f"websocket_files.py still defines {local_def_count} local quoting functions")


# ============================================================================
# PHASE 5: CORS LOCKDOWN
# ============================================================================
@test("Phase 5: CORS configuration")
def test_cors():
    main_py = open(os.path.join(PROJECT_ROOT, "backend", "main.py")).read()

    # 1. No wildcard origin
    check('allow_origins=["*"]' not in main_py,
          "No wildcard CORS origin",
          "CORS still allows origin '*'!")

    # 2. Restricted methods
    check('"GET"' in main_py and '"POST"' in main_py,
          "CORS methods explicitly listed",
          "CORS methods not restricted")

    check('allow_methods=["*"]' not in main_py,
          "No wildcard CORS methods",
          "CORS still allows methods '*'!")

    # 3. Restricted headers
    check('allow_headers=["*"]' not in main_py,
          "No wildcard CORS headers",
          "CORS still allows headers '*'!")

    # 4. Configurable via env var
    check("GUNNER_CORS_ORIGINS" in main_py,
          "CORS origins configurable via GUNNER_CORS_ORIGINS env var",
          "No GUNNER_CORS_ORIGINS env var support")

    # 5. Default is localhost only
    check("127.0.0.1" in main_py and "localhost" in main_py,
          "Default CORS origins restricted to localhost",
          "Default CORS origins not localhost")


# ============================================================================
# PHASE 6: AUTH ON ENDPOINTS
# ============================================================================
@test("Phase 6: Auth guards on endpoints")
def test_auth_guards():
    # Check payloads.py
    payloads_py = open(os.path.join(PROJECT_ROOT, "backend", "payloads.py")).read()

    check("from .dependencies import get_current_user" in payloads_py,
          "payloads.py imports get_current_user",
          "payloads.py missing get_current_user import")

    check("Depends(get_current_user)" in payloads_py,
          "payloads.py uses Depends(get_current_user)",
          "payloads.py missing Depends(get_current_user)")

    # Count how many endpoints have auth
    endpoint_count = payloads_py.count("Depends(get_current_user)")
    check(endpoint_count >= 4,
          f"payloads.py has {endpoint_count} auth-guarded endpoints (expected >=4)",
          f"payloads.py only has {endpoint_count} auth-guarded endpoints")

    # Check auth.py
    auth_py = open(os.path.join(PROJECT_ROOT, "backend", "auth.py")).read()

    check("Depends(get_current_user)" in auth_py,
          "auth.py has get_current_user guards",
          "auth.py missing get_current_user guards")

    check("Depends(get_current_admin)" in auth_py,
          "auth.py has get_current_admin guards",
          "auth.py missing get_current_admin guards")

    # Login should NOT have auth
    login_lines = []
    in_login = False
    for line in auth_py.split("\n"):
        if "def login(" in line:
            in_login = True
        if in_login:
            login_lines.append(line)
            if line.strip() and not line.strip().startswith(("def", "@", "#", '"', "'")):
                break

    login_block = "\n".join(login_lines)
    check("Depends(" not in login_block or "def login(body: LoginRequest):" in auth_py,
          "login endpoint has no auth guard (correctly open)",
          "login endpoint has auth guard (should be open!)")

    # Check auth router is registered in main.py
    main_py = open(os.path.join(PROJECT_ROOT, "backend", "main.py")).read()
    check("auth_router" in main_py and 'include_router(auth_router' in main_py,
          "Auth router registered in backend/main.py",
          "Auth router NOT registered!")

    check('prefix="/auth"' in main_py,
          "Auth router mounted at /auth prefix",
          "Auth router prefix wrong")

    # Admin-only endpoints
    admin_count = auth_py.count("Depends(get_current_admin)")
    check(admin_count >= 2,
          f"auth.py has {admin_count} admin-only endpoints (add_operator, delete_operator)",
          f"auth.py only has {admin_count} admin-only endpoints")


# ============================================================================
# PHASE 7: WEBSOCKET AUTH
# ============================================================================
@test("Phase 7: WebSocket operators auth tightening")
def test_ws_auth():
    ws_ops_py = open(os.path.join(PROJECT_ROOT, "backend", "websocket_operators.py")).read()

    # 1. Invalid token → close with 4001
    check("4001" in ws_ops_py,
          "WebSocket closes with code 4001 on invalid token",
          "No 4001 close code found")

    check("await ws.close(code=4001)" in ws_ops_py,
          "Explicit ws.close(code=4001) call present",
          "Missing explicit close(code=4001)")

    # 2. No silent downgrade on invalid token
    # The old code had: except jwt.InvalidTokenError: claims = None
    check('claims = None' not in ws_ops_py.split("InvalidTokenError")[1].split("\n")[0]
          if "InvalidTokenError" in ws_ops_py else False,
          "Invalid token doesn't silently downgrade to unauthenticated",
          "Invalid token still silently sets claims=None")

    # 3. Unauthenticated guard for non-login actions
    check("unauthorized: login required" in ws_ops_py,
          "Unauthenticated connections get 'unauthorized' error for non-login actions",
          "No unauthorized guard for non-login actions")

    # 4. Login and ping still allowed without auth
    check('"login"' in ws_ops_py and '"ping"' in ws_ops_py,
          "login and ping actions referenced in code",
          "login/ping references missing")

    # Check the guard logic
    guard_present = ('act != "login"' in ws_ops_py or 'act != "ping"' in ws_ops_py)
    check(guard_present,
          "Guard checks for login/ping exemption",
          "No login/ping exemption in guard")


# ============================================================================
# PHASE 8: GUNNERC2 WRAPPER
# ============================================================================
@test("Phase 8: gunnerc2 wrapper script")
def test_wrapper():
    wrapper_path = "/usr/bin/gunnerc2"

    # 1. Exists
    check(os.path.isfile(wrapper_path),
          "gunnerc2 exists at /usr/bin/gunnerc2",
          "gunnerc2 NOT found at /usr/bin/gunnerc2")

    # 2. Executable
    check(os.access(wrapper_path, os.X_OK),
          "gunnerc2 is executable",
          "gunnerc2 is NOT executable")

    # 3. Content checks
    content = open(wrapper_path).read()

    check("--gui" in content,
          "Wrapper handles --gui flag",
          "Wrapper missing --gui handling")

    check("--setup" in content,
          "Wrapper handles --setup flag",
          "Wrapper missing --setup handling")

    check(".deps_ok" in content,
          "Wrapper uses .deps_ok marker file",
          "Wrapper missing .deps_ok marker logic")

    check("pip3 install" in content,
          "Wrapper runs pip3 install",
          "Wrapper missing pip3 install")

    check("--break-system-packages" in content,
          "Wrapper includes --break-system-packages for Kali",
          "Wrapper missing --break-system-packages")

    check("gui/main.py" in content,
          "Wrapper launches gui/main.py for --gui",
          "Wrapper missing gui/main.py reference")

    check("main.py" in content,
          "Wrapper launches main.py for CLI",
          "Wrapper missing main.py reference")

    # 4. Marker file exists (deps already installed)
    marker = os.path.expanduser("~/.gunnerc2/.deps_ok")
    check(os.path.isfile(marker),
          ".deps_ok marker file exists (deps were installed)",
          ".deps_ok marker missing")

    # 5. --help works from /tmp
    result = subprocess.run(
        ["gunnerc2", "--help"],
        capture_output=True, text=True, timeout=10, cwd="/tmp"
    )
    check(result.returncode == 0 and "GunnerC2" in result.stdout,
          "gunnerc2 --help works from /tmp",
          f"gunnerc2 --help failed: rc={result.returncode}, out={result.stdout[:100]}")


# ============================================================================
# PHASE 9: REQUIREMENTS.TXT
# ============================================================================
@test("Phase 9: requirements.txt sanity")
def test_requirements():
    req = open(os.path.join(PROJECT_ROOT, "requirements.txt")).read()

    # 1. No passlib
    check("passlib" not in req,
          "requirements.txt has no passlib",
          "requirements.txt still lists passlib!")

    # 2. bcrypt not pinned to old version
    check("bcrypt==4.3.0" not in req,
          "bcrypt not pinned to old incompatible 4.3.0",
          "bcrypt still pinned to 4.3.0!")

    check("bcrypt>=4.3.0" in req,
          "bcrypt has flexible pin >=4.3.0",
          "bcrypt pin unexpected")

    # 3. tqdm not pinned to old version
    check("tqdm==4.67.1" not in req,
          "tqdm not pinned to old 4.67.1",
          "tqdm still pinned to 4.67.1!")

    # 4. Core deps present
    for dep in ["fastapi", "uvicorn", "pydantic", "PyJWT", "cryptography",
                "bcrypt", "colorama", "requests", "PyQt5", "qtawesome"]:
        check(dep in req,
              f"{dep} in requirements.txt",
              f"{dep} MISSING from requirements.txt!")


# ============================================================================
# LIVE API TESTS (start backend, hit endpoints)
# ============================================================================
@test("Phase 10: Live API — auth enforcement")
def test_live_api():
    import importlib

    # Clean DB for predictable state
    db_path = os.path.expanduser("~/.gunnerc2/operators.db")
    for ext in ["", "-shm", "-wal"]:
        p = db_path + ext
        if os.path.exists(p):
            os.remove(p)

    # Start the backend
    import uvicorn, threading

    # Reload to pick up clean DB
    for mod_name in list(sys.modules.keys()):
        if mod_name.startswith("backend.") or mod_name.startswith("core.teamserver"):
            del sys.modules[mod_name]

    from backend.main import app
    from core.teamserver import auth_manager as auth
    auth._connect()

    config = uvicorn.Config(app=app, host="127.0.0.1", port=16060, log_level="error", access_log=False)
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None
    t = threading.Thread(target=server.run, daemon=True)
    t.start()

    # Wait for it
    import socket
    for _ in range(40):
        try:
            s = socket.socket()
            s.settimeout(0.2)
            s.connect(("127.0.0.1", 16060))
            s.close()
            break
        except:
            time.sleep(0.1)
    else:
        fail("Backend failed to start on port 16060")
        return

    ok("Test backend started on port 16060")

    import requests as req

    BASE = "http://127.0.0.1:16060"

    # --- Unauthenticated requests should fail ---

    # 1. Payloads without auth
    r = req.get(f"{BASE}/payloads/windows/ps1", params={
        "transport": "http", "host": "1.2.3.4", "port": 443
    })
    check(r.status_code in (401, 403),
          f"GET /payloads/windows/ps1 without auth → {r.status_code}",
          f"GET /payloads/windows/ps1 without auth → {r.status_code} (expected 401/403)")

    r = req.get(f"{BASE}/payloads/linux/bash", params={
        "transport": "tcp", "host": "1.2.3.4", "port": 4444
    })
    check(r.status_code in (401, 403),
          f"GET /payloads/linux/bash without auth → {r.status_code}",
          f"GET /payloads/linux/bash without auth → {r.status_code} (expected 401/403)")

    r = req.post(f"{BASE}/payloads/windows", json={
        "format": "ps1", "transport": "http", "host": "1.2.3.4", "port": 443
    })
    check(r.status_code in (401, 403),
          f"POST /payloads/windows without auth → {r.status_code}",
          f"POST /payloads/windows without auth → {r.status_code} (expected 401/403)")

    r = req.post(f"{BASE}/payloads/linux", json={
        "format": "bash", "transport": "tcp", "host": "1.2.3.4", "port": 4444
    })
    check(r.status_code in (401, 403),
          f"POST /payloads/linux without auth → {r.status_code}",
          f"POST /payloads/linux without auth → {r.status_code} (expected 401/403)")

    # 2. Operators without auth
    r = req.get(f"{BASE}/auth/operators")
    check(r.status_code in (401, 403),
          f"GET /auth/operators without auth → {r.status_code}",
          f"GET /auth/operators without auth → {r.status_code} (expected 401/403)")

    r = req.post(f"{BASE}/auth/operators", json={
        "username": "hacker", "password": "pwned", "role": "admin"
    })
    check(r.status_code in (401, 403),
          f"POST /auth/operators without auth → {r.status_code}",
          f"POST /auth/operators without auth → {r.status_code} (expected 401/403)")

    r = req.delete(f"{BASE}/auth/operators/fake-id")
    check(r.status_code in (401, 403),
          f"DELETE /auth/operators/fake-id without auth → {r.status_code}",
          f"DELETE /auth/operators/fake-id without auth → {r.status_code} (expected 401/403)")

    # 3. Login with wrong creds
    r = req.post(f"{BASE}/auth/login", json={"username": "admin", "password": "admin"})
    check(r.status_code == 401,
          f"POST /auth/login with admin:admin → {r.status_code} (rejected)",
          f"POST /auth/login with admin:admin → {r.status_code} (should be 401!)")

    # 4. Login with correct creds
    ops = auth.list_operators() or []
    admin_op = next((o for o in ops if o.get("username") == "admin"), None)
    if admin_op:
        # We need to know the random password — we can't easily.
        # Instead, create a known test user.
        pass

    auth.add_operator("tester", "SecurePass99!", "admin")
    r = req.post(f"{BASE}/auth/login", json={"username": "tester", "password": "SecurePass99!"})
    check(r.status_code == 200,
          f"POST /auth/login with valid creds → {r.status_code}",
          f"POST /auth/login with valid creds → {r.status_code} (expected 200)")

    token = None
    if r.status_code == 200:
        token = r.json().get("token")
        check(token is not None and len(token) > 20,
              f"Login returned JWT token ({len(token)} chars)",
              f"Login returned no/bad token: {r.json()}")

    # --- Authenticated requests should succeed ---
    if token:
        headers = {"Authorization": f"Bearer {token}"}

        r = req.get(f"{BASE}/auth/operators", headers=headers)
        check(r.status_code == 200,
              f"GET /auth/operators with auth → {r.status_code}",
              f"GET /auth/operators with auth → {r.status_code} (expected 200)")

        # 5. CORS test — evil origin should be rejected
        r = req.get(f"{BASE}/auth/operators", headers={
            **headers,
            "Origin": "http://evil.com"
        })
        cors_header = r.headers.get("access-control-allow-origin", "")
        check(cors_header != "*" and "evil.com" not in cors_header,
              f"CORS rejects evil origin (header: '{cors_header}')",
              f"CORS allows evil origin! header: '{cors_header}'")

        # 6. Preflight with evil origin
        r = req.options(f"{BASE}/auth/operators", headers={
            "Origin": "http://evil.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization"
        })
        cors_header = r.headers.get("access-control-allow-origin", "")
        check("evil.com" not in cors_header,
              f"CORS preflight rejects evil origin (header: '{cors_header}')",
              f"CORS preflight allows evil origin: '{cors_header}'")

    # 7. Forged JWT with old hardcoded secret
    import jwt as pyjwt
    forged = pyjwt.encode(
        {"sub": "fake-id", "username": "admin", "role": "admin"},
        "CHANGE_ME_SUPER_SECRET",
        algorithm="HS256"
    )
    r = req.get(f"{BASE}/auth/operators", headers={"Authorization": f"Bearer {forged}"})
    check(r.status_code == 401,
          f"Forged JWT (old hardcoded secret) → {r.status_code} (rejected)",
          f"Forged JWT ACCEPTED! Status {r.status_code}")

    # 8. Expired JWT
    expired = pyjwt.encode(
        {"sub": "fake", "username": "admin", "role": "admin", "exp": 1000000},
        open(os.path.expanduser("~/.gunnerc2/jwt_secret")).read().strip(),
        algorithm="HS256"
    )
    r = req.get(f"{BASE}/auth/operators", headers={"Authorization": f"Bearer {expired}"})
    check(r.status_code == 401,
          f"Expired JWT → {r.status_code} (rejected)",
          f"Expired JWT not rejected: {r.status_code}")

    # Shutdown
    server.should_exit = True


# ============================================================================
# RUN ALL TESTS
# ============================================================================
if __name__ == "__main__":
    import importlib
    print("\n" + "=" * 70)
    print("  GunnerC2 Security Fixes — Comprehensive Test Suite")
    print("=" * 70 + "\n")

    for name, fn in TESTS:
        print(f"\n\033[1m[{name}]\033[0m")
        try:
            fn()
        except Exception as e:
            fail(f"TEST CRASHED: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 70)
    total = PASS + FAIL
    if FAIL == 0:
        print(f"  \033[32mALL {total} TESTS PASSED\033[0m")
    else:
        print(f"  \033[32m{PASS} passed\033[0m, \033[31m{FAIL} FAILED\033[0m out of {total}")
    print("=" * 70 + "\n")
    sys.exit(1 if FAIL else 0)
