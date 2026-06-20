#!/usr/bin/env python3
"""
Live API test — starts gunnerc2 as a subprocess, tests endpoints.
"""
import os, sys, time, json, socket, subprocess, signal, base64

PASS = 0
FAIL = 0

def ok(msg):
    global PASS; PASS += 1
    print(f"  \033[32m✓\033[0m {msg}")

def fail(msg):
    global FAIL; FAIL += 1
    print(f"  \033[31m✗\033[0m {msg}")

def check(cond, pass_msg, fail_msg):
    if cond: ok(pass_msg)
    else: fail(fail_msg)

# Clean state
db_path = os.path.expanduser("~/.gunnerc2/operators.db")
for ext in ["", "-shm", "-wal"]:
    p = db_path + ext
    if os.path.exists(p): os.remove(p)
jwt_path = os.path.expanduser("~/.gunnerc2/jwt_secret")
if os.path.exists(jwt_path): os.remove(jwt_path)

# Pre-seed a known test admin user via auth_manager directly
sys.path.insert(0, "/home/kali/GunnerC2")
from core.teamserver import auth_manager as auth
auth._connect()
auth.add_operator("testadmin", "TestAdminPass99!", "admin")
ok("Pre-seeded testadmin user in DB")

# Start gunnerc2 as a subprocess (it starts the backend on port 6060)
print("[*] Starting gunnerc2 backend...")
proc = subprocess.Popen(
    ["python3", "main.py"],
    cwd="/home/kali/GunnerC2",
    stdin=subprocess.PIPE,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    text=True
)

# Wait for backend to come up
PORT = 6060
for i in range(60):
    try:
        s = socket.socket(); s.settimeout(0.2); s.connect(("127.0.0.1", PORT)); s.close(); break
    except: time.sleep(0.25)
else:
    print("FATAL: Backend didn't start in 15s")
    proc.kill()
    sys.exit(1)

time.sleep(1)
ok(f"Backend started on port {PORT}")
admin_pw = "TestAdminPass99!"

import requests as req
import jwt as pyjwt

BASE = f"http://127.0.0.1:{PORT}"

print(f"\n\033[1m[Unauthenticated requests — should all be rejected]\033[0m")

# Payload endpoints
r = req.get(f"{BASE}/payloads/windows/ps1", params={"transport":"http","host":"1.2.3.4","port":443})
check(r.status_code in (401,403), f"GET /payloads/windows/ps1 → {r.status_code} (blocked)", f"GET /payloads/windows/ps1 → {r.status_code} SHOULD BE 401!")

r = req.get(f"{BASE}/payloads/linux/bash", params={"transport":"tcp","host":"1.2.3.4","port":4444})
check(r.status_code in (401,403), f"GET /payloads/linux/bash → {r.status_code} (blocked)", f"GET /payloads/linux/bash → {r.status_code} SHOULD BE 401!")

r = req.post(f"{BASE}/payloads/windows", json={"format":"ps1","transport":"http","host":"1.2.3.4","port":443})
check(r.status_code in (401,403), f"POST /payloads/windows → {r.status_code} (blocked)", f"POST /payloads/windows → {r.status_code} SHOULD BE 401!")

r = req.post(f"{BASE}/payloads/linux", json={"format":"bash","transport":"tcp","host":"1.2.3.4","port":4444})
check(r.status_code in (401,403), f"POST /payloads/linux → {r.status_code} (blocked)", f"POST /payloads/linux → {r.status_code} SHOULD BE 401!")

# Operator management endpoints
r = req.get(f"{BASE}/auth/operators")
check(r.status_code in (401,403), f"GET /auth/operators → {r.status_code} (blocked)", f"GET /auth/operators → {r.status_code} SHOULD BE 401!")

r = req.post(f"{BASE}/auth/operators", json={"username":"hacker","password":"pwned123","role":"admin"})
check(r.status_code in (401,403), f"POST /auth/operators → {r.status_code} (blocked)", f"POST /auth/operators → {r.status_code} SHOULD BE 401!")

r = req.delete(f"{BASE}/auth/operators/fake-id")
check(r.status_code in (401,403), f"DELETE /auth/operators/fake → {r.status_code} (blocked)", f"DELETE /auth/operators/fake → {r.status_code} SHOULD BE 401!")

print(f"\n\033[1m[Login — credential validation]\033[0m")

# Old hardcoded creds
r = req.post(f"{BASE}/auth/login", json={"username":"admin","password":"admin"})
check(r.status_code == 401, f"admin:admin → {r.status_code} (rejected)", f"admin:admin → {r.status_code} SHOULD BE REJECTED!")

r = req.post(f"{BASE}/auth/login", json={"username":"gunner","password":"admin"})
check(r.status_code == 401, f"gunner:admin → {r.status_code} (rejected)", f"gunner:admin → {r.status_code} SHOULD BE REJECTED!")

# Empty creds
r = req.post(f"{BASE}/auth/login", json={"username":"","password":""})
check(r.status_code in (401, 422), f"empty:empty → {r.status_code} (rejected)", f"empty:empty → {r.status_code}")

# SQL injection attempt
r = req.post(f"{BASE}/auth/login", json={"username":"' OR 1=1 --","password":"anything"})
check(r.status_code in (401, 422), f"SQLi attempt → {r.status_code} (rejected)", f"SQLi attempt → {r.status_code}")

# Login with pre-seeded test admin
token = None
r = req.post(f"{BASE}/auth/login", json={"username":"testadmin","password":admin_pw})
check(r.status_code == 200, f"testadmin:<known_pw> → {r.status_code} (accepted)", f"testadmin:<known_pw> → {r.status_code} SHOULD BE 200!")
if r.status_code == 200:
    token = r.json().get("token")
    check(token and len(token) > 20, f"Got JWT token ({len(token)} chars)", "No valid JWT returned!")

print(f"\n\033[1m[Authenticated requests]\033[0m")

if token:
    headers = {"Authorization": f"Bearer {token}"}

    r = req.get(f"{BASE}/auth/operators", headers=headers)
    check(r.status_code == 200, f"GET /auth/operators with auth → {r.status_code}", f"GET /auth/operators with auth → {r.status_code}")

    # Create an operator (admin can do this)
    r = req.post(f"{BASE}/auth/operators", json={"username":"normie","password":"NormPass123!","role":"operator"}, headers=headers)
    check(r.status_code == 200, f"Admin creates operator → {r.status_code}", f"Admin can't create operator → {r.status_code}")
    normie_id = r.json().get("id") if r.status_code == 200 else None

    # Login as the new operator
    r = req.post(f"{BASE}/auth/login", json={"username":"normie","password":"NormPass123!"})
    normie_token = r.json().get("token") if r.status_code == 200 else None

print(f"\n\033[1m[RBAC — admin vs operator]\033[0m")

if token and normie_token:
    normie_headers = {"Authorization": f"Bearer {normie_token}"}
    admin_headers = {"Authorization": f"Bearer {token}"}

    # Operator CAN list
    r = req.get(f"{BASE}/auth/operators", headers=normie_headers)
    check(r.status_code == 200, f"Operator can list → {r.status_code}", f"Operator can't list → {r.status_code}")

    # Operator CANNOT add
    r = req.post(f"{BASE}/auth/operators", json={"username":"sneaky","password":"x1234567","role":"admin"}, headers=normie_headers)
    check(r.status_code == 403, f"Operator can't add → {r.status_code} (forbidden)", f"Operator CAN add! → {r.status_code}")

    # Operator CANNOT delete
    r = req.delete(f"{BASE}/auth/operators/{normie_id or 'fake'}", headers=normie_headers)
    check(r.status_code == 403, f"Operator can't delete → {r.status_code} (forbidden)", f"Operator CAN delete! → {r.status_code}")

    # Admin CAN delete
    if normie_id:
        r = req.delete(f"{BASE}/auth/operators/{normie_id}", headers=admin_headers)
        check(r.status_code == 200, f"Admin can delete → {r.status_code}", f"Admin can't delete → {r.status_code}")

print(f"\n\033[1m[CORS enforcement]\033[0m")

if token:
    headers = {"Authorization": f"Bearer {token}"}

    r = req.get(f"{BASE}/auth/operators", headers={**headers, "Origin": "http://evil.com"})
    cors = r.headers.get("access-control-allow-origin", "")
    check(cors != "*" and "evil.com" not in cors, f"Evil origin rejected (ACAO: '{cors}')", f"Evil origin ALLOWED! ACAO: '{cors}'")

    r = req.get(f"{BASE}/auth/operators", headers={**headers, "Origin": "http://127.0.0.1:6060"})
    cors = r.headers.get("access-control-allow-origin", "")
    check("127.0.0.1" in cors or cors == "", f"Localhost origin OK (ACAO: '{cors}')", f"Localhost rejected! ACAO: '{cors}'")

    r = req.options(f"{BASE}/auth/operators", headers={
        "Origin": "http://evil.com",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "Authorization"
    })
    cors = r.headers.get("access-control-allow-origin", "")
    check("evil.com" not in cors, f"Preflight rejects evil (ACAO: '{cors}')", f"Preflight allows evil! ACAO: '{cors}'")

print(f"\n\033[1m[JWT token security]\033[0m")

# Forged JWT — old hardcoded secret
forged = pyjwt.encode({"sub":"fake","username":"admin","role":"admin"}, "CHANGE_ME_SUPER_SECRET", algorithm="HS256")
r = req.get(f"{BASE}/auth/operators", headers={"Authorization": f"Bearer {forged}"})
check(r.status_code == 401, f"Forged JWT (old secret) → {r.status_code} (rejected)", f"Forged JWT ACCEPTED! → {r.status_code}")

# Forged JWT — random secret
forged2 = pyjwt.encode({"sub":"fake","username":"admin","role":"admin"}, "totally_wrong_secret_xyz", algorithm="HS256")
r = req.get(f"{BASE}/auth/operators", headers={"Authorization": f"Bearer {forged2}"})
check(r.status_code == 401, f"Forged JWT (random secret) → {r.status_code} (rejected)", f"Forged JWT ACCEPTED! → {r.status_code}")

# Expired JWT — correct secret
real_secret = open(os.path.expanduser("~/.gunnerc2/jwt_secret")).read().strip()
expired = pyjwt.encode({"sub":"fake","username":"admin","role":"admin","exp":1000000}, real_secret, algorithm="HS256")
r = req.get(f"{BASE}/auth/operators", headers={"Authorization": f"Bearer {expired}"})
check(r.status_code == 401, f"Expired JWT → {r.status_code} (rejected)", f"Expired JWT not rejected → {r.status_code}")

# Tampered JWT payload
if token:
    parts = token.split(".")
    if len(parts) == 3:
        tampered = parts[0] + "." + base64.urlsafe_b64encode(b'{"sub":"admin","username":"admin","role":"admin"}').decode().rstrip("=") + "." + parts[2]
        r = req.get(f"{BASE}/auth/operators", headers={"Authorization": f"Bearer {tampered}"})
        check(r.status_code == 401, f"Tampered JWT → {r.status_code} (rejected)", f"Tampered JWT ACCEPTED! → {r.status_code}")

# Garbage token
r = req.get(f"{BASE}/auth/operators", headers={"Authorization": "Bearer not.a.real.jwt"})
check(r.status_code == 401, f"Garbage token → {r.status_code} (rejected)", f"Garbage token → {r.status_code}")

# Empty bearer
r = req.get(f"{BASE}/auth/operators", headers={"Authorization": "Bearer "})
check(r.status_code in (401, 403, 422), f"Empty bearer → {r.status_code} (rejected)", f"Empty bearer → {r.status_code}")

print(f"\n\033[1m[WebSocket auth]\033[0m")

try:
    import websockets
    import asyncio

    async def test_ws():
        global PASS, FAIL

        # 1. Invalid token → close with 4001
        try:
            async with websockets.connect(f"ws://127.0.0.1:{PORT}/ws/operators?token=invalid.jwt.garbage") as ws:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=3)
                    fail(f"Invalid token WS: got msg instead of close: {msg[:80]}")
                except websockets.ConnectionClosed as e:
                    check(e.code == 4001, f"Invalid token → closed with {e.code}", f"Invalid token → closed with {e.code} (expected 4001)")
        except websockets.ConnectionClosedError as e:
            check(e.code == 4001, f"Invalid token → closed with {e.code}", f"Invalid token → closed with {e.code} (expected 4001)")
        except Exception as e:
            fail(f"Invalid token WS test error: {e}")

        # 2. No token — unauthenticated, only login/ping allowed
        try:
            async with websockets.connect(f"ws://127.0.0.1:{PORT}/ws/operators") as ws:
                # Non-login action should be rejected
                await ws.send(json.dumps({"action": "list", "req_id": "t1"}))
                msg = await asyncio.wait_for(ws.recv(), timeout=3)
                data = json.loads(msg)
                check(data.get("type") == "error" and "unauthorized" in data.get("error", "").lower(),
                      f"Unauthed 'list' → error: {data.get('error','')}",
                      f"Unauthed 'list' → unexpected: {data}")

                # add action should be rejected
                await ws.send(json.dumps({"action": "add", "username": "evil", "password": "evil", "role": "admin", "req_id": "t1b"}))
                msg = await asyncio.wait_for(ws.recv(), timeout=3)
                data = json.loads(msg)
                check(data.get("type") == "error" and "unauthorized" in data.get("error", "").lower(),
                      f"Unauthed 'add' → error (blocked)",
                      f"Unauthed 'add' → unexpected: {data}")

                # delete action should be rejected
                await ws.send(json.dumps({"action": "delete", "operator_id": "fake", "req_id": "t1c"}))
                msg = await asyncio.wait_for(ws.recv(), timeout=3)
                data = json.loads(msg)
                check(data.get("type") == "error" and "unauthorized" in data.get("error", "").lower(),
                      f"Unauthed 'delete' → error (blocked)",
                      f"Unauthed 'delete' → unexpected: {data}")

                # Ping should work
                await ws.send(json.dumps({"action": "ping", "req_id": "t2"}))
                msg = await asyncio.wait_for(ws.recv(), timeout=3)
                data = json.loads(msg)
                check(data.get("type") == "pong", f"Unauthed 'ping' → pong (allowed)", f"Unauthed 'ping' → {data}")

                # Login should work
                if admin_pw:
                    await ws.send(json.dumps({"action": "login", "username": "testadmin", "password": admin_pw, "req_id": "t3"}))
                    msg = await asyncio.wait_for(ws.recv(), timeout=3)
                    data = json.loads(msg)
                    check(data.get("type") == "login_ok" and data.get("token"),
                          f"WS login succeeded", f"WS login failed: {data}")

                    # After login, list should work
                    await ws.send(json.dumps({"action": "list", "req_id": "t4"}))
                    msg = await asyncio.wait_for(ws.recv(), timeout=3)
                    data = json.loads(msg)
                    is_ok = data.get("type") in ("snapshot", "operators") or "operators" in data
                    check(is_ok, f"Authed 'list' → success (type={data.get('type','')})", f"Authed 'list' → {data}")

        except Exception as e:
            fail(f"No-token WS test error: {e}")

        # 3. Valid token from the start
        if token:
            try:
                async with websockets.connect(f"ws://127.0.0.1:{PORT}/ws/operators?token={token}") as ws:
                    await ws.send(json.dumps({"action": "list", "req_id": "t5"}))
                    msg = await asyncio.wait_for(ws.recv(), timeout=3)
                    data = json.loads(msg)
                    is_ok = data.get("type") in ("snapshot", "operators") or "operators" in data
                    check(is_ok, f"Valid token WS 'list' → success", f"Valid token WS 'list' → {data}")
            except Exception as e:
                fail(f"Valid-token WS test error: {e}")

    asyncio.run(test_ws())

except ImportError:
    print("  [!] websockets not installed, skipping WS tests")
    # Install and retry
    subprocess.run([sys.executable, "-m", "pip", "install", "--break-system-packages", "websockets"], capture_output=True)
    print("  [!] Installed websockets, please re-run")

# Clean up
proc.kill()
proc.wait()

print(f"\n{'='*70}")
total = PASS + FAIL
if FAIL == 0:
    print(f"  \033[32mALL {total} TESTS PASSED\033[0m")
else:
    print(f"  \033[32m{PASS} passed\033[0m, \033[31m{FAIL} FAILED\033[0m out of {total}")
print(f"{'='*70}\n")
sys.exit(1 if FAIL else 0)
