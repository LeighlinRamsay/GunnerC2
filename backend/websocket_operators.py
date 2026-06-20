# backend/websocket_operators.py
import asyncio, json, hashlib
from typing import Any, Dict, Optional
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import jwt
from contextlib import suppress

from . import config
from .dependencies import create_access_token
from core.teamserver import auth_manager as auth

router = APIRouter()

# ---------- helpers ----------------------------------------------------------

def _serialize_ops():
    ops = auth.list_operators() or []
    return [
        {
            "id": o.get("id") or o.get("uuid") or o.get("op_id"),
            "username": o.get("username",""),
            "role": o.get("role","operator"),
            "created_at": o.get("created_at","")
        }
        for o in ops
    ]

def _get_operator_by_username(username: str) -> Optional[dict]:
    # Mirrors backend/auth.py behavior
    try:
        if hasattr(auth, "get_operator_by_username"):
            row = auth.get_operator_by_username(username)
            if row: return row
    except Exception:
        pass
    try:
        for o in (auth.list_operators() or []):
            if str(o.get("username","")).lower() == (username or "").lower():
                return o
    except Exception:
        pass
    try:
        if hasattr(auth, "verify_username"):
            op_id = auth.verify_username(username)
            if op_id:
                return {"id": op_id, "username": username, "role": "operator"}
    except Exception:
        pass
    return None

async def _ws_send(ws: WebSocket, payload: Dict[str, Any]):
    try:
        await ws.send_text(json.dumps(payload, separators=(",", ":"), default=str))
    except WebSocketDisconnect:
        raise
    except Exception:
        pass

def _normalize_login_result(username: str, raw_row: Optional[dict]) -> Optional[dict]:
    if not raw_row: return None
    uid = raw_row.get("id") or raw_row.get("op_id") or raw_row.get("uuid")
    uname = raw_row.get("username") or username
    role = raw_row.get("role") or "operator"
    if not uid:
        try:
            uid = auth.verify_username(uname)
        except Exception:
            uid = None
    if not uid:
        return None
    return {"id": uid, "username": uname, "role": role}

# ---------- command handlers -------------------------------------------------

async def _cmd_list(ws, req, claims):
    if not claims:
        return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"unauthorized"})
    await _ws_send(ws, {"type":"snapshot", "req_id": req.get("req_id"), "operators": _serialize_ops()})

async def _cmd_add(ws, req, claims):
    if not claims:  # auth required
        return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"unauthorized"})
    if (claims.get("role") or "operator") != "admin":
        return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"forbidden"})
    u = (req.get("username") or "").strip()
    p = req.get("password") or ""
    r = (req.get("role") or "operator").lower()
    try:
        oid = auth.add_operator(u, p, r)
        if oid is True or (isinstance(oid, str) and len(oid) >= 8):
            await _ws_send(ws, {"type":"added","req_id":req.get("req_id"),
                                "operator":{"id":oid, "username":u, "role":r}})
            await _ws_send(ws, {"type":"snapshot","operators":_serialize_ops()})
            return
        if oid in ("ALREADY EXISTS","USERNAME REGEX FAIL","PASSWORD REGEX FAIL"):
            return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":oid})
        await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"add failed"})
    except Exception as e:
        await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":str(e)})

async def _cmd_delete(ws, req, claims):
    if not claims:
        return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"unauthorized"})
    if (claims.get("role") or "operator") != "admin":
        return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"forbidden"})
    ident = (req.get("id") or req.get("username") or "").strip()
    ok = auth.delete_operator(ident)
    if ok:
        await _ws_send(ws, {"type":"deleted","req_id":req.get("req_id"),"id":ident})
        await _ws_send(ws, {"type":"snapshot","operators":_serialize_ops()})
    else:
        await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"Operator not found"})

async def _cmd_update(ws, req, claims):
    if not claims:
        return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"unauthorized"})
    if (claims.get("role") or "operator") != "admin":
        return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"forbidden"})
    ident = (req.get("id") or req.get("username") or "").strip()
    nu = req.get("username_new")
    np = req.get("password_new")
    nr = req.get("role_new")
    res = auth.update_operator(ident, new_username=nu, new_password=np, new_role=nr)
    if res is True:
        await _ws_send(ws, {"type":"updated","req_id":req.get("req_id"),
                            "id": ident, "username": nu, "role": (nr if nr is not None else None)})
        await _ws_send(ws, {"type":"snapshot","operators":_serialize_ops()})
    else:
        err = res if isinstance(res, str) else "update failed"
        await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":err})

async def _cmd_login(ws, req):
    """
    WS login action: {"action":"login","username":"...","password":"..."}
    Replies: {"type":"login_ok","token":"<jwt>","me":{"id":...,"username":...,"role":...}}
    or {"type":"error","error":"Invalid username or password"}
    """
    username = (req.get("username") or "").strip()
    password = req.get("password") or ""
    ok = False
    row: Optional[dict] = None

    # Primary path: verify_credentials (mirrors REST)
    try:
        if hasattr(auth, "verify_credentials"):
            res = auth.verify_credentials(username, password)
            if isinstance(res, tuple) and len(res) >= 2:
                ok, row = bool(res[0]), res[1]
            elif isinstance(res, dict):
                ok, row = True, res
            elif isinstance(res, bool):
                ok = res
                if ok:
                    row = _get_operator_by_username(username)
            else:
                ok = False
        else:
            ok = False
    except Exception:
        try:
            if hasattr(auth, "verify_username") and hasattr(auth, "verify_password"):
                op_id = auth.verify_username(username)
                if op_id and auth.verify_password(op_id, password):
                    ok = True
                    row = _get_operator_by_username(username)
        except Exception:
            ok = False
            row = None

    norm = _normalize_login_result(username, row) if ok else None
    if not ok or not norm:
        return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"Invalid username or password"})

    token = create_access_token({"sub": norm["id"], "username": norm["username"], "role": norm["role"]})
    await _ws_send(ws, {"type":"login_ok","req_id":req.get("req_id"),"token":token,"me":norm})
    return norm  # return claims dict for caller

# ---------- socket -----------------------------------------------------------

@router.websocket("/ws/operators")
async def operators_ws(ws: WebSocket):
    await ws.accept()

    # Connection auth state (None until verified)
    claims: Optional[dict] = None

    token = ws.query_params.get("token")
    if token:
        try:
            claims = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        except jwt.InvalidTokenError:
            await ws.close(code=4001)
            return

    # writer pushes only once authenticated
    last_hash = None
    async def writer():
        nonlocal last_hash, claims
        try:
            while True:
                if claims:
                    snap = {"type":"snapshot","operators":_serialize_ops()}
                    blob = json.dumps(snap, sort_keys=True, separators=(",", ":"), default=str).encode()
                    h = hashlib.sha1(blob).hexdigest()
                    if h != last_hash:
                        await _ws_send(ws, snap)
                        last_hash = h
                await asyncio.sleep(1.0)
        except (WebSocketDisconnect, asyncio.CancelledError):
            pass

    async def reader():
        nonlocal claims
        actions = {
            "login":  _cmd_login,  # special: returns claims on success
            "list":   lambda w,r: _cmd_list(w,r,claims),
            "add":    lambda w,r: _cmd_add(w,r,claims),
            "update": lambda w,r: _cmd_update(w,r,claims),
            "delete": lambda w,r: _cmd_delete(w,r,claims),
            "ping":   lambda w,r: _ws_send(w, {"type":"pong","req_id":r.get("req_id")}),
        }
        while True:
            raw = await ws.receive_text()
            try:
                req = json.loads(raw)
            except Exception:
                await _ws_send(ws, {"type":"error","error":"Invalid JSON"}); continue

            act = (req.get("action") or "").lower()
            if act == "login":
                norm = await _cmd_login(ws, req)
                if isinstance(norm, dict):
                    claims = {"sub": norm["id"], "username": norm["username"], "role": norm["role"]}
                continue

            if act != "ping" and not claims:
                await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"unauthorized: login required"})
                continue

            fn = actions.get(act)
            if not fn:
                await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":f"Unknown action '{act}'"}); continue
            await fn(ws, req)

    writer_task = asyncio.create_task(writer())
    try:
        await reader()
    except WebSocketDisconnect:
        pass
    finally:
        writer_task.cancel()
        with suppress(asyncio.CancelledError):
            await writer_task
