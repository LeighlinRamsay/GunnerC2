# backend/main.py
import os, sys, secrets
# Ensure the project root (the parent of this file's folder) is on sys.path when run directly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# ensure auth DB is initialized via your auth_manager
from core.teamserver import auth_manager as auth

# 🔧 use relative imports inside the backend package
from .websocket_operators import router as operators_ws_router
from backend.websocket_listeners import router as listeners_ws_router
from .websocket_sessions import router as sessions_ws_router
from .files import router as files_router
from .payloads import router as payloads_router
from .websocket_console import router as ws_router
from .websocket_gunnershell import router as gs_router
from .websocket_files import router as files_ws_router
from .websocket_ldap import router as ldap_ws_router
from .auth import router as auth_router

app = FastAPI(title="GunnerC2 Integrated API", version="1.0")

_cors_origins = [
    o.strip() for o in
    os.environ.get("GUNNER_CORS_ORIGINS", "http://127.0.0.1:6060,http://localhost:6060").split(",")
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "PUT", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

@app.on_event("startup")
def _startup():
    auth._connect()
    ops = auth.list_operators() or []
    if not ops:
        password = secrets.token_urlsafe(16)
        auth.add_operator("admin", password, "admin")
        print(f"\n[!] Initial admin operator created. Username: admin / Password: {password}")
        print("[!] Change this password after first login.\n")

# Routers
app.include_router(operators_ws_router)
app.include_router(listeners_ws_router)
#app.include_router(sessions_router, prefix="/sessions", tags=["sessions"])
app.include_router(sessions_ws_router)
app.include_router(files_ws_router)
app.include_router(payloads_router, prefix="/payloads", tags=["payloads"])
app.include_router(ws_router, tags=["websocket"])
app.include_router(gs_router, tags=["websocket"])
app.include_router(ldap_ws_router, tags=["websocket"])
app.include_router(auth_router, prefix="/auth", tags=["auth"])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("GUNNER_BACKEND_PORT", "6060")))
