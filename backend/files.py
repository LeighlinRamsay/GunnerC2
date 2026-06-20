# backend/files.py
from fastapi import APIRouter, HTTPException, UploadFile, File, Query
from fastapi.responses import StreamingResponse
from io import BytesIO
import base64
import json
from typing import List

from core.session_handlers import session_manager
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from .schemas import FileInfo
from .utils import _psq, _shq

router = APIRouter()

def _exec(sid: str, cmd: str, op_id: str = "console", timeout: float = 45.0) -> str:
    sess = session_manager.sessions.get(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    tr = str(getattr(sess, "transport","")).lower()
    if tr in ("http","https"):
        return http_exec.run_command_http(sid, cmd, op_id=op_id, timeout=timeout) or ""
    return tcp_exec.run_command_tcp(sid, cmd, timeout=1.0, op_id=op_id) or ""

@router.get("", response_model=List[FileInfo])
def list_dir(sid: str, path: str = Query(default="."), op_id: str = "console"):
    sess = session_manager.sessions.get(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    os_type = str(getattr(sess, "metadata", {}).get("os","")).lower()

    if "win" in os_type:
        ps = (
            "powershell -NoProfile -Command "
            f"\"Try {{ Get-ChildItem -LiteralPath {_psq(path)} -Force | "
            "Select-Object Name,Length,Mode | ConvertTo-Json -Depth 2 }} "
            "Catch { '' }\""
        )
        raw = _exec(sid, ps, op_id=op_id, timeout=45.0).strip()
        items = []
        if not raw:
            return items
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                data = [data]
            for d in data:
                mode = d.get("Mode","")
                is_dir = "d" in mode.lower()
                items.append({"name": d.get("Name",""), "is_dir": is_dir, "size": (None if is_dir else int(d.get("Length") or 0))})
            return items
        except Exception:
            lines = [l.strip() for l in raw.splitlines() if l.strip()]
            return [{"name": l, "is_dir": l.endswith("\\"), "size": None} for l in lines]
    else:
        sh = f"bash -lc \"ls -1Ap -- {_shq(path)} || true\""
        raw = _exec(sid, sh, op_id=op_id).strip()
        items = []
        for name in [l.strip() for l in raw.splitlines() if l.strip()]:
            is_dir = name.endswith("/")
            clean = name[:-1] if is_dir else name
            items.append({"name": clean, "is_dir": is_dir, "size": None})
        return items

@router.get("/download")
def download_file(sid: str, path: str, op_id: str = "console"):
    sess = session_manager.sessions.get(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    os_type = str(getattr(sess, "metadata", {}).get("os","")).lower()

    if "win" in os_type:
        ps = (
            "powershell -NoProfile -Command "
            f"\"[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
            f"[Convert]::ToBase64String([IO.File]::ReadAllBytes({_psq(path)}))\""
        )
        b64 = _exec(sid, ps, op_id=op_id, timeout=90.0).strip()
    else:
        sh = f"bash -lc \"base64 -w0 -- {_shq(path)} 2>/dev/null || base64 --wrap=0 -- {_shq(path)}\""
        b64 = _exec(sid, sh, op_id=op_id, timeout=90.0).strip()

    try:
        data = base64.b64decode(b64, validate=True)
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to download/parse remote file")

    return StreamingResponse(BytesIO(data), media_type="application/octet-stream")

@router.post("/upload")
async def upload_file(sid: str, path: str, file: UploadFile = File(...), op_id: str = "console"):
    content = await file.read()
    b64 = base64.b64encode(content).decode()

    sess = session_manager.sessions.get(sid)
    if not sess:
        raise HTTPException(status_code=404, detail="Session not found")
    os_type = str(getattr(sess, "metadata", {}).get("os","")).lower()

    if "win" in os_type:
        ps = (
            "powershell -NoProfile -Command "
            f"\"$b=[Convert]::FromBase64String({_psq(b64)}); [IO.File]::WriteAllBytes({_psq(path)},$b)\""
        )
        _ = _exec(sid, ps, op_id=op_id, timeout=180.0)
    else:
        sh = f"bash -lc \"echo {_shq(b64)} | base64 -d > {_shq(path)}\""
        _ = _exec(sid, sh, op_id=op_id, timeout=180.0)

    return {"status": "uploaded", "path": path}
