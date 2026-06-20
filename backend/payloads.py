from fastapi import APIRouter, HTTPException, Depends
from .dependencies import get_current_user
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from typing import Dict, Optional
from colorama import Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

router = APIRouter()

# ---- Import the same generators the CLI uses -------------------------------
# Windows TCP
from core.payload_generator.windows.tcp.ps1 import powershell_reverse_tcp as win_tcp_ps1
from core.payload_generator.windows.tcp.exe import exe_reverse_tcp as win_tcp_exe

# Windows TLS
from core.payload_generator.windows.tls.ps1 import powershell_reverse_tls as win_tls_ps1
from core.payload_generator.windows.tls.exe import exe_reverse_tls as win_tls_exe

# Windows HTTP(S)
from core.payload_generator.windows.http.ps1 import powershell_reverse_http as win_http_ps1
from core.payload_generator.windows.http.exe import exe_reverse_http as win_http_exe
from core.payload_generator.windows.https.ps1 import powershell_reverse_https as win_https_ps1
from core.payload_generator.windows.https.exe import exe_reverse_https as win_https_exe
from core.payload_generator.windows.https.gunnerplant import gunnerplant_reverse_https as win_https_gp

# Linux
from core.payload_generator.linux.tcp import bash_reverse_tcp as lin_tcp
from core.payload_generator.linux.http import bash_reverse_http as lin_http

def _as_text(payload) -> str:
    """
    Normalize generator output to text or raise a clean HTTP error.
    Some generators return False/None on failure; bytes are allowed.
    """
    if payload is None or payload is False:
        raise HTTPException(status_code=400, detail="Failed to generate payload")
    if isinstance(payload, (bytes, bytearray)):
        try:
            return payload.decode("utf-8", "ignore")
        except Exception:
            return payload.decode("latin1", "ignore")
    if not isinstance(payload, str):
        # last resort: stringify but disallow non-useful bools
        return str(payload)
    return payload


# ---- Schemas ----------------------------------------------------------------
class WindowsPayload(BaseModel):
    # format & transport
    format: str = Field(pattern="^(ps1|exe|gunnerplant)$")
    transport: str = Field(pattern="^(tcp|tls|http|https)$")
    host: str
    port: int

    # common/advanced
    obs: int = 0
    no_child: Optional[bool] = False
    beacon: int = 5
    jitter: int = 0
    headers: Optional[Dict[str, str]] = None
    useragent: Optional[str] = None
    accept: Optional[str] = None
    byte_range: Optional[str] = None
    profile: Optional[str] = None

    # stager options for EXE/Gunnerplant builds
    stager_ip: str = "0.0.0.0"
    stager_port: int = 9999


class LinuxPayload(BaseModel):
    format: str = Field(pattern="^(bash)$")
    transport: str = Field(pattern="^(tcp|http)$")
    host: str
    port: int
    # advanced
    obs: int = 0
    beacon: int = 5
    use_ssl: bool = False


# ---- Core builders (wrap generator modules) ---------------------------------
def build_windows(cfg: WindowsPayload) -> str:
    t = cfg.transport.lower()
    f = cfg.format.lower()
    ip, port = cfg.host, cfg.port

    # Informative build banner for heavy formats
    if f == "exe":
        print(brightgreen + "[+] Building exe payload" + reset)
    elif f == "gunnerplant":
        print(brightgreen + "[+] Building GunnerPlant payload" + reset)

    # Guard: Gunnerplant is HTTPS-only
    if f == "gunnerplant" and t != "https":
        raise HTTPException(status_code=400, detail="Gunnerplant is only available over HTTPS")

    # TCP / TLS
    if t == "tcp":
        if f == "ps1":
            return _as_text(win_tcp_ps1.generate_powershell_reverse_tcp(ip, port, cfg.obs, cfg.no_child))
        if f == "exe":
            return _as_text(win_tcp_exe.generate_exe_reverse_tcp(ip, port, cfg.stager_ip, cfg.stager_port))
    if t == "tls":
        if f == "ps1":
            return _as_text(win_tls_ps1.generate_powershell_reverse_tls(ip, port, cfg.obs, cfg.no_child))
        if f == "exe":
            return _as_text(win_tls_exe.generate_exe_reverse_tls(ip, port, cfg.stager_ip, cfg.stager_port))

    # HTTP
    if t == "http":
        if f == "ps1":
            return _as_text(win_http_ps1.generate_windows_powershell_http(
                ip, port, cfg.obs, cfg.beacon, cfg.headers or {},
                cfg.useragent, accept=cfg.accept, byte_range=cfg.byte_range,
                jitter=cfg.jitter, no_child=None, profile=cfg.profile
            ))
        if f == "exe":
            return _as_text(win_http_exe.generate_exe_reverse_http(
                ip, port, cfg.obs, cfg.beacon, cfg.headers or {},
                cfg.useragent, cfg.stager_ip, cfg.stager_port,
                accept=cfg.accept, byte_range=cfg.byte_range,
                jitter=cfg.jitter, profile=cfg.profile
            ))

    # HTTPS
    if t == "https":
        if f == "ps1":
            return _as_text(win_https_ps1.generate_windows_powershell_https(
                ip, port, cfg.obs, cfg.beacon, cfg.headers or {},
                cfg.useragent, accept=cfg.accept, byte_range=cfg.byte_range,
                jitter=cfg.jitter, no_child=None, profile=cfg.profile
            ))
        if f == "exe":
            return _as_text(win_https_exe.generate_exe_reverse_https(
                ip, port, cfg.obs, cfg.beacon, cfg.headers or {},
                cfg.useragent, cfg.stager_ip, cfg.stager_port,
                accept=cfg.accept, byte_range=cfg.byte_range,
                jitter=cfg.jitter, profile=cfg.profile
            ))
        if f == "gunnerplant":
            return _as_text(win_https_gp.generate_gunnerplant_reverse_https(
                ip, port, cfg.obs, cfg.beacon, cfg.headers or {},
                cfg.useragent, cfg.stager_ip, cfg.stager_port,
                accept=cfg.accept, byte_range=cfg.byte_range,
                jitter=cfg.jitter, profile=cfg.profile
            ))

    raise HTTPException(status_code=400, detail="Unsupported format/transport combination")


def build_linux(cfg: LinuxPayload) -> str:
    if cfg.transport.lower() == "tcp":
        return _as_text(lin_tcp.generate_bash_reverse_tcp(cfg.host, cfg.port, cfg.obs, cfg.use_ssl))
    if cfg.transport.lower() == "http":
        return _as_text(lin_http.generate_bash_reverse_http(cfg.host, cfg.port, cfg.obs, cfg.beacon))
    raise HTTPException(status_code=400, detail="Linux transport must be tcp or http")


# ---- New JSON endpoints -----------------------------------------------------
@router.post("/windows", response_class=PlainTextResponse)
def windows_payload(cfg: WindowsPayload, user: dict = Depends(get_current_user)):
    try:
        return build_windows(cfg)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/linux", response_class=PlainTextResponse)
def linux_payload(cfg: LinuxPayload, user: dict = Depends(get_current_user)):
    try:
        return build_linux(cfg)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---- Legacy routes kept for compatibility ----------------------------------
@router.get("/windows/ps1", response_class=PlainTextResponse)
def win_ps1(transport: str, host: str, port: int, beacon: int = 5, user: dict = Depends(get_current_user)):
    t = transport.lower()
    if t not in ("http", "https"):
        raise HTTPException(status_code=400, detail="transport must be http or https")
    cfg = WindowsPayload(format="ps1", transport=t, host=host, port=port, beacon=beacon)
    return build_windows(cfg)


@router.get("/linux/bash", response_class=PlainTextResponse)
def linux_bash(transport: str, host: str, port: int, user: dict = Depends(get_current_user)):
    t = transport.lower()
    if t not in ("tcp", "http"):
        raise HTTPException(status_code=400, detail="transport must be tcp or http")
    cfg = LinuxPayload(format="bash", transport=t, host=host, port=port)
    return build_linux(cfg)