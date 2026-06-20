# backend/websocket_files.py
from __future__ import annotations
import asyncio, json, os, ntpath, tempfile, time, shutil, uuid, hashlib, binascii, struct
from typing import Any, Dict, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import jwt

from contextlib import suppress

from . import config
from core.session_handlers import session_manager
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec
from core.transfers.manager import TransferManager, TransferOpts
from .schemas import FileInfo  # reuse your model

# ---------- logging ----------
from .logutil import get_logger, bind, span, file_magic, sha256_path, safe_preview, redacts
logger = get_logger("backend.websocket_files", file_basename="files_ws")

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
reset = Style.RESET_ALL

router = APIRouter()

# ----------------- shared helpers -----------------
async def _ws_send(ws: WebSocket, payload: Dict[str, Any], log):
	"""Send JSON and log payload type/size."""
	try:
		txt = json.dumps(payload, separators=(",", ":"), default=str)
		await ws.send_text(txt)
		# LOG: outbound frame
		log.debug("ws.send",
				  extra={"payload_type": payload.get("type"),
						 "req_id": payload.get("req_id"),
						 "tid": payload.get("tid"),
						 "status": payload.get("status"),
						 "json_bytes": len(txt)})
	except WebSocketDisconnect:
		raise
	except Exception as e:
		log.exception("ws.send.error", extra={"err": repr(e)})

def _resolve_sid(sid: str) -> str:
	try:
		if hasattr(session_manager, "resolve_sid"):
			return session_manager.resolve_sid(sid) or sid
	except Exception:
		pass
	return sid

def _run_remote(sid: str, cmd: str, transport: str, timeout: float | None = 10.0, log=None, defender_bypass: bool = False) -> str:
	"""Run a command on the session and log the outcome (truncated)."""
	preview = safe_preview(cmd, limit=240)
	if transport in ("http", "https"):
		out = http_exec.run_command_http(sid, cmd, op_id="files", timeout=timeout) or ""
	else:
		out = tcp_exec.run_command_tcp(sid, cmd, timeout=1.0, defender_bypass=defender_bypass, portscan_active=True, op_id="files") or ""

	if log:
		log.debug("remote.exec",
				  extra={"sid": sid, "transport": transport, "timeout": timeout,
						 "cmd_preview": preview, "out_len": len(out)})
	return out

from .utils import _psq, _shq

# ----------------- websocket route -----------------
@router.websocket("/ws/files")
async def files_ws(ws: WebSocket):
	await ws.accept()
	wsid = uuid.uuid4().hex[:8]
	client = None
	try:
		client = f"{ws.client.host}:{ws.client.port}"  # type: ignore[attr-defined]
	except Exception:
		pass
	log = bind(logger, wsid=wsid, client=client)

	# LOG: connection
	log.info("ws.connect", extra={"path": "/ws/files", "client": client})

	# ---- auth (same as sessions ws) ----
	token = ws.query_params.get("token")
	if not token:
		log.warning("ws.auth.missing_token")
		await ws.close(code=1008); return
	try:
		jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
		log.info("ws.auth.ok", extra={"token_preview": redacts(token, show=4)})
	except jwt.InvalidTokenError:
		log.warning("ws.auth.invalid")
		await ws.close(code=1008); return

	# Per-connection state
	tm = TransferManager()
	active_download_task: Optional[asyncio.Task] = None
	active_download_path: Optional[str] = None      # ← add
	active_download_folder: bool = False            # ← add
	active_download_tid: Optional[str] = None       # ← add

	active_upload_tmp: Optional[str] = None
	active_upload_expect: int = 0
	active_upload_sid: Optional[str] = None
	# When uploading a folder we need BOTH an archive path and a target directory:
	active_upload_remote_archive: Optional[str] = None  # e.g. /tmp/core.zip or /tmp/core.tar.gz
	active_upload_remote_dir: Optional[str] = None      # e.g. /tmp/core/
	active_upload_is_folder: bool = False

	async def _do_list(req: Dict[str, Any]):
		sid = _resolve_sid(req.get("sid",""))
		path = req.get("path","")
		req_id = req.get("req_id")
		sess = session_manager.sessions.get(sid)
		if not sess:
			log.warning("fs.list.session_missing", extra={"sid": sid, "path": path, "req_id": req_id})
			return await _ws_send(ws, {"type":"error","req_id":req_id,"error":"Session not found"}, log)

		os_type   = (getattr(sess,"metadata",{}) or {}).get("os","").lower()
		transport = str(getattr(sess,"transport","")).lower()
		log.debug("fs.list.begin", extra={"sid": sid, "path": path, "os": os_type, "transport": transport, "req_id": req_id})

		# ---------- Windows ----------
		if os_type == "windows":
			# Build rows with owner. We keep all fields you already used and add 'owner'.
			ps = (
				f"$p = Get-Item -LiteralPath {_psq(path)} -ErrorAction SilentlyContinue; "
				f"if ($null -eq $p) {{ 'MISSING' }} else {{ "
				f"$full = $p.FullName; "
				f"$rows = @(Get-ChildItem -LiteralPath $full -Force -ErrorAction SilentlyContinue | "
				f"  Select-Object "
				f"    @{{n='name';e={{$_.Name}}}}, "
				f"    @{{n='is_dir';e={{$_.PSIsContainer}}}}, "
				f"    @{{n='size';e={{ if ($_.PSIsContainer) {{ $null }} else {{ [int64]$_.Length }} }}}}, "
				f"    @{{n='mtime';e={{ [double]([DateTimeOffset]$_.LastWriteTimeUtc).ToUnixTimeMilliseconds() }}}}, "
				f"    @{{n='type';e={{ if ($_.PSIsContainer) {{ 'File folder' }} elseif ($_.Extension) {{ ($_.Extension.TrimStart('.') + ' file') }} else {{ 'File' }} }}}}, "
				f"    @{{n='owner';e={{ try {{ (Get-Acl -LiteralPath $_.FullName -ErrorAction Stop).Owner }} catch {{ '' }} }}}} "
				f") ; "
				f"@{{ path = $full; entries = $rows }} | ConvertTo-Json -Compress -Depth 4 }}"
			)

			out = _run_remote(sid, ps, transport, log=log)
			log.debug("fs.list.win.raw", extra={"sid": sid, "path": path, "raw_len": len(out or ""), "raw_preview": (out or "")[:256]})

			if (out or "").strip() == "MISSING":
				log.info("fs.list.missing", extra={"sid": sid, "path": path})
				return await _ws_send(ws, {"type":"fs.list","req_id":req_id,"path":path,"entries":[],"ok":False}, log)

			try:
				obj = json.loads(out) if (out and out.strip().startswith("{")) else {}
			except Exception:
				log.exception("fs.list.parse_error", extra={"sid": sid, "path": path})
				obj = {}

			real_path = obj.get("path", path)
			rows = obj.get("entries", [])
			if isinstance(rows, dict):
				rows = [rows]
			elif rows is None:
				rows = []

			# Normalize: ensure keys exist even if PS failed to get ACL.
			for r in rows:
				r.setdefault("owner", "")

			log.info("fs.list.ok", extra={"sid": sid, "path": real_path, "count": len(rows)})
			return await _ws_send(ws, {"type":"fs.list","req_id":req_id,"path":real_path,"entries":rows,"ok":True}, log)

		else:
			# ---------- Linux / Posix ----------
			# Add %u (owner username) to the printed columns.
			cmd = (
				'P=$1; FMT=$2; '
    			'[ -d "$P" ] || { echo MISSING; exit 0; }; '
    			'find "$P" -maxdepth 1 -mindepth 1 -printf "$FMT" 2>/dev/null || true'
			)

			# One quoted string for the command, then two quoted args: path and format
			sh = "sh -c " + _shq(cmd) + " _ " + _shq(path) + " " + _shq(r"%f\t%y\t%s\t%T@\t%u\n")

			out = _run_remote(sid, sh, transport, log=log, defender_bypass=True)

			if "MISSING" in (out or ""):
				log.info("fs.list.missing", extra={"sid": sid, "path": path})
				return await _ws_send(ws, {"type":"fs.list","req_id":req_id,"path":path,"entries":[],"ok":False}, log)

			entries = []
			for line in (out or "").splitlines():
				name, typ, sz, mt, owner = (line.split("\t") + ["","","","",""])[:5]
				is_dir   = typ.lower().startswith("d")
				size     = None if is_dir else int(sz or 0)
				mtime_ms = int(float(mt or 0) * 1000.0)
				type_label = "File folder" if is_dir else "File"
				entries.append({
					"name":   name,
					"is_dir": is_dir,
					"size":   size,
					"mtime":  mtime_ms,
					"type":   type_label,
					"owner":  owner or ""
				})

			log.info("fs.list.ok", extra={"sid": sid, "path": path, "count": len(entries), "cmd": sh, "output": out})
			await _ws_send(ws, {"type":"fs.list","req_id":req_id,"path":path,"entries":entries,"ok":True}, log)

	async def _do_delete(req: Dict[str, Any]):
		"""
		Delete a remote file or (optionally) a directory.
		Request:
		{ "action": "fs.delete", "sid": "...", "path": "<remote>", "folder": false, "req_id": "..." }
		Response:
		{ "type": "deleted", "req_id": "...", "path": "<remote>", "ok": true|false, "error": "..." }
		"""
		sid     = _resolve_sid(req.get("sid", ""))
		target  = req.get("path") or req.get("remote_path") or ""
		allow_dir = bool(req.get("folder", False))
		req_id  = req.get("req_id")

		if not sid or not target:
			return await _ws_send(ws, {"type":"deleted","req_id":req_id,"path":target,"ok":False,"error":"Missing sid/path"}, log)

		sess = session_manager.sessions.get(sid)
		if not sess:
			return await _ws_send(ws, {"type":"deleted","req_id":req_id,"path":target,"ok":False,"error":"Session not found"}, log)

		os_type   = (getattr(sess, "metadata", {}) or {}).get("os", "").lower()
		transport = str(getattr(sess, "transport", "")).lower()

		log.info("fs.delete.begin", extra={"sid": sid, "path": target, "allow_dir": allow_dir, "os": os_type, "transport": transport, "req_id": req_id})

		try:
			if os_type == "windows":
				allow_ps = "$true" if allow_dir else "$false"
				ps = (
					"$ErrorActionPreference='Stop';"
					f"$p={_psq(target)};"
					f"$allow={allow_ps};"
					"if (-not (Test-Path -LiteralPath $p)) { 'MISSING' } else {"
					"  $it = Get-Item -LiteralPath $p -Force;"
					"  $isDir = $it.PSIsContainer;"
					"  if ($isDir -and -not $allow) { 'DENY_DIR' } else {"
					"    try {"
					"      if ($isDir) { Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction Stop; 'OK:D' }"
					"      else { Remove-Item -LiteralPath $p -Force -ErrorAction Stop; 'OK:F' }"
					"    } catch { 'ERR:' + ($_ | Out-String).Trim() }"
					"  }"
					"}"
				)
				out = _run_remote(sid, ps, transport, log=log)

			else:
				# no `set -e` so we can emit explicit OK/ERR messages
				allow_flag = "1" if allow_dir else "0"
				sh = (
					"bash -lc " +
					_shq(
						f'P={_shq(target)}; ALLOW={allow_flag}; '
						'if [ ! -e "$P" ]; then echo MISSING; exit 0; fi; '
						'if [ -d "$P" ]; then '
						'  if [ "$ALLOW" = "1" ]; then '
						'    if rm -rf -- "$P"; then echo OK:D; else echo ERR:rm_dir_failed; fi; '
						'  else '
						'    echo DENY_DIR; '
						'  fi '
						'else '
						'  if rm -f -- "$P"; then echo OK:F; else echo ERR:rm_file_failed; fi; '
						'fi'
					)
				)
				out = _run_remote(sid, sh, transport, log=log, defender_bypass=True)

			txt = (out or "").replace("\r", "").strip()
			log.debug("fs.delete.raw", extra={"preview": txt[:300]})

			if txt.startswith("OK"):
				await _ws_send(ws, {"type":"deleted","req_id":req_id,"path":target,"ok":True}, log)
				log.info("fs.delete.ok", extra={"sid": sid, "path": target})
			elif "MISSING" in txt:
				await _ws_send(ws, {"type":"deleted","req_id":req_id,"path":target,"ok":False,"error":"Not found"}, log)
			elif "DENY_DIR" in txt:
				await _ws_send(ws, {"type":"deleted","req_id":req_id,"path":target,"ok":False,"error":"Refusing to delete directory without folder=True"}, log)
			else:
				await _ws_send(ws, {"type":"deleted","req_id":req_id,"path":target,"ok":False,"error": (txt[:400] or "delete_failed")}, log)
				log.warning("fs.delete.err", extra={"sid": sid, "path": target, "detail": txt[:400]})

		except Exception as e:
			log.exception("fs.delete.exception", extra={"sid": sid, "path": target})
			await _ws_send(ws, {"type":"deleted","req_id":req_id,"path":target,"ok":False,"error":f"{e!r}"}, log)

	async def _do_new_folder(req: Dict[str, Any]):
		sid = _resolve_sid(req.get("sid",""))
		req_id = req.get("req_id")
		parent = req.get("dir") or req.get("parent") or ""
		name   = req.get("name") or ""
		full   = req.get("path") or ""
		if not full:
			if not (sid and parent and name):
				return await _ws_send(ws, {"type":"fs.new.result","req_id":req_id,"kind":"folder","ok":False,"error":"Missing sid/dir/name or path"}, log)
			# join safe for OS
			sess = session_manager.sessions.get(sid)
			os_type = (getattr(sess,"metadata",{}) or {}).get("os","").lower() if sess else ""
			sep = "\\" if os_type == "windows" else "/"
			full = (parent.rstrip("\\/") + sep + name)

		if not sid or not full:
			return await _ws_send(ws, {"type":"fs.new.result","req_id":req_id,"kind":"folder","ok":False,"error":"Missing sid/path"}, log)

		sess = session_manager.sessions.get(sid)
		if not sess:
			return await _ws_send(ws, {"type":"fs.new.result","req_id":req_id,"kind":"folder","ok":False,"error":"Session not found"}, log)
		os_type   = (getattr(sess,"metadata",{}) or {}).get("os","").lower()
		transport = str(getattr(sess,"transport","")).lower()

		try:
			if os_type == "windows":
				ps = (
					f"$ErrorActionPreference='Stop';"
					f"$p={_psq(full)};"
					f"if (Test-Path -LiteralPath $p) {{ 'EXISTS' }} else {{"
					f"  New-Item -ItemType Directory -Force -Path $p | Out-Null; "
					f"  if (Test-Path -LiteralPath $p) {{ 'OK' }} else {{ 'ERR' }} }}"
				)
				out = _run_remote(sid, ps, transport, log=log)
			else:
				cmd = f"set -e; P={_shq(full)}; if [ -e \"$P\" ]; then echo EXISTS; else mkdir -p \"$P\"; fi; [ -d \"$P\" ] && echo OK || echo ERR"
				out = _run_remote(sid, "bash -lc " + _shq(cmd), transport, log=log, defender_bypass=True)

			txt = (out or "").strip()
			ok = ("OK" in txt) or ("EXISTS" in txt and bool(req.get("ok_if_exists", True)))
			err = "" if ok else (f"create_failed: {txt[:200]}" or "create_failed")
			await _ws_send(ws, {"type":"fs.new.result","req_id":req_id,"kind":"folder","ok":ok,"error":err,"path":full,"name":(name or "")}, log)
		except Exception as e:
			log.exception("fs.new_folder.error")
			await _ws_send(ws, {"type":"fs.new.result","req_id":req_id,"kind":"folder","ok":False,"error":f"{e!r}","path":full}, log)


	async def _do_new_text(req: Dict[str, Any]):
		sid = _resolve_sid(req.get("sid",""))
		req_id = req.get("req_id")
		parent = req.get("dir") or req.get("parent") or ""
		name   = req.get("name") or ""
		full   = req.get("path") or ""
		if not full:
			if not (sid and parent and name):
				return await _ws_send(ws, {"type":"fs.new.result","req_id":req_id,"kind":"text","ok":False,"error":"Missing sid/dir/name or path"}, log)
			sess = session_manager.sessions.get(sid)
			os_type = (getattr(sess,"metadata",{}) or {}).get("os","").lower() if sess else ""
			sep = "\\" if os_type == "windows" else "/"
			full = (parent.rstrip("\\/") + sep + name)

		if not sid or not full:
			return await _ws_send(ws, {"type":"fs.new.result","req_id":req_id,"kind":"text","ok":False,"error":"Missing sid/path"}, log)

		sess = session_manager.sessions.get(sid)
		if not sess:
			return await _ws_send(ws, {"type":"fs.new.result","req_id":req_id,"kind":"text","ok":False,"error":"Session not found"}, log)
		os_type   = (getattr(sess,"metadata",{}) or {}).get("os","").lower()
		transport = str(getattr(sess,"transport","")).lower()

		try:
			if os_type == "windows":
				ps = (
					f"$ErrorActionPreference='Stop';"
					f"$f={_psq(full)}; $d=[System.IO.Path]::GetDirectoryName($f);"
					f"New-Item -ItemType Directory -Force -Path $d | Out-Null;"
					f"if (Test-Path -LiteralPath $f) {{ 'EXISTS' }} else {{ New-Item -ItemType File -Path $f -Force | Out-Null; 'OK' }}"
				)
				out = _run_remote(sid, ps, transport, log=log)
			else:
				cmd = f"set -e; F={_shq(full)}; mkdir -p \"$(dirname \"$F\")\"; [ -e \"$F\" ] && echo EXISTS || ( : > \"$F\" && echo OK )"
				out = _run_remote(sid, "bash -lc " + _shq(cmd), transport, log=log, defender_bypass=True)

			txt = (out or "").strip()
			ok = ("OK" in txt) or ("EXISTS" in txt and bool(req.get("ok_if_exists", True)))
			err = "" if ok else (f"create_failed: {txt[:200]}" or "create_failed")
			await _ws_send(ws, {"type":"fs.new.result","req_id":req_id,"kind":"text","ok":ok,"error":err,"path":full,"name":(name or "")}, log)

		except Exception as e:
			log.exception("fs.new_text.error")
			await _ws_send(ws, {"type":"fs.new.result","req_id":req_id,"kind":"text","ok":False,"error":f"{e!r}","path":full}, log)
	
	async def _do_download(req: Dict[str, Any]):
		"""
		Start a remote download via TransferManager and stream the bytes over this websocket.
		- Emits:
			fs.download.begin { tid, name }
			fs.download.meta  { tid, total_bytes }           (once known)
			fs.download.end   { tid, status, error, bytes_sent, sha256 }
		- Heavily logs progress and forensics (sizes, head/tail hex, sha256).
		- Drains any remaining bytes after TM finalizes/renames the file to avoid truncation.
		"""

		nonlocal active_download_task, active_download_path, active_download_folder, active_download_tid

		# lightweight peer id for logs
		try:
			ws_peer = f"{ws.client.host}:{ws.client.port}" if ws.client else "?"
		except Exception:
			ws_peer = "?"

		sid    = _resolve_sid(req.get("sid", ""))
		path   = req.get("path", "")
		req_id = req.get("req_id")
		sess   = session_manager.sessions.get(sid)
		if not sess:
			logger.warning("fs.download.session_missing sid=%s path=%s req_id=%s", sid, path, req_id)
			await _ws_send(ws, {"type": "error", "req_id": req_id, "error": "Session not found"}, log)
			return

		os_type = (getattr(sess, "metadata", {}) or {}).get("os", "").lower()

		tmp_dir = tempfile.mkdtemp(prefix="gc2_dl_ws_")
		fname   = (ntpath.basename(path) if os_type == "windows" or "\\" in path else os.path.basename(path)) or "file.bin"
		dest    = os.path.join(tmp_dir, fname)

		folder = bool(req.get("folder", False))

		if active_download_task and not active_download_task.done():
			req_path = req.get("path", "")
			req_folder = bool(req.get("folder", False))
			if req_path == (active_download_path or "") and req_folder == active_download_folder:
				# Duplicate click for the same file while streaming; just acknowledge and return
				logger.info("fs.download.duplicate sid=%s path=%s (already streaming)", sid, req_path)
				await _ws_send(ws, {"type": "fs.download.already", "path": req_path, "tid": active_download_tid}, log)
				return
			logger.warning("fs.download.reject_busy sid=%s req_id=%s", req.get("sid"), req.get("req_id"))
			await _ws_send(ws, {"type": "error", "req_id": req.get("req_id"), "error": "Download already in progress on this socket"}, log)
			return
			
		logger.info("fs.download.begin sid=%s peer=%s path=%s folder=%s tmp_dir=%s dest=%s req_id=%s",
					sid, ws_peer, path, folder, tmp_dir, dest, req_id)

		# Kick off transfer manager (GUI extracts locally; we defer extraction here)
		tid = tm.start_download(sid, path, dest, folder=folder, opts=TransferOpts(quiet=True, defer_extract=True))
		active_download_path = path
		active_download_folder = folder
		active_download_tid = tid
		logger.info("DL start tid=%s sid=%s remote=%s -> %s (folder=%s)", tid, sid, path, dest, folder)

		await _ws_send(ws, {"type": "fs.download.begin", "req_id": req_id, "tid": tid, "name": fname}, log)

		async def _pump():
			nonlocal active_download_path, active_download_folder, active_download_tid
			t0 = time.perf_counter()
			hasher = hashlib.sha256()
			last = 0                       # how many bytes we have sent to the GUI so far
			part_path = None               # path to TM's part file (data.part)
			announced_total = False
			last_log_t = t0

			def _hex_head_tail(p: str, head_n: int = 16, tail_n: int = 64) -> tuple[str, str]:
				try:
					size = os.path.getsize(p)
					with open(p, "rb") as f:
						head = f.read(head_n)
						if size > tail_n:
							f.seek(size - tail_n)
							tail = f.read(tail_n)
						else:
							f.seek(0)
							tail = f.read(size)
					return binascii.hexlify(head).decode(), binascii.hexlify(tail).decode()
				except Exception:
					return "", ""

			def _probe_zip_eocd(path: str, max_scan: int = 22 + 65535 + 4096):
				"""
				Return (ok: bool, meta: dict, err: str|None) for a ZIP EOCD footer.
				meta keys: offset, size, comment_len, cd_size, cd_offset, entries_total, entries_on_disk, disk_no, disk_cd
				"""
				try:
					size = os.path.getsize(path)
					if size < 22:
						return False, {"size": size}, "file_too_small_for_eocd"
					sig = b"\x50\x4b\x05\x06"
					scan = min(max_scan, size)
					with open(path, "rb") as f:
						f.seek(size - scan)
						buf = f.read(scan)
					i = buf.rfind(sig)
					if i == -1:
						return False, {"size": size}, "eocd_signature_not_found"
					off = size - scan + i
					if off + 22 > size:
						return False, {"offset": off, "size": size}, "eocd_truncated_header"
					disk_no, disk_cd, entries_disk, entries_total, cd_size, cd_offset, comment_len = \
						struct.unpack_from("<HHHHIIH", buf, i + 4)
					meta = dict(offset=off, size=size, comment_len=comment_len,
								cd_size=cd_size, cd_offset=cd_offset,
								entries_total=entries_total, entries_on_disk=entries_disk,
								disk_no=disk_no, disk_cd=disk_cd)
					# comment must end exactly at EOF
					if off + 22 + comment_len != size:
						return False, meta, "comment_len_mismatch"
					# central directory should fit before EOCD for non-ZIP64 indicators
					if cd_offset != 0xFFFFFFFF and cd_size != 0xFFFFFFFF and cd_offset + cd_size > off:
						return False, meta, "central_dir_bounds_invalid"
					return True, meta, None
				except Exception as e:
					return False, {}, f"probe_exception:{e!r}"

			try:
				while True:
					st = tm.store.load(sid, tid)

					# Announce total_bytes once known (useful for client-side completeness checks)
					if not announced_total and (st.total_bytes or 0) > 0:
						await _ws_send(ws, {"type": "fs.download.meta", "tid": tid, "total_bytes": st.total_bytes}, log)
						logger.debug("DL[%s] meta total_bytes=%s sid=%s", tid, st.total_bytes, sid)
						announced_total = True

					# terminal states
					if st.status in ("done", "error", "cancelled", "paused"):
						# On success, stream the FINAL artifact once to avoid reading holes/zeros from a preallocated part file.
						bytes_sent = 0
						final_src = st.local_path if (st.local_path and os.path.exists(st.local_path)) else ""
						if st.status == "done" and final_src:
							logger.debug("DL[%s] final stream start sid=%s file=%s", tid, sid, final_src)
							try:
								with open(final_src, "rb") as f:
									#chunk = f.read(256 * 1024)
									# send bigger websocket frames to reduce per-frame overhead
									chunk = f.read(1024 * 1024)  # 1 MiB frames
									while chunk:
										await ws.send_bytes(chunk)
										hasher.update(chunk)
										bytes_sent += len(chunk)
										now = time.perf_counter()
										if now - last_log_t >= 1.0:
											elapsed = max(1e-6, now - t0)
											bps = int(bytes_sent / elapsed)
											logger.debug("fs.download.stream tid=%s sent=%d bps=%d sid=%s src=final",
														 tid, bytes_sent, bps, sid)
											last_log_t = now
										#chunk = f.read(256 * 1024)
										chunk = f.read(1024 * 1024)
							except Exception as de:
								logger.exception("DL[%s] final stream failed sid=%s err=%r", tid, sid, de)
								# downgrade to error so GUI won’t try to extract
								st.status = "error"
								st.error = f"final_stream_failed:{de}"

						size_on_disk = os.path.getsize(final_src) if final_src and os.path.exists(final_src) else -1
						head_hex, tail_hex = _hex_head_tail(final_src) if final_src else ("", "")
						sha_stream = hasher.hexdigest()
						eocd_ok = None; eocd_meta = None; eocd_err = None

						# If it looks like a ZIP, validate EOCD before telling the GUI it's 'done'
						end_status = st.status
						end_error = st.error
						#eocd_meta = {}
						try:
							if final_src and size_on_disk >= 4:
								with open(final_src, "rb") as _ff:
									head4 = _ff.read(4)
								if head4.startswith(b"PK\x03\x04"):
									ok, eocd_meta, eocd_err = _probe_zip_eocd(final_src)
									logger.info("zip.eocd.probe tid=%s sid=%s ok=%s meta=%s err=%s",
												tid, sid, ok, eocd_meta, eocd_err)
									if not ok and st.status == "done":
										# Mark as error so the GUI won't attempt extraction
										end_status = "error"
										end_error = f"zip_eocd_invalid: {eocd_err}"
						except Exception as _pe:
							logger.exception("zip.eocd.probe_exception tid=%s sid=%s err=%r", tid, sid, _pe)

						logger.info(
							"fs.download.end tid=%s sid=%s status=%s error=%s sent=%d expect=%s sha256=%s file=%s size=%d head=%s tail=%s peer=%s",
						tid, sid, st.status, st.error, (bytes_sent or 0), (st.total_bytes or "n/a"), sha_stream,
							(final_src or "<none>"), size_on_disk, head_hex, tail_hex, ws_peer
						)

						# If it looks like a ZIP, validate EOCD now (after we have the complete final file).
						eocd_ok = None; eocd_meta = None; eocd_err = None
						try:
							if final_src and size_on_disk >= 4:
								with open(final_src, "rb") as _ff:
									if _ff.read(4).startswith(b"PK\x03\x04"):
										ok, eocd_meta, eocd_err = _probe_zip_eocd(final_src)
										eocd_ok = ok
										logger.info("zip.eocd.probe tid=%s sid=%s ok=%s meta=%s err=%s", tid, sid, ok, eocd_meta, eocd_err)
										if not ok and st.status == "done":
											st.status = "error"
											st.error = f"zip_eocd_invalid:{eocd_err}"
						except Exception as _pe:
							logger.exception("zip.eocd.probe_exception tid=%s sid=%s err=%r", tid, sid, _pe)

						# let the GUI verify bytes & hash before extracting
						await _ws_send(
							ws,
							{
								"type": "fs.download.end",
								"tid": tid,
								"status": st.status,
								"error": st.error,
								"bytes_sent": (bytes_sent or 0),
								"sha256": sha_stream,
								"head_hex": head_hex,
								"tail_hex": tail_hex,
								"eocd_ok": eocd_ok,
								"eocd": eocd_meta,
								"eocd_err": eocd_err,
							},
							log,
						)
						active_download_path = None
						active_download_folder = False
						active_download_tid = None
						break

					await asyncio.sleep(0.10)
			finally:
					try:
						shutil.rmtree(tmp_dir, ignore_errors=True)
						logger.debug("fs.download.tmp_cleanup tid=%s tmp_dir=%s sid=%s", tid, tmp_dir, sid)
					except Exception as e:
						logger.exception("fs.download.tmp_cleanup_error tid=%s sid=%s err=%r", tid, sid, e)

		active_download_task = asyncio.create_task(_pump())

	async def _do_upload_begin(req: Dict[str, Any]):
		nonlocal active_upload_tmp, active_upload_expect, active_upload_sid, active_upload_remote_archive, active_upload_remote_dir, active_upload_is_folder
		if active_upload_tmp is not None:
			log.warning("fs.upload.reject_busy", extra={"req_id": req.get("req_id")})
			return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),"error":"Upload already in progress on this socket"}, log)

		sid = _resolve_sid(req.get("sid",""))
		is_folder = bool(req.get("folder", False))
		size = int(req.get("size") or 0)

		# Accept both shapes:
		#  A) folder=False: expect remote_path (file)
		#  B) folder=True:
		#     - preferred:  remote_path (archive) + remote_dir (extract target)
		#     - legacy:     remote_dir only  -> derive remote_path from OS + extension
		remote_path = req.get("remote_path") or ""
		remote_dir  = req.get("remote_dir")  or ""



		# Derive missing pieces for folder uploads
		if is_folder:
			# Need session to decide archive extension if remote_path missing
			sess = session_manager.sessions.get(sid)
			os_type = (getattr(sess,"metadata",{}) or {}).get("os","").lower() if sess else ""

			if not remote_path and remote_dir:
				# Choose extension by target OS
				ext = ".zip" if os_type == "windows" else ".tar.gz"
				remote_path = (remote_dir.rstrip("/\\") + ext)
				log.debug("fs.upload.begin.derive_remote_path",
						  extra={"sid": sid, "os": os_type, "derived_remote_path": remote_path, "from_remote_dir": remote_dir})

			if not remote_dir and remote_path:
				# Derive a directory name from archive name
				lp = remote_path.lower()
				if lp.endswith(".tar.gz"):
					remote_dir = remote_path[:-7]
				elif lp.endswith(".zip"):
					remote_dir = remote_path[:-4]
				else:
					remote_dir = remote_path + ".dir"
				log.debug("fs.upload.begin.derive_remote_dir",
						  extra={"sid": sid, "derived_remote_dir": remote_dir, "from_remote_path": remote_path})

		# For plain file upload, remote_path is the target file.
		target_descriptor = remote_path if not is_folder else f"{remote_path} (extract→ {remote_dir})"

		# Validate
		if not sid or size < 0 or (not remote_path and not is_folder) or (is_folder and (not remote_path and not remote_dir)):
			log.warning("fs.upload.bad_request",
						extra={"sid": sid, "folder": is_folder, "remote_path": remote_path, "remote_dir": remote_dir, "size": size})
			return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),
									   "error":"Missing sid/remote_path/size (or remote_dir for folder)"},
								  log)

		# Validation
		if not sid or size < 0 or (not is_folder and not remote_path) or (is_folder and (not remote_path or not remote_dir)):
			log.warning("fs.upload.bad_request",
						extra={"sid": sid, "folder": is_folder, "remote_path": remote_path, "remote_dir": remote_dir, "size": size})
			return await _ws_send(ws, {"type":"error","req_id":req.get("req_id"),
									   "error":"Missing sid/remote_path/size (and remote_dir for folder)"}, log)

		# Pick a concrete path we will write first: file uploads -> remote_path;
		# folder uploads -> the archive path (remote_path) we upload, not the extract dir.
		test_target = remote_path or ""
		if is_folder and not test_target:
			# very defensive; shouldn't happen because we derive it above
			sess = session_manager.sessions.get(sid)
			os_type = (getattr(sess,"metadata",{}) or {}).get("os","").lower() if sess else ""
			ext = ".zip" if os_type == "windows" else ".tar.gz"
			test_target = (remote_dir.rstrip("/\\") + ext)

		ok, detail = await _preflight_can_write(sid, test_target)
		if not ok:
			log.warning("fs.upload.preflight_denied", extra={"sid": sid, "target": test_target, "detail": detail})
			# Tell the UI immediately and DO NOT accept the upload stream.
			return await _ws_send(
				ws,
				{
					"type": "fs.upload.result",
					"req_id": req.get("req_id"),
					"status": "error",
					"error": f"access_denied: {detail[:200]}",
				},
				log,
			)

		fd, tmp_path = tempfile.mkstemp(prefix="gc2_ul_ws_")
		os.close(fd)
		active_upload_tmp = tmp_path
		active_upload_expect = size
		active_upload_sid = sid
		active_upload_is_folder = is_folder
		active_upload_remote_archive = remote_path or None
		active_upload_remote_dir = (remote_dir or None) if is_folder else None

		log.info("fs.upload.accept",
				 extra={"sid": sid, "folder": is_folder, "target": target_descriptor, "expect_bytes": size,
						"tmp_file": tmp_path})
		log.debug("fs.upload.accept.details",
				  extra={"remote_path": remote_path, "remote_dir": remote_dir})
		await _ws_send(ws, {"type":"fs.upload.accept","req_id":req.get("req_id"), "explicit_finish": False}, log)

	async def _do_upload_finish():
		nonlocal active_upload_tmp, active_upload_expect, active_upload_sid, active_upload_remote_archive, active_upload_remote_dir, active_upload_is_folder
		# Always upload the file/archive first; extraction is handled here after success.
		tid = tm.start_upload(active_upload_sid, active_upload_tmp, (active_upload_remote_archive or ""),
							  folder=False, opts=TransferOpts(quiet=True))

		# Local tmp meta before we lose it
		try:
			meta = {
				"tmp_path": active_upload_tmp,
				"size": os.path.getsize(active_upload_tmp) if active_upload_tmp and os.path.exists(active_upload_tmp) else 0,
				"magic": file_magic(active_upload_tmp) if active_upload_tmp else "",
				"sha256": sha256_path(active_upload_tmp) if active_upload_tmp and os.path.exists(active_upload_tmp) else "",
			}
			log.debug("fs.upload.tmp_meta", extra=meta)
		except Exception:
			log.exception("fs.upload.tmp_meta_error")

		log.info("fs.upload.tm_begin",
				 extra={"sid": active_upload_sid, "remote_path": active_upload_remote_archive,
						"folder": active_upload_is_folder, "remote_dir": active_upload_remote_dir,
						"tmp": active_upload_tmp, "tid": tid})

		terminal = {"done","error","cancelled","paused"}  # include paused so the waiter always ends
		while True:
			st = tm.store.load(active_upload_sid, tid)
			log.debug("fs.upload.tm_poll", extra={"tid": tid, "status": st.status, "error": st.error, "total_bytes": st.total_bytes})
			if (st.status or "").lower() in terminal:
				log.info("fs.upload.tm_end", extra={"tid": tid, "status": st.status, "error": st.error})
				final_status = st.status or "done"
				final_error = st.error or ""
				# If this was a folder upload, extract on the remote host and delete the archive.
				try:
					if final_status == "done" and active_upload_is_folder and active_upload_remote_dir and active_upload_remote_archive:
						sess = session_manager.sessions.get(active_upload_sid)
						os_type = (getattr(sess,"metadata",{}) or {}).get("os","").lower() if sess else ""
						transport = str(getattr(sess,"transport","")).lower() if sess else ""
						log.info("fs.upload.extract.begin", extra={"sid": active_upload_sid, "os": os_type, "transport": transport,
										"archive": active_upload_remote_archive, "dest_dir": active_upload_remote_dir})

						if os_type == "windows":
							ps = (
								# Emit strong, single-line diagnostics we can parse upstream
								f"$ErrorActionPreference='Stop';"
								f"$arch={_psq(active_upload_remote_archive)};"
								f"$dest={_psq(active_upload_remote_dir)};"
								f"try {{ "
								f"  if (-not (Test-Path -LiteralPath $arch)) {{ Write-Output ('ERR:archive_not_found ' + $arch); return }};"
								f"  $len=(Get-Item -LiteralPath $arch -ErrorAction Stop).Length;"
								f"  New-Item -ItemType Directory -Force -Path $dest | Out-Null;"
								f"  Expand-Archive -LiteralPath $arch -DestinationPath $dest -Force -ErrorAction Stop;"
								f"  Remove-Item -LiteralPath $arch -Force -ErrorAction Stop;"
								f"  Write-Output ('OK: extracted ' + $len + ' bytes to ' + $dest)"
								f"}} catch {{ "
								f"  $msg = ($_ | Out-String).Trim();"
								f"  Write-Output ('ERR:' + $msg)"
								f"}}"
							)
							try:
								_prev = safe_preview(ps, limit=220)
							except TypeError:
								_prev = safe_preview(ps)
							log.debug("fs.upload.extract.ps", extra={"cmd_preview": _prev})
							out = _run_remote(active_upload_sid, ps, transport, log=log)
							txt = ((out or "").replace("\r","")).strip()
							log.debug("fs.upload.extract.ps.out", extra={"len": len(txt), "preview": txt[:400]})
							if "ERR:" in txt:
								final_status, final_error = "error", f"expand_archive_failed: {txt!r}"
							else:
								# Avoid reserved LogRecord fields like 'msg'/'message'
								log.info("fs.upload.extract.win.ok", extra={"detail": txt[:300]})
						else:
							sh = (
								"bash -lc " +
								_shq(
									f"set -e; mkdir -p {active_upload_remote_dir}; "
									f"tar -xzf {active_upload_remote_archive} -C {active_upload_remote_dir}; "
									f"rm -f {active_upload_remote_archive}; echo OK"
								)
							)
							try:
								_prev = safe_preview(sh, limit=220)
							except TypeError:
								_prev = safe_preview(sh)
							log.debug("fs.upload.extract.sh", extra={"cmd_preview": _prev})
							out = _run_remote(active_upload_sid, sh, transport, log=log)
							txt = ((out or "").replace("\r","")).strip()
							log.debug("fs.upload.extract.sh.out", extra={"len": len(txt), "preview": txt[:400]})
							if "ERR:" in txt:
								final_status, final_error = "error", f"tar_extract_failed: {txt!r}"
							else:
								log.info("fs.upload.extract.posix.ok", extra={"detail": txt[:300]})
				except Exception as ex:
					log.exception("fs.upload.extract.error", extra={"err": repr(ex)})
					final_status, final_error = "error", f"extract_exception:{ex!r}"

				await _ws_send(ws, {"type":"fs.upload.result","tid":tid,"status":final_status,"error":final_error}, log)
				log.info("fs.upload.result.sent", extra={"tid": tid, "status": final_status, "error": final_error})
				break
			await asyncio.sleep(0.2)
		try:
			if active_upload_tmp:
				os.remove(active_upload_tmp)
				log.debug("fs.upload.tmp_removed", extra={"tmp": active_upload_tmp})
		except Exception as e:
			log.exception("fs.upload.tmp_remove_error", extra={"err": repr(e)})
		active_upload_tmp = None
		active_upload_expect = 0
		active_upload_sid = None
		active_upload_remote_archive = None
		active_upload_remote_dir = None
		active_upload_is_folder = False

	async def _preflight_can_write(sid: str, target_file: str) -> tuple[bool, str]:
		"""Return (ok, detail). Verifies we can create/overwrite at target_file."""
		sess = session_manager.sessions.get(sid)
		if not sess:
			return False, "session_missing"
		os_type = (getattr(sess, "metadata", {}) or {}).get("os", "").lower()
		transport = str(getattr(sess, "transport", "")).lower()

		try:
			if os_type == "windows":
				ps = (
					"$ErrorActionPreference='Stop';"
					f"$p={_psq(target_file)};"
					"$d=[System.IO.Path]::GetDirectoryName($p);"
					"if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null };"
					"if (Test-Path -LiteralPath $p) {"
					"  try { $fs=[System.IO.File]::Open($p,'Open','ReadWrite','None'); $fs.Close(); 'OK' }"
					"  catch { 'DENIED:' + ($_ | Out-String) }"
					"} else {"
					"  try { "
					"    $t=[System.IO.Path]::Combine($d,[Guid]::NewGuid().ToString()+'.ulperm');"
					"    $fs=[System.IO.File]::Open($t,'OpenOrCreate','ReadWrite','None'); $fs.Close();"
					"    Remove-Item -LiteralPath $t -Force; 'OK'"
					"  } catch { 'DENIED:' + ($_ | Out-String) }"
					"}"
				)
				out = _run_remote(sid, ps, transport, log=log) or ""
				return out.strip().startswith("OK"), out.strip()
			else:
				sh = (
					"bash -lc " +
					_shq(
						f"set -e; P={_shq(target_file)}; D=$(dirname \"$P\"); (mkdir -p \"$D\" 2>/dev/null || true); "
						"if [ -e \"$P\" ]; then "
						"  [ -w \"$P\" ] && echo OK || echo DENIED:file_not_writable;"
						"else "
						"  T=\"$D/.ulperm.$$\"; if : > \"$T\" 2>/dev/null; then rm -f \"$T\"; echo OK; "
						"  else echo DENIED:dir_not_writable; fi;"
						"fi"
					)
				)
				out = _run_remote(sid, sh, transport, log=log) or ""
				return ("OK" in out), out.strip()
		except Exception as e:
			log.exception("fs.upload.preflight.exception", extra={"err": repr(e)})
			return False, f"exception:{e!r}"

	# -------- Explorer helpers --------
	async def _do_drives(req: Dict[str, Any]):
		sid = _resolve_sid(req.get("sid",""))
		req_id = req.get("req_id")
		sess = session_manager.sessions.get(sid)
		if not sess:
			log.warning("fs.drives.session_missing", extra={"sid": sid})
			return await _ws_send(ws, {"type":"error","req_id":req_id,"error":"Session not found"}, log)
		os_type = (getattr(sess,"metadata",{}) or {}).get("os","").lower()
		transport = str(getattr(sess,"transport","")).lower()
		log.debug("fs.drives.begin", extra={"sid": sid, "os": os_type, "transport": transport})

		if os_type == "windows":
			ps = (
				"Get-CimInstance Win32_LogicalDisk | "
				"Select-Object DeviceID, Size, FreeSpace, VolumeName | "
				"Sort-Object DeviceID | "
				"% { "
				"  $u = [int64]$_.Size - [int64]$_.FreeSpace; "
				"  @{ letter=$_.DeviceID; size=[int64]$_.Size; free=[int64]$_.FreeSpace; used=$u; label=$($_.VolumeName) } "
				"} | ConvertTo-Json -Compress -Depth 3"
			)
			out = _run_remote(sid, ps, transport, log=log)
			try:
				rows = json.loads(out) if out.strip() else []
			except Exception:
				rows = []
			if isinstance(rows, dict): rows = [rows]
			log.info("fs.drives.ok", extra={"sid": sid, "count": len(rows)})
			return await _ws_send(ws, {"type":"fs.drives","drives":rows, "req_id":req_id}, log)

		# ---------- LINUX / POSIX ----------
		# Use POSIX format (-P) so the mountpoint is always the *last* field.
		# Then join fields 6..NF as the mountpoint to keep spaces intact.
		sh = (
			"bash -lc " +
			_shq(r"""
			LC_ALL=C df -P -B1 | tail -n +2 | awk '
			{
			mp = $6;
			if (NF > 6) { for (i = 7; i <= NF; i++) mp = mp " " $i; }
			printf("%s\t%s\t%s\t%s\t%s\n", mp, $2, $3, $4, $1);
			}'
			"""
			)
		)
		out = _run_remote(sid, sh, transport, log=log)

		rows = []
		for line in (out or "").splitlines():
			mp, size, used, free, filesystem = (line.split("\t") + ["", "", "", "", ""])[:5]
			if not (mp or "").startswith("/"):
				continue
			try:
				size_i = int(size or 0)
				used_i = int(used or 0)
				free_i = int(free or 0)
			except Exception:
				size_i = used_i = free_i = 0
			rows.append({
				"letter": mp,   # mountpoint shown in the UI
				"size":   size_i,
				"used":   used_i,
				"free":   free_i,
				"label":  filesystem  # shows device/fs name
			})

		log.info("fs.drives.ok", extra={"sid": sid, "count": len(rows)})
		await _ws_send(ws, {"type": "fs.drives", "drives": rows, "req_id": req_id}, log)

	async def _do_quickpaths(req: Dict[str, Any]):
		sid = _resolve_sid(req.get("sid",""))
		req_id = req.get("req_id")
		sess = session_manager.sessions.get(sid)
		if not sess:
			log.warning("fs.quickpaths.session_missing", extra={"sid": sid})
			return await _ws_send(ws, {"type":"error","req_id":req_id,"error":"Session not found"}, log)
		os_type = (getattr(sess,"metadata",{}) or {}).get("os","").lower()
		transport = str(getattr(sess,"transport","")).lower()
		log.debug("fs.quickpaths.begin", extra={"sid": sid, "os": os_type, "transport": transport})

		if os_type == "windows":
			ps = (
				"$h=$env:USERPROFILE;"
				"$o=@{"
				"home=$h;"
				"desktop = Join-Path $h 'Desktop';"
				"documents = Join-Path $h 'Documents';"
				"downloads = Join-Path $h 'Downloads';"
				"pictures = Join-Path $h 'Pictures';"
				"videos = Join-Path $h 'Videos'"
				"}; $o | ConvertTo-Json -Compress"
			)
			out = _run_remote(sid, ps, transport, log=log)
			try: obj = json.loads(out) if out.strip() else {}
			except Exception: obj = {}
			log.info("fs.quickpaths.ok", extra={"sid": sid})
			return await _ws_send(ws, {"type":"fs.quickpaths","paths":obj, "req_id":req_id}, log)

		sh = (
			"bash -lc " +
			_shq(
				'printf \'{"home":"%s","desktop":"%s","documents":"%s","downloads":"%s","pictures":"%s","videos":"%s"}\' '
				'"$HOME" "$HOME/Desktop" "$HOME/Documents" "$HOME/Downloads" "$HOME/Pictures" "$HOME/Videos"'
			)
		)
		out = _run_remote(sid, sh, transport, log=log)
		try: obj = json.loads(out) if out.strip() else {}
		except Exception: obj = {}
		log.info("fs.quickpaths.ok", extra={"sid": sid})
		await _ws_send(ws, {"type":"fs.quickpaths","paths":obj, "req_id":req_id}, log)

	# ---------- main loop ----------
	try:
		recv_written = 0
		# throttle state for upload progress frames
		progress_last_t = 0.0
		progress_last_reported = 0
		while True:
			msg = await ws.receive()
			if msg["type"] == "websocket.receive":
				if "text" in msg:
					# LOG: inbound JSON frame
					txt = msg["text"]
					try:
						req = json.loads(txt)
					except Exception:
						log.warning("ws.recv.bad_json", extra={"len": len(txt)})
						await _ws_send(ws, {"type":"error","error":"Invalid JSON"}, log)
						continue

					act = (req.get("action") or "").lower()
					req_id = req.get("req_id")
					log.debug("ws.recv", extra={
						"action": act, "req_id": req_id, "sid": req.get("sid"),
						"path": req.get("path") or req.get("remote_path"),
						"remote_path": req.get("remote_path"),
						"remote_dir": req.get("remote_dir"),
						"folder": req.get("folder"), "expect_size": req.get("size")
					})

					if act in ("fs.list","list"):
						await _do_list(req)

					elif act in ("fs.delete", "delete"):
						await _do_delete(req)

					elif act in ("fs.new_folder","new.folder"):
						await _do_new_folder(req)

					elif act in ("fs.new_text","new.text"):
						await _do_new_text(req)

					elif act in ("fs.download","download"):
						await _do_download(req)

					elif act in ("fs.upload.begin","upload.begin"):
						recv_written = 0
						progress_last_t = 0.0
						progress_last_reported = 0
						await _do_upload_begin(req)

					elif act in ("fs.upload.finish","upload.finish"):
						if active_upload_tmp is None:
							log.debug("fs.upload.finish_ignored")
							continue
						else:
							await _do_upload_finish()

					elif act in ("fs.drives",):
						await _do_drives(req)

					elif act in ("fs.quickpaths",):
						await _do_quickpaths(req)
						if active_upload_tmp is None:
							pass
						else:
							await _do_upload_finish()

					elif act in ("ping",):
						await _ws_send(ws, {"type":"pong","req_id":req.get("req_id")}, log)
					else:
						log.warning("ws.unknown_action", extra={"action": act})
						await _ws_send(ws, {"type":"error","error":f"Unknown action '{act}'"}, log)

				elif "bytes" in msg:
					# LOG: inbound binary frame (upload data)
					if active_upload_tmp is None:
						log.debug("ws.bytes_ignored", extra={"len": len(msg["bytes"])})
						continue
					data: bytes = msg["bytes"]
					try:
						with open(active_upload_tmp, "ab") as f:
							f.write(data)
					except Exception as e:
						log.exception("fs.upload.write_error", extra={"err": repr(e)})
						await _ws_send(ws, {"type":"error","error":f"Upload write failed: {e}"}, log)
						try:
							if active_upload_tmp: os.remove(active_upload_tmp)
						except Exception:
							pass
						active_upload_tmp = None
						active_upload_expect = 0
						active_upload_sid = None
						active_upload_remote = None
						continue

					"""recv_written += len(data)
					log.debug("fs.upload.progress", extra={"written": recv_written, "expect": active_upload_expect})
					await _ws_send(ws, {"type":"fs.upload.progress","written":recv_written,"total":active_upload_expect}, log)"""

					recv_written += len(data)
					# Throttle progress frames: time-based and size-based
					now_t = time.perf_counter()
					if (
						now_t - progress_last_t >= 0.20  # at most 5/s
						or recv_written == active_upload_expect
						or (recv_written - progress_last_reported) >= (2 * 1024 * 1024)  # every +2 MiB
					):
						log.debug("fs.upload.progress", extra={"written": recv_written, "expect": active_upload_expect})
						await _ws_send(ws, {"type":"fs.upload.progress","written":recv_written,"total":active_upload_expect}, log)
						progress_last_t = now_t
						progress_last_reported = recv_written

					if active_upload_expect and recv_written >= active_upload_expect:
						log.info("fs.upload.bytes_complete", extra={"written": recv_written, "expect": active_upload_expect})
						try:
							await _do_upload_finish()
						except Exception as e:
							log.exception("fs.upload.finalize_error", extra={"err": repr(e)})
							await _ws_send(ws, {"type":"error","error":f"Upload finalize failed: {e}"}, log)
							try:
								if active_upload_tmp: os.remove(active_upload_tmp)
							except Exception:
								pass
							active_upload_tmp = None
							active_upload_expect = 0
							active_upload_sid = None
							active_upload_remote_archive = None
							active_upload_remote_dir = None
							active_upload_is_folder = False
			elif msg["type"] == "websocket.disconnect":
				log.info("ws.disconnect")
				break
	except WebSocketDisconnect:
		log.info("ws.disconnect.ws")
	finally:
		if active_download_task:
			active_download_task.cancel()
			with suppress(asyncio.CancelledError):
				await active_download_task
		log.info("ws.cleanup")
