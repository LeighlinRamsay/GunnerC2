from core.transfers.logutil import setup_once, get_logger
setup_once()
logger = get_logger("manager")  # name will be 'core.transfers.manager'
MB = 1024 * 1024

import os, threading, time, uuid, traceback, ntpath, zipfile, tarfile, re, tempfile, shutil
from dataclasses import dataclass
from typing import Optional, Dict, Any, Literal, Iterable
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec
from .state import StateStore, TransferState
from .chunker import human_bytes, chunk_count, ensure_prealloc
from .protocols.shell import ShellProtocol, _linux_shq, _ps_quote
from core.session_handlers import session_manager
from core.utils import echo

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

@dataclass
class TransferOpts:
	chunk_size: int = 4 * 1024 * 1024
	compress: Optional[str] = None  # reserved; shell protocol uses archive for folders
	encrypt: Optional[str] = None   # reserved; enable in future protocols
	force_proto: Optional[str] = None  # reserved; e.g., "http-binary"
	to_console: bool = True
	to_op: Optional[str] = None
	quiet: bool = True   # <— NEW: suppress start/progress/complete chatter
	# NEW: when True, keep folder downloads as an archive and do NOT extract on controller.
	# This is needed for websocket streaming to the GUI, which extracts client-side.
	defer_extract: bool = False

class TransferManager:
	def __init__(self):
		self.store = StateStore()
		self._threads: Dict[str, threading.Thread] = {}
		self._stop_flags: Dict[str, threading.Event] = {}
		self._lock = threading.RLock()

	# ---------- helpers ----------
	def _protocol(self, op_id: Optional[str], timeout: float = None) -> ShellProtocol:
		# For now we only ship the ShellProtocol (works over HTTP/TCP/TLS).
		return ShellProtocol(op_id, timeout=timeout or 30)
 
	def _new_tid(self) -> str:
		return uuid.uuid4().hex[:12]

	# ---------- Windows path normalization ----------
	@staticmethod
	def _ensure_win_double_backslashes(path: str) -> str:
		if not path:
			return path
		# Replace any single '\' that is NOT already escaped on either side with '\\'
		# (?<!\\)   - previous char is not a backslash
		# \\        - the backslash we want to double
		# (?!\\)    - next char is not a backslash
		return re.sub(r'(?<!\\)\\(?!\\)', r'\\\\', path)


	def _mk_state(self, direction: Literal["download","upload"], sid: str, remote_path: str, local_path: str, is_folder: bool, opts: TransferOpts) -> TransferState:
		sess = session_manager.sessions[sid]
		os_type = sess.metadata.get("os","").lower()
		if os_type not in ("windows","linux"):
			raise RuntimeError(f"Unsupported OS for transfer: {os_type}")
		chunk = int(opts.chunk_size)
		st = TransferState(
			tid=self._new_tid(),
			sid=sid,
			direction=direction,
			remote_path=remote_path,
			local_path=local_path if direction=="download" else local_path,  # local_path is source for upload
			is_folder=is_folder,
			os_type=os_type, transport=sess.transport.lower(),
			chunk_size=chunk, total_bytes=0, total_chunks=0, tmp_local_path=None,
			options={"compress":opts.compress, "encrypt":opts.encrypt}
		)
		#print(st)
		logger.debug("TransferState: %r", st)
		return st

	def _progress_line(self, st: TransferState) -> str:
		done = st.bytes_done
		total = st.total_bytes or 0
		pct = (done/total*100.0) if total else 0.0
		return f"[{st.tid}] {pct:5.1f}%  {human_bytes(done)}/{human_bytes(total)}"

	def _emit(self, opts: TransferOpts, msg: str, color: Optional[str]=None, override_quiet: bool=False, world_wide: bool=False) -> None:
		if opts.quiet:
			if color:
				logger.debug(color + f"{msg}" + reset)

			else:
				logger.debug(f"{msg}")

		else:
			echo(msg, to_console=opts.to_console, to_op=opts.to_op, world_wide=world_wide, color=color)

	def _backfill_is_folder(self, st) -> None:
		"""
		Ensure st.is_folder is a boolean. Prefer persisted hints; fall back to safe heuristics.
		"""
		# If already a bool, keep it
		if isinstance(getattr(st, "is_folder", None), bool):
			return

		opt = getattr(st, "options", {}) or {}

		# Strong signals from our own pipeline
		if opt.get("is_archive_transfer") or opt.get("extract_to"):
			st.is_folder = True
			return

		# Archive extension is also a strong hint
		ext = (opt.get("archive_ext") or "").lower()
		lp  = (st.local_path or "").lower()
		rp  = (st.remote_path or "").lower()
		if ext and (lp.endswith(ext) or rp.endswith(ext)):
			st.is_folder = True
			return

		# Uploads: original local path tells the truth
		if st.direction == "upload":
			olp = opt.get("original_local_path") or st.local_path
			try:
				st.is_folder = bool(olp and os.path.isdir(olp))
				return
			except Exception:
				pass

		# Downloads: original remote path trailing sep is a decent last resort
		orp = opt.get("original_remote_path") or st.remote_path or ""
		if orp.rstrip().endswith("/") or orp.rstrip().endswith("\\"):
			st.is_folder = True
			return

		# Fallback default
		st.is_folder = False

	# ---------- public API ----------
	def start_download(self, sid: str, remote_path: str, local_path: str, folder: Optional[bool]=None, opts: Optional[TransferOpts]=None, timeout: float = None) -> str:
		opts = opts or TransferOpts()
		# For folder downloads, choose an archive file path and record extraction target
		sess = session_manager.sessions[sid]
		os_type = sess.metadata.get("os","").lower()

		# Normalize Windows remote path slashes if needed
		"""if os_type == "windows":
			remote_path = self._ensure_win_double_backslashes(remote_path)"""

		# Auto-detect if we weren't told explicitly
		if folder is None:
			try:
				folder = self._probe_remote_is_dir(sid, remote_path, os_type, to_op=getattr(opts, "to_op", None))
			except Exception as e:
				# Fallback heuristic (very conservative): treat as FILE unless the path ends with a slash/backslash
				self._emit(opts, f"[!] Could not probe remote path type ({e}); guessing from path")
				rp = (remote_path or "").rstrip()
				folder = rp.endswith("/") or rp.endswith("\\")

		if folder:
			base = self._remote_basename(remote_path)
			ext  = ".zip" if os_type=="windows" else ".tar.gz"
			# local_path is the destination directory (as provided by -o)
			# If user passed a specific path that isn't an existing dir, treat it as a directory root.
			try:
				if os.path.isdir(local_path):
					out_dir = local_path
				else:
					# allow user to pass a not-yet-existing directory
					out_dir = local_path
					os.makedirs(out_dir, exist_ok=True)
			except Exception:
				out_dir = local_path
				os.makedirs(out_dir, exist_ok=True)
			archive_dest = os.path.join(out_dir, base + ext)
			extract_to   = os.path.join(out_dir, base)
			st = self._mk_state("download", sid, remote_path, archive_dest, True, opts)
			st.options["extract_to"] = extract_to
			# Pass through streaming preference so _run_download can skip local extraction.
			st.options["defer_extract"] = bool(getattr(opts, "defer_extract", False))
		else:
			# Single file download:
			# Resolve the *actual* target path:
			#   - if local_path is an existing directory → join with remote basename
			#   - if local_path looks like a directory (ends with '/' or '\') → create and join
			#   - else treat local_path as the file path
			target_file = self._resolve_file_target(local_path, remote_path)
			st = self._mk_state("download", sid, remote_path, target_file, False, opts)

		# Longer timeout for folder downloads (archive creation/size checks).
		proto = self._protocol(opts.to_op, timeout=(90.0 if folder else 30.0))
		try:
			st = proto.init_download(st)
		except Exception as e:
			# Surface as a normal transfer error instead of crashing the websocket.
			st.status = "error"
			st.error = f"{e}"
			self.store.save(st)
			self._emit(opts, f"[!] Transfer error {st.tid}: {e}", color=brightred, override_quiet=True)
			return st.tid

		st.total_chunks = chunk_count(st.total_bytes, st.chunk_size)

		# If the remote reports -1 (missing/unreadable), fail fast as an ERROR.
		if st.total_bytes is None or st.total_bytes < 0:
			st.status = "error"
			st.error = "Remote path not found or not accessible"
			self.store.save(st)
			self._emit(opts, f"[{st.tid}] remote path missing/unreadable; aborting", color=brightred, override_quiet=True)
			return st.tid

		self.store.save(st)
		stop = threading.Event()
		self._stop_flags[st.tid] = stop
		t = threading.Thread(target=self._run_download, args=(proto, st, opts, stop, timeout), daemon=True)
		t.start()
		self._threads[st.tid] = t
		self._emit(opts, f"[*] Transfer started (download) TID={st.tid} → {st.local_path}")
		return st.tid

	def start_upload(self, sid: str, local_path: str, remote_path: str, folder: Optional[bool] = None, opts: Optional[TransferOpts] = None, timeout: float = None) -> str:
		"""
		Upload a file (or folder by first packing it) to the agent.
		- local_path: path on controller (this machine)
		- remote_path: destination file path on agent
		"""
		opts = opts or TransferOpts()
		sess = session_manager.sessions[sid]
		os_type = (sess.metadata.get("os") or "").lower()
		transport = (sess.transport or "").lower()

		# Normalize Windows remote slashes so PowerShell literal paths behave
		if os_type == "windows":
			remote_path = self._ensure_win_double_backslashes(remote_path)

		if folder is None:
			try:
				folder = bool(local_path and os.path.isdir(local_path))
			except Exception:
				folder = False

		logger.debug(
			f"UL:start sid={sid} os={os_type} transport={transport} "
			f"local={local_path!r} remote={remote_path!r} folder={folder}"
		)

		src_for_upload = local_path
		pack_tmpdir = None

		# If folder, pack to archive first and upload the archive
		if folder:
			src_for_upload, pack_tmpdir = self._pack_folder_to_archive(local_path, os_type)
			# Remote archive path: if caller gave ".../name", append ext we produced
			if os_type == "windows":
				if not remote_path.lower().endswith(".zip"):
					remote_path = remote_path + ".zip"
			else:
				if not remote_path.endswith(".tar.gz"):
					remote_path = remote_path + ".tar.gz"

		# Build state
		st = self._mk_state("upload", sid, remote_path, src_for_upload, bool(folder), opts)
		st.options["original_local_path"] = local_path
		if pack_tmpdir:
			st.options["pack_tmp_dir"] = pack_tmpdir
			st.options["extract_dest"] = self._remote_dir_of(remote_path, os_type)

		# Initialize protocol (if supported) or fill totals here
		proto = self._protocol(opts.to_op, timeout=timeout)
		if hasattr(proto, "init_upload"):
			st = proto.init_upload(st)  # may set total_bytes/chunk_size
		if not st.total_bytes:
			try:
				st.total_bytes = os.path.getsize(st.local_path)
			except Exception:
				st.total_bytes = 0
		st.total_chunks = chunk_count(st.total_bytes, st.chunk_size)

		logger.debug(
			f"UL[{st.tid}] prepared: src={st.local_path!r} -> remote={st.remote_path!r} "
			f"bytes={st.total_bytes} chunks={st.total_chunks} chunk_size={st.chunk_size}"
		)

		self.store.save(st)
		stop = threading.Event()
		self._stop_flags[st.tid] = stop
		t = threading.Thread(target=self._run_upload, args=(proto, st, opts, stop, timeout), daemon=True)
		t.start()
		self._threads[st.tid] = t

		self._emit(opts, f"[*] Transfer started (upload) TID={st.tid} → {st.remote_path}")
		return st.tid

	def _run_download(self, proto: ShellProtocol, st: TransferState, opts: TransferOpts, stop: threading.Event, timeout: float = None):
		completed = False
		logger.debug(
			f"DL[{st.tid}] start: status={st.status} dir={st.direction} "
			f"remote={st.remote_path!r} local={st.local_path!r} chunk={st.chunk_size} "
			f"total_bytes={st.total_bytes} next_index={st.next_index} bytes_done={st.bytes_done}"
		)
		try:
			if st.status != "running":
				st.status = "running"
				self.store.save(st)
				logger.debug(f"DL[{st.tid}] set running (initial)")

			# Guard: size became invalid (e.g., state reloaded mid-run)
			if st.total_bytes is None or st.total_bytes < 0:
				st.status = "error"
				st.error = "Remote size unavailable (-1)"
				self.store.save(st)
				self._emit(opts, f"[{st.tid}] remote size unavailable; aborting", color=brightred, override_quiet=True)
				return

			# --- Resume alignment (ignore sparse prealloc size; trust counters) ---
			try:
				if st.tmp_local_path and os.path.exists(st.tmp_local_path):
					logger.debug(
						f"DL[{st.tid}] align: tmp exists at {st.tmp_local_path!r}; "
						f"persisted bytes_done={st.bytes_done} next_index={st.next_index}"
					)
					part_sz = int(st.bytes_done or 0)
					if st.total_bytes:
						part_sz = min(part_sz, st.total_bytes)
					full_chunks = part_sz // st.chunk_size
					tail = part_sz - (full_chunks * st.chunk_size)
					if tail:
						try:
							with open(st.tmp_local_path, "r+b") as f:
								f.truncate(full_chunks * st.chunk_size)
							logger.debug(f"DL[{st.tid}] align: truncated tail={tail} -> {full_chunks * st.chunk_size} bytes")
						except Exception:
							logger.debug(f"DL[{st.tid}] align: truncate failed (non-fatal)", exc_info=True)
						part_sz = full_chunks * st.chunk_size
					st.next_index = full_chunks
					st.bytes_done = part_sz
					self.store.save(st)
					logger.debug(f"DL[{st.tid}] align -> next_index={st.next_index} bytes_done={st.bytes_done}")
			except Exception:
				logger.debug(f"DL[{st.tid}] align block raised (ignored)", exc_info=True)

			# --- SAFETY: refuse resume if remote size changed (prevents corruption) ---
			try:
				if st.next_index > 0 or (st.bytes_done and st.bytes_done > 0):
					logger.debug(f"DL[{st.tid}] safety: probing remote size; stored total_bytes={st.total_bytes}")
					try:
						current_total = proto._remote_size(st)
						logger.debug(f"DL[{st.tid}] safety: remote_size={current_total}")
					except Exception:
						st.status = "paused"
						self.store.save(st)
						logger.debug(f"DL[{st.tid}] PAUSE: SAFETY_REMOTE_UNREACHABLE at chunk={st.next_index}", exc_info=True)
						self._emit(opts, f"[{st.tid}] remote not reachable; paused at chunk {st.next_index}", color=brightred, override_quiet=True)
						return

					if st.total_bytes and current_total != st.total_bytes:
						st.status = "paused"
						self.store.save(st)
						logger.debug(
							f"DL[{st.tid}] PAUSE: SAFETY_SIZE_MISMATCH stored={st.total_bytes} remote_now={current_total} at chunk={st.next_index}"
						)
						self._emit(opts, f"[{st.tid}] remote file changed (was {st.total_bytes} bytes, now {current_total}); paused", color=brightred, override_quiet=True)
						return
			except Exception:
				logger.debug(f"DL[{st.tid}] safety block raised (ignored)", exc_info=True)

			last = time.time()
			while not stop.is_set():
				pre_idx = st.next_index
				logger.debug(f"DL[{st.tid}] loop: requesting chunk idx={pre_idx}/{st.total_chunks} (bytes_done={st.bytes_done})")
				try:
					idx = proto.next_download_chunk(st)
				except (ConnectionError, ConnectionResetError, BrokenPipeError, OSError) as neterr:
					try:
						want_bytes = pre_idx * st.chunk_size
						if want_bytes > st.total_bytes:
							want_bytes = st.total_bytes
						if st.tmp_local_path and os.path.exists(st.tmp_local_path):
							with open(st.tmp_local_path, "r+b") as f:
								f.truncate(want_bytes)
						st.bytes_done = want_bytes
						logger.debug(
							f"DL[{st.tid}] neterr={neterr.__class__.__name__} -> truncate to {want_bytes} bytes; reset next_index={pre_idx}"
						)
					except Exception:
						logger.debug(f"DL[{st.tid}] truncate after neterr failed (non-fatal)", exc_info=True)

					st.next_index = pre_idx
					st.status = "paused"
					self.store.save(st)
					logger.debug(f"DL[{st.tid}] PAUSE: NETERR_DURING_CHUNK at idx={st.next_index} ({neterr.__class__.__name__})")
					self._emit(opts, f"[{st.tid}] connection lost ({neterr.__class__.__name__}); paused at chunk {st.next_index}", color=brightred, override_quiet=True)
					return

				if idx is None:
					logger.debug(f"DL[{st.tid}] loop: proto returned None at idx={pre_idx} (total_chunks={st.total_chunks})")
					break

				logger.debug(f"DL[{st.tid}] chunk_ok: wrote idx={idx} -> next_index={st.next_index} bytes_done={st.bytes_done}")

				if time.time() - last >= 0.5:
					self.store.save(st)
					last = time.time()
					logger.debug(f"DL[{st.tid}] progress saved: next_index={st.next_index} bytes_done={st.bytes_done}")

			if stop.is_set():
				st.status = "paused"
				self.store.save(st)
				logger.debug(f"DL[{st.tid}] PAUSE: STOPFLAG at chunk={st.next_index}")
				self._emit(opts, f"[{st.tid}] paused at chunk {st.next_index}", color=brightred, override_quiet=True)
				return

			def _have_all_bytes() -> bool:
				try:
					have = int(st.bytes_done or 0)
					need = int(st.total_bytes or 0)
					logger.debug(f"DL[{st.tid}] completion_check: have={have} need={need}")
					return need >= 0 and have >= need
				except Exception:
					logger.debug(f"DL[{st.tid}] completion_check raised", exc_info=True)
					return False

			if not _have_all_bytes():
				st.status = "paused"
				self.store.save(st)
				logger.debug(
					f"DL[{st.tid}] PAUSE: NOT_ALL_BYTES next_index={st.next_index} bytes_done={st.bytes_done} total_bytes={st.total_bytes}"
				)
				self._emit(opts, f"[{st.tid}] paused at chunk {st.next_index}", color=brightred, override_quiet=True)
				return

			# Handle true 0-byte files: ensure an empty .part exists so finalize can move it.
			if int(st.total_bytes or 0) == 0:
				try:
					ensure_prealloc(st.tmp_local_path, 0)
				except Exception:
					pass

			# Normalize counters and finalize
			st.bytes_done = st.total_bytes
			st.next_index = st.total_chunks
			logger.debug(f"DL[{st.tid}] finalize: moving {st.tmp_local_path!r} -> {st.local_path!r}")
			self.store.finalize(st)
			st.status = "done"
			self.store.save(st)
			completed = True
			logger.debug(f"DL[{st.tid}] done: saved state; is_folder={st.is_folder}")

			

			# If this was a folder download, extract locally then remove archive
			final_msg = st.local_path
			if st.is_folder:
				try:
					with open(st.local_path, "rb") as f:
						head = f.read(4)
					if st.os_type == "windows":
						if head != b"PK\x03\x04":
							logger.debug(f"DL[{st.tid}] failed: zip header mismatch, head={head}")
							raise ValueError("zip header mismatch")
					else:
						if not (len(head) >= 2 and head[0] == 0x1F and head[1] == 0x8B):
							raise ValueError("gz header mismatch")
				except Exception as ex:
					st.status = "error"
					st.error = f"Downloaded archive invalid: {ex}"
					self.store.save(st)
					logger.debug(f"DL[{st.tid}] error: archive header check failed: {ex}")
					self._emit(opts, f"[!] Downloaded archive invalid; left at {st.local_path}")
					return

				# Only extract locally if not deferring extraction (e.g., CLI use).
				if not st.options.get("defer_extract"):
					logger.debug(f"DL[{st.tid}] Extracting locally on server side!")
					extract_to = st.options.get("extract_to")
					try:
						if st.os_type == "windows" and st.local_path.lower().endswith(".zip"):
							with zipfile.ZipFile(st.local_path, 'r') as zf:
								self._safe_extract_zip(zf, extract_to)
							try:
								os.remove(st.local_path)
							except Exception:
								logger.debug(f"DL[{st.tid}] post-extract: remove zip failed (ignored)", exc_info=True)
							final_msg = extract_to
						elif st.os_type == "linux" and st.local_path.endswith(".tar.gz"):
							with tarfile.open(st.local_path, "r:gz") as tf:
								self._safe_extract_tar(tf, extract_to)
							try:
								os.remove(st.local_path)
							except Exception:
								logger.debug(f"DL[{st.tid}] post-extract: remove tar failed (ignored)", exc_info=True)
							final_msg = extract_to
					except Exception as ex:
						logger.debug(f"DL[{st.tid}] local extraction failed: {ex} (archive left)", exc_info=True)
						self._emit(opts, f"[!] Local extraction failed ({ex}); archive left at {st.local_path}")

				# Clean up remote archive regardless
				try:
					proto.cleanup(st)
					logger.debug(f"DL[{st.tid}] cleanup: remote archive cleaned")
				except Exception:
					logger.debug(f"DL[{st.tid}] cleanup: remote cleanup failed (ignored)", exc_info=True)
			else:
				try:
					proto.cleanup(st)
					logger.debug(f"DL[{st.tid}] cleanup: non-folder remote cleanup ok")
				except Exception as ce:
					logger.debug(f"DL[{st.tid}] cleanup: post-complete cleanup failed (ignored): {ce}")

			self._emit(opts, f"[+] Transfer complete: {final_msg}")

		except (ConnectionError, ConnectionResetError, BrokenPipeError) as e:
			if completed:
				logger.debug(f"DL[{st.tid}] network error after completion (ignored): {e.__class__.__name__}")
				self._emit(opts, f"[{st.tid}] network error after completion: {e.__class__.__name__} (ignored)")
				return
			st.status = "paused"
			self.store.save(st)
			logger.debug(f"DL[{st.tid}] PAUSE: OUTER_NETERR {e.__class__.__name__} at chunk={st.next_index}")
			self._emit(opts, f"[{st.tid}] connection lost ({e.__class__.__name__}); paused at chunk {st.next_index}", color=brightred, override_quiet=True)

		except Exception as e:
			if completed:
				logger.debug(f"DL[{st.tid}] post-complete exception (ignored): {e}", exc_info=True)
				self._emit(opts, f"[{st.tid}] post-complete exception (ignored): {e}")
				return
			st.status = "error"
			st.error = f"{e}"
			self.store.save(st)
			logger.debug(f"DL[{st.tid}] ERROR: {e}", exc_info=True)
			self._emit(opts, f"[!] Transfer error {st.tid}: {e}", color=brightred, override_quiet=True)

	def _run_upload(self, proto: ShellProtocol, st: TransferState, opts: TransferOpts, stop: threading.Event, timeout: float = None):
		logger.debug(
			f"UL[{st.tid}] start: status={st.status} dir={st.direction} "
			f"local={st.local_path!r} remote={st.remote_path!r} chunk={st.chunk_size} "
			f"total_bytes={st.total_bytes} next_index={st.next_index} bytes_done={st.bytes_done} "
			f"is_folder={st.is_folder}"
		)
		try:
			if st.status != "running":
				st.status = "running"
				self.store.save(st)
				logger.debug(f"UL[{st.tid}] set running (initial)")

			# --- Align remote to whole-chunk boundary (resume-safe) ---
			try:
				try:
					rsz = proto._remote_size(st)
				except Exception:
					rsz = 0
				if rsz < 0:
					rsz = 0
				if st.total_bytes:
					rsz = min(rsz, st.total_bytes)
				full_chunks = rsz // st.chunk_size
				tail = rsz - (full_chunks * st.chunk_size)
				logger.debug(f"UL[{st.tid}] remote_size={rsz} full_chunks={full_chunks} tail={tail}")

				if tail:
					safe_bytes = full_chunks * st.chunk_size
					logger.debug(f"UL[{st.tid}] truncating remote to {safe_bytes} to drop partial chunk")
					try:
						if st.os_type == "windows":
							ps = (
								f"$p={_ps_quote(st.remote_path)};$len={safe_bytes};"
								"$fs=[System.IO.File]::Open($p,'OpenOrCreate','ReadWrite','None');"
								"$fs.SetLength($len);$fs.Close()"
							)
							tx = session_manager.sessions[st.sid].transport.lower()
							if tx in ("http", "https"):
								http_exec.run_command_http(st.sid, ps, op_id=getattr(opts, "to_op", None), transfer_use=True, timeout=timeout)
							else:
								tcp_exec.run_command_tcp(st.sid, ps, timeout=0.5, portscan_active=True, op_id=getattr(opts, "to_op", None), transfer_use=True)
						else:
							sh = f"bash -lc \"truncate -s {safe_bytes} {_linux_shq(st.remote_path)}\""
							tx = session_manager.sessions[st.sid].transport.lower()
							if tx in ("http","https"):
								http_exec.run_command_http(st.sid, sh, op_id=getattr(opts, "to_op", None), transfer_use=True, timeout=timeout)
							else:
								tcp_exec.run_command_tcp(st.sid, sh, timeout=0.5, portscan_active=True, op_id=getattr(opts, "to_op", None), transfer_use=True)
						rsz = safe_bytes
					except Exception:
						logger.debug(f"UL[{st.tid}] remote truncate failed (non-fatal)", exc_info=True)

				st.next_index = full_chunks
				st.bytes_done = rsz
				self.store.save(st)
				logger.debug(f"UL[{st.tid}] aligned: next_index={st.next_index} bytes_done={st.bytes_done}")
			except Exception:
				logger.debug(f"UL[{st.tid}] align block raised (ignored)", exc_info=True)

			last = time.time()
			while not stop.is_set():
				pre_idx = st.next_index
				logger.debug(f"UL[{st.tid}] loop: sending chunk idx={pre_idx}/{st.total_chunks} (bytes_done={st.bytes_done})")
				try:
					idx = proto.next_upload_chunk(st)
				except (ConnectionResetError, BrokenPipeError, OSError, ConnectionError) as neterr:
					# Roll remote back to last whole chunk
					safe_bytes = pre_idx * st.chunk_size
					logger.debug(f"UL[{st.tid}] neterr={neterr.__class__.__name__} -> rollback remote to {safe_bytes} bytes")
					try:
						if st.os_type == "windows":
							ps = (
								f"$p={_ps_quote(st.remote_path)};$len={safe_bytes};"
								"$fs=[System.IO.File]::Open($p,'OpenOrCreate','ReadWrite','None');"
								"$fs.SetLength($len);$fs.Close()"
							)
							tx = session_manager.sessions[st.sid].transport.lower()
							if tx in ("http","https"):
								http_exec.run_command_http(st.sid, ps, op_id=getattr(opts, "to_op", None), transfer_use=True, timeout=timeout)
							else:
								tcp_exec.run_command_tcp(st.sid, ps, timeout=0.5, portscan_active=True, op_id=getattr(opts, "to_op", None), transfer_use=True)
						else:
							sh = f"bash -lc \"truncate -s {safe_bytes} {_linux_shq(st.remote_path)}\""
							tx = session_manager.sessions[st.sid].transport.lower()
							if tx in ("http","https"):
								http_exec.run_command_http(st.sid, sh, op_id=getattr(opts, "to_op", None), transfer_use=True, timeout=timeout)
							else:
								tcp_exec.run_command_tcp(st.sid, sh, timeout=0.5, portscan_active=True, op_id=getattr(opts, "to_op", None), transfer_use=True)
						st.bytes_done = min(safe_bytes, st.total_bytes)
					except Exception:
						logger.debug(f"UL[{st.tid}] remote rollback failed (ignored)", exc_info=True)
					finally:
						st.next_index = pre_idx
						st.status = "paused"
						self.store.save(st)

					logger.debug(f"UL[{st.tid}] PAUSE: NETERR_DURING_CHUNK at idx={st.next_index}")
					self._emit(opts, f"[{st.tid}] connection lost ({neterr.__class__.__name__}); paused at chunk {st.next_index}",
							   color=brightred, override_quiet=True, world_wide=True)
					return

				if idx is None:
					logger.debug(f"UL[{st.tid}] loop: proto returned None at idx={pre_idx} (total_chunks={st.total_chunks})")
					break

				logger.debug(f"UL[{st.tid}] chunk_ok: sent idx={idx} -> next_index={st.next_index} bytes_done={st.bytes_done}")

				if time.time() - last >= 0.5:
					self.store.save(st)
					last = time.time()
					logger.debug(f"UL[{st.tid}] progress saved: next_index={st.next_index} bytes_done={st.bytes_done}")

			if stop.is_set():
				st.status = "paused"
				self.store.save(st)
				logger.debug(f"UL[{st.tid}] PAUSE: STOPFLAG at chunk={st.next_index}")
				self._emit(opts, f"[{st.tid}] paused at chunk {st.next_index}",
						   color=brightred, override_quiet=True)
				return

			# Zero-byte uploads: ensure remote empty file exists
			if int(st.total_bytes or 0) == 0:
				try:
					if st.os_type == "windows":
						ps = f"New-Item -ItemType File -Path {_ps_quote(st.remote_path)} -Force | Out-Null"
						tx = session_manager.sessions[st.sid].transport.lower()
						if tx in ('http','https'):
							http_exec.run_command_http(st.sid, ps, op_id=getattr(opts, "to_op", None), transfer_use=True, timeout=timeout)
						else:
							tcp_exec.run_command_tcp(st.sid, ps, timeout=0.5, portscan_active=True, op_id=getattr(opts, "to_op", None), transfer_use=True)
					else:
						sh = f"bash -lc \": > {_linux_shq(st.remote_path)}\""
						tx = session_manager.sessions[st.sid].transport.lower()
						if tx in ('http','https'):
							http_exec.run_command_http(st.sid, sh, op_id=getattr(opts, "to_op", None), transfer_use=True, timeout=timeout)
						else:
							tcp_exec.run_command_tcp(st.sid, sh, timeout=0.5, portscan_active=True, op_id=getattr(opts, "to_op", None), transfer_use=True)
					logger.debug(f"UL[{st.tid}] created empty remote file")
				except Exception:
					logger.debug(f"UL[{st.tid}] failed to create empty remote file (ignored)", exc_info=True)

			# Not all chunks sent → treat as paused
			if st.next_index < st.total_chunks:
				st.status = "paused"
				self.store.save(st)
				logger.debug(f"UL[{st.tid}] PAUSE: NOT_ALL_CHUNKS next_index={st.next_index}/{st.total_chunks}")
				self._emit(opts, f"[{st.tid}] paused at chunk {st.next_index}",
						   color=brightred, override_quiet=True)
				return

			st.status = "done"
			self.store.save(st)
			logger.debug(f"UL[{st.tid}] done: uploaded; is_folder={st.is_folder}")

			if st.is_folder:
				# Extract archive remotely then delete it
				proto = self._protocol(op_id=opts.to_op if opts else None, timeout=st.options.get("timeout"))
				dest = st.options.get("extract_dest") or self._remote_dir_of(st.remote_path, st.os_type)
				logger.debug(f"UL[{st.tid}] extracting on agent to {dest!r}")

				if st.os_type == "windows":
					def psq(s: str) -> str: return "'" + str(s).replace("'", "''") + "'"
					ps = (
						f"$dest={psq(dest)};"
						f"if (-not (Test-Path -LiteralPath $dest)) "
						f"{{ New-Item -ItemType Directory -Path $dest -Force | Out-Null }};"
						f"Expand-Archive -LiteralPath {psq(st.remote_path)} -DestinationPath $dest -Force;"
						f"Remove-Item -LiteralPath {psq(st.remote_path)} -Force"
					)
					proto._run_cmd(st.sid, ps, st.transport, proto.op_id)
				else:
					def shq(s: str) -> str: return "'" + str(s).replace("'", "'\"'\"'") + "'"
					sh = (
						f"mkdir -p {shq(dest)} && "
						f"tar xzf {shq(st.remote_path)} -C {shq(dest)} && "
						f"rm -f {shq(st.remote_path)}"
					)
					proto._run_cmd(st.sid, f"bash -lc \"{sh}\"", st.transport, proto.op_id)

				# Clean up local pack temp (archive and folder)
				try:
					if st.options.get("pack_tmp_dir"):
						shutil.rmtree(st.options["pack_tmp_dir"], ignore_errors=True)
					elif st.local_path and os.path.exists(st.local_path):
						os.remove(st.local_path)
				except Exception:
					logger.debug(f"UL[{st.tid}] local pack cleanup failed (ignored)", exc_info=True)

				self._emit(opts, f"\n[+] Folder extracted to: {dest}")
			else:
				self._emit(opts, "\n[+] Upload complete")

		except (ConnectionError, ConnectionResetError, BrokenPipeError, OSError) as e:
			st.status = "paused"
			self.store.save(st)
			logger.debug(f"UL[{st.tid}] PAUSE: OUTER_NETERR {e.__class__.__name__} at chunk={st.next_index}")
			self._emit(opts, f"[{st.tid}] connection lost ({e.__class__.__name__}); paused at chunk {st.next_index}",
					   color=brightred, override_quiet=True, world_wide=True)
			return

		except Exception as e:
			st.status = "error"
			st.error = f"{e}"
			self.store.save(st)
			logger.debug(f"UL[{st.tid}] ERROR: {e}", exc_info=True)
			self._emit(opts, f"[!] Transfer error {st.tid}: {e}",
					   color=brightred, override_quiet=True, world_wide=True)

	# control plane
	def resume(self, sid: str, tid: str, opts: Optional[TransferOpts]=None, timeout: float = None) -> bool:
		opts = opts or TransferOpts()
		st = self.store.load(sid, tid)
		if st.status not in ("paused","error"):
			return False

		# flip to running for immediate, correct UI
		st.status = "running"
		self.store.save(st)

		# restart appropriate runner
		stop = threading.Event()
		self._stop_flags[tid] = stop
		proto = self._protocol(opts.to_op, timeout=timeout)
		runner = self._run_download if st.direction == "download" else self._run_upload
		t = threading.Thread(target=runner, args=(proto, st, opts, stop), daemon=True)
		t.start()
		self._threads[tid] = t
		self._emit(opts, f"[*] Resuming TID={tid} at chunk {st.next_index}")
		return True

	def cancel(self, sid: str, tid: str) -> bool:
		if tid not in self._stop_flags:
			self._stop_flags[tid] = threading.Event()
		self._stop_flags[tid].set()
		try:
			st = self.store.load(sid, tid)
			st.status = "cancelled"
			self.store.save(st)
			return True
		except Exception:
			return False

	def status(self, sid: str, tid: str) -> Optional[Dict[str,Any]]:
		try:
			st = self.store.load(sid, tid)
			return st.to_dict()
		except Exception:
			return None

	def list(self, sid: Optional[str]=None) -> Dict[str,Any]:
		out = []
		base = self.store.base
		if sid:
			roots = [os.path.join(base, sid)]
		else:
			roots = [os.path.join(base, d) for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))]
		for root in roots:
			for tid in (os.listdir(root) if os.path.isdir(root) else []):
				try:
					st = self.store.load(os.path.basename(root), tid)
					out.append(st.to_dict())
				except Exception:
					continue
		return {"transfers": out}

# --- Safe extract helpers -------------------------------------------------
	def _safe_extract_zip(self, zf: zipfile.ZipFile, dest_dir: str) -> None:
		"""
		Extract a ZIP while:
		  - normalizing Windows-style backslashes to the local OS separator
		  - preventing ZipSlip/path traversal
		  - creating intermediate directories
		"""
		os.makedirs(dest_dir, exist_ok=True)
		for info in zf.infolist():
			# Normalize separators (Windows zips often contain '\')
			raw = info.filename
			if not raw or raw.endswith('/') or raw.endswith('\\'):
				# directory entry
				norm = raw.replace('\\', '/').rstrip('/')
				if not norm:
					continue
				target = os.path.join(dest_dir, *norm.split('/'))
				self._ensure_inside(dest_dir, target)
				os.makedirs(target, exist_ok=True)
				continue
			norm = raw.replace('\\', '/')
			target = os.path.join(dest_dir, *norm.split('/'))
			self._ensure_inside(dest_dir, target)
			os.makedirs(os.path.dirname(target), exist_ok=True)
			with zf.open(info, 'r') as src, open(target, 'wb') as dst:
				while True:
					chunk = src.read(1024 * 1024)
					if not chunk:
						break
					dst.write(chunk)

	def _safe_extract_tar(self, tf: tarfile.TarFile, dest_dir: str) -> None:
		"""
		Extract a tar.gz safely with traversal protection.
		"""
		os.makedirs(dest_dir, exist_ok=True)
		for member in tf.getmembers():
			# tarfile already uses '/' separators; still enforce traversal checks
			target = os.path.join(dest_dir, member.name)
			self._ensure_inside(dest_dir, target)
			if member.isdir():
				os.makedirs(target, exist_ok=True)
			elif member.issym() or member.islnk():
				# Skip links in lab/CTF mode for safety; could be made configurable.
				continue
			else:
				os.makedirs(os.path.dirname(target), exist_ok=True)
				with tf.extractfile(member) as src, open(target, 'wb') as dst:
					if src is None:
						continue
					while True:
						chunk = src.read(1024 * 1024)
						if not chunk:
							break
						dst.write(chunk)

	def _pack_folder_to_archive(self, src_dir: str, os_type: str) -> str:
		"""
		Create a temp archive of src_dir and return the local archive path.
		Windows -> .zip ; Linux -> .tar.gz
		"""
		base = os.path.basename(src_dir.rstrip("/\\"))
		tmpdir = tempfile.mkdtemp(prefix="gc2_ul_pack_")
		if os_type == "windows":
			archive_path = os.path.join(tmpdir, base + ".zip")
			logger.debug(f"PACK: zipping folder {src_dir!r} -> {archive_path!r}")
			with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
				for root, dirs, files in os.walk(src_dir):
					rel = os.path.relpath(root, src_dir)
					rel = "" if rel == "." else rel
					# write empty dirs too
					if not files and not dirs:
						zf.writestr((base + "/" + rel + "/").lstrip("/"), b"")
					for fn in files:
						full = os.path.join(root, fn)
						arcname = (base + "/" + (rel + "/" if rel else "") + fn)
						zf.write(full, arcname.replace("\\", "/"))
		else:
			archive_path = os.path.join(tmpdir, base + ".tar.gz")
			logger.debug(f"PACK: tarring folder {src_dir!r} -> {archive_path!r}")
			with tarfile.open(archive_path, "w:gz") as tf:
				tf.add(src_dir, arcname=base)
		return archive_path, tmpdir

	def _remote_dir_of(self, p: str, os_type: str) -> str:
		return ntpath.dirname(p) if os_type == "windows" or ("\\" in p and "/" not in p) else os.path.dirname(p)

	def _ensure_inside(self, root: str, path: str) -> None:
		"""
		Prevents writing outside dest_dir (ZipSlip/.. protection).
		"""
		ab_root = os.path.abspath(root)
		ab_path = os.path.abspath(path)
		if not ab_path.startswith(ab_root + os.sep) and ab_path != ab_root:
			logger.warning(brightred + f"Unsafe path in archive: {path}" + reset)
			raise RuntimeError(f"Unsafe path in archive: {path}")

	# --- Path helpers ---------------------------------------------------------
	def _remote_basename(self, remote_path: str) -> str:
		"""
		Return the final component of a remote path regardless of whether it is Windows- or POSIX-style.
		Examples:
		  'C:\\Users\\leigh\\repos\\' -> 'repos'
		  '\\\\server\\share\\stuff'  -> 'stuff'
		  '/var/www/html/'            -> 'html'
		"""
		if not remote_path:
			return ""
		rp = remote_path.rstrip("/\\")
		# Heuristics: Windows drive ('C:'), UNC (starts with '\\'), or contains backslashes
		if (len(rp) >= 2 and rp[1] == ':') or rp.startswith('\\\\') or ('\\' in rp):
			base = ntpath.basename(rp)
		else:
			base = os.path.basename(rp)
		# Fallback if something odd returns empty
		return base or rp

	# --- Remote probing -------------------------------------------------------
	def _probe_remote_is_dir(self, sid: str, remote_path: str, os_type: str, to_op: Optional[str]=None) -> bool:
		"""
		Returns True if the remote_path is a directory on the agent, False if it's a file.
		Raises on 'missing' or if transport output can't be parsed.
		"""
		sess = session_manager.sessions[sid]
		transport = getattr(sess, "transport", "").lower()

		if os_type == "windows":
			# PS: robust, literal path, no exceptions
			ps = (
				f"$p = Get-Item -LiteralPath {_ps_quote(remote_path)} -ErrorAction SilentlyContinue; "
				"if ($null -eq $p) { 'MISSING' } "
				"elseif ($p.PSIsContainer) { 'DIR' } else { 'FILE' }"
			)
			out = self._run_remote(sid, ps, transport, to_op)
		else:
			# Linux/Unix
			sh = f"bash -lc 'if [ -d {_linux_shq(remote_path)} ]; then echo DIR; " \
				 f"elif [ -f {_linux_shq(remote_path)} ]; then echo FILE; else echo MISSING; fi'"
			out = self._run_remote(sid, sh, transport, to_op)

		out = (out or "").strip().upper()
		if "DIR" in out:
			return True
		if "FILE" in out:
			return False
		if "MISSING" in out:
			logger.warning(brightred + "Remote path does not exist" + reset)
			raise RuntimeError("Remote path does not exist")
		# Unknown – be defensive
		logger.warning(brightred + f"Unrecognized probe result: {out!r}" + reset)
		raise RuntimeError(f"Unrecognized probe result: {out!r}")

	def _run_remote(self, sid: str, cmd: str, transport: str, to_op: Optional[str], timeout: float = None) -> str:
		"""
		Execute a short command on the agent via the appropriate transport and return the output.
		"""
		if transport in ("http", "https"):
			# existing adapter: http_exec.run_command_http(sid, cmd, op_id=...)
			return http_exec.run_command_http(sid, cmd, op_id=to_op, transfer_use=True, timeout=timeout)

		else:
			# TCP/TLS paths use TCP adapter
			return tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=to_op, transfer_use=True)

	def _resolve_file_target(self, local_path: str, remote_path: str) -> str:
		"""
		Normalize the destination path for a *file* download.
		- If local_path is an existing directory, write into it using the remote basename.
		- If local_path ends with a path separator, treat it as a directory (create if needed)
		  and write into it using the remote basename.
		- Otherwise, treat local_path as the file name to write to.
		"""
		try:
			if os.path.isdir(local_path):
				return os.path.join(local_path, self._remote_basename(remote_path))
		except Exception:
			# if os.path.isdir throws (weird permissions, etc), fall through to other checks
			pass

		# Ends with local OS separator → treat as a directory string
		if local_path.endswith(os.sep) or local_path.endswith('\\'):
			try:
				os.makedirs(local_path, exist_ok=True)
			except Exception:
				# Best-effort: if we cannot create, we'll still attempt to join and let the failure surface later
				pass
			return os.path.join(local_path, self._remote_basename(remote_path))

		# Otherwise, it's a concrete file path
		return local_path
