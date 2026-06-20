from core.transfers.logutil import setup_once, get_logger
setup_once()
logger = get_logger("manager")  # name will be 'core.transfers.manager'

import base64, os, time, re, ntpath, textwrap
from typing import Optional
from .base import TransferProtocol
from ..state import TransferState
from ..chunker import chunk_count, index_to_offset, ensure_prealloc, write_at
from core.session_handlers import session_manager
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution  as tcp_exec

from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

# --------- logging helpers (structured + readable) ---------------------------
BANNER = "=" * 72
SUBBAR = "-" * 72

def _banner(title: str):
	# Leading newline to visually separate blocks in single log file.
	logger.debug("\n%s\n%s\n%s", BANNER, f"[TRANSFERS] {title}", BANNER)

def _sub(title: str):
	logger.debug("%s\n[%s]", SUBBAR, title)

def _kv(**pairs):
	# Compact key=value line; values repr-ed; None shown explicitly
	items = ", ".join(f"{k}={repr(v)}" for k, v in pairs.items())
	logger.debug("  %s", items)

def _preview(s: str, n: int = 160) -> str:
	if s is None:
		return "None"
	s = str(s).replace("\r", "\\r").replace("\n", "\\n")
	return (s[:n] + ("…(+%d)" % (len(s) - n) if len(s) > n else ""))

def _bytes(n: int) -> str:
	try:
		return f"{n} bytes"
	except Exception:
		return str(n)


def _b64_to_bytes(s: str) -> bytes:
	# strip whitespace/newlines safely
	s = "".join(s.split())
	if not s:
		return b""
	return base64.b64decode(s.encode(), validate=False)

def _ps_quote(s: str) -> str:
	return "'" + str(s).replace("'", "''") + "'"

def _linux_shq(s: str) -> str:
	return "'" + str(s).replace("'", "'\"'\"'") + "'"

def _parse_int(s: str, default: int = 0) -> int:
	try:
		return int(str(s).strip())
	except Exception:
		return default

class ShellProtocol(TransferProtocol):
	"""
	Fully compatible with your current agents:
	- Linux: dd + base64 for downloads; printf+base64 -d for uploads
	- Windows: PowerShell FileStream for both directions
	Supports: resumable, chunked transfers; folder via remote archive (zip/tar.gz)
	"""
	def __init__(self, op_id: Optional[str] = None, timeout: float = None):
		self.op_id = op_id
		self.timeout = timeout
		_banner("ShellProtocol.__init__")
		_kv(op_id=self.op_id, timeout=self.timeout)

	def _run_cmd(self, sid: str, cmd: str, transport: str, op_id: Optional[str], defender_bypass: bool = False) -> str:
		"""
		Route command to the correct execution path and return stdout as string (normalized).
		"""
		_sub("RUN_CMD begin")
		_kv(sid=sid, transport=transport, op_id=op_id)
		logger.debug("  cmd.preview=%s", _preview(cmd))
		t0 = time.time()

		tr = transport.lower()

		_eff_timeout = self.timeout if (self.timeout is not None) else 5.0
		logger.debug("  _run_cmd.timeout=%.3fs transport=%s", _eff_timeout, tr)
		try:
			out = (
				http_exec.run_command_http(sid, cmd, op_id=op_id, transfer_use=True, timeout=_eff_timeout) if tr in ("http","https")
				else tcp_exec.run_command_tcp(sid, cmd, timeout=_eff_timeout, defender_bypass=defender_bypass, portscan_active=True,
											  op_id=op_id, transfer_use=True)
			)
		except Exception as e:
			# Normalize into a connection error for the transfer manager.
			logger.debug("  _run_cmd.exception=%r (elapsed=%.4fs)", e, time.time() - t0)
			raise ConnectionError(str(e))

		out = (out or "")
		# Some older paths may return operator-formatted error lines instead of raising.
		if out.lstrip().startswith("[!]") or "Error:" in out:
			logger.debug("  _run_cmd.operator_error_line=%s", _preview(out))
			raise ConnectionError(out.strip())

		elapsed = time.time() - t0
		logger.debug("  _run_cmd.ok elapsed=%.4fs out.len=%d out.preview=%s", elapsed, len(out), _preview(out))
		
		return out

	# ---------- helpers ----------
	def _remote_size(self, st: TransferState) -> int:
		"""
		Return file size in bytes, or -1 if missing/unreachable.
		Use simple, newline-terminated integer output to avoid fragile parsing.
		"""
		_banner("REMOTE_SIZE probe")
		_kv(sid=st.sid, os_type=st.os_type, transport=st.transport, remote_path=st.remote_path, is_folder=getattr(st, "is_folder", None))

		if st.os_type == "linux":
			sh = (
				"bash -c "
				f"\"if [ -f { _linux_shq(st.remote_path) } ]; then stat -c %s { _linux_shq(st.remote_path) }; "
				"else echo -1; fi\""
			)
			try:
				logger.debug("  linux.stat.cmd=%s", _preview(sh))
				out = (self._run_cmd(st.sid, sh, st.transport, self.op_id, defender_bypass=True) or "").strip()

			except Exception as e:
				logger.warning(brightred + f"Connection Error in remote size grabber: {e}" + reset)
				raise ConnectionError("Connection Error in remote size in upload function _remote_size") from e

			if out == "":
				logger.debug("  linux.stat.result=EMPTY -> -1")
				#logger.warning(brightred + "agent unreachable while Get-Item (empty output)" + reset)
				# Treat as missing instead of throwing; caller will decide how to proceed.
				return -1

			try:
				val = int(out)
				logger.debug("  linux.stat.result=%s", val)
				return val

			except Exception:
				logger.warning(brightred + f"bad stat output: {out!r}" + reset)
				raise ConnectionError(f"bad stat output: {out!r}")

		else:
			# Windows: deterministic output
			#  - integer size for files
			#  - 'DIR' for directories
			#  - '-1' for missing/denied/any error
			ps = (
				"$ErrorActionPreference='Stop';"
				"[Console]::OutputEncoding=[System.Text.Encoding]::ASCII;"
				f"$p={_ps_quote(st.remote_path)};"
				"try {"
				"  $i=Get-Item -LiteralPath $p -Force;"
				"  if ($null -eq $i) { '-1' } "
				"  elseif ($i.PSIsContainer) { 'DIR' } "
				"  else { [string]$i.Length }"
				"} catch { '-1' }"
			)

			try:
				logger.debug("  win.size.cmd=%s", ps)
				out = (self._run_cmd(st.sid, ps, st.transport, self.op_id) or "").strip()

			except Exception as e:
				logger.warning(brightred + f"Connection Error in remote size grabber: {e}" + reset)
				raise ConnectionError("Connection Error in remote size in upload function _remote_size") from e

			logger.debug(f"GOT OUTPUT SIZE: {out}")

			if out == "":
				"""logger.warning(brightred + "agent unreachable while Get-Item" + reset)
				raise ConnectionError("agent unreachable while Get-Item")"""
				# Non-terminating PS noise can yield empty stdout; treat as "missing".
				logger.debug("  win.size.result=EMPTY -> coerced to -1")
				out = "-1"

			if out.upper() == "DIR":
				# Directory sentinel (lets caller decide next step).
				logger.debug("  win.size.result=DIR -> -2 sentinel")
				return -2

			if out == "-1":
				logger.debug("  win.size.result=-1 (missing/denied)")
				return -1

			try:
				val = int(out)
				logger.debug("  win.size.result=%s", val)
				return val

			except Exception:
				logger.warning(brightred + f"bad size output: {out!r}" + reset)
				raise ConnectionError(f"bad size output: {out!r}")

	def _linux_read_chunk(self, st: TransferState, index: int) -> bytes:
		# dd avoids partial lines and is faster than tail/head for big files
		#bs = st.chunk_size
		#cmd = f"dd if={_linux_shq(st.remote_path)} bs={bs} skip={index} count=1 status=none | base64"

		# Read a full block at index with no short reads and emit unwrapped base64.
		# - iflag=fullblock → dd reads exactly one whole bs block unless it's the tail
		# - base64 -w 0     → avoid line wraps (smaller payload, faster decode)
		bs = st.chunk_size
		cmd = (
			f"dd if={_linux_shq(st.remote_path)} "
			f"bs={bs} skip={index} count=1 status=none iflag=fullblock | base64 -w 0"
		)

		_sub("LINUX READ CHUNK")
		_kv(index=index, chunk_size=st.chunk_size, offset=index*st.chunk_size)
		logger.debug("  cmd.preview=%s", _preview(cmd))

		try:
			out = self._run_cmd(st.sid, cmd, st.transport, self.op_id)

		except Exception as e:
			logger.warning(brightred + f"Connection Error in _run_cmd: {e}")
			raise ConnectionError("Connection Error in _run_cmd") from e

		if not out.strip():
			logger.warning(brightred + "No output from agent for linux chunk read!" + reset)
			raise ConnectionError("no output from agent for linux chunk read")
		dec = _b64_to_bytes(out)
		logger.debug("  read.ok b64.len=%d decoded.len=%d", len(out.strip()), len(dec))
		return dec

	def _windows_read_chunk(self, st: TransferState, index: int) -> bytes:
		offset = index * st.chunk_size
		n      = st.chunk_size

		_sub("WINDOWS READ CHUNK")
		_kv(index=index, offset=offset, chunk_size=n)

		ps = (
			f"$fs=[System.IO.File]::OpenRead({_ps_quote(st.remote_path)});"
			f"$fs.Seek({offset},'Begin') > $null;"
			f"$buf=New-Object byte[] {n};"
			f"$read=$fs.Read($buf,0,{n});"
			"$fs.Close();"
			"[Convert]::ToBase64String($buf,0,$read)"
		)
		try:
			out = self._run_cmd(st.sid, ps, st.transport, self.op_id)

		except Exception as e:
			logger.warning(brightred + f"Connection Error in _run_cmd: {e}")
			raise ConnectionError("Connection Error in _run_cmd") from e

		if not out.strip():
			raise ConnectionError("no output from agent for windows chunk read")
		dec = _b64_to_bytes(out)
		logger.debug("  read.ok b64.len=%d decoded.len=%d", len(out.strip()), len(dec))
		return dec

	def _linux_write_chunk(self, st: TransferState, offset: int, chunk_b64: str) -> None:
		"""
		Idempotent write at absolute offset using dd (no append). Truncation is not performed here.
		"""

		_sub("LINUX WRITE CHUNK")
		_kv(offset=offset, b64_len=len(chunk_b64))

		# bash -lc for strict error propagation; dd writes exactly at byte offset
		cmd = (
			"bash -lc "
			f"\"set -euo pipefail; "
			f"printf '%s' '{chunk_b64}' | base64 -d | "
			f"dd of={_linux_shq(st.remote_path)} bs=1 seek={offset} conv=notrunc status=none\""
		)
		try:
			self._run_cmd(st.sid, cmd, st.transport, self.op_id)

		except Exception as e:
			logger.warning(brightred + f"Connection Error in _run_cmd: {e}")
			raise ConnectionError("Connection Error in _run_cmd") from e

	def _windows_write_chunk(self, st: TransferState, offset: int, chunk_b64: str) -> None:
		"""
		Append one base64-encoded chunk to the remote file using **inline PowerShell**,
		avoiding a new 'powershell.exe' process so Session-Defender does not block it.
		"""
		# Defensively escape any single quotes in the payload/path for PS single-quoted literals.
		# (Base64 normally has no single quotes, but this is future-proof and safe.)

		_sub("WINDOWS WRITE CHUNK")
		_kv(offset=offset, b64_len=len(chunk_b64))

		safe_chunk = chunk_b64.replace("'", "''")
		safe_path  = st.remote_path.replace("'", "''")

		ps = (
			"[Console]::OutputEncoding=[System.Text.Encoding]::ASCII; "
			f"$bytes=[Convert]::FromBase64String('{safe_chunk}'); "
			f"$s=[System.IO.File]::Open('{safe_path}','OpenOrCreate','ReadWrite','None'); "
			f"$null=$s.Seek({offset}, [System.IO.SeekOrigin]::Begin); "
			"$s.Write($bytes,0,$bytes.Length); "
			"$s.Close()"
		)
		# IMPORTANT: send the snippet directly; do NOT wrap with 'powershell -Command ...'
		try:
			self._run_cmd(st.sid, ps, st.transport, self.op_id)

		except Exception as e:
			logger.warning(brightred + f"Connection Error in _run_cmd: {e}")
			raise ConnectionError("Connection Error in _run_cmd") from e

	def _prepare_remote_archive(self, st: TransferState) -> None:
		"""
		If is_folder, create an archive remotely and switch st.remote_path to that archive (resumable by bytes).
		"""

		_banner("PREPARE REMOTE ARCHIVE")
		_kv(sid=st.sid, os_type=st.os_type, transport=st.transport, remote_path=st.remote_path, is_folder=st.is_folder)

		if not st.is_folder:
			return

		opt = getattr(st, "options", {}) or {}
		# If we've already prepared an archive once and st.remote_path already points to it, skip.
		if opt.get("archive_prepared") and opt.get("archive_path"):
			# Best-effort: verify it still exists; otherwise we'll rebuild once.
			try:
				if st.os_type == "windows":
					ps = f"(Test-Path -LiteralPath {_ps_quote(opt['archive_path'])})"
					try:
						exists = (self._run_cmd(st.sid, ps, st.transport, self.op_id) or "").strip().lower() == "true"

					except Exception as e:
						logger.warning(brightred + f"Connection Error in _run_cmd: {e}")
						raise ConnectionError("Connection Error in _run_cmd") from e

				else:
					sh = f"bash -lc 'test -f {_linux_shq(opt['archive_path'])} && echo OK || echo NO'"
					try:
						exists = "OK" in (self._run_cmd(st.sid, sh, st.transport, self.op_id) or "")

					except Exception as e:
						logger.warning(brightred + f"Connection Error in _run_cmd: {e}" + reset)
						raise ConnectionError("Connection Error in _run_cmd") from e

				if exists:
					st.remote_path = opt["archive_path"]
					return

			except Exception:
				pass

		# Derive names using OS-appropriate semantics.
		if st.os_type == "windows":
			base = ntpath.basename(st.remote_path.rstrip("/\\"))
			parent = ntpath.dirname(st.remote_path.rstrip("/\\"))
		else:
			base = os.path.basename(st.remote_path.rstrip("/\\"))
			parent = os.path.dirname(st.remote_path.rstrip("/\\"))

		_kv(base=base, parent=parent)
		if st.os_type == "windows":
			# Build ...\repos.zip next to the folder, never inside it.
			remote_zip = ntpath.join(parent, base + ".zip")
			# Remove any existing archive; CreateFromDirectory will fail if it exists.
			rm = f"if (Test-Path {_ps_quote(remote_zip)}) {{ Remove-Item {_ps_quote(remote_zip)} -Force }}"
			try:
				self._run_cmd(st.sid, rm, st.transport, self.op_id)

			except Exception as e:
				logger.warning(brightred + f"Connection Error in _run_cmd: {e}" + reset)
				raise ConnectionError("Connection Error in _run_cmd") from e

			_kv(remote_zip=remote_zip)
			# Prefer Compress-Archive when available; otherwise fall back to .NET ZipFile.
			zip_cmd = (
				"$ErrorActionPreference='Stop';"
				f"$src={_ps_quote(st.remote_path)}; $dst={_ps_quote(remote_zip)};"
				"try {"
				"  Compress-Archive -Path $src -DestinationPath $dst -Force -ErrorAction Stop"
				"} catch {"
				"  [Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null; "
				"  [IO.Compression.ZipFile]::CreateFromDirectory($src,$dst,[IO.Compression.CompressionLevel]::Optimal,$false)"
				"}"
			)
			try:
				out = self._run_cmd(st.sid, zip_cmd, st.transport, self.op_id)
				logger.debug("  zip.create.output=%s", _preview(out))

			except Exception as e:
				logger.warning(brightred + f"Connection Error in _run_cmd: {e}" + reset)
				raise ConnectionError("Connection Error in _run_cmd") from e

			# Optional: poll until size > EOCD (22 bytes) to avoid empty placeholder issues.
			size_ps = (
				f"if (Test-Path {_ps_quote(remote_zip)}) {{ (Get-Item {_ps_quote(remote_zip)}).Length }} else {{ 0 }}"
			)
			logger.debug("  zip.poll.size.cmd=%s", _preview(size_ps))
			for _ in range(30):
				try:
					sz = (self._run_cmd(st.sid, size_ps, st.transport, self.op_id) or "").strip()

				except Exception as e:
					logger.warning(brightred + f"Connection Error in _run_cmd: {e}" + reset)
					raise ConnectionError("Connection Error in _run_cmd") from e

				try:
					logger.debug("    zip.poll.size.val=%r", sz)
					if int(sz) > 22:  # larger than empty ZIP EOCD
						break
				except Exception:
					pass
				time.sleep(0.2)
			st.archive_remote_path = remote_zip
			st.cleanup_remote_cmd  = f"Remove-Item {_ps_quote(remote_zip)} -Force"
			st.remote_path         = remote_zip
			# Save fingerprint + mark prepared
			mtime_ps = f"(Get-Item {_ps_quote(remote_zip)}).LastWriteTimeUtc.Ticks"
			logger.debug("  zip.mtime.cmd=%s", _preview(mtime_ps))
			try:
				mtime = _parse_int(self._run_cmd(st.sid, mtime_ps, st.transport, self.op_id))
				length = _parse_int(self._run_cmd(st.sid, size_ps,   st.transport, self.op_id))

			except Exception as e:
				logger.warning(brightred + f"Connection Error in _run_cmd: {e}" + reset)
				raise ConnectionError("Connection Error in _run_cmd") from e

			opt["archive_prepared"] = True
			opt["archive_path"] = remote_zip
			opt["archive_ext"] = ".zip"
			opt["archive_fp"] = {"size": length, "mtime": mtime}
			_kv(archive_path=opt["archive_path"], size=length, mtime_ticks=mtime)
			st.options = opt

		else:
			remote_tar = f"/tmp/{base}.tar.gz"
			_kv(remote_tar=remote_tar)
			try:
				self._run_cmd(st.sid, f"rm -f {_linux_shq(remote_tar)}", st.transport, self.op_id)
				tar_cmd = f"tar czf {_linux_shq(remote_tar)} -C {_linux_shq(st.remote_path)} ."
				logger.debug("  tar.create.cmd=%s", _preview(tar_cmd))
				self._run_cmd(st.sid, tar_cmd, st.transport, self.op_id)

			except Exception as e:
				logger.warning(brightred + f"Connection Error in _run_cmd: {e}" + reset)
				raise ConnectionError("Connection Error in _run_cmd") from e

			st.archive_remote_path = remote_tar
			st.cleanup_remote_cmd  = f"rm -f {_linux_shq(remote_tar)}"
			st.remote_path         = remote_tar
			# Save fingerprint + mark prepared
			size_sh = f"bash -lc 'stat -c %s {_linux_shq(remote_tar)}'"
			mtime_sh = f"bash -lc 'stat -c %Y {_linux_shq(remote_tar)}'"
			logger.debug("  tar.size.cmd=%s", _preview(size_sh))
			logger.debug("  tar.mtime.cmd=%s", _preview(mtime_sh))
			try:
				length = _parse_int(self._run_cmd(st.sid, size_sh,  st.transport, self.op_id))
				mtime  = _parse_int(self._run_cmd(st.sid, mtime_sh, st.transport, self.op_id))

			except Exception as e:
				logger.warning(brightred + f"Connection Error in _run_cmd: {e}" + reset)
				raise ConnectionError("Connection Error in _run_cmd") from e

			opt["archive_prepared"] = True
			opt["archive_path"] = remote_tar
			opt["archive_ext"] = ".tar.gz"
			opt["archive_fp"] = {"size": length, "mtime": mtime}
			_kv(archive_path=opt["archive_path"], size=length, mtime_epoch=mtime)
			st.options = opt

	# ---------- protocol API ----------
	def init_download(self, st: TransferState) -> TransferState:
		# If folder → build remote archive first.
		_banner("INIT DOWNLOAD")
		_kv(tid=st.tid, sid=st.sid, os_type=st.os_type, transport=st.transport, remote_path=st.remote_path, is_folder=st.is_folder, chunk_size=st.chunk_size)
		self._prepare_remote_archive(st)
		try:
			total = self._remote_size(st)

		except Exception as e:
			logger.warning(brightred + f"Connection Error in _remote_size: {e}" + reset)
			raise ConnectionError("Connection Error in _remote_size") from e

		st.total_bytes  = total
		st.total_chunks = chunk_count(total, st.chunk_size)
		st.status = "running"
		_kv(total_bytes=st.total_bytes, total_chunks=st.total_chunks, status=st.status)
		return st

	def next_download_chunk(self, st: TransferState) -> Optional[int]:
		_sub("NEXT DOWNLOAD CHUNK")
		idx = st.next_index
		if idx >= st.total_chunks:
			logger.debug("  finished: idx=%d total_chunks=%d", idx, st.total_chunks)
			return None
		offset = index_to_offset(idx, st.chunk_size)
		_kv(idx=idx, offset=offset, chunk_size=st.chunk_size, bytes_done=st.bytes_done, total_bytes=st.total_bytes)
		# Pull the chunk bytes
		try:
			data = self._linux_read_chunk(st, idx) if st.os_type == "linux" else self._windows_read_chunk(st, idx)

		except Exception as e:
			logger.warning(brightred + f"Connection Error in _run_cmd: {e}" + reset)
			raise ConnectionError("Connection Error in _run_cmd") from e

		# Empty output is never OK for mid-stream chunks.
		if not data:
			if idx < st.total_chunks - 1:
				raise ConnectionError("short read (empty) mid-transfer")
			# Last chunk can be empty only if file size aligned exactly to chunk size.
			# In that rare case, we’re effectively done.
			st.next_index = st.total_chunks
			return None

		# Non-final chunk must be exactly chunk_size bytes
		if idx < st.total_chunks - 1 and len(data) != st.chunk_size:
			logger.debug("  short_read mid-stream: got=%d expected=%d", len(data), st.chunk_size)
			raise ConnectionError(f"short read ({len(data)} bytes) at chunk {idx}")

		"""# If we are NOT on the last chunk, we must receive a full chunk.
		# A shorter block here means the command was interrupted; do not write or advance.
		is_last = (idx == st.total_chunks - 1)
		if (not is_last) and (len(data) < st.chunk_size):
			# Propagate a connection-type error so the manager pauses the transfer.
			raise ConnectionError(f"short read at chunk {idx} ({len(data)} < {st.chunk_size})")"""

		# If last chunk is larger than expected for some reason, trim to expected size
		# (defensive; normally Windows/Linux readers won’t exceed the requested size).
		is_last = (idx == st.total_chunks - 1)
		if is_last:
			expected_last = st.total_bytes - index_to_offset(idx, st.chunk_size)
			if len(data) > expected_last:
				data = data[:expected_last]
		
		logger.debug("  write_at: path=%s offset=%d write_len=%d (is_last=%r)", st.tmp_local_path, offset, len(data), is_last)
		ensure_prealloc(st.tmp_local_path, st.total_bytes)
		write_at(st.tmp_local_path, offset, data)
		st.bytes_done += len(data)
		st.next_index += 1
		_kv(bytes_done=st.bytes_done, next_index=st.next_index)
		return idx

	def init_upload(self, st: TransferState) -> TransferState:
		# clear or create remote target
		"""if st.os_type == "linux":
			_run_cmd(st.sid, f"rm -f \"{st.remote_path}\"", st.transport, self.op_id)
		else:
			_run_cmd(st.sid, f"&{{ Try {{ Remove-Item -Path \"{st.remote_path}\" -ErrorAction Stop }} Catch {{ }} }}", st.transport, self.op_id)"""
		# For brand-new uploads we will start at offset 0; manager handles resume alignment
		# Do not delete the remote file here — resume logic depends on its size.
		st.status = "running"
		return st

	def next_upload_chunk(self, st: TransferState) -> Optional[int]:
		idx = st.next_index
		if idx >= st.total_chunks:
			return None
		with open(st.local_path, "rb") as f:
			f.seek(index_to_offset(idx, st.chunk_size))
			data = f.read(st.chunk_size)
		if not data:
			st.next_index = st.total_chunks
			return None
		b64 = base64.b64encode(data).decode()
		# Absolute byte offset for this chunk
		offset = index_to_offset(idx, st.chunk_size)
		try:
			if st.os_type == "linux":
				self._linux_write_chunk(st, offset, b64)
			else:
				self._windows_write_chunk(st, offset, b64)

		except Exception as e:
			logger.warning(brightred + f"Connection Error in _run_cmd: {e}" + reset)
			raise ConnectionError("Connection Error in _run_cmd") from e

		# Verify remote size reached at least offset + len(data)
		try:
			try:
				rsz = self._remote_size(st)

			except Exception as e:
				logger.warning(brightred + f"Connection Error in _remote_size: {e}" + reset)
				raise ConnectionError("Connection Error in _remote_size") from e

			need = min(st.total_bytes, offset + len(data))
			if rsz < need:
				#print(brightred + f"remote short write: {rsz} < {need}" + reset)
				logger.warning(brightred + f"remote short write: {rsz} < {need}" + reset)
				raise ConnectionError(f"remote short write: {rsz} < {need}")

		except Exception as e:
			# Surface as a connection error so manager doesn't advance index
			logger.warning(brightred + f"Exception in next upload chunk function {str(e)}" + reset)
			raise ConnectionError(str(e))

		st.bytes_done += len(data)
		st.next_index += 1
		return idx

	def cleanup(self, st: TransferState) -> None:
		_banner("CLEANUP")
		_kv(tid=st.tid, sid=st.sid, cleanup_cmd=st.cleanup_remote_cmd, archive=st.archive_remote_path)
		if st.cleanup_remote_cmd:
			try:
				self._run_cmd(st.sid, st.cleanup_remote_cmd, st.transport, self.op_id)
			except Exception:
				pass
