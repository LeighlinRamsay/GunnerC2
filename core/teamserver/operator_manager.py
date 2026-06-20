import uuid
import queue
import socket
import threading
import time
import datetime
import os
import signal
import re
import json
import hashlib
import fnmatch
import sys
import secrets
import pathlib
from core.teamserver import auth_manager as auth
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
reset = Style.RESET_ALL

init()

operators = {}
operator_lock = threading.RLock()
lockout_lock = threading.Lock()

shutdown_event = threading.Event()
LOCKOUT_FILE = os.path.expanduser("~/.gunnerc2/lockouts.json")

def _load_or_create_operator_secret():
    secret_path = pathlib.Path(os.path.expanduser("~/.gunnerc2/operator_secret"))
    if secret_path.is_file() and secret_path.stat().st_size > 0:
        secret = secret_path.read_text().strip()
        if secret:
            return secret
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32)
    secret_path.write_text(key)
    os.chmod(secret_path, 0o600)
    return key

_SECRET = _load_or_create_operator_secret()
_KEY    = hashlib.sha256(_SECRET.encode()).digest()
_AESGCM = AESGCM(_KEY)


class Operator:
	def __init__(self, op_id, queue, handler, username, role):
		self.op_id = op_id
		self.op_queue = queue
		self.handler = handler
		self.username = username
		self.role = role
		self.shell = "main"
		self.gs = None
		self.last_activity = time.time()
		self.registered = time.time()
		self.alias = None

def _recvall(sock, n):
	data = b''
	while len(data) < n:
		try:
			chunk = sock.recv(n - len(data))
			# peer closed connection
			if not chunk:
				break
			data += chunk
			
		except Exception:
			break

	return data

def read_line(sock) -> str:
	"""
	Read from the encrypted socket one byte at a time until newline,
	return the decoded line (no trailing newline).
	"""
	buf = b''
	while True:
		c = sock.recv(1)
		if not c or c == b'\n':
			break
		buf += c
	return buf.decode(errors='ignore').strip()
 

def send_encrypted(raw_sock, plaintext: bytes):
	try:
		nonce = os.urandom(12)
		ct    = _AESGCM.encrypt(nonce, plaintext, None)
		payload = nonce + ct
		header  = len(payload).to_bytes(4, 'big')
		raw_sock.sendall(header + payload)

	except OSError:
		return False

	return True

# deframe & decrypt a message
def recv_encrypted(raw_sock) -> bytes:
	"""
	Read a 4‑byte length prefix, then that many bytes of AES‑GCM payload,
	decrypt it, and return the plaintext.  Silently handles *any* error
	(short reads, malformed data, decryption failure, etc.) by returning b''.
	"""
	try:
		# 1) Read exactly 4 bytes for the length header
		header = _recvall(raw_sock, 4)
		if len(header) < 4:
			return b''

		# 2) Decode length, bail on non‑positive
		MAX_OP_MSG = 10 * 1024 * 1024  # 10MB
		length = int.from_bytes(header, 'big')
		if length <= 0 or length > MAX_OP_MSG:
			return b''

		# 3) Read the full encrypted blob
		blob = _recvall(raw_sock, length)
		# must be at least 12 bytes nonce + some ciphertext
		if len(blob) < 13:
			return b''

		# 4) Split nonce/ciphertext and decrypt
		nonce, ct = blob[:12], blob[12:]
		return _AESGCM.decrypt(nonce, ct, None) or b''

	except Exception:
		# on *any* error, just return empty
		return b''

	# wrap a socket so .send/.recv become our AES routines
class EncryptedSocket:
	def __init__(self, sock):
		self.sock = sock

	def sendall(self, data):
		return send_encrypted(self.sock, data)

	def send(self, data):
		return send_encrypted(self.sock, data)

	def recv(self, _):
		return recv_encrypted(self.sock)

	def close(self):
		return self.sock.close()

	def __getattr__(self, n):
		return getattr(self.sock, n)

def _is_alive(op):
	"""
	Return False if underlying TCP socket is closed/broken.
	"""
	raw = op.handler.sock     # get at the real socket
	try:
		raw.setblocking(False)
		# peek one byte; if recv returns b'' or raises OSError → dead
		data = raw.recv(1, socket.MSG_PEEK)
		if data == b'':
			return False

	except BlockingIOError:
		# no data right now, but still open
		return True

	except Exception:
		# any other error → treat as dead
		return False

	finally:
		raw.setblocking(True)
	return True

def monitor_idle():
	IDLE_TIMEOUT = 1200  # seconds
	while not shutdown_event.is_set():
		time.sleep(60)
		now = time.time()
		with operator_lock:
			for op_id, op in list(operators.items()):
				# 1) socket‐liveness check
				if not _is_alive(op):
					# immediate cleanup
					operators.pop(op_id, None)
					try:
						op.handler.close()

					except:
						pass
					continue

				# 2) then idle‐timeout‐by‐last_activity
				if now - op.last_activity > IDLE_TIMEOUT:
					operators.pop(op_id, None)
					try:
						op.handler.close()
					except:
						pass


def start_operator_listener(host='0.0.0.0', port=5555):
	serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	try:
		serv.bind((host, port))
		serv.listen(100)

	except OSError:
		print(brightred + f"[!] Failed to listen on port {port}, use --port")
		sys.exit(1)

	def accept_loop():
		# brute‑force data structures
		BF_WINDOW     = 60
		BF_THRESHOLD  = 5       # failures per BF_WINDOW ⇒ block
		USER_THRESHOLD = 5       # per-user failures per BF_WINDOW ⇒ lockout
		BLOCK_TIME    = 300      # seconds
		# ─── load + deserialize persistent lockout state ───────────────
		ip_failures = {}
		ip_blocked_until = {}
		user_failures = {}
		user_blocked_until = {}
		if os.path.exists(LOCKOUT_FILE):
			try:
				with open(LOCKOUT_FILE, 'r') as f:
					state = json.load(f)

				ip_failures      = state.get("ip_failures", {})
				ip_blocked_until = state.get("ip_blocked_until", {})

				# convert the string‑keys back into (ip,username) tuples
				uf = {}
				for sk, times in state.get("user_failures", {}).items():
					ip_str, uname = sk.split("|", 1)
					uf[(ip_str, uname)] = times
				user_failures = uf

				ub = {}
				for sk, ts in state.get("user_blocked_until", {}).items():
					ip_str, uname = sk.split("|", 1)
					ub[(ip_str, uname)] = ts
				user_blocked_until = ub

			except (IOError, json.JSONDecodeError):
				# on any I/O or parse error, start fresh
				ip_failures = {}
				ip_blocked_until = {}
				user_failures = {}
				user_blocked_until = {}

		def persist_state():
			# build a JSON‑safe dict: join tuple keys with '|'
			with lockout_lock:
				serial = {
					"ip_failures":        ip_failures,
					"ip_blocked_until":   ip_blocked_until,
					"user_failures":      {"|".join(k): v for k, v in user_failures.items()},
					"user_blocked_until": {"|".join(k): v for k, v in user_blocked_until.items()},
				}

			# ensure dir
			os.makedirs(os.path.dirname(LOCKOUT_FILE), exist_ok=True)
			tmp = LOCKOUT_FILE + ".tmp"
			with open(tmp, "w") as f:
				json.dump(serial, f)

			# atomic replace
			os.replace(tmp, LOCKOUT_FILE)

		while not shutdown_event.is_set():
			try:
				cli, addr = serv.accept()
				cli.settimeout(30)  # prevent client from hanging us
				ip = addr[0]
				now = time.time()

				cli.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

				if hasattr(socket, "TCP_KEEPIDLE"):
					cli.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
					cli.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
					cli.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)

				enc_cli = EncryptedSocket(cli)

				# 1) Global per‑IP block?
				if ip in ip_blocked_until:
					if now < ip_blocked_until[ip]:
						# still blocked
						enc_cli.sendall(b"[!] Too many failed attempts; try again later.\n")
						enc_cli.close()
						continue
					else:
						del ip_blocked_until[ip]

				# 1) prompt for credentials
				enc_cli.sendall(b"Username: ")
				username = enc_cli.recv(4096).decode(errors="ignore").strip()
				if not re.fullmatch(r"[A-Za-z0-9@._-]{1,32}", username):
					enc_cli.sendall(b"[!] Invalid-format username; closing.\n")
					enc_cli.close()
					continue
				uname_lc = username.lower()

				# 4) per‑user lockout?
				key = (ip, uname_lc)
				if key in user_blocked_until:
					if now < user_blocked_until[key]:
						enc_cli.sendall(b"[!] Too many bad password attempts on this account; try again later.\n")
						enc_cli.close()
						continue
					else:
						del user_blocked_until[key]
				
				enc_cli.sendall(b"Password: ")
				password = enc_cli.recv(4096).decode(errors="ignore").strip()

				# simple password‐format check
				if not re.fullmatch(r"\S{1,64}", password):
					enc_cli.sendall(b"[!] Invalid password format; closing.\n")
					enc_cli.close()
					continue

				# 2) verify against your persistent store
				creds = auth.verify_credentials(username, password)
				if not creds:
					# record global failure
					ip_failures.setdefault(ip, []).append(now)
					# prune old
					ip_failures[ip] = [t for t in ip_failures[ip] if now - t < BF_WINDOW]
					if len(ip_failures[ip]) >= BF_THRESHOLD:
						ip_blocked_until[ip] = now + BLOCK_TIME
						persist_state()

					# record per-user failure
					user_failures.setdefault(key, []).append(now)
					user_failures[key] = [t for t in user_failures[key] if now - t < BF_WINDOW]
					if len(user_failures[key]) >= USER_THRESHOLD:
						user_blocked_until[key] = now + BLOCK_TIME
						persist_state()

					enc_cli.sendall(b"[!] Invalid credentials, closing.\n")
					enc_cli.close()
					continue

				# on success, clear any failure counters
				ip_failures.pop(ip, None)
				user_failures.pop(key, None)

				cli.settimeout(None)
				cli.setblocking(True)
					
				op_id = str(uuid.uuid4())
				# enforce session cap to avoid DOS
				with operator_lock:
					if len(operators) >= 200:
						enc_cli.sendall(b"[!] Too many operators, try later.\n")
						enc_cli.close()
						continue

				q = queue.Queue(maxsize=100)
				with operator_lock:
					role = creds["role"]
					operators[op_id] = Operator(op_id, q, enc_cli, username, role)

				enc_cli.sendall(
					f"[+] Authenticated as {username} with role {role} (operator ID {op_id})\n".encode()
				)
				threading.Thread(target=handle_operator, args=(op_id,), daemon=True).start()

			except MemoryError as e:
				print(brightred + f"[!] MemoryError: {e}")
				sys.exit()

			except SystemExit as e:
				print(brightred + f"[!] SystemExit: {e}")
				sys.exit()

			except:
				pass

	# start accept + idle threads once
	accept_thread = threading.Thread(target=accept_loop, daemon=True)
	idle_thread   = threading.Thread(target=monitor_idle, daemon=True)
	accept_thread.start()
	idle_thread.start()

	# graceful shutdown handler
	def _shutdown(signum, frame):
		shutdown_event.set()
		serv.close()
		accept_thread.join()
		idle_thread.join()
		sys.exit(0)

	signal.signal(signal.SIGINT,  _shutdown)
	signal.signal(signal.SIGTERM, _shutdown)

def handle_operator(op_id):
	with operator_lock:
		operator = operators.get(op_id)
		if not operator:
			return

		sock = operator.handler
		q    = operator.op_queue

	try:
		buf = b''
		while True:
			try:
				data = sock.recv(4096)

			except ConnectionResetError:
				break

			if not data:
				break

			operator.last_activity = time.time()
			buf += data
			while b'\n' in buf:
				line, buf = buf.split(b'\n',1)
				# strip CR/LF
				try:
					q.put(line.decode(errors='ignore').strip())

				except queue.Full:
					pass
	finally:
		# cleanup on disconnect
		with operator_lock:
			operators.pop(op_id, None)

		try:
			sock.close()

		except: 
			pass

def list_operators(name: str = None):
	# Column widths
	NAME_W     = 15
	ROLE_W     = 10
	ALIAS_W    = 15
	ID_W       = 36
	REG_W      = 19

	# If filtering by name/alias
	if name:
		op_id = resolve_operator(name)
		if not op_id:
			return "NO OPERATOR FOUND"

		op    = operators[op_id]
		name_ = op.username
		role_ = op.role
		alias = op.alias or "N/A"
		ts    = datetime.datetime.fromtimestamp(op.registered)
		reg   = ts.strftime("%Y-%m-%d %H:%M:%S")

		header = (
			f"{'Name':<{NAME_W}}  "
			f"{'Role':<{ROLE_W}}  "
			f"{'Alias':<{ALIAS_W}}  "
			f"{'Operator ID':<{ID_W}}  "
			f"{'Registered':<{REG_W}}"
		)
		print(brightgreen + header + reset)
		print(brightgreen + "-" * len(header) + reset)
		print(
			brightred
			+ f"{name_:<{NAME_W}}  {role_:<{ROLE_W}}  {alias:<{ALIAS_W}}  "
			+ f"{op_id:<{ID_W}}  {reg:<{REG_W}}"
			+ reset
		)
		return

	# Otherwise list all operators
	if not operators:
		return "NO OPERATORS FOUND"

	header = (
		f"{'Name':<{NAME_W}}  "
		f"{'Role':<{ROLE_W}}  "
		f"{'Alias':<{ALIAS_W}}  "
		f"{'Operator ID':<{ID_W}}  "
		f"{'Registered':<{REG_W}}"
	)
	print(brightgreen + header + reset)
	print(brightgreen + "-" * len(header) + reset)

	with operator_lock:
		for op in operators.values():
			name_ = op.username
			role_ = op.role
			alias = op.alias or "N/A"
			ts    = datetime.datetime.fromtimestamp(op.registered)
			reg   = ts.strftime("%Y-%m-%d %H:%M:%S")

			# truncate alias if too long
			if len(alias) > ALIAS_W:
				alias = alias[:ALIAS_W-3] + "..."

			print(
				brightred
				+ f"{name_:<{NAME_W}}  {role_:<{ROLE_W}}  {alias:<{ALIAS_W}}  "
				+ f"{op.op_id:<{ID_W}}  {reg:<{REG_W}}"
				+ reset
			)

def resolve_operator(raw: str) -> str | None:
	"""
	Given raw input (operator ID, alias, or wildcard), return the unique operator ID,
	or None if not found (or ambiguous).
	"""
	# exact ID match?
	if raw in operators:
		return raw

	# exact alias match?
	for op_id, op in operators.items():
		if op.alias == raw:
			return op_id

	# wildcard support?
	if any(ch in raw for ch in "*?"):
		matches = []
		# match against IDs
		matches += [oid for oid in operators if fnmatch.fnmatch(oid, raw)]
		# match against aliases
		matches += [
			op.op_id
			for op in operators.values()
			if op.alias and fnmatch.fnmatch(op.alias, raw)
		]
		# dedupe, preserve order
		seen = {}
		for m in matches:
			seen.setdefault(m, True)
		matches = list(seen.keys())

		if len(matches) == 1:
			return matches[0]
		elif len(matches) > 1:
			print(
				brightred
				+ f"[!] Ambiguous operator pattern '{raw}' → matches {matches!r}"
				+ reset
			)
			return None

	# nothing found
	return None