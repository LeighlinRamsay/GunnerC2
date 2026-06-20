import logging
logger = logging.getLogger(__name__)

from core.print_override import set_output_context
import shlex
import readline
import ntpath
import os, sys
import re
import base64
from pathlib import Path
import posixpath
import argparse
from core.module_loader import load_module, discover_module_files, search_modules, MODULE_DIR as BASE_MODULE_DIR
from core.session_handlers.session_manager import resolve_sid
from core.utils import print_help, print_gunnershell_help, defender
from core.help_menus import gunnershell_commands_windows, gunnershell_commands_linux
from core import shell, portfwd, utils
from core.session_handlers import session_manager
from core.banner import print_banner
from colorama import init, Fore, Style
from core.prompt_manager import prompt_manager

# Modular Command System Imports

from core.gunnershell.commands.base import get as get_command, list_commands, load, COMMANDS

# Modular BOF Loader & Library Imports

from core.gunnershell.bofs.base import (
	load as load_bof_registry,
	BOFS as BOF_REGISTRY,
	Bof as BofBase,
)

# Command Execution Imports

from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

# Helper functions

from core.gunnershell.gunnershell_utils import help_menu, pop_commands, _detect_gunnerplant

# Transfer Framework Imports
from core.transfers.manager import TransferManager, TransferOpts
from core.transfers import xfer as xcmd

# Colorama variables
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"
UNDERLINE_ON  = "\001\x1b[4m\002"
UNDERLINE_OFF = "\001\x1b[24m\002"
reset = Style.RESET_ALL

#MODULE_DIR = os.path.join(os.path.dirname(__file__), "modules")

MODULE_DIR = BASE_MODULE_DIR
MAIN_HISTORY = os.path.expanduser("~/.gunnerc2_history")

class QuietParser(argparse.ArgumentParser):
	def error(self, message):
		raise SystemExit


class Gunnershell:
	"""
	A Meterpreter-like subshell that can load and run Gunner modules against a session.
	Usage:
	  gs = Gunnershell(session_id)
	  gs.interact()
	"""
	def __init__(self, sid, op_id=None):
		self.sid = sid
		logger.debug(brightblue + f"IN __INIT__ GUNNERSHELL FUNC WITH SID {sid} AS OP {op_id} ABOUT TO RESOLVE SID" + reset)
		real = resolve_sid(sid)
		if not real or real not in session_manager.sessions:
			logger.debug(brightred + f"INVALID SESSION {sid}" + reset)
			raise ValueError(brightred + f"Invalid session: {sid}")

		self.session = session_manager.sessions[self.sid]
		prompt = f"{UNDERLINE_ON}{brightblue}GunnerShell{UNDERLINE_OFF} > "
		if not op_id:
			prompt_manager.set_prompt(prompt)
			self.prompt = prompt_manager.get_prompt()
		else:
			prompt_manager.set_prompt(prompt, op_id)
			self.prompt = prompt_manager.get_prompt(op_id)

		logger.debug(brightblue + f"SET GUNNERSHELL PROMPTS FOR SID {sid} AS OP {op_id}" + reset)

		self.os_type = self.session.metadata.get("os","").lower()

		if self.os_type == "windows":
			self.commands = gunnershell_commands_windows

		elif self.os_type == "linux":
			self.commands = gunnershell_commands_linux

		load(self.os_type)


		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)
		self.sid = real
		self.display = display
		self.gunnerplant = False
		self.bofs_enabled = False
		self.bof_registry = {}
		_detect_gunnerplant(gunnershell_class=self, op_id=op_id)
		self.MAIN_HIST = os.path.expanduser("~/.gunnerc2_history")
		SESSION_HIST = os.path.expanduser(f"~/.gunnerc2_gs_{self.sid}_history")
		self.SESSION_HIST = SESSION_HIST
		logger.debug(brightblue + "SUCCESSFULLY SET GUNNERSHELL HISTORY FILES" + reset) 

		# discover available modules once
		self.available = discover_module_files(MODULE_DIR)
		if op_id and op_id != "console":
			logger.debug(brightblue + f"GETTING PWD WITH OP ID: {op_id}" + reset)
			self.cwd = self.run_pwd(to_console=False, op_id=op_id) or ""

		else:
			logger.debug(brightblue + "GETTING PWD WITH MAIN C2 CONSOLE" + reset)
			self.cwd = self.run_pwd(to_console=True, op_id="console") or ""

		if op_id:
			logger.debug(brightgreen + f"SUCCESSFULLY INITALIZED GUNNERSHELL FOR SID {sid} as OP {op_id}" + reset)

		else:
			logger.debug(brightgreen + f"SUCCESSFULLY INITALIZED GUNNERSHELL FOR SID {sid} as CONSOLE" + reset)

		# Conditionally load BOF registry (no agent execution here)
		if self.gunnerplant:
			try:
				load_bof_registry()
				self.bof_registry = dict(BOF_REGISTRY)
				self.bofs_enabled = True
				logger.debug(brightgreen + f"Loaded {len(self.bof_registry)} BOF provider(s)" + reset)
			except Exception as e:
				logger.debug(brightred + f"BOF registry load error: {e}" + reset)

		pop_commands(self)

	def make_abs(self, p):
		"""
		Resolve p (which may be relative) against the current working
		directory (self.cwd), using the right path logic for windows/linux.
		"""
		

		# if it's already absolute, just return it
		if ("windows" in self.os_type and ntpath.isabs(p)) or \
		   ("linux"   in self.os_type and p.startswith("/")):
			return p

		base = self.cwd or ""
		joiner = ntpath if "windows" in self.os_type else posixpath
		return joiner.normpath(joiner.join(base, p))


	def completer(self, text, state):
		# simple tab completion: modules and built-in commands
		try:
			builtins = list(self.commands.keys())
			if not self.gunnerplant and "bofexec" in builtins:
				builtins.remove("bofexec")
			options  = [c for c in self.available + builtins if c.startswith(text)]
			return options[state]

		except IndexError:
			pass

	def run_module(self, modname):
		"""
		Load and run a module by name, using default options from session metadata.
		"""
		module = load_module(modname)
		if not module:
			print(f"[!] Module not found: {modname}")
			return
		# auto-set common options if present
		meta = self.session.metadata
		for opt in ("sid", "session_id", "target", "host", "user"):  # example keys
			if opt in module.options and "sid" in module.options:
				module.set_option(opt, self.sid)
		missing = module.validate()
		if missing is not True:
			print(f"[!] Missing options: {', '.join(missing)}")
			return
		module.run()

	def run_pwd(self, to_console=True, op_id=None):
		#cmd_cls, n_consumed = get_command("pwd")
		cmd_cls, n_consumed = get_command(["pwd"])
		if cmd_cls:
			try:
				instance = cmd_cls(self, to_console, op_id)
				instance.execute()

			except Exception as e:
				logger.debug(f"HIT ERROR GETTING CWD ON GS START: {e}")
				return None

	# ─── BOF Resolution Helper ──────────────────────────────────────────────
	def _resolve_bof_bytes(self, name_or_path: str):
		"""
		Resolution order:
		  1) If `name_or_path` is a real file, read bytes and return (name, bytes).
		  2) Else, consult BOF registry (core/gunnershell/bofs/base.py).
			 If a provider class is registered under that name and has a
			 class attribute `bofbase64`, decode and return (name, bytes).
			 (Optional) If no `bofbase64`, but the class defines `load_bytes()`,
			 call it and return (name, bytes).

		Returns:
		  (bof_name: str, bof_bytes: bytes) or None if not found/failed.
		"""
		# 1) Filesystem
		try:
			if os.path.isfile(name_or_path):
				name = os.path.splitext(os.path.basename(name_or_path))[0]
				with open(name_or_path, "rb") as f:
					data = f.read()
				logger.debug(brightgreen + f"Resolved BOF from file: {name_or_path} ({len(data)} bytes)" + reset)
				return name, data

		except Exception as e:
			logger.debug(brightyellow + f"BOF file read failed for {name_or_path}: {e}" + reset)

		# 2) BOF registry
		try:
			# Lazy-load registry once (only if we think it might be relevant)
			if not self.bofs_enabled:
				try:
					load_bof_registry()
				finally:
					self.bofs_enabled = True

			cls = BOF_REGISTRY.get(name_or_path)
			if not cls:
				# Try by basename (common convenience)
				basename = os.path.splitext(os.path.basename(name_or_path))[0]
				cls = BOF_REGISTRY.get(basename)
				if not cls:
					logger.debug(brightyellow + f"BOF not found in registry: {name_or_path}" + reset)
					return None

			# Prefer the requested key as the logical name; fall back to class name
			logical_name = name_or_path if name_or_path in BOF_REGISTRY else basename

			# Primary path: class variable `bofbase64`
			b64val = getattr(cls, "bofbase64", None)
			if isinstance(b64val, str) and b64val.strip():
				try:
					data = base64.b64decode(b64val, validate=False)
					logger.debug(brightgreen + f"Resolved BOF '{logical_name}' from registry via bofbase64 ({len(data)} bytes)" + reset)
					return logical_name, data
				except Exception as e:
					logger.debug(brightyellow + f"Failed to decode bofbase64 for '{logical_name}': {e}" + reset)

			# Fallback: provider instance with load_bytes()
			try:
				provider = cls(self) if callable(getattr(cls, "__call__", None)) else None
				if provider and hasattr(provider, "load_bytes"):
					data = provider.load_bytes()
					if isinstance(data, (bytes, bytearray)):
						logger.debug(brightgreen + f"Resolved BOF '{logical_name}' from provider.load_bytes() ({len(data)} bytes)" + reset)
						return logical_name, bytes(data)

			except Exception as e:
				logger.debug(brightyellow + f"Provider load_bytes() failed for '{logical_name}': {e}" + reset)

		except Exception as e:
			logger.debug(brightred + f"BOF registry resolution error: {e}" + reset)

		return None

	def interact(self, cmd, to_console=True, op_id=None):
		set_output_context(to_console=to_console, to_op=op_id, world_wide=False)
		#readline.set_completer(self.completer)
		#readline.parse_and_bind("tab: complete")

		if not op_id:
			op_id = "console"
		try:
			user = cmd
			try:
				parts = shlex.split(user.strip())

			except ValueError:
				print(brightred + "[!] No escaped character!")
				return

			if not user:
				return


			elif not parts:
				return

			try:
				cmd = parts[0]

			except Exception:
				return

			# exit subshell
			if cmd in ("exit", "quit", "back"):
				PROMPT = brightblue + "GunnerC2 > " + brightblue
				if not op_id:
					prompt_manager.set_prompt(PROMPT)
					self.prompt = prompt_manager.get_prompt()
				else:
					prompt_manager.set_prompt(PROMPT, op_id)
					self.prompt = prompt_manager.get_prompt(op_id)
				return "exit"

			# help
			elif cmd == "help":
				parts = user.split()

				# help
				if len(parts) == 1:
					#out = print_gunnershell_help(to_console=to_console, op_id=op_id, gunnerplant=self.gunnerplant)
					out = print_gunnershell_help(to_console=to_console, op_id=op_id, gunnerplant=self.gunnerplant, os_type=self.os_type)
					if out:
						return out

					else:
						logger.debug("HELP OUTPUT NOT FOUND")

				# help <command>
				elif len(parts) == 2:
					print_gunnershell_help(parts[1], os_type=self.os_type)
					return

				# help <command> <subcommand>
				elif len(parts) == 3:
					print_gunnershell_help(f"{parts[1]} {parts[2]}", os_type=self.os_type)
					return

				else:
					print(brightyellow + "Usage: help or help <command> [subcommand]")
					return

				return

			elif cmd == "banner":
				os.system("clear")
				print_banner()
				return

			# list modules
			elif cmd == "list":
				print(brightgreen + "Available modules:")
				for m in self.available:
					print(brightgreen + f"  {m}")
				return

			elif cmd == "gunnerid":
				print(brightgreen + self.sid)
				return

			elif cmd == "sessions":
				utils.list_sessions()
				return

			elif cmd == "alias":
				parts = shlex.split(user)
				if len(parts) != 3:
					print(brightyellow + "Usage: alias <OLD_SID_or_ALIAS> <NEW_ALIAS>")
					return

				old, new = parts[1], parts[2]
				real = session_manager.resolve_sid(old)
				if not real:
					print(brightred + f"No such session or alias: {old}")
					return

				session_manager.set_alias(new, real)
				print(brightgreen + f"Alias set: {new!r} → {real}")

				old_display = old
				for entry in portforwards.values():
					if entry["sid"] == old_display:
						entry["sid"] = new

				return

			elif cmd == "switch":
				parts = shlex.split(user)
				if len(parts) != 2:
					print(brightyellow + "Usage: switch <session_id_or_alias>")
					return

				raw = parts[1]
				new_sid = resolve_sid(raw)
				if not new_sid or new_sid not in session_manager.sessions:
					print(brightred + f"No such session or alias: {raw}")
					return

				if new_sid == self.sid:
					print(brightyellow + f"Already in GunnerShell for session {self.display}")
					return

				display = next((a for a, rsid in session_manager.alias_map.items() if rsid == new_sid), new_sid)
				print(brightgreen + f"[*] Switching out of this subshell and into session {display}...")
				# return the new SID so the caller can re-spawn at top level
				return f"SIDSWITCH {new_sid}"

			elif cmd == "shelldefence":
				parts = user.split()
				try:
					if len(parts) != 2 or parts[1] not in ("on", "off"):
						print(brightyellow + "Usage: shelldefence <on|off>")
						return

					if parts[1] == "on":
						defender.is_active = True

					elif parts[1] == "off":
						defender.is_active = False

				except IndexError:
					print(brightyellow + "Usage: shelldefence <on|off>")
					return

				except Exception as e:
					print(brightred + f"[!] An unknown error has ocurred: {e}")
					return
				return

			# === upload (new TransferManager flow; supports flags + legacy positional) ===
			elif cmd == "upload":
				try:
					args = shlex.split(user)

					parser = QuietParser(prog="upload", add_help=False)
					parser.add_argument("-l", required=True, help="Local file or folder path")
					parser.add_argument("-r", required=True, help="Remote destination file or directory")
					parser.add_argument("-t", "--timeout", dest="timeout", type=float, required=False, default=None, help="Timeout per chunk (seconds)")
					parser.add_argument("--chunk", type=int, default=262144, required=False, help="Chunk size (bytes)")

					try:
						parsed_args = parser.parse_args(args[1:])

					except SystemExit:
						print(brightyellow + "Usage: upload -l <local> -r <remote> [--chunk N] [--timeout S]")
						return

					sid = self.sid
					session = session_manager.sessions.get(sid)

					if not session:
						print(brightred + f"Invalid session: {sid}")
						return

					trans = session.transport.lower()
					if trans in ("http", "https") and not parsed_args.timeout:
						print(brightyellow + "You must specify a timeout for HTTP/HTTPS transfers (use ~2× interval, 3× if jittery).")
						return
					timeout = parsed_args.timeout

					remote_os = (session.metadata or {}).get("os", "").lower()
					remote_path = parsed_args.r
					local_path  = parsed_args.l

					if remote_os == "windows" and ("\\" not in remote_path):
						print(brightyellow + "[*] Windows agents require double backslashes in remote paths (e.g., C:\\\\path\\\\to)")
						return

					if not os.path.exists(local_path):
						print(brightred + f"[!] Local path does not exist: {local_path}")
						return

					is_folder = os.path.isdir(local_path)
					tm = TransferManager()
					try:
						opts = TransferOpts(chunk_size=parsed_args.chunk, to_console=to_console, to_op=op_id)
					except NameError:
						# Fallback if to_console/to_op not in this scope
						opts = TransferOpts(chunk_size=parsed_args.chunk)

					tid = tm.start_upload(
						sid=sid,
						local_path=local_path,
						remote_path=remote_path,
						folder=is_folder,
						opts=opts,
						timeout=timeout
					)
					print(brightyellow + f"[*] TID={tid} (use: xfer status -t {tid} | xfer resume -t {tid})")
				except Exception as e:
					try:
						logger.exception(f"Upload start failed: {e}")
					except Exception:
						pass
					print(brightred + f"[!] Upload failed to start: {e}")
				return

			# === download (new TransferManager flow; supports flags + legacy positional) ===
			elif cmd == "download":
				try:
					args = shlex.split(user)

				   
					parser = QuietParser(prog="download", add_help=False)
					parser.add_argument("-f", required=True, help="Remote file or folder path")
					parser.add_argument("-o", required=True, help="Local output file or directory")
					parser.add_argument("-t", "--timeout", dest="timeout", type=float, required=False, default=None, help="Timeout per chunk (seconds)")
					parser.add_argument("--chunk", type=int, default=262144, required=False, help="Chunk size (bytes)")

					try:
						parsed_args = parser.parse_args(args[1:])
					except SystemExit:
						print(brightyellow + "Usage: download -f <remote> -o <local> [--chunk N] [--timeout S]")
						return

					sid = self.sid
					session = session_manager.sessions.get(sid)
					if not session:
						print(brightred + f"Invalid session: {sid}")
						return

					trans = session.transport.lower()
					if trans in ("http", "https") and not parsed_args.timeout:
						print(brightyellow + "You must specify a timeout for HTTP/HTTPS transfers (use ~2× interval, 3× if jittery).")
						return
					timeout = parsed_args.timeout

					remote_os = (session.metadata or {}).get("os", "").lower()
					remote_path = parsed_args.f
					local_out   = parsed_args.o

					if remote_os == "windows" and ("\\" not in remote_path):
						print(brightred + "Use double backslashes for Windows remote paths.")
						return

					tm = TransferManager()
					try:
						opts = TransferOpts(chunk_size=parsed_args.chunk, to_console=to_console, to_op=op_id)
					except NameError:
						opts = TransferOpts(chunk_size=parsed_args.chunk)

					# folder=None => let remote probe determine file vs folder
					tid = tm.start_download(
						sid=sid,
						remote_path=remote_path,
						local_path=local_out,
						folder=None,
						opts=opts,
						timeout=timeout
					)
					print(brightyellow + f"[*] TID={tid} (use: xfer status -t {tid} | xfer resume -t {tid})")
				except Exception as e:
					try:
						logger.exception(f"Download start failed: {e}")
					except Exception:
						pass
					print(brightred + f"[!] Error starting download: {e}")
				return

			elif cmd.startswith("xfer"):
				try:
					def _usage():
						"""print(brightyellow + (
							"Usage:\n"
							"  xfer list [-i <session_id_or_alias>]\n"
							"  xfer status -t <tid|prefix> [-i <session_id_or_alias>]\n"
							"  xfer resume -t <tid|prefix> [-i <session_id_or_alias>]\n"
							"  xfer cancel -t <tid|prefix> [-i <session_id_or_alias>]\n"
						))"""
						utils.print_help("xfer")

					args = shlex.split(user)
					if len(args) == 1 or args[1] in ("-h", "--help"):
						_usage()
						return

					sub = args[1].lower()
					rest = args[2:]

					if sub == "clear":		
						parser = QuietParser(prog="xfer clear", add_help=False)
						g = parser.add_mutually_exclusive_group(required=True)
						g.add_argument("-a", "--all", action="store_true")
						g.add_argument("-t", metavar="TIDS", help="TID or comma-separated TIDs/prefixes")
						g.add_argument("-i", metavar="SIDPAT", help="Session ID wildcard (e.g., 2g3sj-*)")
						g.add_argument("-f", metavar="FILE", help="File containing TIDs (one per line)")
						try:
							ns = parser.parse_args(args[2:])
						except SystemExit:
							utils.print_help("xfer clear")
							return
						xcmd.handle_clear(ns, to_console=to_console, to_op=op_id)
						return

					elif sub == "list":
						p = QuietParser(prog="xfer list", add_help=False)
						p.add_argument("-i", required=False)
						try:
							ns = p.parse_args(rest)
						except SystemExit:
							_usage()
							return
						xcmd.cmd_list(getattr(ns, "i", None), to_console=to_console, to_op=op_id)
						return

					def _parse_tid(cmdname: str):
						if cmdname == "resume":
							p = QuietParser(prog=f"xfer {cmdname}", add_help=False)
							p.add_argument("-t", required=True)
							p.add_argument("-i", required=False)
							p.add_argument("--timeout", required=False, default=None, dest="timeout")

						else:
							p = QuietParser(prog=f"xfer {cmdname}", add_help=False)
							p.add_argument("-t", required=True)
							p.add_argument("-i", required=False)

						try:
							return p.parse_args(rest)

						except SystemExit:
							_usage()
							return None

					if sub == "status":
						ns = _parse_tid("status")
						if ns is None:
							return
						xcmd.cmd_status(ns.t, getattr(ns, "i", None), to_console=to_console, to_op=op_id)
						return

					if sub == "resume":
						ns = _parse_tid("resume")
						if ns is None:
							return
						xcmd.cmd_resume(ns.t, getattr(ns, "i", None), to_console=to_console, to_op=op_id, timeout=ns.timeout)
						return

					if sub == "cancel":
						ns = _parse_tid("cancel")
						if ns is None:
							return
						xcmd.cmd_cancel(ns.t, getattr(ns, "i", None), to_console=to_console, to_op=op_id)
						return

					_usage()

				except Exception as e:
					print(brightred + f"[!] xfer failed: {e}")

			# shell: drop into full interactive shell
			elif cmd == "shell":
				if session_manager.sessions[self.sid].transport in ("http","https"):
					shell.interactive_http_shell(self.sid)
				else:
					shell.interactive_tcp_shell(self.sid)
				return

			# modhelp: show a module’s options
			elif cmd == "modhelp":
				parts = shlex.split(user)
				if len(parts) != 2:
					print(brightyellow + "Usage: modhelp <module_name>")
					return
				else:
					modname = parts[1]
					module = load_module(modname)
					if module:
						print(brightyellow + f"Module: {module.name}\n")
						print(brightgreen + f"{module.description}\n")
						module.show_options()
				return

			elif cmd == "search":
				parts = shlex.split(user)
				if len(parts) != 2:
					print(brightyellow + "Usage: search <keyword>   or   search all")
					return

				else:
					term = parts[1]
					if term.lower() == "all":
						results = discover_module_files(MODULE_DIR)
					else:
						results = search_modules(term)

					if not results:
						print(brightred + f"No modules found matching '{term}'.")
					else:
						self.available = results
						print(brightgreen + f"Found {len(results)} modules:")
						for idx, m in enumerate(results, 1):
							print(brightgreen + f"  [{idx}] {m}")
				return

			# run: execute a module with inline key=val args
			elif cmd == "run":
				parts = shlex.split(user)
				if len(parts) < 2:
					print(brightyellow + "Usage: run <module_name> [KEY=VALUE ...]")
					return

				else:
					modname = parts[1]
					module = load_module(modname)
					if not module:
						return

					# parse key=val pairs
					for kv in parts[2:]:
						if "=" in kv:
							key, val = kv.split("=",1)
							try:
								module.set_option(key, val)
							except Exception:
								print(brightred + f"Unknown option '{key}'")
					missing = module.validate()
					if missing is True:
						module.run()
					else:
						print(brightred + "[!] Missing required options: " + ", ".join(missing))
				return

			elif cmd == "portfwd":
				parts = shlex.split(user)
				# must have at least: portfwd <subcommand>
				if len(parts) < 2 or parts[1] not in ("add","list","delete"):
					print(brightyellow + "Usage: portfwd <add|list|delete> [options]")
					return

				sub = parts[1]

				# portfwd list
				if sub == "list":
					from core.utils import list_forwards
					fwd = list_forwards()
					if not fwd:
						print(brightyellow + "No active port-forwards.")

					else:
						for rid, info in fwd.items():
							print(brightgreen + f"{rid}: {info['local_host']}:{info['local']} → {info['sid']} → {info['remote']}")
					return

				# portfwd delete -i <rule_id>
				if sub == "delete":
					if "-i" not in parts:
						print(brightyellow + "Usage: portfwd delete -i <rule_id>")

					else:
						rid = parts[parts.index("-i")+1]
						from core.utils import unregister_forward
						unregister_forward(rid)
						print(brightyellow + f"Removed forward {rid}")
					return

				# portfwd add -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port> -cp <chisel_port>
				if sub == "add":
					try:
						opts = dict(zip(parts[2::2], parts[3::2]))
						lh = opts["-lh"]
						lp = int(opts["-lp"])
						rh = opts["-rh"]
						rp = int(opts["-rp"])
						cp = int(opts["-cp"])

					except Exception:
						print(brightyellow + "Usage: portfwd add -lh <local_host> -lp <local_port> -rh <remote_host> -rp <remote_port> -cp <chisel_port>")
						return

					# start the listener thread
					from core import portfwd as _pfwd
					import threading
					rid = str(len(utils.portforwards) + 1)
					sid = session_manager.resolve_sid(self.sid)
					t = threading.Thread(
						target=_pfwd.portfwd_listener,
						args=(rid, sid, lh, lp, rh, rp, cp),
						daemon=True
					)
					t.start()

					# register it so `list` can see it
					utils.register_forward(rid, self.sid, lh, lp, rh, rp, t, _pfwd.last_listener_socket)
					print(brightgreen + f"[+] Forward #{rid} {lh}:{lp} → {self.sid} → {rh}:{rp}")
					return

			# Try to find a registered command (possibly multi-word)
			cmd_cls, n_consumed = get_command(parts)
			if cmd_cls:
				args = parts[n_consumed:]           # only the remainder go to execute()
				try:
					instance = cmd_cls(self, to_console, op_id)
					instance.execute(args)
				except Exception as e:
					print(f"{brightred}[!] Error running {parts[:n_consumed]!r}: {e}")
				return

			else:
				parts = user.split()
				out = help_menu(parts, to_console=to_console, op_id=op_id)
				if not out:
					print(brightred + "[!] Unknown command")

				else:
					pass

		except (EOFError, KeyboardInterrupt):
			print()

	def loop(self, cmd=None, to_console=True, op_id=None):
		#print("TEST IN GUNNERSHELL LOOP")
		set_output_context(to_console=to_console, to_op=op_id)
		logger.debug("GunnerShell.loop entry: cmd=%r, to_console=%r, op_id=%r", cmd, to_console, op_id)
		if not cmd:
			logger.debug("Entering interactive mode")
			while True:
				readline.clear_history()
				readline.set_completer(self.completer)
				readline.parse_and_bind("tab: complete")

				if not os.path.exists(self.SESSION_HIST):
						# create an empty history file
						open(self.SESSION_HIST, 'a').close()
		
				readline.read_history_file(self.SESSION_HIST)

				try:
					user = input(self.prompt).strip()
					logger.debug("Read user input: %r", user)

					if not user:
						logger.debug("Empty input, reprompting")
						continue

					else:
						out = self.interact(user, to_console=to_console, op_id=op_id)
						if out:
							return out

				finally:
					try:
						readline.write_history_file(self.SESSION_HIST)

					except Exception:
						pass

					readline.clear_history()

					# restore no-completer
					readline.set_completer(None)

		else:
			logger.debug("Dispatching to interact()")
			out = self.interact(cmd=cmd, to_console=to_console, op_id=op_id)
			logger.debug("interact() returned: %r", out)
			if out:
				logger.debug("Returning from loop with output")
				return out