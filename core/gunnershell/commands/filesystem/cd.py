from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager
from core.utils_shell_quoting import shq, psq

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec


@register("cd")
class CdCommand(Command):
	"""Change the remote working directory: cd <path>"""

	@property
	def help(self):
		return "cd <path>    Change the remote working directory"

	def execute(self, args):
		if len(args) != 1:
			print(brightyellow + "Usage: cd <path>")
			return
			
		path = args[0]
		path = self.gs.make_abs(path)
		new_cwd = self.logic(self.gs.sid, self.gs.os_type, path, op_id=self.op_id)
		if new_cwd:
			self.gs.cwd = new_cwd
			print(brightgreen + new_cwd)
		else:
			print(brightred + f"[!] Failed to cd to '{path}'")

	def logic(self, sid, os_type, path, op_id="console"):
		"""
		Change the remote working directory and return the new cwd.

		- sid:      the real session ID
		- os_type:  session.metadata.get("os") lower‐cased ("windows" vs. "linux")
		- path:     directory to cd into

		Returns the new cwd on success, or None on failure.
		"""
		# resolve display name for error messages
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		# build the correct command for the OS
		if "windows" in os_type:
			# /d allows changing drive and directory, then print %CD%
			cmd = f"Set-Location -LiteralPath {psq(path)}; (Get-Location).Path"

		elif "linux" in os_type:
			cmd = f"cd {shq(path)} && pwd"

		else:
			print(brightred + f"[!] Unsupported operating system on {display}")
			return None

		# look up session
		sess = session_manager.sessions.get(sid)
		if not sess:
			print(brightred + f"[!] No such session: {display}")
			return None

		# send it via HTTP(S) or TCP/TLS
		transport = sess.transport.lower()
		if transport in ("http", "https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)

		elif transport in ("tcp", "tls"):
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, defender_bypass=True, portscan_active=True, op_id=op_id)

		else:
			print(brightred + f"[!] Unsupported shell type: {transport}")
			return None

		# return the new cwd if we got one
		if out:
			#out = out.rstrip("\\/")
			return out

		else:
			return None