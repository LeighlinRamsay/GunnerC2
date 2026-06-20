from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager
from core.utils_shell_quoting import shq, psq

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

from colorama import Style, Fore
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"

@register("mkdir", "md")
class MkdirCommand(Command):
	"""Create a directory on the remote host: mkdir <path>"""

	@property
	def help(self):
		return "mkdir <path>    Create a directory remotely"

	def execute(self, args):
		if len(args) != 1:
			print(brightyellow + "Usage: mkdir <path>")
			return

		path = args[0]
		path = self.gs.make_abs(path)
		out = self.logic(self.gs.sid, self.gs.os_type, path, op_id=self.op_id)
		if out:
			print(brightgreen + out)
		else:
			print(brightgreen + f"Created directory: {path}")

	def logic(self, sid, os_type, path, op_id="console"):
		"""
		Create a directory on the remote host.

		- sid:      the real session ID
		- os_type:  session.metadata.get("os") lower-cased
		- path:     directory to create

		Returns raw output or None on error.
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		if "windows" in os_type:
			# PowerShell: make folder
			cmd = f"New-Item -ItemType Directory -Force -Path {psq(path)}"

		elif "linux" in os_type:
			cmd = f"mkdir -p {shq(path)}"

		else:
			print(brightred + f"[!] Unsupported OS on {display}")
			return None

		sess = session_manager.sessions.get(sid)
		if not sess:
			print(brightred + f"[!] No such session: {display}")
			return None

		if sess.transport.lower() in ("http", "https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)

		else:
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id)

		return out or None