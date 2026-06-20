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

@register("checksum")
class ChecksumCommand(Command):
	"""Compute a SHA256 checksum of a file: checksum <path>"""

	@property
	def help(self):
		return "checksum <path>    Compute SHA256 of a file"

	def execute(self, args):
		if len(args) != 1:
			print(brightyellow + "Usage: checksum <path>")
			return

		path = args[0]
		path = self.gs.make_abs(path)
		out = self.logic(self.gs.sid, self.gs.os_type, path, op_id=self.op_id)
		if out:
			print(brightgreen + out)
		else:
			print(brightyellow + "[*] No output")

	def logic(self, sid, os_type, path, op_id="console"):
		"""
		Compute a SHA256 checksum of a file on the remote host.
		- Windows: Get-FileHash -Algorithm SHA256
		- Linux:   sha256sum
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		if "windows" in os_type:
			cmd = f"(Get-FileHash -Algorithm SHA256 -Path {psq(path)}).Hash"

		elif "linux" in os_type:
			cmd = f"sha256sum {shq(path)}"

		else:
			print(brightred + f"[!] Unsupported OS on {display}")
			return None

		sess = session_manager.sessions.get(sid)
		if not sess:
			print(brightred + f"[!] No such session: {display}")
			return None

		transport = sess.transport.lower()
		if transport in ("http", "https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)

		elif transport in ("tcp", "tls"):
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id)

		else:
			print(brightred + f"[!] Unsupported shell type: {transport}")
			return None

		return out or None