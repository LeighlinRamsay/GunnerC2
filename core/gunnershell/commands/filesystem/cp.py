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

@register("cp")
class CpCommand(Command):
	"""Copy a file on the remote host: cp <src> <dst>"""

	@property
	def help(self):
		return "cp <src> <dst>    Copy a file remotely"

	def execute(self, args):
		if len(args) != 2:
			print(brightyellow + "Usage: cp <src> <dst>")
			return

		src, dst = args
		src = self.gs.make_abs(src)
		dst = self.gs.make_abs(dst)
		out = self.logic(self.gs.sid, self.gs.os_type, src, dst, op_id=self.op_id)
		if out:
			print(brightgreen + out)
		else:
			print(brightyellow + "[*] Copy completed!")

	def logic(self, sid, os_type, src, dst, op_id="console"):
		"""
		Copy a file on the remote host.
		* Windows: uses PowerShell Copy-Item
		* Linux:   uses cp -f
		"""
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		if "windows" in os_type:
			# -Force to overwrite
			cmd = f"Copy-Item -Path {psq(src)} -Destination {psq(dst)} -Force"

		elif "linux" in os_type:
			cmd = f"cp -f {shq(src)} {shq(dst)}"

		else:
			print(brightred + f"[!] Unsupported OS on {display}")
			return ""

		sess = session_manager.sessions.get(sid)
		if not sess:
			print(brightred + f"[!] No such session: {display}")
			return ""

		if sess.transport.lower() in ("http","https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)

		elif sess.transport.lower() in ("tls", "tcp"):
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id)

		else:
			print(brightred + f"[!] Unsupported shell type: {transport}")
			return None

		return out or None