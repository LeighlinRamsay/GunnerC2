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

@register("cat", "type")
class CatCommand(Command):
	"""Print the contents of a file: cat <path>"""

	@property
	def help(self):
		return "cat <path>    Print file contents"

	def execute(self, args):
		if len(args) != 1:
			print(brightyellow + "Usage: cat <path>")
			return
			
		path = args[0]
		path = self.gs.make_abs(path)
		out = self.logic(self.gs.sid, self.gs.os_type, path, op_id=self.op_id)
		if out:
			print(brightgreen + out)
		else:
			print(brightyellow + "[*] No output or file not found")

	def logic(self, sid, os_type, path, op_id="console"):
		"""
		Print the contents of a file on the remote host.

		- sid:      the real session ID
		- os_type:  session.metadata.get("os") lower‐cased ("windows" vs. "linux")
		- path:     path to the file to read

		Returns the raw output from the remote command, or None on error.
		"""
		# resolve display name for error messages
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		# build the correct command for the OS
		if "windows" in os_type:
			# PowerShell: get the file contents
			cmd = f"Get-Content -LiteralPath {psq(path)}"

		elif "linux" in os_type:
			cmd = f"cat {shq(path)}"

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
			out = tcp_exec.run_command_tcp(sid, cmd, timeout=0.5, portscan_active=True, op_id=op_id)

		else:
			print(brightred + f"[!] Unsupported shell type: {transport}")
			return None

		return out or None