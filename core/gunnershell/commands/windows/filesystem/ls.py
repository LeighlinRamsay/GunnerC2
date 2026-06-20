from core.gunnershell.commands.base import register, Command
from core.session_handlers import session_manager
from core.utils_shell_quoting import shq, psq
from colorama import Style, Fore

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"

# Command Execution Imports
from core.command_execution import http_command_execution as http_exec
from core.command_execution import tcp_command_execution as tcp_exec

@register("ls", "dir")
class LsCommand(Command):
	"""List files on the remote host: ls [<path>]"""

	@property
	def help(self):
		return "ls [<path>]    List files in <path> (default = cwd)"

	def execute(self, args):
		path = args[0] if args else self.gs.cwd
		path = self.gs.make_abs(path)
		out = self.logic(self.gs.sid, self.gs.os_type, path, op_id=self.op_id)
		if out:
			print(brightgreen + "\n" + out)
		else:
			print(brightyellow + "[*] No output")

	def logic(self, sid, os_type, path, op_id="console"):
		"""
		List files on the remote host.
	
		- sid:       the real session ID
		- os_type:   session.metadata.get("os") lower-cased ("windows" vs. "linux")
		- path:      directory or file to list
	
		Returns the raw output from the remote command.
		"""
		# build the correct command for the OS
		display = next((a for a, rsid in session_manager.alias_map.items() if rsid == sid), sid)

		if "windows" in os_type:
			# /B gives bare format, /A shows all files (including hidden)
			cmd = f"Get-ChildItem {psq(path)}"

		elif "linux" in os_type:
			cmd = f"ls -la {shq(path)}"

		else:
			print(brightred + f"[!] Unsupported operating system on {display}")

		# pick the right transport
		sess = session_manager.sessions[sid]
		if sess.transport.lower() in ("http", "https"):
			out = http_exec.run_command_http(sid, cmd, op_id=op_id)
			return out

		elif sess.transport.lower() in ("tcp", "tls"):
			out =  tcp_exec.run_command_tcp(sid, cmd, timeout=1, portscan_active=True, op_id=op_id)
			return out

		else:
			try:
				print(brightred + f"[!] Unsupported shell type: {sess.transport.lower()}")

			except Exception as e:
				print(brightred + f"[!] An unknown error has ocurred: {e}")