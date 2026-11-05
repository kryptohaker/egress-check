#!/usr/bin/env bash
set -uo pipefail
DNS=1.1.1.1; DOMAIN=duckduckgo.com; HOST=104.18.74.230; URL=https://1.1.1.1; TIMEOUT=5; DATA=''; OUTPUT=''; SHOW_HEX=0; VERBOSE=0; ALL=0; DO_DNS=0; DO_ICMP=0; DO_TCP=0; DO_HTTPS=0; PORTS=80,443; OAST=''; OAST_ID=''
usage(){ cat <<'HELP'
Usage: ./egress-check.sh [OPTIONS]
  --all                 Run DNS, ICMP, TCP 80/443, HTTPS (default)
  --oast HOSTNAME       Run DNS and HTTPS callbacks to an authorized OAST hostname
  --dns [IP]            DNS test, optional resolver (default 1.1.1.1)
  --domain DOMAIN       DNS query domain (default duckduckgo.com)
  --data TEXT           Synthetic DNS test marker, max 24 ASCII bytes
  --show-hex            Display raw DNS packet hex
  --verbose             Show timings, response codes and connection errors
  --icmp                Test ICMP echo
  --tcp PORTS           Test comma-separated TCP ports (e.g. 80,443)
  --https               Test HTTPS request
  --host IP             ICMP/TCP target (default 104.18.74.230)
  --url HTTPS_URL       HTTPS target (default https://1.1.1.1)
  --timeout SECONDS     Per-test timeout (default 5)
  --output FILE.json    Write JSON results (requires python3)
  -h, --help            Show help
Examples:
  ./egress-check.sh --all
  ./egress-check.sh --oast YOUR-ID.oastify.com --verbose
  ./egress-check.sh --dns 1.1.1.1 --domain YOUR-ID.oastify.com --data test-data
  ./egress-check.sh --icmp --tcp 80,443 --host 1.1.1.1
HELP
}
while (($#)); do
 case "$1" in
  --all) ALL=1; shift;;
  --dns) DO_DNS=1; if (($#>1)) && [[ "$2" != --* ]]; then DNS=$2; shift 2; else shift; fi;;
  --domain|--data|--host|--url|--timeout|--output|--tcp|--oast)
   if (($#<2)); then echo "Missing value for $1" >&2; exit 2; fi
   case "$1" in --domain) DOMAIN=$2;; --data) DATA=$2;; --host) HOST=$2;; --url) URL=$2;; --timeout) TIMEOUT=$2;; --output) OUTPUT=$2;; --tcp) DO_TCP=1; PORTS=$2;; --oast) OAST=$2;; esac; shift 2;;
  --icmp) DO_ICMP=1; shift;;
  --https) DO_HTTPS=1; shift;;
  --show-hex) SHOW_HEX=1; shift;;
  --verbose|-v) VERBOSE=1; shift;;
  -h|--help) usage; exit 0;;
  *) echo "Unknown option: $1" >&2; usage; exit 2;;
 esac
done
if [[ -n "$OAST" ]]; then
 [[ "$OAST" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ && "$OAST" == *.* && ${#OAST} -le 180 ]] || { echo "Invalid OAST hostname" >&2; exit 2; }
 [[ "$OAST" != *..* ]] || { echo "Invalid OAST hostname" >&2; exit 2; }
 for label in ${OAST//./ }; do (( ${#label} <= 63 )) || { echo "Invalid OAST label" >&2; exit 2; }; done
 OAST_ID=$(python3 -c "import secrets; print(secrets.token_hex(5))")
 DOMAIN="dns-${OAST_ID}.${OAST}"
 URL="https://https-${OAST_ID}.${OAST}/"
 DO_DNS=1; DO_HTTPS=1
 echo "[OAST] Unique test ID: $OAST_ID"
 echo "[OAST] DNS query: $DOMAIN"
 echo "[OAST] HTTPS URL: $URL"
 echo "[OAST] Verify receipt in your OAST service; local PASS alone is not callback confirmation."
fi
if ((ALL)) || ((DO_DNS+DO_ICMP+DO_TCP+DO_HTTPS==0)); then DO_DNS=1; DO_ICMP=1; DO_TCP=1; DO_HTTPS=1; fi
[[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || { echo 'Timeout must be a positive integer' >&2; exit 2; }
[[ "$DNS" =~ ^[0-9.]+$ && "$HOST" =~ ^[0-9.]+$ ]] || { echo 'DNS and host must be IPv4 addresses' >&2; exit 2; }
[[ "$URL" == https://* ]] || { echo 'URL must start with https://' >&2; exit 2; }
[[ "$PORTS" =~ ^[0-9]+(,[0-9]+)*$ ]] || { echo 'Invalid ports' >&2; exit 2; }
IFS=, read -ra PORT_ARRAY <<< "$PORTS"
for port in "${PORT_ARRAY[@]}"; do ((10#$port >= 1 && 10#$port <= 65535)) || { echo "Invalid port: $port" >&2; exit 2; }; done
if [[ -n "$DATA" ]]; then
 [[ "$DATA" =~ ^[a-zA-Z0-9_-]{1,24}$ ]] || { echo 'Marker must be 1-24 ASCII letters, numbers, _ or -' >&2; exit 2; }
fi
if ((DO_DNS)) || [[ -n "$OUTPUT" ]] || [[ -n "$OAST" ]]; then command -v python3 >/dev/null || { echo 'python3 required for DNS and JSON output' >&2; exit 2; }; fi
RESULTS=$(mktemp); trap 'rm -f "$RESULTS"' EXIT
record(){ local kind=$1 dest=$2 status=$3 detail=$4; printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$kind" "$dest" "$status" "$detail" >> "$RESULTS"; printf '[%s] %-7s %-26s %s\n' "$status" "$kind" "$dest" "$detail"; }
if ((DO_DNS)); then
 DNS_RESULT=$(DNS="$DNS" DOMAIN="$DOMAIN" DATA="$DATA" TIMEOUT="$TIMEOUT" SHOW_HEX="$SHOW_HEX" VERBOSE="$VERBOSE" python3 - <<'PY'
import os,socket,struct,secrets,ipaddress,time
try:
 server=str(ipaddress.IPv4Address(os.environ['DNS']))
 domain=os.environ['DOMAIN'].rstrip('.').lower()
 marker=os.environ['DATA']
 if marker: domain=marker.encode('ascii').hex()+'.'+domain
 labels=domain.encode('ascii').split(b'.')
 if not labels or any(not x or len(x)>63 for x in labels): raise ValueError('Invalid DNS label')
 qname=b''.join(bytes([len(x)])+x for x in labels)+b'\x00'
 if len(qname)>255: raise ValueError('DNS name too long')
 tid=secrets.randbelow(65536)
 packet=struct.pack('!HHHHHH',tid,0x0100,1,0,0,0)+qname+struct.pack('!HH',1,1)
 if os.environ['SHOW_HEX']=='1': print('PACKET_HEX='+packet.hex())
 start=time.monotonic()
 with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
  s.settimeout(int(os.environ['TIMEOUT']))
  s.sendto(packet,(server,53))
  while True:
   response,addr=s.recvfrom(4096)
   if addr[0]==server and len(response)>=12 and struct.unpack('!H',response[:2])[0]==tid: break
 flags=struct.unpack('!H',response[2:4])[0]
 if not flags & 0x8000: raise ValueError('Not a DNS response')
 rcode=flags&15
 elapsed=(time.monotonic()-start)*1000
 if os.environ['VERBOSE']=='1': print('DEBUG=DNS rcode='+str(rcode)+'; response_bytes='+str(len(response))+'; elapsed_ms='+format(elapsed,'.1f'))
 print('RESULT=PASS|query='+domain+'; rcode='+str(rcode)+'; bytes='+str(len(response)))
except Exception as e:
 print('RESULT=FAIL|'+str(e).replace('|','/'))
PY
 )
 if ((VERBOSE)); then printf '%s\n' "$DNS_RESULT" | grep '^DEBUG=' | sed 's/^DEBUG=/  [verbose] /' || true; fi
 if [[ "$DNS_RESULT" == *PACKET_HEX=* ]]; then printf '%s\n' "$DNS_RESULT" | grep '^PACKET_HEX='; fi
 DNS_LINE=$(printf '%s\n' "$DNS_RESULT" | grep '^RESULT=' | tail -1)
 DNS_LINE=${DNS_LINE#RESULT=}; record DNS "$DNS:53" "${DNS_LINE%%|*}" "${DNS_LINE#*|}"
fi
if ((DO_ICMP)); then
 if command -v ping >/dev/null; then
  ICMP_OUTPUT=$(ping -n -c 1 -W "$TIMEOUT" "$HOST" 2>&1); RC=$?
  if ((RC==0)); then record ICMP "$HOST" PASS 'Echo reply received'; else record ICMP "$HOST" FAIL 'No echo reply (may be filtered)'; fi
  if ((VERBOSE)); then
   printf '%s\n' "$ICMP_OUTPUT" | grep -E 'time=|round-trip|rtt |100% packet loss|Name or service|unreachable|Operation not permitted' | sed 's/^/  [verbose] /' || true
   echo "  [verbose] ping exit code: $RC"
  fi
 else record ICMP "$HOST" SKIP 'ping unavailable'; fi
fi
if ((DO_TCP)); then
 for port in "${PORT_ARRAY[@]}"; do
  if command -v timeout >/dev/null; then
   TCP_START=$(date +%s%N)
   TCP_ERROR=$(timeout "$TIMEOUT" bash -c 'echo > /dev/tcp/"$1"/"$2"' _ "$HOST" "$port" 2>&1); RC=$?
   TCP_END=$(date +%s%N)
   if ((RC==0)); then record TCP "$HOST:$port" PASS 'TCP connection established'; else record TCP "$HOST:$port" FAIL 'TCP connection failed or timed out'; fi
   if ((VERBOSE)); then
    echo "  [verbose] elapsed_ms=$(( (TCP_END-TCP_START)/1000000 )); exit_code=$RC"
    [[ -z "$TCP_ERROR" ]] || printf '  [verbose] %s\n' "$TCP_ERROR"
   fi
  else record TCP "$HOST:$port" SKIP 'timeout utility unavailable'; fi
 done
fi
if ((DO_HTTPS)); then
 if command -v curl >/dev/null; then
  CURL_ERROR=$(mktemp)
  HTTP_INFO=$(curl -k -sS -L --max-redirs 2 --connect-timeout "$TIMEOUT" --max-time "$TIMEOUT" -o /dev/null -w '%{http_code}|%{time_total}|%{time_connect}|%{time_appconnect}' "$URL" 2>"$CURL_ERROR"); RC=$?
  IFS='|' read -r HTTP_CODE TOTAL CONNECT TLS <<< "$HTTP_INFO"
  if ((RC==0)); then record HTTPS "$URL" PASS "HTTP status $HTTP_CODE (TLS verification disabled)"; else record HTTPS "$URL" FAIL "curl exit code $RC; HTTP status ${HTTP_CODE:-000}"; fi
  if ((VERBOSE)); then
   echo "  [verbose] curl_exit=$RC; total_s=${TOTAL:-N/A}; connect_s=${CONNECT:-N/A}; tls_s=${TLS:-N/A}"
   if [[ -s "$CURL_ERROR" ]]; then sed 's/^/  [verbose] /' "$CURL_ERROR"; fi
  fi
  rm -f "$CURL_ERROR"
 elif command -v wget >/dev/null; then
  WGET_ERROR=$(mktemp)
  if wget -q --no-check-certificate --timeout="$TIMEOUT" -O /dev/null "$URL" 2>"$WGET_ERROR"; then record HTTPS "$URL" PASS 'HTTPS request completed (TLS verification disabled)'; else record HTTPS "$URL" FAIL 'HTTPS request failed'; fi
  if ((VERBOSE)) && [[ -s "$WGET_ERROR" ]]; then sed 's/^/  [verbose] /' "$WGET_ERROR"; fi
  rm -f "$WGET_ERROR"
 else record HTTPS "$URL" SKIP 'Neither curl nor wget available'; fi
fi
if [[ -n "$OUTPUT" ]]; then
 RESULTS="$RESULTS" OUTPUT="$OUTPUT" python3 - <<'PY'
import json,os
records=[]
with open(os.environ['RESULTS']) as f:
 for line in f:
  timestamp,kind,destination,status,detail=line.rstrip('\n').split('\t',4)
  records.append(dict(timestamp=timestamp,check=kind,destination=destination,status=status,detail=detail))
with open(os.environ['OUTPUT'],'w') as f: json.dump({'results':records},f,indent=2)
PY
 echo "JSON report: $OUTPUT"
fi
if [[ -n "$OAST" ]]; then echo "[OAST] Check your OAST dashboard for DNS and HTTPS interactions containing ID: $OAST_ID"; fi
echo 'Interpretation: PASS = connectivity check succeeded; FAIL = failed or timed out; SKIP = unavailable.'
echo 'A PASS does not establish unrestricted egress or successful data exfiltration.'
if grep -q $'\tFAIL\t' "$RESULTS"; then exit 1; fi
