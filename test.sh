#!/bin/bash
# Proves DataSecure v0.1 works on this Mac without touching the installed copy.
# Starts a throwaway server on a spare port with its own data folder, then checks every feature.
set -uo pipefail
cd "$(dirname "$0")"

PORT=7799
TMP="$(mktemp -d)"
export DATASECURE_HOME="$TMP" DATASECURE_PORT="$PORT"
URL="http://127.0.0.1:$PORT"
fails=0
pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1"; fails=$((fails + 1)); }
check() { if eval "$2"; then pass "$1"; else fail "$1"; fi; }

# Reuse the installed lookup table if there is one, so the test doesn't download 9 MB.
[ -f "$HOME/.datasecure/ip2asn-combined.tsv" ] && ln -s "$HOME/.datasecure/ip2asn-combined.tsv" "$TMP/"

/usr/bin/ruby datasecure.rb >"$TMP/server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null; rm -rf "$TMP"' EXIT
for _ in $(seq 1 20); do curl -fs -o /dev/null "$URL/" && break; sleep 0.3; done

post() { curl -s -H "Origin: $URL" -H 'Content-Type: application/json' -d "$2" "$URL$1"; }

check "page loads" '[ "$(curl -s -o /dev/null -w "%{http_code}" "$URL/")" = 200 ]'
check "tutorial pictures load" '[ "$(curl -s -o /dev/null -w "%{http_code} %{content_type}" "$URL/docs/shield-1-settings.svg")" = "200 image/svg+xml" ]'
check "no files outside docs/ can be read" '[ "$(curl -s -o /dev/null -w "%{http_code}" --path-as-is "$URL/docs/../datasecure.rb")" = 404 ]'
check "every check answers ok, bad or unknown" \
  'curl -s "$URL/api/checks" | /usr/bin/ruby -rjson -e "c = JSON.parse(STDIN.read); exit(c.size == 7 && c.all? { |x| %w[ok bad unknown].include?(x[%q(status)]) } ? 0 : 1)"'
check "a foreign website is blocked (DNS rebinding)" \
  '[ "$(curl -s -o /dev/null -w "%{http_code}" -H "Host: evil.example:$PORT" "$URL/api/checks")" = 403 ]'
check "buttons can't be pressed from another site" \
  '[ "$(curl -s -o /dev/null -w "%{http_code}" -H "Origin: http://evil.example" -H "Content-Type: application/json" -d "{}" "$URL/api/test-notification")" = 403 ]'
check "only a 5-character prefix is accepted" \
  '[ "$(curl -s -o /dev/null -w "%{http_code}" -H "Origin: $URL" -H "Content-Type: application/json" -d "{\"prefix\":\"password\"}" "$URL/api/password-range")" = 400 ]'
# SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
check "leaked password is found" 'post /api/password-range "{\"prefix\":\"5BAA6\"}" | grep -q "1E4C9B93F3F0682250B6CF8331B7EE68FD8"'
check "watched websites are saved and past hacks found" \
  'post /api/services "{\"domains\":[\"https://www.LinkedIn.com/\"]}" | /usr/bin/ruby -rjson -e "r = JSON.parse(STDIN.read); exit(r[%q(domains)] == [%q(linkedin.com)] && r[%q(breaches)].any? ? 0 : 1)"'
check "daily check runs (dry run, no notification)" '/usr/bin/ruby datasecure.rb --daily --dry-run | grep -q "known breaches"'
check "shield profile is a valid Mac profile" '/usr/bin/ruby datasecure.rb --profile "$TMP/s.mobileconfig" && plutil -lint -s "$TMP/s.mobileconfig"'
# macOS refuses a user-scoped DNS profile: "profile must be scoped to system" (shown as "VPN service could not be created")
check "shield profile applies to the whole Mac" '[ "$(plutil -extract PayloadScope raw "$TMP/s.mobileconfig" 2>/dev/null)" = System ]'
if [ -f "$TMP/ip2asn-combined.tsv" ]; then
  check "8.8.8.8 belongs to Google in the US" '/usr/bin/ruby datasecure.rb --lookup 8.8.8.8 | grep -q "\"country\":\"US\",\"org\":\"GOOGLE\""'
  check "IPv6 lookup works" '/usr/bin/ruby datasecure.rb --lookup 2a00:1450:4001:80b::200e | grep -q GOOGLE'
  check "home network addresses are not looked up" '[ "$(/usr/bin/ruby datasecure.rb --lookup 192.168.1.1)" = null ]'
else
  printf '  skip  company lookup (run install.sh first to download the table)\n'
fi
check "live connections list answers" 'curl -s "$URL/api/connections" | grep -q "\"rows\""'

echo
if [ "$fails" = 0 ]; then echo "  DataSecure v0.1: all checks passed."; else echo "  $fails check(s) failed. Server log: $TMP/server.log"; cat "$TMP/server.log"; exit 1; fi
