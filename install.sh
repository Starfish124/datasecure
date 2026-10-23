#!/bin/bash
# DataSecure v0.1 by Sarvesh Singh. MIT License.
# Install:   curl -fsSL https://raw.githubusercontent.com/Starfish124/datasecure/v0.1.0/install.sh | bash
# Remove:    curl -fsSL https://raw.githubusercontent.com/Starfish124/datasecure/v0.1.0/install.sh | bash -s -- --uninstall
set -euo pipefail

VERSION="v0.1.0"
RAW="https://raw.githubusercontent.com/Starfish124/datasecure/$VERSION"
DEST="$HOME/.datasecure"
AGENTS="$HOME/Library/LaunchAgents"
PORT=7777
GUI="gui/$(id -u)"

say() { printf '\n  %s\n' "$1"; }

stop_agents() {
  for job in server daily; do
    launchctl bootout "$GUI/com.datasecure.$job" 2>/dev/null || true
  done
}

if [ "${1:-}" = "--uninstall" ]; then
  stop_agents
  rm -f "$AGENTS/com.datasecure.server.plist" "$AGENTS/com.datasecure.daily.plist"
  rm -rf "$DEST"
  say "DataSecure is removed."
  say "Last step: remove the Private Shield in System Settings > General > Device Management (opening it now)."
  open "x-apple.systempreferences:com.apple.Profiles-Settings.extension" 2>/dev/null || true
  exit 0
fi

[ "$(uname)" = "Darwin" ] || { say "DataSecure only works on a Mac."; exit 1; }
[ -x /usr/bin/ruby ] || { say "This Mac has no built-in Ruby, which DataSecure needs. Please tell Sarvesh."; exit 1; }

say "Installing DataSecure…"
mkdir -p "$DEST" "$AGENTS"

# Run from a downloaded copy of the repo? Use those files. Otherwise fetch the pinned release.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" 2>/dev/null && pwd || echo .)"
for f in datasecure.rb index.html install.sh; do
  if [ -f "$HERE/$f" ] && [ "$HERE" != "$DEST" ]; then
    cp "$HERE/$f" "$DEST/$f"
  else
    curl -fsSL "$RAW/$f" -o "$DEST/$f"
  fi
done

stop_agents

cat > "$AGENTS/com.datasecure.server.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.datasecure.server</string>
  <key>ProgramArguments</key><array><string>/usr/bin/ruby</string><string>$DEST/datasecure.rb</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>$DEST/server.log</string>
</dict></plist>
EOF

# Separate job: launchd won't start a calendar run of a job that is already running.
cat > "$AGENTS/com.datasecure.daily.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.datasecure.daily</string>
  <key>ProgramArguments</key><array><string>/usr/bin/ruby</string><string>$DEST/datasecure.rb</string><string>--daily</string></array>
  <key>StartCalendarInterval</key><dict><key>Hour</key><integer>10</integer><key>Minute</key><integer>0</integer></dict>
  <key>RunAtLoad</key><true/>
  <key>StandardErrorPath</key><string>$DEST/daily.log</string>
</dict></plist>
EOF

launchctl bootstrap "$GUI" "$AGENTS/com.datasecure.server.plist"
launchctl bootstrap "$GUI" "$AGENTS/com.datasecure.daily.plist" # first run also downloads the company lookup table

for _ in $(seq 1 20); do
  curl -fs -o /dev/null "http://127.0.0.1:$PORT/" && break
  sleep 0.5
done

if curl -fs -o /dev/null "http://127.0.0.1:$PORT/"; then
  open "http://127.0.0.1:$PORT/"
  say "Done. DataSecure is open in your browser."
  say "Bookmark the page (Command + D) to come back: http://127.0.0.1:$PORT"
else
  say "DataSecure installed, but the page did not start. Send Sarvesh this file: $DEST/server.log"
  exit 1
fi
