#!/usr/bin/env bash
# Re-make the README recording (docs/assets/mcpprobe-demo.{cast,gif,png}).
#
#   pip install -e . asciinema     # plus agg: https://github.com/asciinema/agg
#   docs/assets/record-demo.sh            # records and renders
#   docs/assets/record-demo.sh --play     # internal: the session being recorded
#
# The commands are typed with a short per-character delay so viewers can read them;
# they then run unmodified and their output is recorded as is. asciinema's
# --idle-time-limit only shortens pauses. Nothing else is edited.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ASSETS="$ROOT/docs/assets"

if [[ "${1:-}" == "--play" ]]; then
  cd "$ROOT"
  export FORCE_COLOR=1 COLUMNS=120
  type_run() {
    printf '\033[1;32m$\033[0m '
    local s="$1" i
    for ((i = 0; i < ${#s}; i++)); do printf '%s' "${s:i:1}"; sleep 0.035; done
    sleep 0.4
    printf '\n'
    eval "$1"
  }
  type_run "python -m tests.fake_server --preset vulnerable --port 8765 &"
  sleep 1.2
  type_run "mcpprobe http://127.0.0.1:8765/mcp | head -n 43"
  sleep 4
  kill %1 2>/dev/null || true
  exit 0
fi

# asciinema needs a terminal; `script` provides one in CI or a non-interactive shell.
script -qec "stty cols 120 rows 50; asciinema rec --overwrite -q --cols 120 --rows 50 -i 2 \
  -c '$ASSETS/record-demo.sh --play' '$ASSETS/mcpprobe-demo.cast'" /dev/null >/dev/null
agg --font-size 14 --idle-time-limit 2 --last-frame-duration 6 --theme dracula \
  "$ASSETS/mcpprobe-demo.cast" "$ASSETS/mcpprobe-demo.gif"
# Still image: the last frame of the GIF.
ffmpeg -loglevel error -y -i "$ASSETS/mcpprobe-demo.gif" -vf reverse -frames:v 1 -update 1 \
  "$ASSETS/mcpprobe-demo.png"
