#!/usr/bin/env bash
#
# Unattended installer for the Claude Code safeguards (macOS / Linux).
#
# Safe to run over SSH or from an RMM/MDM job: it never prompts, never opens a
# pager or an editor, and reports what it did on stdout with a distinct exit
# code on failure.
#
#   ./install.sh                     # user install -> ~/.claude
#   ./install.sh --dry-run           # print what would change, write nothing
#   ./install.sh --ref v1.2.0        # install a specific branch or tag
#   ./install.sh --project /srv/app  # project install -> <dir>/.claude
#   ./install.sh --uninstall
#
# If install.cjs sits next to this script (you cloned the repo), that copy is
# used. Otherwise the repo is cloned into a temporary directory and removed
# again afterwards.
#
# Run it as the developer who uses Claude Code, not as root or a service
# account: a user install writes to that user's own $HOME/.claude.
#
# Exit codes: 0 ok | 2 bad usage | 3 missing prerequisite | 4 download failed
#             5 installer failed

set -euo pipefail

REPO_URL="https://github.com/thecrmfirm/claude_safeguards.git"
REF=""
PROJECT_DIR=""
MODE_PROJECT=0
PASS_THROUGH=()
KEEP_CLONE=0
DRY=0
TMP_CLONE=""

log()  { printf '%s [safeguards] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
fail() { printf '%s [safeguards] ERROR: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$2" >&2; exit "$1"; }

usage() {
  sed -n '3,23p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

cleanup() {
  if [ -n "$TMP_CLONE" ] && [ -d "$TMP_CLONE" ] && [ "$KEEP_CLONE" -eq 0 ]; then
    rm -rf "$TMP_CLONE"
  fi
}
trap cleanup EXIT

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)      [ $# -ge 2 ] || fail 2 "--repo needs a URL"; REPO_URL="$2"; shift 2 ;;
    --ref)       [ $# -ge 2 ] || fail 2 "--ref needs a branch or tag"; REF="$2"; shift 2 ;;
    --project)   MODE_PROJECT=1
                 # Optional directory argument; bare --project means $PWD.
                 if [ $# -ge 2 ] && [ "${2#-}" = "$2" ]; then PROJECT_DIR="$2"; shift 2; else shift; fi ;;
    --dry-run)   DRY=1; PASS_THROUGH+=("--dry-run"); shift ;;
    --uninstall) PASS_THROUGH+=("--uninstall"); shift ;;
    --keep)      KEEP_CLONE=1; shift ;;
    -h|--help)   usage 0 ;;
    *)           fail 2 "unknown option: $1 (try --help)" ;;
  esac
done

# --- prerequisites -----------------------------------------------------------

command -v node >/dev/null 2>&1 || fail 3 "node not found on PATH. Install Node 18+ and re-run."

NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
[ "$NODE_MAJOR" -ge 18 ] 2>/dev/null \
  || fail 3 "Node 18+ required, found $(node --version 2>/dev/null || echo 'none')."

# --- locate the sources ------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -f "$SCRIPT_DIR/install.cjs" ]; then
  SRC="$SCRIPT_DIR"
  log "Using local sources at $SRC"
else
  command -v git >/dev/null 2>&1 || fail 3 "git not found on PATH, and no local copy next to this script."
  TMP_CLONE="$(mktemp -d "${TMPDIR:-/tmp}/claude_safeguards.XXXXXX")"
  SRC="$TMP_CLONE/repo"
  log "Cloning $REPO_URL${REF:+ (ref $REF)}"
  # GIT_TERMINAL_PROMPT=0 makes a credential prompt fail instead of hanging a
  # job that has no terminal attached.
  GIT_TERMINAL_PROMPT=0 git clone --quiet --depth 1 ${REF:+--branch "$REF"} "$REPO_URL" "$SRC" \
    || fail 4 "clone failed. Check the URL, the ref, and this machine's git credentials."
fi

[ -f "$SRC/install.cjs" ] || fail 4 "install.cjs not found in $SRC"

# --- run the installer -------------------------------------------------------

if [ "$MODE_PROJECT" -eq 1 ]; then
  TARGET="${PROJECT_DIR:-${CLAUDE_PROJECT_DIR:-$PWD}}"
  [ -d "$TARGET" ] || fail 2 "project directory does not exist: $TARGET"
  TARGET="$(cd "$TARGET" && pwd)"
  # A project install references $CLAUDE_PROJECT_DIR/hooks, so the hooks have to
  # be in the project before the installer wires them up.
  if [ "$SRC" != "$TARGET" ]; then
    if [ "$DRY" -eq 1 ]; then
      log "DRY RUN - would copy hooks -> $TARGET/hooks"
    else
      log "Copying hooks -> $TARGET/hooks"
      mkdir -p "$TARGET/hooks"
      cp -R "$SRC/hooks/." "$TARGET/hooks/"
    fi
  fi
  log "Running project install in $TARGET"
  ( cd "$TARGET" && CLAUDE_PROJECT_DIR="$TARGET" node "$SRC/install.cjs" --project ${PASS_THROUGH[@]+"${PASS_THROUGH[@]}"} ) \
    || fail 5 "installer failed (see output above)."
else
  log "Running user install for $(id -un) (home: $HOME)"
  node "$SRC/install.cjs" ${PASS_THROUGH[@]+"${PASS_THROUGH[@]}"} || fail 5 "installer failed (see output above)."
fi

log "Finished. Restart Claude Code, or type /hooks in an open session and press Esc."
