#!/usr/bin/env node
/*
 * Installer for the Claude Code safeguards.
 *
 *   node install.cjs            # user/team install -> ~/.claude
 *   node install.cjs --project  # project install   -> ./.claude (uses $CLAUDE_PROJECT_DIR)
 *   node install.cjs --dry-run  # print what would change, write nothing
 *   node install.cjs --uninstall
 *
 * It copies the hooks into place (user install only) and idempotently merges
 * the three hook entries into the target settings.json, backing it up first.
 * Pure Node, no dependencies.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const SRC = __dirname;
const args = process.argv.slice(2);
const has = (f) => args.includes(f);
const DRY = has('--dry-run');
const PROJECT = has('--project');
const UNINSTALL = has('--uninstall');

const HOOK_MARKER = 'guard.cjs'; // identifies our hook entries for idempotency

function log(...m) {
  console.log('[install]', ...m);
}

// Read the existing settings. A missing file is fine (start empty); a file
// that exists but can't be parsed is NOT: treating it as empty would replace
// the user's whole configuration with just our hooks. Stop instead.
function readSettings(file) {
  if (!fs.existsSync(file)) return {};
  const text = fs.readFileSync(file, 'utf8');
  if (!text.trim()) return {};
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
  } catch {
    /* fall through */
  }
  console.error(
    `[install] ${file} is not valid JSON, so it was left untouched. ` +
      `Fix or move it, then run the installer again.`
  );
  process.exit(1);
}

// settings.json.bak-20261012-101530: one backup per run, never overwritten,
// so a second run can't replace the copy of the original settings.
function backupName(file) {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  const stamp =
    `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-` +
    `${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
  let name = `${file}.bak-${stamp}`;
  for (let i = 2; fs.existsSync(name); i++) name = `${file}.bak-${stamp}-${i}`;
  return name;
}

function copyDir(from, to) {
  fs.mkdirSync(to, { recursive: true });
  for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
    const s = path.join(from, entry.name);
    const d = path.join(to, entry.name);
    if (entry.isDirectory()) copyDir(s, d);
    else fs.copyFileSync(s, d);
  }
}

// Build the command string the hook will run.
function guardCommand(projectMode, installedHooksDir) {
  if (projectMode) return 'node "$CLAUDE_PROJECT_DIR/hooks/guard.cjs"';
  return `node "${path.join(installedHooksDir, 'guard.cjs')}"`;
}

function makeEntry(matcher, command) {
  const entry = { hooks: [{ type: 'command', command }] };
  if (matcher) entry.matcher = matcher;
  return entry;
}

// Remove any existing safeguard entries (identified by HOOK_MARKER) from an
// event's array, so re-installing never stacks duplicates.
function stripOurs(arr) {
  if (!Array.isArray(arr)) return [];
  return arr.filter(
    (e) =>
      !(
        e &&
        Array.isArray(e.hooks) &&
        e.hooks.some(
          (h) => h && typeof h.command === 'string' && h.command.includes(HOOK_MARKER)
        )
      )
  );
}

function main() {
  const home = os.homedir();
  // A project install targets $CLAUDE_PROJECT_DIR when set (as the README
  // says), else the current directory.
  const projectDir = process.env.CLAUDE_PROJECT_DIR || process.cwd();
  const claudeDir = PROJECT
    ? path.join(projectDir, '.claude')
    : path.join(home, '.claude');
  const settingsFile = path.join(claudeDir, 'settings.json');

  // For a user install we copy the hooks somewhere stable and reference them
  // by absolute path. For a project install we assume hooks/ already lives at
  // the project root next to .claude and use $CLAUDE_PROJECT_DIR.
  const installedHooksDir = PROJECT
    ? path.join(projectDir, 'hooks')
    : path.join(claudeDir, 'safeguards', 'hooks');

  const command = guardCommand(PROJECT, installedHooksDir);

  const settings = readSettings(settingsFile);
  settings.hooks = settings.hooks || {};

  const events = {
    PreToolUse: 'Bash|BashOutput|Read|Edit|Write|MultiEdit|NotebookEdit|NotebookRead|WebFetch|Grep',
    UserPromptSubmit: '',
    PostToolUse: 'Bash|Read|Grep|WebFetch',
  };

  // Start from the user's config with our old entries removed.
  for (const ev of Object.keys(events)) {
    settings.hooks[ev] = stripOurs(settings.hooks[ev]);
  }

  if (!UNINSTALL) {
    for (const [ev, matcher] of Object.entries(events)) {
      settings.hooks[ev].push(makeEntry(matcher || undefined, command));
    }
  }

  // Drop now-empty arrays for tidiness.
  for (const ev of Object.keys(events)) {
    if (settings.hooks[ev].length === 0) delete settings.hooks[ev];
  }

  if (DRY) {
    log('DRY RUN — settings.json would become:');
    console.log(JSON.stringify(settings, null, 2));
    if (!PROJECT && !UNINSTALL)
      log('Would copy hooks/ ->', installedHooksDir);
    return;
  }

  // Copy hook sources for a user install.
  if (!PROJECT && !UNINSTALL) {
    copyDir(path.join(SRC, 'hooks'), installedHooksDir);
    log('Copied hooks ->', installedHooksDir);
  }

  fs.mkdirSync(claudeDir, { recursive: true });
  if (fs.existsSync(settingsFile)) {
    const backup = backupName(settingsFile);
    fs.copyFileSync(settingsFile, backup);
    log('Backed up existing settings ->', backup);
  }
  fs.writeFileSync(settingsFile, JSON.stringify(settings, null, 2) + '\n');
  log(UNINSTALL ? 'Removed safeguard hooks from' : 'Wrote hooks into', settingsFile);
  log('Done. Restart Claude Code, or type /hooks in an open session and press Esc to close the menu.');
}

main();
