/*
 * Scripts a command runs: rules 1, 2 and 4 in CLAUDE.md. The other checks
 * read only the command line, so `./seed.sh acme-prod` hides the `sf`
 * commands inside the script. For each local shell script a command runs,
 * read it, fill in the arguments it was called with, and run the same checks
 * over its body as if it had been typed.
 *
 * Not a shell interpreter. Filled in: positional parameters ($1, ${1:-x},
 * "$@") and simple literal assignments (ORG="$1", then "$ORG"). Anything else
 * stays a variable. An `sf` command whose org is still a variable can't be
 * judged, so it asks (rule 1: ask when unsure).
 *
 * Returns null, or { decision: 'deny' | 'ask', rule: 'prod' | 'write' |
 * 'destructive', why }.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { stripHeredocs, findForbiddenCommand } = require(path.join(__dirname, 'patterns.cjs'));
const orgs = require(path.join(__dirname, 'orgs.cjs'));
const writes = require(path.join(__dirname, 'writes.cjs'));

const MAX_BYTES = 256 * 1024;
const MAX_DEPTH = 2; // a script that calls a script that calls a script
const SHELLS = /^(bash|sh|zsh|dash|ksh|source|\.)$/;
const SHELL_EXT = /\.(sh|bash|zsh|ksh)$/i;
const SHEBANG = /^#!.*\b(ba|z|k|da)?sh\b/;
const TARGET_FLAGS = ['-o', '--target-org', '-u', '--targetusername'];

function homeDir() {
  return process.env.CLAUDE_SAFEGUARD_HOME || os.homedir();
}

function resolvePath(p, dir) {
  return path.resolve(dir, String(p).replace(/^~(?=$|\/)/, homeDir()));
}

/*
 * The local scripts a command runs: [{ file, args, dir, viaShell }]. `dir` is
 * the working directory at that point (after any `cd`), which is where the
 * script's own relative paths and default org resolve.
 */
function scriptCalls(command, cwd) {
  const calls = [];
  let dir = cwd || process.cwd();
  for (const seg of orgs.segments(stripHeredocs(command))) {
    const { name, token, args } = orgs.program(seg);
    if (name === 'cd' && args[0]) {
      dir = resolvePath(args[0], dir);
      continue;
    }
    if (SHELLS.test(name)) {
      const i = args.findIndex((a) => !a.startsWith('-'));
      if (i < 0) continue;
      const flags = args.slice(0, i);
      // `bash -c "..."` is code, not a file; `bash -n x.sh` only parses it.
      if (flags.some((f) => /^-[a-z]*[cn]/.test(f))) continue;
      calls.push({ file: resolvePath(args[i], dir), args: args.slice(i + 1), dir, viaShell: true });
    } else if (token.includes('/') || SHELL_EXT.test(token)) {
      calls.push({ file: resolvePath(token, dir), args, dir, viaShell: false });
    }
  }
  return calls;
}

// The script's text, or null when it isn't a readable local shell script.
function readScript(file, viaShell) {
  try {
    const st = fs.statSync(file);
    if (!st.isFile() || st.size > MAX_BYTES) return null;
    const text = fs.readFileSync(file, 'utf8');
    if (text.includes('\0')) return null;
    if (!viaShell && !SHELL_EXT.test(file) && !SHEBANG.test(text.split('\n', 1)[0])) return null;
    return text;
  } catch {
    return null;
  }
}

// Fill in positional parameters and simple literal assignments.
function fillIn(text, args) {
  const pos = (n) => (n >= 1 ? args[n - 1] || '' : '');
  let s = text
    .replace(/^\s*#.*$/gm, '') // comments name commands as text
    .replace(/\$\{(\d)(?::?([-=?+])([^}]*))?\}/g, (m, n, op, word) => {
      const v = pos(+n);
      if (op === '-' || op === '=') return v || word;
      if (op === '+') return v ? word : '';
      return v;
    })
    .replace(/\$\{?[@*]\}?/g, args.join(' '))
    .replace(/\$(\d)/g, (m, n) => pos(+n));

  const vars = {};
  const assign = /^\s*(?:export\s+|local\s+|readonly\s+)?([A-Za-z_]\w*)=(?:"([^"$`]*)"|'([^']*)'|([^\s"'$`;|&()]*))\s*$/gm;
  let m;
  while ((m = assign.exec(s))) vars[m[1]] = m[2] ?? m[3] ?? m[4] ?? '';
  for (const [name, value] of Object.entries(vars)) {
    s = s
      .replace(new RegExp(`\\$\\{${name}(?::?[-=]([^}]*))?\\}`, 'g'), (x, word) => value || word || '')
      .replace(new RegExp(`\\$${name}\\b`, 'g'), value);
  }
  return s;
}

// Rule 1 over a script body: deny reasons, plus `sf` targets left as variables.
function orgFindings(body, cwd) {
  const deny = [];
  const unsure = [];
  let dir = cwd;
  for (const seg of orgs.segments(stripHeredocs(body))) {
    const { name, args } = orgs.program(seg);
    if (name === 'cd' && args[0]) {
      if (!/[$`]/.test(args[0])) dir = resolvePath(args[0], dir);
      continue;
    }
    if (name === 'sf' || name === 'sfdx') {
      const target = orgs.flagValue(args, TARGET_FLAGS);
      if (target && /[$`]/.test(target)) {
        unsure.push(target);
        continue;
      }
      const r = orgs.checkSf(args, dir);
      if (r) deny.push(r);
      continue;
    }
    const r = orgs.checkCommand(seg.join(' '), dir); // org URLs given to curl, python -c ...
    if (r) deny.push(r);
  }
  return { deny: [...new Set(deny)], unsure: [...new Set(unsure)] };
}

function checkScript(call, depth) {
  const text = readScript(call.file, call.viaShell);
  if (text === null) return [];
  const body = fillIn(text, call.args);
  const label = `the script ${path.basename(call.file)}`;
  const found = [];

  const forbidden = findForbiddenCommand(body);
  if (forbidden) {
    found.push({ decision: 'deny', rule: 'destructive', why: `${label} runs a dangerous command [${forbidden.id}]: ${forbidden.why}` });
  }
  const org = orgFindings(body, call.dir);
  if (org.deny.length) found.push({ decision: 'deny', rule: 'prod', why: `${label} reaches an org it may not: ${org.deny.join('; ')}` });
  // Every command in the script, so a later deny isn't hidden behind an earlier ask.
  const writeHits = orgs.segments(stripHeredocs(body)).map((seg) => writes.checkCommand(seg.join(' '))).filter(Boolean);
  const write = writeHits.find((w) => w.decision === 'deny') || writeHits[0];
  if (write) found.push({ decision: write.decision, rule: 'write', why: `${label} contains a command that ${write.why.replace(/^`[^`]*` /, '')}`, hint: write.hint });
  if (org.unsure.length) {
    found.push({
      decision: 'ask',
      rule: 'prod',
      why: `${label} runs \`sf\` against an org named by a variable (${org.unsure.join(', ')}) that the guard couldn't resolve, so the org couldn't be confirmed as non-production`,
    });
  }
  if (depth < MAX_DEPTH) {
    for (const inner of scriptCalls(body, call.dir)) found.push(...checkScript(inner, depth + 1));
  }
  return found;
}

/*
 * Check every local script a command runs. Deny beats ask; the first finding
 * of the strongest decision is returned.
 */
function checkCommand(command, cwd) {
  try {
    const found = [];
    for (const call of scriptCalls(command, cwd)) found.push(...checkScript(call, 1));
    return found.find((f) => f.decision === 'deny') || found.find((f) => f.decision === 'ask') || null;
  } catch {
    return null; // fail open
  }
}

module.exports = { checkCommand, scriptCalls, fillIn };
