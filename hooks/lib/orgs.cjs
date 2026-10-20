/*
 * Production-org guard: rule 1 in CLAUDE.md ("never access a production
 * Salesforce org"). Decides, WITHOUT contacting any org, whether a command
 * Claude is about to run would reach a production org.
 *
 * Two routes are checked:
 *   1. `sf` / `sfdx` commands. The target org comes from -o/--target-org (or
 *      the legacy -u/--targetusername), else the project's or the global
 *      default org. The alias is resolved to a username and the org's
 *      instance URL is read from the Salesforce CLI's local auth file.
 *   2. Direct calls to an org's address: curl/wget/httpie, inline
 *      python/node/ruby code, and Claude's WebFetch tool.
 *
 * An org passes when its address is clearly non-production (sandbox, scratch,
 * Developer Edition, Trailhead playground) or when its org ID is on the local
 * allowlist with an expiry date that hasn't passed (trial orgs, and greenfield
 * client orgs before go-live: their address looks exactly like production).
 * Anything else, including an org that can't
 * be resolved, is blocked with a message telling Claude to ask the user:
 * the policy says to ask when unsure, never to check by connecting.
 *
 * This guards Claude's tool calls only. Commands a person types in their own
 * terminal never pass through it.
 */

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { stripHeredocs } = require(path.join(__dirname, 'patterns.cjs'));

// Overridable so tests can point at a fake home directory.
function homeDir() {
  return process.env.CLAUDE_SAFEGUARD_HOME || os.homedir();
}

function allowlistPath() {
  return (
    process.env.CLAUDE_SAFEGUARD_ALLOWED_ORGS ||
    path.join(homeDir(), '.claude', 'safeguards', 'allowed-orgs.json')
  );
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Classifying an org by its address
// ---------------------------------------------------------------------------
// Returns one of: 'sandbox', 'scratch', 'developer', 'production', or null
// when the host is not a Salesforce org at all (docs, help, Trailhead ...).
function classifyHost(host) {
  const h = String(host || '').toLowerCase().replace(/:\d+$/, '');
  // Org UI/API hosts only. Visualforce and file hosts are left out: their
  // `--c` package marker would read as a sandbox name.
  const isOrgHost =
    /\.(my\.salesforce|lightning\.force|my\.salesforce-setup)\.com$/.test(h) ||
    /^(login|test)\.salesforce\.com$/.test(h) ||
    /^(na|eu|ap|um|cs|usa|gs|aus|can|ind|jpn|deu|fra|swe|gbr)\d+\.salesforce\.com$/.test(h);
  if (!isOrgHost) return null;
  if (/\.scratch\./.test(h)) return 'scratch';
  // Enhanced domains: name--sbx.sandbox.my.salesforce.com. Older ones drop
  // `.sandbox.` but keep the `--sbx` suffix, which My Domain names can't use.
  if (/\.sandbox\./.test(h) || /^[a-z0-9-]+--[a-z0-9]+\./.test(h)) return 'sandbox';
  if (/^cs\d+\./.test(h) || h === 'test.salesforce.com') return 'sandbox';
  if (/-dev-ed\.(develop|my)\./.test(h) || /\.develop\./.test(h) || /\.trailblaze\./.test(h)) return 'developer';
  return 'production';
}

function hostOf(url) {
  try {
    return new URL(/^[a-z]+:\/\//i.test(url) ? url : 'https://' + url).host;
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------
// Resolving a target (alias / username / default) from local CLI files
// ---------------------------------------------------------------------------
function aliasMap() {
  const j = readJson(path.join(homeDir(), '.sfdx', 'alias.json'));
  return (j && j.orgs) || {};
}

// The default org (or Dev Hub): project config, walking up from cwd, then
// global config. `sfKey` is the sf v2 key, `legacyKey` the sfdx one.
function defaultTarget(cwd, sfKey = 'target-org', legacyKey = 'defaultusername') {
  let dir = path.resolve(cwd || process.cwd());
  for (;;) {
    const sf = readJson(path.join(dir, '.sf', 'config.json'));
    if (sf && sf[sfKey]) return sf[sfKey];
    const sfdx = readJson(path.join(dir, '.sfdx', 'sfdx-config.json'));
    if (sfdx && sfdx[legacyKey]) return sfdx[legacyKey];
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  const g = readJson(path.join(homeDir(), '.sf', 'config.json'));
  if (g && g[sfKey]) return g[sfKey];
  const gl = readJson(path.join(homeDir(), '.sfdx', 'sfdx-config.json'));
  if (gl && gl[legacyKey]) return gl[legacyKey];
  return null;
}

// Only the non-secret fields ever leave this function.
function authInfo(username) {
  if (!username || /[\\/]/.test(username)) return null;
  const j = readJson(path.join(homeDir(), '.sfdx', `${username}.json`));
  if (!j) return null;
  return {
    instanceUrl: j.instanceUrl || j.loginUrl || '',
    orgId: j.orgId || '',
    isSandbox: j.isSandbox === true,
    isScratch: j.isScratch === true || j.isScratchOrg === true,
  };
}

// Every locally authorized org, for mapping a raw URL back to an org ID.
function allAuths() {
  const dir = path.join(homeDir(), '.sfdx');
  let files = [];
  try {
    files = fs.readdirSync(dir).filter((f) => f.includes('@') && f.endsWith('.json'));
  } catch {
    return [];
  }
  return files.map((f) => authInfo(f.slice(0, -5))).filter(Boolean);
}

function allowlist() {
  const j = readJson(allowlistPath());
  return Array.isArray(j) ? j : (j && Array.isArray(j.orgs) ? j.orgs : []);
}

function today() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function entriesFor(orgId) {
  if (!orgId) return [];
  const id15 = String(orgId).slice(0, 15);
  return allowlist().filter((e) => e && String(e.orgId || '').slice(0, 15) === id15);
}

// An allowlist entry for this org ID whose expiry date hasn't passed.
function allowlisted(orgId) {
  return (
    entriesFor(orgId).find(
      (e) => /^\d{4}-\d{2}-\d{2}$/.test(String(e.expires || '')) && today() <= e.expires
    ) || null
  );
}

// Why a production-looking org isn't allowed: absent, expired, or malformed.
function notAllowedWhy(orgId) {
  const entries = entriesFor(orgId);
  if (!entries.length) return 'is not on the allowlist';
  const dated = entries.filter((e) => /^\d{4}-\d{2}-\d{2}$/.test(String(e.expires || '')));
  if (!dated.length) return 'has an allowlist entry without a valid expires date (YYYY-MM-DD)';
  const last = dated.map((e) => e.expires).sort().pop();
  return `has an allowlist entry that expired on ${last}`;
}

/*
 * Decide about one org target. Returns { ok, why } where `why` explains a
 * block (or, for an allowed org, what made it safe).
 */
function judgeTarget(target, cwd) {
  const t = target || defaultTarget(cwd);
  if (!t) {
    return { ok: false, why: 'no target org was given and no default org is set, so the org could not be identified' };
  }
  const username = t.includes('@') ? t : aliasMap()[t];
  const auth = username ? authInfo(username) : null;
  if (!auth || !auth.instanceUrl) {
    return { ok: false, why: `org "${t}" is not logged in on this machine, so it could not be confirmed as non-production` };
  }
  const host = hostOf(auth.instanceUrl);
  let kind = classifyHost(host);
  if (auth.isScratch) kind = 'scratch';
  else if (auth.isSandbox && kind === 'production') kind = 'sandbox';
  if (kind && kind !== 'production') return { ok: true, why: `${t} is a ${kind} org (${host})` };
  const entry = allowlisted(auth.orgId);
  if (entry) return { ok: true, why: `${t} is allowlisted until ${entry.expires}` };
  return {
    ok: false,
    why: `org "${t}" (${host}) looks like a production org and ${notAllowedWhy(auth.orgId)}`,
  };
}

// Decide about a raw org URL (route 2).
function judgeUrl(url) {
  const host = hostOf(url);
  const kind = classifyHost(host);
  if (kind === null || kind !== 'production') return { ok: true };
  if (/^(login)\.salesforce\.com$/i.test(host)) {
    return { ok: false, why: `${host} is the production login endpoint` };
  }
  const auth = allAuths().find((a) => hostOf(a.instanceUrl).toLowerCase() === host.toLowerCase());
  const entry = auth && allowlisted(auth.orgId);
  if (entry) return { ok: true, why: `${host} is allowlisted until ${entry.expires}` };
  return {
    ok: false,
    why: `${host} looks like a production org and ${auth ? notAllowedWhy(auth.orgId) : 'is not on the allowlist'}`,
  };
}

// ---------------------------------------------------------------------------
// Reading commands
// ---------------------------------------------------------------------------
// Split a shell command into simple-command segments and tokenize each one.
// Not a full shell parser: enough to find `sf ... -o alias` reliably.
function segments(command) {
  const out = [];
  let cur = [];
  let tok = '';
  let quote = null;
  let hasTok = false;
  const push = () => {
    if (hasTok) cur.push(tok);
    tok = '';
    hasTok = false;
  };
  const end = () => {
    push();
    if (cur.length) out.push(cur);
    cur = [];
  };
  const s = String(command || '');
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote) {
      if (ch === quote) quote = null;
      else if (ch === '\\' && quote === '"' && i + 1 < s.length) tok += s[++i];
      else tok += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      hasTok = true;
    } else if (ch === '\\' && i + 1 < s.length) {
      if (s[i + 1] === '\n') i++;
      else {
        tok += s[++i];
        hasTok = true;
      }
    } else if (ch === '\n' || ch === ';' || ch === '|' || ch === '&' || ch === '(' || ch === ')') {
      end();
    } else if (/\s/.test(ch)) {
      push();
    } else {
      tok += ch;
      hasTok = true;
    }
  }
  end();
  return out;
}

// Drop leading `FOO=bar`, `sudo`, `npx`, `env`, `command`, `time` wrappers.
function program(seg) {
  let i = 0;
  while (i < seg.length && (/^[A-Za-z_][A-Za-z0-9_]*=/.test(seg[i]) || /^(sudo|npx|env|command|time|exec|nohup)$/.test(seg[i]))) i++;
  // `token` keeps the path as typed (`./seed.sh`), so a script can be found.
  return { name: (seg[i] || '').split('/').pop(), token: seg[i] || '', args: seg.slice(i + 1) };
}

// sf subcommands that never contact an org.
const LOCAL_ONLY = [
  /^(alias|config|plugins|autocomplete|update|version|help|which|search|info|doctor|whatsnew|commands)\b/,
  /^org list auth\b/,
  /^project (generate|convert|list ignored|reset tracking)\b/,
  /^(apex|lightning|static-resource|visualforce|analytics|schema|template) generate\b/,
];

function flagValue(args, names) {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    for (const n of names) {
      if (a === n) return args[i + 1] || '';
      if (a.startsWith(n + '=')) return a.slice(n.length + 1);
    }
  }
  return null;
}

/*
 * Check one `sf`/`sfdx` invocation. Returns null when it's fine, or a reason
 * string when it must be blocked.
 */
function checkSf(args, cwd) {
  if (args.includes('--help') || args.includes('-h')) return null;
  const words = args.filter((a) => !a.startsWith('-')).slice(0, 3);
  const sub = words.join(' ').replace(/:/g, ' ').replace(/^force /, '');
  if (!sub) return null;

  // `project generate manifest --from-org x` reads org x.
  const fromOrg = flagValue(args, ['--from-org']);
  if (fromOrg !== null) {
    const v = judgeTarget(fromOrg, cwd);
    if (!v.ok) return v.why;
  }
  if (LOCAL_ONLY.some((re) => re.test(sub))) return null;

  // Bare `sf org list` checks every org's connection status, production included.
  if (sub === 'org list') {
    return args.includes('--skip-connection-status')
      ? null
      : '`sf org list` contacts every authorized org (production included) to check its connection status. Use `sf org list --skip-connection-status`.';
  }

  // Logging in: judge the login URL (default is the production login).
  if (/^(org login|auth|force auth)\b/.test(sub)) {
    const url = flagValue(args, ['--instance-url', '-r', '--instanceurl']) || 'https://login.salesforce.com';
    const kind = classifyHost(hostOf(url));
    if (kind && kind !== 'production') return null;
    return `logging in through ${hostOf(url) || url} would authorize a production org. Logging in is for the user to do.`;
  }

  const reasons = [];
  // Creating a scratch org talks only to the Dev Hub, checked below.
  if (!/^org create scratch\b/.test(sub)) {
    const target = flagValue(args, ['-o', '--target-org', '-u', '--targetusername']);
    const verdict = judgeTarget(target, cwd);
    if (!verdict.ok) reasons.push(verdict.why);
  }
  // A Dev Hub is normally the firm's production org. On `sf data` commands
  // `-v` is `--values` (record field values), not the Dev Hub.
  const hubFlags = ['--target-dev-hub', '--targetdevhubusername'];
  if (!/^data\b/.test(sub)) hubFlags.push('-v');
  const hub = flagValue(args, hubFlags);
  if (hub !== null || /^org (create|delete) scratch\b/.test(sub)) {
    const hubTarget = hub || defaultTarget(cwd, 'target-dev-hub', 'defaultdevhubusername');
    if (!hubTarget) reasons.push('no Dev Hub was given and none is set, so it could not be confirmed as non-production');
    else {
      const hv = judgeTarget(hubTarget, cwd);
      if (!hv.ok) reasons.push(`Dev Hub ${hv.why}`);
    }
  }
  return reasons.length ? reasons.join('; ') : null;
}

const NET_CLIENTS = /^(curl|wget|http|https|xh|httpie|invoke-webrequest|iwr|invoke-restmethod|irm)$/i;
const INLINE_CODE = /^(python[0-9.]*|node|ruby|perl|deno|bun)$/i;
const URL_IN_TEXT = /(?:https?:\/\/)?[a-z0-9.-]+\.(?:my\.salesforce|lightning\.force|my\.salesforce-setup)\.com\b|(?:https?:\/\/)?(?:login|(?:na|eu|ap|um|usa|gs|aus|can|ind|jpn|deu|fra|swe|gbr)\d+)\.salesforce\.com\b/gi;

function urlsIn(text) {
  return String(text).match(URL_IN_TEXT) || [];
}

/*
 * Check a whole shell command. Returns null when it's fine, or a reason.
 */
function checkCommand(command, cwd) {
  try {
    const reasons = [];
    let dir = cwd || process.cwd();
    // A runbook written with a heredoc names orgs as text, not as commands.
    for (const seg of segments(stripHeredocs(command))) {
      const { name, args } = program(seg);
      // `cd other-project && sf ...` uses that project's default org.
      if (name === 'cd' && args[0]) {
        dir = path.resolve(dir, args[0].replace(/^~(?=$|\/)/, homeDir()));
        continue;
      }
      if (name === 'sf' || name === 'sfdx') {
        const r = checkSf(args, dir);
        if (r) reasons.push(r);
        continue;
      }
      const inline = INLINE_CODE.test(name) && args.some((a) => a === '-c' || a === '-e' || a === '--eval');
      if (NET_CLIENTS.test(name) || inline) {
        for (const u of urlsIn(args.join(' '))) {
          const v = judgeUrl(u);
          if (!v.ok) reasons.push(v.why);
        }
      }
    }
    return reasons.length ? [...new Set(reasons)].join('; ') : null;
  } catch (err) {
    // Policy: when unsure, ask. A bug here blocks sf commands, not everything.
    return /\b(sf|sfdx)\b|salesforce\.com|force\.com/.test(String(command))
      ? `the production-org check failed (${err && err.message}), so the target could not be confirmed`
      : null;
  }
}

function checkUrl(url) {
  try {
    const v = judgeUrl(url);
    return v.ok ? null : v.why;
  } catch {
    return null;
  }
}

/*
 * Commands whose output contains a Salesforce credential, for ANY org: the
 * token would land in the transcript. Returns a reason, or null.
 *   sf org display            access token (+ auth URL with --verbose)
 *   sf org open -r/--json     login URL carrying a live session ID
 *   sf org list [auth] --json every org's access token
 *   security find-*-password -w/-g   a stored password (e.g. the sfdx key)
 */
function checkTokenCommand(command) {
  try {
    for (const seg of segments(stripHeredocs(command))) {
      const { name, args } = program(seg);
      if (name === 'security') {
        if (args.some((a) => /^find-(generic|internet)-password$/.test(a)) && args.some((a) => a === '-w' || a === '-g')) {
          return '`security find-*-password -w` prints a stored password from the keychain';
        }
        continue;
      }
      if (name !== 'sf' && name !== 'sfdx') continue;
      if (args.includes('--help') || args.includes('-h')) continue;
      const sub = args
        .filter((a) => !a.startsWith('-'))
        .slice(0, 3)
        .join(' ')
        .replace(/:/g, ' ')
        .replace(/^force /, '');
      const json = args.includes('--json');
      if (/^org display\b/.test(sub) && !/^org display user\b/.test(sub)) {
        return args.includes('--verbose')
          ? '`sf org display --verbose` prints the org\'s access token and its SFDX auth URL (a refresh token)'
          : '`sf org display` prints the org\'s access token';
      }
      if (/^org open\b/.test(sub) && (args.includes('-r') || args.includes('--url-only') || json)) {
        return '`sf org open --url-only` / `--json` prints a login URL that carries a live session ID';
      }
      if (/^(org list( auth)?|auth list)\b/.test(sub) && json) {
        return 'the JSON output of `sf org list` includes each org\'s access token';
      }
    }
    return null;
  } catch {
    return null;
  }
}

module.exports = {
  classifyHost,
  segments,
  program,
  flagValue,
  checkSf,
  judgeTarget,
  judgeUrl,
  checkCommand,
  checkUrl,
  checkTokenCommand,
  allowlistPath,
};
