/*
 * No-persisting-changes rule: rule 2 in CLAUDE.md. Claude makes no lasting
 * change to any Salesforce org, sandboxes included; the user deploys and
 * changes data. Read-only and check-only work stays allowed: queries,
 * describes, retrieves, `deploy start --dry-run`, `deploy validate`, and Apex
 * test runs (test DML rolls back).
 *
 * Each rule returns { decision: 'deny' | 'ask', why, hint }. `ask` is for
 * commands that are sometimes harmless (anonymous Apex that only reads), so
 * the user decides instead of being blocked.
 */

'use strict';

const path = require('path');
const { stripHeredocs } = require(path.join(__dirname, 'patterns.cjs'));
const { segments, program, flagValue, classifyHost } = require(path.join(__dirname, 'orgs.cjs'));

const has = (args, ...flags) => args.some((a) => flags.some((f) => a === f || a.startsWith(f + '=')));

// `sub` is the subcommand with colons as spaces and any legacy `force ` removed.
const SF_RULES = [
  // ---- Metadata ----
  {
    re: /^project deploy start\b/,
    skip: (args) => has(args, '--dry-run'),
    decision: 'deny',
    why: '`sf project deploy start` deploys metadata to the org',
    hint: 'To check that the deploy would succeed, use `--dry-run` or `sf project deploy validate`.',
  },
  {
    re: /^project deploy (quick|resume)\b/,
    decision: 'deny',
    why: '`sf project deploy quick` / `resume` completes a deploy to the org',
  },
  {
    re: /^(source|mdapi) deploy\b/,
    skip: (args) => has(args, '-c', '--checkonly'),
    decision: 'deny',
    why: '`sfdx force:source:deploy` / `mdapi:deploy` deploys metadata to the org',
    hint: 'To check that the deploy would succeed, add `--checkonly`.',
  },
  { re: /^source push\b/, decision: 'deny', why: '`sfdx force:source:push` deploys metadata to the org' },
  {
    re: /^(project delete source|source delete)\b/,
    skip: (args) => has(args, '--check-only'),
    decision: 'deny',
    why: 'deleting source deletes metadata from the org',
  },
  { re: /^package (install|uninstall)\b/, decision: 'deny', why: 'installing or uninstalling a package changes the org' },
  {
    re: /^(org assign (permset|permsetlicense)|user (permset|permsetlicense) assign)\b/,
    decision: 'deny',
    why: 'assigning a permission set changes user access in the org',
  },
  {
    re: /^(org generate password|org create user|user (create|password generate))\b/,
    decision: 'deny',
    why: 'creating users or passwords changes the org',
  },
  { re: /^community (publish|create)\b/, decision: 'deny', why: 'publishing or creating an Experience site changes the org' },

  // ---- Data ----
  {
    re: /^data (create|update|delete|upsert|import)\b/,
    decision: 'deny',
    why: '`sf data create/update/delete/upsert/import` writes records to the org',
  },
  {
    re: /^data (record (create|update|delete)|tree import|bulk (upsert|delete))\b/,
    decision: 'deny',
    why: 'legacy `sfdx force:data` record, tree and bulk commands write records to the org',
  },
  {
    re: /^api request rest\b/,
    skip: (args) => !WRITE_METHODS.test(flagValue(args, ['-X', '--method']) || 'GET'),
    decision: 'deny',
    why: '`sf api request rest` with POST/PUT/PATCH/DELETE changes data in the org',
  },

  // ---- Sometimes harmless: the user decides ----
  {
    // Anonymous Apex may only read (a debug query) or may write. `apex run
    // test` runs tests, whose DML rolls back, and stays allowed.
    re: /^(apex run(?! test(\s|$))|apex execute)\b/,
    decision: 'ask',
    why: '`sf apex run` executes anonymous Apex, which can change data in the org',
  },
  {
    re: /^org (create|delete)( (scratch|sandbox))?\b|^org (resume|refresh) sandbox\b/,
    decision: 'ask',
    why: 'this creates, refreshes or deletes a scratch org or sandbox',
  },
];

const WRITE_METHODS = /^(POST|PUT|PATCH|DELETE)$/i;

// curl/wget/httpie sending a write to a Salesforce org (any kind of org; the
// production-org rule already blocks reaching production at all).
function httpWriteToOrg(name, args) {
  const hosts = args.map((a) => (/https?:\/\/([^/\s'"?#]+)/i.exec(a) || [])[1]).filter(Boolean);
  if (!hosts.some((h) => classifyHost(h) !== null)) return false;
  if (name === 'curl') {
    const method = flagValue(args, ['-X', '--request']);
    if (method) return WRITE_METHODS.test(method);
    if (has(args, '-G', '--get')) return false;
    return has(args, '-d', '--data', '--data-raw', '--data-binary', '--data-urlencode', '--json', '-F', '--form', '-T', '--upload-file');
  }
  if (name === 'wget') return has(args, '--post-data', '--post-file') || /^(POST|PUT|PATCH|DELETE)$/i.test(flagValue(args, ['--method']) || '');
  // httpie / xh: `http POST https://...`
  return args.some((a) => WRITE_METHODS.test(a));
}

function subcommand(args) {
  return args
    .filter((a) => !a.startsWith('-'))
    .slice(0, 3)
    .join(' ')
    .replace(/:/g, ' ')
    .replace(/^force /, '');
}

/*
 * Check a whole shell command. Returns null, or { decision, why, hint }.
 */
function checkCommand(command) {
  try {
    for (const seg of segments(stripHeredocs(command))) {
      const { name, args } = program(seg);
      if (/^(curl|wget|http|https|xh)$/.test(name)) {
        if (httpWriteToOrg(name, args)) {
          return { decision: 'deny', why: 'this HTTP request writes to a Salesforce org (POST/PUT/PATCH/DELETE)', hint: '' };
        }
        continue;
      }
      if (name !== 'sf' && name !== 'sfdx') continue;
      if (args.includes('--help') || args.includes('-h')) continue;
      const sub = subcommand(args);
      for (const rule of SF_RULES) {
        if (!rule.re.test(sub)) continue;
        if (rule.skip && rule.skip(args)) break;
        return { decision: rule.decision, why: rule.why, hint: rule.hint || '' };
      }
    }
    return null;
  } catch {
    return null; // fail open
  }
}

module.exports = { checkCommand };
