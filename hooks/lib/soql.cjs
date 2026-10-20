/*
 * Sensitive-field query check: rule 3 in CLAUDE.md, applied BEFORE a query
 * runs rather than after its results are already in the transcript.
 *
 * The production-org rule lets sandboxes through, but a full or partial copy
 * sandbox holds copied production data, and the Salesforce CLI's files can't
 * tell a full copy from a developer sandbox. So every `sf data query` /
 * `sf data search` is read first, whatever org it targets:
 *
 *   - It selects a field whose NAME marks it as sensitive (SSN__c, Birthdate,
 *     Bank_Account_Number__c, Credit_Card_Number__c ...)      -> deny
 *   - It selects FIELDS(ALL) / FIELDS(CUSTOM), FIELDS(STANDARD) on a
 *     person object, or uses `sf data get record` (all fields) -> ask the user
 *   - Its output goes to a file (--output-file, `> file`) or it is an export
 *     (sf data export ...), so nothing reaches the transcript   -> allow
 *
 * COUNT(field) / COUNT_DISTINCT(field) are allowed: they return numbers, which
 * is what data profiling for an estimate actually needs.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { fieldWords, fieldRuleFor, stripHeredocs } = require(path.join(__dirname, 'patterns.cjs'));
const { segments, program, flagValue } = require(path.join(__dirname, 'orgs.cjs'));

// Names that are sensitive even though no value check applies here: we're
// judging the query, not its results.
// A name ending in one of these describes the value rather than holding it:
// SSN_or_TIN_Picklist__c ("SSN" / "TIN"), SSN_Verified__c, SSN_Last4__c.
const DESCRIPTOR = new Set([
  'picklist', 'type', 'flag', 'indicator', 'status', 'verified', 'provided',
  'present', 'format', 'label', 'last4', 'last', '4', 'masked', 'source',
]);

function sensitiveFieldKind(name) {
  const words = fieldWords(name);
  if (DESCRIPTOR.has(words[words.length - 1])) return null;
  const rule = fieldRuleFor(name);
  if (rule) return rule.type.replace(/ \(labeled field\)$/, '');
  const w = fieldWords(name);
  const j = w.join('');
  // "CC" is also a common client-code prefix (CC_Lot_Number__c), so it only
  // counts when it directly precedes the number word at the end of the name.
  const last = w[w.length - 1];
  const numberWord = ['number', 'num', 'no'].includes(last);
  if ((w.includes('card') && numberWord) || (numberWord && w[w.length - 2] === 'cc') || /^ccn(um)?$/.test(j)) {
    return 'Card number';
  }
  if (w.includes('cvv') || w.includes('cvc')) return 'Card security code';
  if (w.includes('passport')) return 'Passport number';
  if (/driverslicen[cs]e|driverlicen[cs]e/.test(j)) return "Driver's license";
  return null;
}

const PERSON_OBJECTS = /^(contact|lead|account|user|individual|personaccount)$/i;
const COUNTING = /^(count|count_distinct)$/i;
const KEYWORDS = new Set([
  'select', 'from', 'where', 'and', 'or', 'not', 'in', 'like', 'null', 'true', 'false',
  'order', 'by', 'group', 'having', 'limit', 'offset', 'asc', 'desc', 'nulls', 'first',
  'last', 'with', 'for', 'view', 'reference', 'update', 'tracking', 'viewstat', 'using',
  'scope', 'typeof', 'when', 'then', 'else', 'end', 'includes', 'excludes', 'rollup',
  'cube', 'returning', 'find', 'all', 'fields', 'in', 'name', 'email', 'phone',
  'sidebar', 'security_enforced', 'user_mode', 'system_mode', 'data', 'category',
]);

/*
 * Walk a SOQL or SOSL string and collect what it SELECTs (or RETURNs), at any
 * nesting depth. Fields used only in WHERE/ORDER BY/GROUP BY don't return
 * values, so they are ignored.
 */
function analyze(query) {
  const tokens = String(query).match(/'(?:[^'\\]|\\.)*'|\{[^}]*\}|\(|\)|,|[A-Za-z_][\w.]*|\S/g) || [];
  const selected = []; // field names whose values come back
  const fieldsFns = []; // { arg, object }
  // Each level is a SELECT list (or a SOSL RETURNING object list).
  const stack = [];
  let level = null;
  const open = (kind) => {
    level = { kind, mode: 'list', object: null, fns: [], parent: level, funcs: [] };
    stack.push(level);
  };
  const close = () => {
    for (const f of level.fns) fieldsFns.push({ arg: f, object: level.object });
    stack.pop();
    level = stack[stack.length - 1] || null;
  };

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const lower = t.toLowerCase();
    const next = (tokens[i + 1] || '').toLowerCase();

    if (lower === 'select') {
      open('select');
      continue;
    }
    if (lower === 'returning') {
      // SOSL: RETURNING Obj1(f1, f2 WHERE ...), Obj2(...)
      level = { kind: 'returning', mode: 'objects', object: null, fns: [], funcs: [] };
      stack.push(level);
      continue;
    }
    if (!level) continue;

    if (t === '(') {
      if (next === 'select') continue; // the SELECT token opens the level
      const prev = tokens[i - 1] || '';
      if (level.kind === 'returning' && level.mode === 'objects') {
        open('select');
        level.object = prev;
        continue;
      }
      level.funcs.push(prev.toLowerCase());
      continue;
    }
    if (t === ')') {
      if (level.funcs.length) {
        level.funcs.pop();
        continue;
      }
      if (level.kind === 'select') close();
      continue;
    }
    if (level.kind === 'returning') continue;

    if (lower === 'from') {
      level.mode = 'from';
      continue;
    }
    if (level.mode === 'from') {
      if (/^[A-Za-z_]/.test(t)) {
        level.object = t;
        level.mode = 'clause';
        // A top-level FROM ends the outer SELECT list.
      }
      continue;
    }
    if (['where', 'order', 'group', 'having', 'limit', 'offset', 'with', 'for', 'using'].includes(lower)) {
      level.mode = 'clause';
      continue;
    }
    if (level.mode !== 'list') continue;

    if (/^[A-Za-z_]/.test(t) && !KEYWORDS.has(lower)) {
      const fn = level.funcs[level.funcs.length - 1];
      if (fn === 'fields') level.fns.push(lower);
      else if (fn && COUNTING.test(fn)) continue;
      else if (next === '(') continue; // a function name, not a field
      else selected.push(t.split('.').pop());
    } else if (/^[A-Za-z_]/.test(t) && level.funcs[level.funcs.length - 1] === 'fields') {
      level.fns.push(lower); // FIELDS(ALL) -- "all" is also a keyword
    }
  }
  while (level) close();
  return { selected, fieldsFns };
}

// Judge one query string. Returns null, or { decision: 'deny'|'ask', why }.
function judgeQuery(query) {
  const { selected, fieldsFns } = analyze(query);
  const hits = [];
  for (const f of selected) {
    const kind = sensitiveFieldKind(f);
    if (kind) hits.push(`${f} (${kind})`);
  }
  if (hits.length) {
    return { decision: 'deny', why: `the query selects ${[...new Set(hits)].join(', ')}` };
  }
  for (const fn of fieldsFns) {
    if (fn.arg === 'all' || fn.arg === 'custom') {
      return { decision: 'ask', why: `FIELDS(${fn.arg.toUpperCase()}) returns every ${fn.arg === 'custom' ? 'custom ' : ''}field, which can include SSNs, birthdates and other personal data` };
    }
    if (fn.arg === 'standard' && fn.object && PERSON_OBJECTS.test(fn.object)) {
      return { decision: 'ask', why: `FIELDS(STANDARD) on ${fn.object} includes personal fields such as Birthdate` };
    }
  }
  return null;
}

// Does this segment send its stdout somewhere other than the transcript?
function outputToFile(seg, args) {
  if (flagValue(args, ['--output-file']) !== null) return true;
  return seg.some((t) => /^(1?>|>>)/.test(t) && !/^2>/.test(t));
}

function readQueryFile(file, cwd) {
  try {
    return fs.readFileSync(path.resolve(cwd || process.cwd(), file), 'utf8');
  } catch {
    return null;
  }
}

/*
 * Check a whole shell command. Returns null, or { decision, why }.
 */
function checkCommand(command, cwd) {
  try {
    let dir = cwd || process.cwd();
    const segs = segments(stripHeredocs(command));
    for (let s = 0; s < segs.length; s++) {
      const seg = segs[s];
      const { name, args } = program(seg);
      if (name === 'cd' && args[0]) {
        dir = path.resolve(dir, args[0]);
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

      const isQuery = /^data (query|search|soql query|sosl search)\b/.test(sub) || /^data soql query\b/.test(sub);
      const isGetRecord = /^data (get record|record get)\b/.test(sub);
      if (!isQuery && !isGetRecord) continue;
      // Piped into `tee` still echoes; any other redirect keeps it out.
      const teed = segs[s + 1] && program(segs[s + 1]).name === 'tee';
      if (outputToFile(seg, args) && !teed) continue;

      if (isGetRecord) {
        return { decision: 'ask', why: '`sf data get record` returns every field of the record, which can include SSNs, birthdates and other personal data' };
      }
      let query = flagValue(args, ['-q', '--query']);
      if (query === null) {
        const file = flagValue(args, ['-f', '--file', '--soqlqueryfile']);
        if (file) query = readQueryFile(file, dir);
      }
      if (!query) continue;
      const verdict = judgeQuery(query);
      if (verdict) return verdict;
    }
    return null;
  } catch {
    return null; // fail open: the after-the-fact scan still applies
  }
}

module.exports = { analyze, judgeQuery, checkCommand, sensitiveFieldKind };
