#!/usr/bin/env node
/*
 * Claude Code safeguard hook — single entry point for three protections:
 *
 *   1. PreToolUse       Block reading credential/secret files and running
 *                       destructive shell commands before they execute.
 *   2. UserPromptSubmit Stop a prompt that contains secrets / PII from ever
 *                       being sent to Anthropic.
 *   3. PostToolUse      Detect secrets that a tool result pulled into the
 *                       transcript and warn Claude not to echo them. This
 *                       layer is best-effort (detective, not preventive) —
 *                       see README.
 *
 * Wire the SAME script into all three events in settings.json; it branches
 * on hook_event_name internally. Pure Node, no dependencies.
 *
 * Behavior can be softened for a rollout period:
 *   CLAUDE_SAFEGUARD_MODE=warn   -> log to stderr but never block
 *   CLAUDE_SAFEGUARD_MODE=block  -> enforce (default)
 */

'use strict';

const path = require('path');
const {
  isSensitiveFile,
  commandTouchesSensitiveFile,
  findForbiddenCommand,
  scanForPII,
  isBinaryPath,
  looksBinary,
  SECRET_TYPES,
} = require(path.join(__dirname, 'lib', 'patterns.cjs'));
const orgs = require(path.join(__dirname, 'lib', 'orgs.cjs'));
const soql = require(path.join(__dirname, 'lib', 'soql.cjs'));
const writes = require(path.join(__dirname, 'lib', 'writes.cjs'));
const scripts = require(path.join(__dirname, 'lib', 'scripts.cjs'));
const io = require(path.join(__dirname, 'lib', 'io.cjs'));

function productionOrgReason(why) {
  return (
    `Blocked by the no-production-org rule: ${why}. ` +
    `Claude must not reach production orgs, even read-only. Ask the user: ` +
    `they can run the command themselves, or, if this is a trial org or a ` +
    `greenfield org with no real data yet, add its org ID and an expiry date ` +
    `(trial end or go-live) to ` +
    `${orgs.allowlistPath()}. Do not try to identify the org by connecting to it.`
  );
}

const MODE = (process.env.CLAUDE_SAFEGUARD_MODE || 'block').toLowerCase();
const WARN_ONLY = MODE === 'warn';

// Tools whose input carries a file path we should vet before a read/write.
const FILE_PATH_TOOLS = new Set([
  'Read',
  'Edit',
  'Write',
  'MultiEdit',
  'NotebookEdit',
  'NotebookRead',
  'Grep', // its `path` can name a single file, e.g. .env
]);

// A Grep glob that names a protected file: ".env", "**/.envrc", "*.pem".
// Wildcards are dropped and the rest is checked like a path.
function globTargetsSensitiveFile(glob) {
  if (!glob || typeof glob !== 'string') return false;
  return glob
    .split(/[,{}]/)
    .map((g) => g.replace(/\*+/g, '').trim())
    .some((g) => g && isSensitiveFile(g));
}

// Tools that run a shell command.
const COMMAND_TOOLS = new Set(['Bash', 'BashOutput']);

// Upper bound on how much of a tool result we scan. Beyond this the content is
// a build log or a dump, not something a human is about to read a value out of,
// and scanning megabytes on every tool call is a visible latency cost.
const MAX_SCAN_CHARS = 256 * 1024;

// Content-block types whose payload is bytes (base64) rather than prose.
const BINARY_BLOCK_TYPES = new Set(['image', 'document', 'audio', 'video']);

// Response keys that hold a raw encoded payload.
const BINARY_RESPONSE_KEYS = new Set(['source', 'base64', 'bytes', 'buffer']);

function extractFilePath(toolInput) {
  if (!toolInput || typeof toolInput !== 'object') return null;
  return (
    toolInput.file_path ||
    toolInput.notebook_path ||
    toolInput.path ||
    null
  );
}

function extractCommand(toolInput) {
  if (!toolInput || typeof toolInput !== 'object') return null;
  return toolInput.command || null;
}

/*
 * Pull the readable text out of a tool response, leaving out everything that is
 * bytes rather than prose. A `Read` of a PNG comes back as an image content
 * block whose `source.data` is a multi-megabyte base64 string; JSON.stringify-ing
 * the whole response and running regexes over it is what produced the spurious
 * "driver's license" and "IBAN" hits.
 */
function extractScannableText(resp, depth = 0) {
  if (resp == null || depth > 8) return '';
  if (typeof resp === 'string') return resp;
  if (typeof resp === 'number' || typeof resp === 'boolean') return String(resp);
  if (Array.isArray(resp)) {
    return resp
      .map((item) => extractScannableText(item, depth + 1))
      .filter(Boolean)
      .join('\n');
  }
  if (typeof resp !== 'object') return '';

  if (BINARY_BLOCK_TYPES.has(resp.type)) return '';
  if (resp.type === 'text' && typeof resp.text === 'string') return resp.text;

  const parts = [];
  for (const key of Object.keys(resp)) {
    if (BINARY_RESPONSE_KEYS.has(key)) continue;
    const part = extractScannableText(resp[key], depth + 1);
    if (part) parts.push(part);
  }
  return parts.join('\n');
}

/*
 * Where in a tool response the findings sit: [{ path, types }], e.g.
 * { path: 'stdout', types: ['AWS Access Key ID'] }. Walks the same parts of
 * the response that extractScannableText reads. Never returns values.
 */
function findingLocations(resp, at = '', depth = 0, out = []) {
  if (resp == null || depth > 8 || out.length >= 20) return out;
  if (typeof resp === 'string') {
    const types = scanForPII(resp.slice(0, MAX_SCAN_CHARS), { maxFindings: 10 }).map((f) => f.type);
    if (types.length) out.push({ path: at || '(whole response)', types });
    return out;
  }
  if (Array.isArray(resp)) {
    resp.forEach((item, i) => findingLocations(item, `${at}[${i}]`, depth + 1, out));
    return out;
  }
  if (typeof resp !== 'object' || BINARY_BLOCK_TYPES.has(resp.type)) return out;
  for (const key of Object.keys(resp)) {
    if (BINARY_RESPONSE_KEYS.has(key)) continue;
    findingLocations(resp[key], at ? `${at}.${key}` : key, depth + 1, out);
  }
  return out;
}

/*
 * Append one JSON line per after-tool finding to a local log, so a warning
 * nobody can explain can be traced to the tool and the part of its result
 * that matched. Records types and locations only, never the values or the
 * command. Off with CLAUDE_SAFEGUARD_LOG=off. Kept under ~1 MB (one rollover).
 */
function logFinding(event, findings) {
  if ((process.env.CLAUDE_SAFEGUARD_LOG || '').toLowerCase() === 'off') return;
  try {
    const fs = require('fs');
    const os = require('os');
    const file =
      process.env.CLAUDE_SAFEGUARD_LOG_FILE ||
      path.join(process.env.CLAUDE_SAFEGUARD_HOME || os.homedir(), '.claude', 'safeguards', 'findings.log');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    try {
      if (fs.statSync(file).size > 1024 * 1024) fs.renameSync(file, file + '.1');
    } catch {
      /* no log yet */
    }
    const resp = event.tool_response;
    const entry = {
      time: new Date().toISOString(),
      tool: event.tool_name || '',
      file: extractFilePath(event.tool_input || {}) || undefined,
      responseKeys: resp && typeof resp === 'object' && !Array.isArray(resp) ? Object.keys(resp) : typeof resp,
      types: findings.map((f) => `${f.type} x${f.count}`),
      locations: findingLocations(resp),
    };
    fs.appendFileSync(file, JSON.stringify(entry) + '\n');
  } catch {
    /* logging must never affect the decision */
  }
}

function summarizeFindings(findings) {
  return findings
    .map((f) => `${f.type} (x${f.count}, e.g. ${f.sample})`)
    .join('; ');
}

// If WARN_ONLY, print the reason to stderr (visible in transcript/debug) and
// return true so the caller falls through to allow. Otherwise return false.
function softened(reason) {
  if (WARN_ONLY) {
    process.stderr.write(`[safeguard:warn] ${reason}\n`);
    return true;
  }
  return false;
}

async function handlePreToolUse(event) {
  const toolName = event.tool_name || '';
  const toolInput = event.tool_input || {};

  // --- Shell commands: destructive ops + reads of sensitive files ---
  if (COMMAND_TOOLS.has(toolName)) {
    const command = extractCommand(toolInput);

    const forbidden = findForbiddenCommand(command);
    if (forbidden) {
      const reason =
        `Blocked dangerous command [${forbidden.id}]: ${forbidden.why}. ` +
        `If this is intentional and reviewed, run it outside Claude Code.`;
      if (!softened(reason)) return io.denyTool(reason);
    }

    const touched = commandTouchesSensitiveFile(command);
    if (touched) {
      const reason =
        `Blocked: command accesses a sensitive file ("${touched}"). ` +
        `Reading credentials into the session would send them to Anthropic. ` +
        `Redact or reference values by name instead.`;
      if (!softened(reason)) return io.denyTool(reason);
    }

    const prodOrg = orgs.checkCommand(command, event.cwd);
    if (prodOrg) {
      const reason = productionOrgReason(prodOrg);
      if (!softened(reason)) return io.denyTool(reason);
    }

    // Commands that print a Salesforce token, whatever the org.
    const tokenCmd = orgs.checkTokenCommand(command);
    if (tokenCmd) {
      const reason =
        `Blocked: ${tokenCmd}. The credential would enter the conversation and ` +
        `be sent to Anthropic. To see an org's username, org ID or instance ` +
        `URL, use \`sf org list auth\` (the table, without --json). If the ` +
        `token itself is needed, ask the user to run the command.`;
      if (!softened(reason)) return io.denyTool(reason);
    }

    // No lasting changes to any org: the user deploys and changes data.
    const write = writes.checkCommand(command);
    if (write && write.decision === 'deny') {
      const reason =
        `Blocked by the no-persisting-changes rule: ${write.why}. Claude makes ` +
        `no lasting changes to any Salesforce org, sandboxes included; the ` +
        `user deploys and changes data themselves. Give the user the exact ` +
        `command to run instead. ${write.hint}`.trim();
      if (!softened(reason)) return io.denyTool(reason);
    } else if (write && write.decision === 'ask') {
      const reason =
        `No-persisting-changes check: ${write.why}. Approve only if it ` +
        `makes no lasting change, or you have decided Claude may make this one.`;
      if (!softened(reason)) return io.askTool(reason);
    }

    // Local scripts the command runs: the same checks over what's inside them.
    const script = scripts.checkCommand(command, event.cwd);
    if (script) {
      let reason;
      if (script.rule === 'prod' && script.decision === 'deny') {
        reason = productionOrgReason(script.why);
      } else if (script.rule === 'prod') {
        reason =
          `Production-org check: ${script.why}. Approve only if you know the ` +
          `org the script will use is not production.`;
      } else if (script.rule === 'write' && script.decision === 'deny') {
        reason =
          `Blocked by the no-persisting-changes rule: ${script.why}. Claude makes ` +
          `no lasting changes to any Salesforce org, sandboxes included; the user ` +
          `runs scripts that change an org. Give the user the exact command to run instead.`;
      } else if (script.rule === 'write') {
        reason =
          `No-persisting-changes check: ${script.why}. Approve only if it makes ` +
          `no lasting change, or you have decided Claude may make this one.`;
      } else {
        reason = `Blocked dangerous command: ${script.why}. If this is intentional and reviewed, run it outside Claude Code.`;
      }
      if (!softened(reason)) return script.decision === 'deny' ? io.denyTool(reason) : io.askTool(reason);
    }

    // Sandboxes can hold copied production data, so read the query first.
    const query = soql.checkCommand(command, event.cwd);
    if (query && query.decision === 'deny') {
      const reason =
        `Blocked: ${query.why}. The values would enter the conversation and ` +
        `be sent to Anthropic, even from a sandbox, which may hold copied ` +
        `production data. To profile data, use COUNT(field) or filter on ` +
        `field != null and count the rows. If the values themselves are ` +
        `needed, ask the user to run the query. Do not work around this by ` +
        `writing the results to a file and reading the file.`;
      if (!softened(reason)) return io.denyTool(reason);
    } else if (query && query.decision === 'ask') {
      const reason =
        `Sensitive-data check: ${query.why}. Approve only if this org holds ` +
        `no real personal data; otherwise select specific fields instead.`;
      if (!softened(reason)) return io.askTool(reason);
    }
  }

  // --- Web fetches: no direct calls to a production org ---
  if (toolName === 'WebFetch' && toolInput.url) {
    const prodOrg = orgs.checkUrl(toolInput.url);
    if (prodOrg) {
      const reason = productionOrgReason(prodOrg);
      if (!softened(reason)) return io.denyTool(reason);
    }
  }

  // --- File tools: block reads/writes of credential & secret files ---
  if (FILE_PATH_TOOLS.has(toolName)) {
    const filePath = extractFilePath(toolInput);
    if (filePath && isSensitiveFile(filePath)) {
      const reason =
        `Blocked: "${filePath}" looks like a credential/secret file. ` +
        `Opening it would pull its contents into the transcript sent to ` +
        `Anthropic. Use an example/template file or a secrets manager.`;
      if (!softened(reason)) return io.denyTool(reason);
    }
  }

  // --- Grep: a glob that picks out credential files ---
  if (toolName === 'Grep' && globTargetsSensitiveFile(toolInput.glob)) {
    const reason =
      `Blocked: the search pattern "${toolInput.glob}" targets credential/secret ` +
      `files. Matching lines would be pulled into the transcript sent to ` +
      `Anthropic. Search the code instead, or reference values by name.`;
    if (!softened(reason)) return io.denyTool(reason);
  }

  return io.allowTool();
}

async function handleUserPromptSubmit(event) {
  const prompt = event.prompt || '';
  const findings = scanForPII(prompt);
  if (findings.length) {
    const reason =
      `Your message appears to contain sensitive data and was not sent to ` +
      `Anthropic: ${summarizeFindings(findings)}. ` +
      `Remove or mask it and try again.`;
    if (!softened(reason)) return io.blockPrompt(reason);
  }
  return io.pass();
}

async function handlePostToolUse(event) {
  // Detective layer: a tool result may have pulled secrets into the
  // transcript. We cannot un-send it, but we can flag it loudly so Claude
  // does not repeat it and the user is alerted.
  //
  // Binary content is excluded first. Image, archive, and office-document
  // bytes cannot carry sensitive data in a form these regexes could recover,
  // but they trip them constantly — so scanning them is pure false-positive.
  const filePath = extractFilePath(event.tool_input || {});
  if (filePath && isBinaryPath(filePath)) return io.pass();

  let text = extractScannableText(event.tool_response);
  if (text.length > MAX_SCAN_CHARS) text = text.slice(0, MAX_SCAN_CHARS);
  if (looksBinary(text)) return io.pass();

  const findings = scanForPII(text, { maxFindings: 10 });
  if (findings.length) {
    logFinding(event, findings);
    // Credentials can be rotated; personal data can't, so the advice differs.
    const secrets = findings.filter((f) => SECRET_TYPES.has(f.type));
    const personal = findings.filter((f) => !SECRET_TYPES.has(f.type));
    const forClaude =
      `A tool result contains what looks like sensitive data: ` +
      `${summarizeFindings(findings)}. Do NOT repeat, summarize, or store ` +
      `these values, or copy them into files, commits or messages. ` +
      (secrets.length
        ? `Tell the user a credential may have been exposed so they can check whether it's real and rotate it. `
        : '') +
      (personal.length
        ? `Tell the user personal data was read into the session, so they can decide whether that source should be off-limits. `
        : '') +
      `If these are obviously test or sample values, say so briefly.`;
    const kinds = [secrets.length && 'a credential', personal.length && 'personal data']
      .filter(Boolean)
      .join(' and ');
    const forUser =
      `Safeguard notice: a tool result contained what looks like ${kinds} ` +
      `(${findings.map((f) => f.type).join(', ')}). It is already in this session; ` +
      `Claude has been told not to repeat it.` +
      (secrets.length ? ' If the credential is real, rotate it.' : '');
    if (!softened(forClaude)) return io.warnAfterTool(forClaude, forUser);
  }
  return io.pass();
}

(async function main() {
  let event;
  try {
    event = await io.readEvent();
  } catch {
    return io.pass(); // never let the guard itself break the session
  }

  const kind = event.hook_event_name || event.hookEventName || '';
  try {
    switch (kind) {
      case 'PreToolUse':
        return await handlePreToolUse(event);
      case 'UserPromptSubmit':
        return await handleUserPromptSubmit(event);
      case 'PostToolUse':
        return await handlePostToolUse(event);
      default:
        return io.pass();
    }
  } catch (err) {
    // Fail open: a bug in detection must not brick the developer's session.
    process.stderr.write(`[safeguard:error] ${err && err.message}\n`);
    return io.pass();
  }
})();
