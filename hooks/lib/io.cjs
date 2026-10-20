/*
 * Hook I/O helpers for Claude Code safeguards.
 *
 * Claude Code invokes a hook by spawning the command and writing a JSON
 * event object to the hook's stdin. The hook communicates its decision
 * back either through a JSON object on stdout or through its exit code.
 *
 * This module hides those details so the guard logic can stay declarative.
 * Pure Node, no dependencies.
 */

'use strict';

// Read the entire hook event JSON from stdin. Resolves to a plain object,
// or {} if stdin is empty / not valid JSON (so a malformed event can never
// crash the hook and accidentally block every tool call).
function readEvent() {
  return new Promise((resolve) => {
    let data = '';
    const done = () => {
      if (!data.trim()) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        resolve({});
      }
    };
    try {
      process.stdin.setEncoding('utf8');
    } catch {
      /* stdin may be a non-TTY in tests */
    }
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', done);
    process.stdin.on('error', done);
    // Safety valve: if stdin never closes, don't hang the tool call forever.
    const t = setTimeout(done, 5000);
    if (t.unref) t.unref();
  });
}

// ---- PreToolUse decisions -------------------------------------------------
// Deny a tool call. Claude sees the reason and does not run the tool.
function denyTool(reason) {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: reason,
      },
    })
  );
  process.exit(0);
}

// Pause and ask the user to approve the tool call. For calls that are
// legitimate often enough that a hard deny would get in the way.
function askTool(reason) {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'ask',
        permissionDecisionReason: reason,
      },
    })
  );
  process.exit(0);
}

// Let the tool call proceed without further prompting.
function allowTool() {
  process.exit(0);
}

// ---- UserPromptSubmit decisions ------------------------------------------
// Block a prompt from ever being sent to Anthropic. The user sees the reason.
function blockPrompt(reason) {
  process.stdout.write(JSON.stringify({ decision: 'block', reason }));
  process.exit(0);
}

// ---- PostToolUse decisions ------------------------------------------------
// After a tool ran (best-effort / detective): give Claude instructions as
// additional context and show the user a short notice. Not `decision: block`,
// which the UI renders as a "hook blocking error" although nothing was blocked.
function warnAfterTool(forClaude, forUser) {
  process.stdout.write(
    JSON.stringify({
      systemMessage: forUser || forClaude,
      hookSpecificOutput: {
        hookEventName: 'PostToolUse',
        additionalContext: forClaude,
      },
    })
  );
  process.exit(0);
}

// Neutral exit — nothing to say.
function pass() {
  process.exit(0);
}

module.exports = {
  readEvent,
  denyTool,
  askTool,
  allowTool,
  blockPrompt,
  warnAfterTool,
  pass,
};
