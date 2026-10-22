# CRMF Claude Code rules of engagement

This repo holds the Claude Code hooks that TheCRMFirm installs on every
developer's machine. The hooks exist to **enforce the firm's rules below**.
When you audit or change this repo, check the hooks against these rules, not
just against the code: a missing protection is as much a defect as a buggy
regex.

## The rules

1. **Never access a production Salesforce org** (company policy, 2026-09-30).
   This applies to the firm's own org and every client production org, even
   read-only. It covers anything that reaches the org: `sf`/`sfdx` commands
   (queries, describes, retrieves, dry-run deploys, test runs, anonymous Apex,
   `org display`/`org open`), REST/Tooling API calls, and Salesforce MCP
   connectors. Only sandbox, scratch and personal developer orgs are allowed,
   plus production-type orgs a developer has put on their allowlist with an
   expiry date (approved by Jordan, 2026-10-13): trial orgs, until the trial
   ends, and a brand-new (greenfield) client org that holds no real data yet,
   until its go-live date. If it is unclear whether an org is production,
   Claude must ask rather than check by connecting.
2. **Claude makes no persisting changes to any org.** Developers deploy and
   change data themselves. On non-production orgs Claude may only run
   read-only or non-persisting commands: queries, describes, retrieves,
   `sf project deploy start --dry-run`, and Apex test runs (test DML rolls
   back).
3. **No secrets or personal data are sent to Anthropic.** Credentials,
   tokens, and personal data (SSNs, card numbers, account numbers ...) must
   not enter the transcript, whether through a prompt or through a file or
   command output that a tool pulls in.
4. **No destructive local commands**, such as wiping disks, deleting system
   or home directories, or piping a download into a shell.

## Enforcement status

Keep this table current when a rule's enforcement changes.

| Rule | Enforced by | Status |
|------|-------------|--------|
| 1. No production orgs | `PreToolUse` production-org block ([hooks/lib/orgs.cjs](hooks/lib/orgs.cjs)) | **Enforced** for `sf`/`sfdx` commands, `curl`/`wget`/httpie, inline `python -c`/`node -e`, `WebFetch`, and the same commands inside local shell scripts a command runs ([hooks/lib/scripts.cjs](hooks/lib/scripts.cjs): `$1`/`${1:-x}` and simple `VAR="$1"` assignments are filled in; an org left as a variable asks). Orgs are judged from local CLI files only; trial orgs need an allowlist entry with an expiry date. Gaps: Salesforce MCP connectors; scripts that read an org URL from a file; `--flags-dir` target overrides. A Dev Hub on the firm's production org blocks scratch-org creation unless allowlisted. |
| 2. No persisting org changes | `PreToolUse` no-persisting-changes check ([hooks/lib/writes.cjs](hooks/lib/writes.cjs)) | **Enforced** for any org: real deploys, source deletes, package installs, permission-set and user changes, record writes (`sf data create/update/delete/upsert/import`, REST and curl writes) are denied; anonymous Apex and creating or deleting scratch orgs/sandboxes ask the user. Check-only work (`--dry-run`, `deploy validate`, retrieves, queries, Apex tests) is allowed. Local shell scripts a command runs are read and every command in them is checked (the strongest finding wins). Gaps: writes made by tools the hook can't read (a Node/Python script calling the API, Data Loader), shell scripts over 256 KB or nested more than two deep, and Salesforce MCP connectors. |
| 3. No secrets to Anthropic | `PreToolUse` sensitive-file block and sensitive-field query check ([hooks/lib/soql.cjs](hooks/lib/soql.cjs)); `UserPromptSubmit` and `PostToolUse` scans | **Partial.** Queries are checked before they run, by field name, against any org (sandboxes may hold copied production data). Salesforce CLI credential files and token-printing commands (`sf org display`, `sf org open --url-only`, `sf org list --json`) are blocked, and Salesforce tokens are detected in text. Gaps: field names the rules don't recognise (custom PII without SSN/birth/account/card in its name); anonymous Apex and `sf api request` output; Salesforce MCP connectors; a shell `grep -r`/`rg` over a folder that contains a credential file (its output is scanned afterwards, not blocked). `PostToolUse` scans Bash, Read, Grep and WebFetch results. |
| 4. No destructive commands | `PreToolUse` forbidden-command list | **Enforced.** Rules check only the parts of a command that run: heredoc bodies and quoted prose are ignored, code passed to `bash -c` / `powershell -Command` is checked, and program-only rules (`reboot`, `mkfs`, `diskpart` ...) match only in command position. Local shell scripts a command runs are checked too. Known gap: a destructive command built from variables, or in a non-shell script (Python, Node), isn't seen. |

## Working in this repo

- **Tests are mandatory.** Every rule change ships with tests for what it
  should catch and what it should let through. Run `node test/run-tests.cjs`
  and keep it green.
- **Keep fixtures out of plain sight.** Build secret-shaped test values at
  runtime (for example `'1' + '23-45-6789'`) so that the guard does not flag
  this repo's own files whenever they are read.
- **Never print real credentials while developing.** When you need the layout
  of a credential file (for example a Salesforce CLI auth file), list its
  field names, never its values.
- **Fail open, except where policy says to ask.** A bug in the guard must not
  brick a session, so the default on error or uncertainty is to allow. The
  exception is rule 1, where policy says to ask when unsure.
- **One fix per commit**, straight to `main`, with a message that says what
  false positive or gap it fixes and any trade-off it accepts.
- **After changing the hooks, re-run `node install.cjs`** so the installed
  copy in `~/.claude/safeguards/hooks/` picks up the change.

## Accepted trade-offs

- The shape-only detectors (card, SSN, EIN, IBAN) skip URL hosts and paths,
  where long digit runs are record IDs. An unlabeled card number or SSN in a
  URL path is therefore not detected. Query strings are still scanned, and
  sensitive or credential parameters are flagged by name.
