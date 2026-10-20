# Claude Code Safeguards

1. **Never access a production Salesforce org**, even read-only.
2. **Make no lasting changes to any org**: people deploy and change data.
3. **Don't send secrets or personal data to Anthropic**, whether through a
   prompt or through a file or command result Claude reads.
4. **Don't run destructive local commands** that wipe disks, delete system
   folders, or pipe a download into a shell.

They guard against accidents (a rushed request, a forgotten rule), not
against someone determined to get around them. They act only on what Claude
does: commands you type in your own terminal are never affected.

Everything is **pure Node** — no dependencies, no build step. It runs
identically on macOS, Linux, and Windows, and any machine with Claude Code
already has Node.

## Install

**Requirements:** Node 18+ (`node --version`), git, and Claude Code.

### 1. Download

```bash
git clone https://github.com/thecrmfirm/claude_safeguards.git
cd claude_safeguards
```

No `npm install` — there are no dependencies.

### 2. Install for every project on your machine (recommended)

Run from the cloned directory. This copies the hooks to
`~/.claude/safeguards/hooks/` and wires them into `~/.claude/settings.json`,
first backing up your existing settings to a timestamped
`settings.json.bak-YYYYMMDD-HHMMSS`. Your other settings and hooks are kept. If
`settings.json` isn't valid JSON, the installer stops and changes nothing:

```bash
node install.cjs --dry-run   # optional: print the resulting settings, write nothing
node install.cjs
```

### 3. Restart Claude Code

Settings are read at startup. Either restart Claude Code, or, in a session
that's already open, type `/hooks` and press Enter. A menu listing your hooks
pops up. **You don't need to do anything in it**: opening it is what reloads
the settings. Press **Esc** to close it and carry on.

### 4. Verify

```bash
node test/run-tests.cjs   # expect: All tests passed.
```

Then, in Claude Code, try two things:

- Ask it to read a `.env` file: the tool call should be denied with a reason.
- Ask it to deploy something to one of your sandboxes (without `--dry-run`):
  it should refuse and give you the command to run yourself.

After this, the clone is only needed for updates; the installed copy under
`~/.claude/safeguards/hooks/` is what runs.

### Installing for a single project instead

The project install references hooks at `$CLAUDE_PROJECT_DIR/hooks/`, so copy
`hooks/` to the project root yourself, then run the installer **from that
project root** — it writes to `./.claude/settings.json` and copies nothing:

```bash
cp -R /path/to/claude_safeguards/hooks ./hooks
node /path/to/claude_safeguards/install.cjs --project
```

Or paste the `hooks` block from [settings.sample.json](settings.sample.json)
into your settings by hand.

### Updating

Pull and re-run the installer. It is idempotent — it strips its own previous
entries before adding fresh ones, so entries never stack up:

```bash
git pull && node install.cjs
```

Then restart Claude Code, or type `/hooks` and press **Esc** to close the menu
(see step 3).

### Uninstalling

```bash
node install.cjs --uninstall            # user install
node install.cjs --project --uninstall  # project install, from the project root
```

This removes the hook entries from settings.json. The copied hook files under
`~/.claude/safeguards/` are left in place; delete that directory to remove them.

### Unattended install (SSH, WinRM, RMM/MDM)

For rolling the hooks out to a machine you are not sitting at, use the
bootstrap wrappers instead of the steps above. They clone the repo (or use the
clone they sit in), check for Node 18+, run `install.cjs`, and clean up after
themselves. They never prompt — a missing git credential fails the job rather
than hanging it — and they report a distinct exit code:
`2` bad usage, `3` missing prerequisite, `4` download failed, `5` installer
failed.

```bash
./install.sh --dry-run          # print what would change, write nothing
./install.sh                    # user install -> ~/.claude
./install.sh --ref v1.2.0       # pin to a branch or tag
./install.sh --project /srv/app # project install -> /srv/app/.claude
./install.sh --uninstall
```

```bat
install.bat --dry-run
install.bat
install.bat --ref v1.2.0
install.bat --project C:\src\app
install.bat --uninstall
```

Both take `--repo <url>` for a mirror and `--keep` to leave the temporary clone
behind for inspection.

**Run it as the developer who uses Claude Code.** A user install writes to that
account's own `~/.claude` (`%USERPROFILE%\.claude`), so an RMM agent running as
root or SYSTEM installs into a profile Claude Code will never read.

**Download the script, then run it** — don't pipe it from the network into a
shell. Rule 4 forbids that, and the guard blocks the pattern, so a `curl ... |
bash` rollout would be denied on any machine that already has the hooks.

## What you'll notice

Day to day, with the hooks installed:

- **Claude won't deploy or change data**, in any org. It hands you the exact
  command to run yourself. `--dry-run`, `sf project deploy validate`,
  retrieves, queries and Apex test runs still work.
- **Claude won't touch production orgs**, even to read. Ask it for the query
  and run it yourself, or work in a sandbox.
- **Trial or greenfield org?** Add it to the
  [org allowlist](#allowlist-trial-and-greenfield-orgs) with an expiry date.
- **Some commands ask first**: anonymous Apex, creating or deleting scratch
  orgs and sandboxes, `FIELDS(ALL)` queries. Approve only if you're sure.
- **Queries that select SSN, birthdate or account-number fields are refused.**
  For profiling, `COUNT(field)` works.
- **`sf org display` is blocked** because it prints the org's token. For the
  username, org ID or instance URL, use `sf org list auth`.
- **A message with an SSN, card number or key in it won't be sent.** Mask the
  value and send it again.
- **Commands you type in your own terminal are never affected.**

**Something blocked that shouldn't be, or a warning you can't explain?** Open
an issue. Include the block message, and for a warning, the matching line from
`~/.claude/safeguards/findings.log` (it holds no values, so it's safe to share).

## What it does

| Layer | Hook event | Enforcement | Protection |
|-------|-----------|-------------|------------|
| Sensitive-file read/write block | `PreToolUse` | **Preventive** (denies the tool) | Blocks `Read`/`Edit`/`Write`/`Grep` and shell reads of `.env`, `.envrc`, SSH keys, `.aws/credentials`, `*.pem`, the Salesforce CLI's stored logins (`~/.sfdx/<user>.json`, `key.json`) and saved auth-URL files. |
| Salesforce token commands | `PreToolUse` | **Preventive** (denies the tool) | Blocks commands that print an org's token: `sf org display`, `sf org open --url-only`/`--json`, `sf org list --json`. Use the `sf org list auth` table instead. |
| Destructive command block | `PreToolUse` | **Preventive** (denies the tool) | Blocks recursive deletes of `/`, raw writes to a disk device, filesystem formatting, fork bombs, `curl … \| sh`, force-push to main, and Windows equivalents. |
| Production-org block | `PreToolUse` | **Preventive** (denies the tool) | Blocks `sf`/`sfdx` commands, `curl`-style calls and `WebFetch` that would reach a production Salesforce org. See [below](#production-org-rule). |
| Sensitive-field query check | `PreToolUse` | **Preventive** (denies, or asks the user) | Reads `sf data query` / `sf data search` before it runs: denies queries that select SSN, birthdate, account, routing or card fields; asks before `FIELDS(ALL)` or `sf data get record`. See [below](#sensitive-field-queries). |
| No-persisting-changes check | `PreToolUse` | **Preventive** (denies, or asks the user) | Denies deploys and record writes to any org; asks before anonymous Apex and creating or deleting orgs. See [below](#no-persisting-changes). |
| Prompt secret scan | `UserPromptSubmit` | **Preventive** (blocks the prompt) | Stops a message containing an SSN, card number, API key, private key, Salesforce token, or a pasted query result with an SSN/birthdate/account column from ever being sent to Anthropic. |
| Tool-output secret scan | `PostToolUse` | **Detective** (warns Claude, shows you a notice) | If a Bash, Read, Grep or WebFetch result contains secrets or personal data, tells Claude not to repeat it and shows you a notice; for credentials it advises rotating. Logged to the [findings log](#findings-log). *Best-effort — see Limitations.* |

Detection lives in [hooks/lib/patterns.cjs](hooks/lib/patterns.cjs) — one file of
arrays/regexes you tune for your org. The hook entry point is
[hooks/guard.cjs](hooks/guard.cjs).

## Production-org rule

Claude must never reach a production Salesforce org, even read-only. Before
Claude runs a command, [hooks/lib/orgs.cjs](hooks/lib/orgs.cjs) works out
which org it targets, **using only local files, never by contacting the org**:

- **`sf` / `sfdx` commands:** the `-o`/`--target-org` value (or legacy `-u`),
  else the project's default org, else the global default. The alias is
  resolved to the org's address through the Salesforce CLI's local auth files.
  Scratch-org creation checks the Dev Hub.
- **Direct calls:** `curl`, `wget`, httpie, inline `python -c` / `node -e`
  code, and Claude's `WebFetch`, when they name an org address
  (`*.my.salesforce.com`, `*.lightning.force.com`, `login.salesforce.com`, legacy
  `na123.salesforce.com`). Docs sites like `help.salesforce.com` are not orgs.

An org is **allowed** when its address shows it is a sandbox
(`name--sbx.sandbox.my.salesforce.com`, `name--sbx.my.salesforce.com`,
`cs42.salesforce.com`), a scratch org, a Developer Edition or a Trailhead
playground. Everything else is **blocked**, including an org that isn't logged
in on the machine, and Claude is told to ask you. Commands that never contact
an org (`sf project generate`, `sf alias list`, `sf config set`, `--help` ...)
are always allowed. Commands you type in your own terminal are never affected.

### Allowlist (trial and greenfield orgs)

Some production-type orgs are safe to work in for a while, but their address
looks exactly like production, so they must be allowed by org ID. Add them to
`~/.claude/safeguards/allowed-orgs.json`:

- **Trial orgs**, until the trial ends: use the date from
  `SELECT TrialExpirationDate FROM Organization` (run the query yourself).
- **Greenfield orgs**: a brand-new client org built directly, with no
  sandbox, that holds no real data yet. Use the go-live date (or the date
  real data is first loaded, if earlier).

```json
[
  { "orgId": "00D5g000004XXXXEAA", "expires": "2026-11-05", "note": "NPC trial, Example Co evaluation" },
  { "orgId": "00D8a000001YYYYEAA", "expires": "2026-12-01", "note": "Acme greenfield build, go-live 2026-12-01" }
]
```

`expires` (YYYY-MM-DD) is required: on that date the entry stops working, so a
trial that is bought, or a greenfield org that goes live, is blocked again
without anyone having to remember to remove it. If go-live moves, update the
date. The no-persisting-changes rule still applies to allowlisted orgs. The
installer never touches this file.

## Sensitive-field queries

Sandboxes are allowed by the production-org rule, but a full or partial copy
sandbox holds copied production data, and local files can't tell it from a
developer sandbox. So [hooks/lib/soql.cjs](hooks/lib/soql.cjs) reads every
`sf data query` and `sf data search` (including `--file` queries) **before it
runs**, whatever org it targets:

| The query ... | Result |
|---|---|
| selects a field named like an SSN / tax ID, birthdate, bank or brokerage account number, routing number, card number, passport or driver's license (`SSN__c`, `Contact.Tax_Id__c`, `PersonBirthdate`, a subquery field ...) | **Denied.** Claude is told to profile with `COUNT(field)` instead, or ask you to run it |
| uses `FIELDS(ALL)`, `FIELDS(CUSTOM)`, `FIELDS(STANDARD)` on a person object, or is `sf data get record` | **You're asked** to approve it |
| only counts sensitive fields (`COUNT(SSN__c)`), or writes its output to a file (`--output-file`, `> out.csv`, `sf data export`) | Allowed: no values reach the conversation |

Fields that describe a value rather than hold it (`SSN_or_TIN_Picklist__c`,
`SSN_Verified__c`, `SSN_Last4__c`) are not flagged, nor is a `CC_` client-code
prefix.

## No persisting changes

Claude makes no lasting change to any Salesforce org, sandboxes included:
people deploy and change data themselves.
[hooks/lib/writes.cjs](hooks/lib/writes.cjs) checks every shell command:

| Command | Result |
|---|---|
| `sf project deploy start` (without `--dry-run`), `deploy quick` / `resume`, `sfdx force:source:deploy` / `push`, `sf project delete source`, `sf package install`, permission-set assignment, user and password creation | **Denied.** Claude gives you the exact command to run |
| `sf data create/update/delete/upsert/import` (record, bulk, tree), `sf api request rest -X POST/PUT/PATCH/DELETE`, `curl`/`wget`/httpie writes to an org | **Denied** |
| Anonymous Apex (`sf apex run`), creating, refreshing or deleting a scratch org or sandbox | **You're asked** to approve it |
| `--dry-run`, `sf project deploy validate`, retrieves, queries, exports, `sf apex run test`, logs | Allowed |

A runbook that merely mentions these commands (written to a file with a
heredoc) is not affected.

## Findings log

Each time the after-tool scan flags a result, a line is appended to
`~/.claude/safeguards/findings.log`: the time, the tool, the file (for
Read/Grep), the fields of the tool result, the finding types, and **which
field matched** (`stdout`, `stderr`, `content` ...). Values and commands are
never written. Use it to trace a warning nobody can explain, or to review
false positives during a rollout. Turn it off with
`CLAUDE_SAFEGUARD_LOG=off`; it rolls over at about 1 MB.

## Rollout: warn before you block

For a soft launch, set the mode to `warn`. The guard then logs to stderr but
never blocks — useful for seeing what *would* be caught without disrupting the
team:

```bash
export CLAUDE_SAFEGUARD_MODE=warn   # default is "block"
```

Put this in the shell profile you use to launch Claude Code, or in an `env`
block in settings.json.

## Tuning

Edit [hooks/lib/patterns.cjs](hooks/lib/patterns.cjs):

- `SENSITIVE_FILE_PATTERNS` / `SENSITIVE_FILE_ALLOWLIST` — which paths are secret.
- `FORBIDDEN_COMMANDS` — dangerous shell commands (each has an `id`, `re`, `why`).
- `PII_DETECTORS` — secret/PII regexes, each with an optional `validate()` (e.g.
  the card-network + Luhn check on credit cards to cut false positives).
  Shape-only (`structural`) detectors skip URL hosts/paths, where long digit
  runs are record IDs, but still scan query strings; URL parameters named
  like `dob`, `acct_no`, `sid`, `code` or `X-Amz-Signature` are flagged by name.
- `LABELED_FIELDS` — PII recognized by its column or field name in pasted query
  results (CSV, TSV, markdown, `sf data query` tables, JSON, `Field: value`):
  e.g. 9-digit values under `SSN__c`, dates under `Birthdate`, account numbers
  under `Bank_Account_Number__c`.

**Always re-run the tests after editing, then re-run `node install.cjs`** so the
installed copy picks up your changes:

```bash
node test/run-tests.cjs
```

The suite covers the pattern library directly and drives `guard.cjs` end-to-end
by feeding it real hook events.

## How blocking works

- `PreToolUse` returns **deny**, so the tool call never runs and Claude is told
  why and what to do instead; or **ask**, so Claude Code pauses and you approve
  or decline (used where a command is sometimes harmless, such as anonymous
  Apex or `FIELDS(ALL)`).
- `UserPromptSubmit` returns a `block` decision, so the prompt is discarded
  before transmission and the user sees the reason.
- `PostToolUse` can't block (the tool already ran): it gives Claude
  instructions and shows you a short notice.
- The hook **fails open**: any malformed event or bug in detection results in
  *allow*, never a bricked session. A guard that blocks everything on a bad day
  is worse than one that occasionally misses. **One exception:** the
  production-org rule blocks an `sf` command when it can't tell which org it
  targets (for example, an alias that isn't logged in), because the policy
  says to ask when unsure.

## Limitations (read these)

- **Detection is heuristic.** Regexes catch common shapes of secrets/commands,
  not all of them. This reduces accidents; it is not a guarantee and not a
  substitute for a real DLP tool, `.gitignore` hygiene, or a secrets manager.
- **The `PostToolUse` layer is detective, not preventive.** By the time a tool
  has run, its output is already in the transcript. The hook can warn Claude and
  the user, but it cannot un-send data. The strong guards are the preventive
  `PreToolUse` checks — keep sensitive files matched by
  `SENSITIVE_FILE_PATTERNS` so they're blocked *before* a read.
- **Only what the hook can read is checked.** Local shell scripts a command
  runs (`./seed.sh my-org`, `bash deploy.sh`) are read and their `sf` commands
  checked, but a Python or Node script that calls the Salesforce API itself,
  Data Loader, or a Salesforce MCP connector isn't seen.
- **Expect some false positives/negatives.** Tune the patterns for your
  codebase, and keep `SENSITIVE_FILE_ALLOWLIST` (template files such as
  `.env.example`) current. That file allowlist is separate from the
  [org allowlist](#allowlist-trial-and-greenfield-orgs).

## Files

```
hooks/guard.cjs          entry point; branches on hook_event_name
hooks/lib/patterns.cjs   detection rules — tune these
hooks/lib/orgs.cjs       production-org rule (target resolution, allowlist)
hooks/lib/soql.cjs       sensitive-field query check
hooks/lib/writes.cjs     no-persisting-changes check
hooks/lib/io.cjs         stdin/stdout hook protocol helpers
install.cjs              idempotent installer / uninstaller
settings.sample.json     hook wiring to merge by hand
test/run-tests.cjs       test suite — run after any edit
```
