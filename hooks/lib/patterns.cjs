/*
 * Shared detection logic for the Claude Code safeguard hooks.
 *
 * This file is pure Node.js (no dependencies) so it runs identically on
 * macOS, Linux, and Windows. Every machine that has Claude Code installed
 * already has Node, so no extra runtime is required.
 *
 * Tune the arrays/regexes below to fit your organization, then re-run the
 * test suite (node test/run-tests.cjs) before redistributing.
 */

'use strict';

// ---------------------------------------------------------------------------
// 1. SENSITIVE FILES  — reading these should be blocked entirely
// ---------------------------------------------------------------------------
// Matched against a normalized (forward-slash, lower-cased) file path.
const SENSITIVE_FILE_PATTERNS = [
  // dotenv files (.env, .env.local, .env.production ...) but NOT .env.example / .env.sample / .env.template
  /(^|\/)\.env(\.[a-z0-9_-]+)?$/i,
  // AWS credentials & config
  /(^|\/)\.aws\/(credentials|config)$/i,
  // SSH private keys
  /(^|\/)\.ssh\/(id_[a-z0-9]+|.*_rsa|.*_dsa|.*_ecdsa|.*_ed25519)$/i,
  /(^|\/)\.ssh\/identity$/i,
  // Cloud provider credentials
  /(^|\/)\.gcp\//i,
  /(^|\/)gcloud\/.*credential/i,
  /(^|\/)\.azure\/(credentials|accessTokens\.json)$/i,
  /(^|\/)\.kube\/config$/i,
  // Package registry / npm / pypi / docker tokens
  /(^|\/)\.npmrc$/i,
  /(^|\/)\.pypirc$/i,
  /(^|\/)\.docker\/config\.json$/i,
  // credential/secret files, by name.
  //
  // Deliberately NOT matched as a bare word. The previous rule here was
  //   /(^|\/)(credentials|secret|secrets)(\.[a-z0-9]+)?$/i
  // which matched the token "secret" with nothing around it. Because
  // commandTouchesSensitiveFile splits a command on quotes as well as
  // whitespace, `grep -rn "secret" src/` and `ls secrets` were blocked despite
  // touching no such file. A name now has to look like a path or a file:
  // a directory separator, or an extension.
  //
  // a) exact name carrying extensions -> secrets.json, credentials.yml.enc
  /(^|\/)(credentials?|secrets?)(\.[a-z0-9]+)+$/i,
  // b) exact name qualified by a directory -> ~/.aws/credentials, ./secrets
  /\/(credentials?|secrets?)$/i,
  // c) anything inside a secrets/ directory -> secrets/db.json
  /(^|\/)(credentials?|secrets?)\//i,
  // d) the names vendors actually ship, where the word carries a prefix or a
  //    suffix: client_secret_817.json (Google), new_user_credentials.csv (the AWS
  //    console), app-secrets.json, secret_key.txt. Restricted to data and config
  //    extensions, so a script like update-secrets.sh still runs.
  /(^|\/)[a-z0-9_.-]*(credentials?|secrets?)([_-][a-z0-9_-]*)?\.(json|ya?ml|toml|ini|cfg|conf|csv|tsv|properties|plist|xml|tfvars|enc|txt|dat)$/i,
  /(^|\/).*\.(pem|pfx|p12|key|keystore|jks)$/i,
  /(^|\/)id_rsa$/i,
  // Cloud CLI / terraform state (often contains secrets)
  /(^|\/)terraform\.tfstate(\.backup)?$/i,
  // Browser / OS credential stores
  /(^|\/)\.netrc$/i,
  /(^|\/)\.pgpass$/i,
  // direnv: exports environment variables, often tokens and passwords
  /(^|\/)\.envrc$/i,
  // Salesforce CLI credential store: one <username>.json per login (access
  // and refresh tokens) plus the key that encrypts them. The project-level
  // .sf/config.json and the alias list hold no secrets and stay readable.
  /(^|\/)\.sfdx\/[^/]*@[^/]*\.json$/i,
  /(^|\/)\.(sf|sfdx)\/key\.json$/i,
  // SFDX auth URL files saved for `sf org login sfdx-url` (refresh token inside)
  /(^|\/)[^/]*auth[_-]?url[^/]*\.(txt|json)$/i,
];

// Files that LOOK sensitive but are safe templates — explicitly allowed.
const SENSITIVE_FILE_ALLOWLIST = [
  /(^|\/)\.env\.(example|sample|template|dist|defaults)$/i,
  /(^|\/)\.env\.example\.[a-z0-9]+$/i,
  // Prose *about* credentials is not a credential. Blocking docs/secrets.md taught
  // people the guard was noise rather than teaching them anything about secrets.
  /\.(md|mdx|rst|adoc|html?)$/i,
  // Test files, by the near-universal .test./.spec. convention.
  /\.(test|spec)\.[a-z0-9]+$/i,
  // Templates and fixtures that are committed on purpose.
  /(^|\/)[a-z0-9_.-]*(example|sample|template|fixture|dummy|placeholder)[a-z0-9_.-]*\.[a-z0-9]+$/i,
];

function normalizePath(p) {
  if (!p) return '';
  return String(p).replace(/\\/g, '/');
}

function isSensitiveFile(filePath) {
  const p = normalizePath(filePath);
  if (!p) return false;
  if (SENSITIVE_FILE_ALLOWLIST.some((re) => re.test(p))) return false;
  return SENSITIVE_FILE_PATTERNS.some((re) => re.test(p));
}

/*
 * Remove heredoc bodies that are data, e.g. a runbook written with
 * `cat > DEPLOY.md <<'EOF'`: its deploy commands are text, not commands.
 * A heredoc fed to a shell (`bash <<EOF`, `sh -s <<EOF`, `ssh host <<EOF`)
 * IS code, so its body is kept and checked like any other command.
 */
const SHELL_FED = /(?:^|[;&|(]\s*|\b(?:sudo|exec|env)\s+)(?:bash|sh|zsh|dash|ksh|pwsh|powershell|ssh)\b[^;&|<]*$/i;

function stripHeredocs(text) {
  const kept = [];
  let delim = null;
  let keepBody = false;
  for (const line of String(text || '').split('\n')) {
    if (delim !== null) {
      if (line.trim() === delim) delim = null;
      else if (keepBody) kept.push(line);
      continue;
    }
    kept.push(line);
    const m = /<<-?\s*(['"]?)([A-Za-z_][\w-]*)\1/.exec(line);
    if (m) {
      delim = m[2];
      keepBody = SHELL_FED.test(line.slice(0, m.index));
    }
  }
  return kept.join('\n');
}

/*
 * The parts of a shell command that will actually execute.
 *
 * Matching rules against the raw string blocked commands that merely MENTION
 * something: `git commit -m "fix reboot loop"`, a heredoc that writes a README
 * describing `rm -rf /`, `echo "don't commit .env"`. So:
 *   - heredoc bodies are dropped (they are data fed to a command);
 *   - quoted text that reads like prose (contains whitespace and doesn't
 *     start like a path) is blanked; a quoted single word or path ("/",
 *     ".env", "C:\Program Files") is kept, so quoting can't hide a target;
 *   - code handed to a shell (`bash -c "..."`, `powershell -Command "..."`)
 *     is extracted and returned as an extra string, so it is still checked.
 */
function activeCode(command, depth = 0) {
  const text = String(command || '');
  // 1. Drop heredoc bodies that are data (kept when fed to a shell).
  const noHeredoc = stripHeredocs(text);

  // 2. Code handed to a shell is still code.
  const nested = [];
  if (depth < 3) {
    const SHELL_C = /\b(?:bash|sh|zsh|dash|ksh|pwsh|powershell|cmd)(?:\.exe)?\s+(?:-[a-z]*c|-command|\/c)\s+(?:"((?:[^"\\]|\\.)*)"|'([^']*)')/gi;
    let m;
    while ((m = SHELL_C.exec(noHeredoc)) !== null) {
      nested.push(...activeCode(m[1] != null ? m[1] : m[2], depth + 1));
    }
  }

  // 3. Blank prose in quotes; keep single words and paths.
  const blanked = noHeredoc.replace(/"((?:[^"\\]|\\.)*)"|'([^']*)'/g, (all, dq, sq) => {
    const s = dq != null ? dq : sq;
    const pathLike = /^([/~.$]|[a-z]:\\)/i.test(s);
    return /\s/.test(s) && !pathLike ? ' _ ' : ` ${s} `;
  });
  return [blanked, ...nested];
}

// Detect commands that read a sensitive file, e.g.  cat .env  /  type .aws\credentials
// We look for a sensitive-looking token in the parts of the command that run.
function commandTouchesSensitiveFile(command) {
  if (!command) return null;
  for (const code of activeCode(command)) {
    // Split on whitespace and common shell separators to inspect each token.
    const tokens = code.split(/[\s|;&><'"()`]+/).filter(Boolean);
    for (const tok of tokens) {
      if (isSensitiveFile(tok)) return tok;
      // bare .env reference or path fragment
      const p = normalizePath(tok);
      if (SENSITIVE_FILE_ALLOWLIST.some((re) => re.test(p))) continue;
      if (SENSITIVE_FILE_PATTERNS.some((re) => re.test(p))) return tok;
    }
  }
  return null;
}

// Where a program name can appear: start of the command, after a separator,
// or after a wrapper such as sudo. Used for rules that are only dangerous as
// the command being run (`reboot`), not as a word in an argument (`--reboot`).
const CMD_POS = String.raw`(?:^|[;&|(){}\n]\s*|\b(?:sudo|exec|nohup|time|xargs|env|command|then|do|else)\s+)`;
const atCommand = (re) => new RegExp(CMD_POS + re.source, re.flags.includes('i') ? 'im' : 'm');

// ---------------------------------------------------------------------------
// 2. FORBIDDEN COMMANDS  — dangerous shell operations, macOS + Windows
// ---------------------------------------------------------------------------
// Each entry: { id, re, why }.  `re` is tested against activeCode(command):
// heredoc bodies and quoted prose removed, shell -c payloads included.
// Rules for programs that are only dangerous when RUN use atCommand().
const FORBIDDEN_COMMANDS = [
  // ---- Destructive filesystem deletion (Unix / macOS) ----
  { id: 'rm-rf-root', re: /\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r)\b[^\n]*\s+\/(\s|$)/i, why: 'Recursive force-delete of filesystem root' },
  { id: 'rm-rf-root-star', re: /\brm\s+-[a-z]*rf?[a-z]*\s+(\/\*|\/\s|~\s*$|--no-preserve-root)/i, why: 'Recursive force-delete of root, home, or /* ' },
  { id: 'rm-no-preserve-root', re: /--no-preserve-root/i, why: 'Explicitly disables root-deletion guard' },
  { id: 'rm-rf-home', re: /\brm\s+-[a-z]*rf?[a-z]*\s+(\$HOME|~)(\/|\s|$)/i, why: 'Recursive force-delete of the home directory' },

  // ---- Disk / partition destruction (Unix / macOS) ----
  { id: 'dd-to-disk', re: /\bdd\b[^\n]*\bof=\/dev\/(disk|sd|nvme|hd|rdisk)/i, why: 'dd writing directly to a raw disk device' },
  { id: 'mkfs', re: atCommand(/mkfs(\.[a-z0-9]+)?\b/i), why: 'Formatting a filesystem' },
  { id: 'diskutil-erase', re: /\bdiskutil\s+(erase|reformat|partitionDisk|zeroDisk)/i, why: 'macOS diskutil erase/reformat' },
  { id: 'fdisk-write', re: atCommand(/(fdisk|gpart|parted)\b[^\n]*\b(delete|destroy|-d)\b/i), why: 'Partition table destruction' },
  { id: 'overwrite-dev', re: />\s*\/dev\/(sd|disk|nvme|hd|rdisk)[a-z0-9]*/i, why: 'Redirecting output onto a raw disk device' },

  // ---- Fork bombs / resource exhaustion ----
  { id: 'fork-bomb', re: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, why: 'Classic bash fork bomb' },
  { id: 'fork-bomb-generic', re: /\)\s*\{\s*[a-z]+\s*\|\s*[a-z]+\s*&\s*\}\s*;/i, why: 'Fork-bomb style self-recursive function' },

  // ---- Piping the internet straight into a shell ----
  { id: 'curl-pipe-sh', re: /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python[0-9.]*|node|perl|ruby)\b/i, why: 'Downloading and executing a remote script unseen' },
  { id: 'iwr-pipe-iex', re: /\b(iwr|invoke-webrequest|curl|wget)\b[^\n|]*\|\s*(iex|invoke-expression)\b/i, why: 'PowerShell download-and-execute of remote code' },
  { id: 'iex-download', re: /iex\s*\(\s*(new-object\s+net\.webclient|iwr|invoke-webrequest)/i, why: 'PowerShell in-memory remote code execution' },

  // ---- Privilege / ownership changes that break systems ----
  { id: 'chmod-777-root', re: /\bchmod\s+-[a-z]*R[a-z]*\s+777\s+\/(\s|$)/i, why: 'Recursive chmod 777 on filesystem root' },
  { id: 'chown-root-recursive', re: /\bchown\s+-[a-z]*R[a-z]*\s+[^\s]+\s+\/(\s|$)/i, why: 'Recursive chown on filesystem root' },

  // ---- Windows: destructive deletion ----
  { id: 'win-del-systemroot', re: /\bdel\s+\/[a-z\s\/]*\b[cC]:\\(windows|users|program files)/i, why: 'Deleting Windows system directories' },
  { id: 'win-rmdir-root', re: /\b(rd|rmdir)\s+\/s\b[^\n]*\b[a-z]:\\?(\s|$)/i, why: 'Recursive removal of a drive root on Windows' },
  { id: 'win-del-force-root', re: /\bdel\s+\/[fsq\s\/]*\s+[a-z]:\\\*/i, why: 'Force delete of a drive root on Windows' },
  { id: 'ps-remove-recurse-root', re: /remove-item\b[^\n]*-recurse[^\n]*(-force)?[^\n]*\b([a-z]:\\|\$env:systemroot|\/)/i, why: 'PowerShell recursive Remove-Item on system root' },

  // ---- Windows: disk / partition destruction ----
  { id: 'win-format', re: atCommand(/format(\.com)?\s+[a-z]:/i), why: 'Formatting a Windows drive' },
  { id: 'win-diskpart-clean', re: atCommand(/diskpart\b/i), why: 'diskpart can wipe partitions non-interactively' },
  { id: 'win-clear-disk', re: /\bclear-disk\b/i, why: 'PowerShell Clear-Disk wipes a disk' },
  { id: 'win-cipher-wipe', re: atCommand(/cipher\s+\/w/i), why: 'cipher /w securely wipes free space' },

  // ---- System control / bricking ----
  { id: 'win-bcdedit', re: /\bbcdedit\b[^\n]*\/(delete|deletevalue|set)/i, why: 'Editing the Windows boot configuration' },
  { id: 'win-shutdown', re: atCommand(/shutdown\s+\/[rsp]/i), why: 'Forced shutdown/restart of the machine' },
  { id: 'win-reg-delete-hive', re: /\breg\s+delete\s+hk(lm|ey_local_machine)\\?(\s|\\)/i, why: 'Deleting a root registry hive' },
  { id: 'win-vssadmin-delete', re: /\bvssadmin\s+delete\s+shadows/i, why: 'Deleting shadow copies (ransomware behavior)' },
  { id: 'win-wbadmin-delete', re: /\bwbadmin\s+delete\b/i, why: 'Deleting Windows backups' },
  { id: 'win-bcdedit-recovery', re: /bcdedit\b[^\n]*recoveryenabled\s+no/i, why: 'Disabling Windows recovery' },

  // ---- Powering off / killing the machine ----
  { id: 'unix-shutdown', re: atCommand(/(shutdown|halt|poweroff|reboot|init\s+0)\b(?![.\-])/i), why: 'Powering off or rebooting the machine' },
  { id: 'kill-init', re: /\bkill(all)?\s+-9\s+1\b/i, why: 'Killing PID 1 / init' },

  // ---- Git history / force destruction (optional, comment out if too strict) ----
  { id: 'git-push-force-main', re: /\bgit\s+push\b[^\n]*(--force|-f)\b[^\n]*\b(origin\s+)?(main|master|prod|production)\b/i, why: 'Force-pushing over a protected branch' },
];

function findForbiddenCommand(command) {
  if (!command) return null;
  for (const code of activeCode(command)) {
    for (const rule of FORBIDDEN_COMMANDS) {
      if (rule.re.test(code)) return rule;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// 3. BINARY / OPAQUE CONTENT  — recognize it so we never scan it
// ---------------------------------------------------------------------------
// The detectors below are written for prose and config text. Run them over the
// bytes of a PNG — or over the base64 Claude Code sends back for an image read
// — and they fire constantly on byte sequences that merely look like an ID
// number. A real SSN or card number cannot hide in those bytes in a form a
// regex would find anyway, so the correct move is to recognize binary and skip.

const BINARY_FILE_EXTENSIONS = new Set([
  // images
  'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'tif', 'tiff', 'ico', 'icns',
  'heic', 'heif', 'avif', 'psd', 'ai', 'eps', 'raw', 'cr2', 'nef',
  // audio / video
  'mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a', 'mp4', 'mov', 'avi', 'mkv',
  'webm', 'wmv', 'm4v',
  // archives & compressed
  'zip', 'gz', 'tgz', 'bz2', 'xz', 'zst', '7z', 'rar', 'tar', 'jar', 'war',
  // office & documents
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'odt', 'ods',
  'odp', 'rtf',
  // fonts
  'woff', 'woff2', 'ttf', 'otf', 'eot',
  // compiled / binary data
  'so', 'dylib', 'dll', 'exe', 'bin', 'o', 'a', 'obj', 'lib', 'class',
  'pyc', 'pyo', 'wasm', 'dat', 'db', 'sqlite', 'sqlite3', 'mdb',
  'parquet', 'avro', 'orc', 'npy', 'npz', 'pkl', 'pickle', 'h5', 'hdf5',
  'pt', 'pth', 'onnx', 'safetensors', 'gguf', 'dmg', 'iso', 'img',
]);

function isBinaryPath(filePath) {
  const m = /\.([a-z0-9]+)$/i.exec(normalizePath(filePath));
  return !!m && BINARY_FILE_EXTENSIONS.has(m[1].toLowerCase());
}

// Content-based fallback for paths we can't judge by extension (e.g. the
// stdout of `cat some-image`). Binary decoded as UTF-8 is full of NULs,
// control bytes, and U+FFFD replacement characters; text is not.
function looksBinary(text) {
  if (!text) return false;
  const sample = String(text).slice(0, 8192);
  if (!sample.length) return false;
  if (sample.indexOf('\u0000') !== -1) return true;
  let odd = 0;
  for (let i = 0; i < sample.length; i++) {
    const c = sample.charCodeAt(i);
    // control bytes other than tab/LF/VT/FF/CR, DEL, and the U+FFFD that
    // appears wherever invalid UTF-8 was decoded.
    if (c < 0x09 || (c > 0x0d && c < 0x20) || c === 0x7f || c === 0xfffd) odd++;
  }
  return odd / sample.length > 0.02;
}

// The other big noise source is base64/hex embedded *inside* otherwise normal
// text: data: URIs in HTML, integrity hashes in lockfiles, minified bundles,
// a `base64 image.png` in a shell transcript. Blank those runs out before the
// structural (shape-only) detectors run. Labeled detectors still see the
// original text, so a genuine `aws_secret_access_key=...` is unaffected.
// The upper bounds are not a length limit on what gets stripped: the regex is
// global, so a longer run is simply consumed in consecutive chunks. They exist
// because V8 overflows its stack building a single multi-megabyte match, which
// a base64-encoded image is.
const OPAQUE_RUN =
  /data:[^;,\s]*;base64,[A-Za-z0-9+/=]{1,4096}|[A-Za-z0-9+/=_-]{64,4096}/g;

// The host and path of a URL are opaque to the structural detectors too. Record
// and object IDs in links (Asana, Jira, Zendesk, Box ...) are long digit runs,
// so a pasted link was blocked as a "credit card". The query string and
// fragment are different: that is where a form or a careless integration puts
// submitted values, so those are kept (keys and values split onto separate
// words) and still scanned. Labeled detectors always see the original text.
// The class is a single negated set with no alternation, so V8 matches a long
// URL in place.
const URL_RUN = /\b(?:https?|ftps?|sftp|file):\/\/[^\s<>"'`]+|\bwww\.[^\s<>"'`]+/gi;

function urlQueryText(url) {
  const at = url.search(/[?#]/);
  if (at === -1) return ' ';
  let tail = url.slice(at + 1).replace(/\+/g, ' ');
  try {
    tail = decodeURIComponent(tail);
  } catch {
    /* malformed %-escape: scan it as-is */
  }
  return ' ' + tail.replace(/[?#&;=]/g, ' ') + ' ';
}

function stripOpaqueRuns(text) {
  return String(text).replace(URL_RUN, urlQueryText).replace(OPAQUE_RUN, ' ');
}

// ---------------------------------------------------------------------------
// 4. PII / SENSITIVE DATA  — content that must not be sent to Anthropic
// ---------------------------------------------------------------------------

// SSN-shaped values that are never real: one repeated digit (111-11-1111, a
// common test value) and well-known samples. 123-45-6789 is the textbook
// example; 078-05-1120 and 219-09-9999 were printed in advertisements and
// voided by the SSA. Skipping them keeps test classes and docs quiet.
const SAMPLE_SSNS = new Set(['123456789', '078051120', '219099999']);

function isPlaceholderSSN(value) {
  const d = String(value).replace(/\D/g, '');
  if (d.length !== 9) return false;
  return /^(\d)\1{8}$/.test(d) || SAMPLE_SSNS.has(d);
}

// Luhn check to reduce credit-card false positives.
function luhnValid(number) {
  const digits = String(number).replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i], 10);
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// Issuer prefix + length for the networks a US firm will actually see. One in
// ten random digit runs passes Luhn; a run must also look like a real card
// from a real network, which most record IDs (wrong prefix or wrong length)
// do not.
const CARD_NETWORKS = [
  { name: 'Visa', re: /^4/, lengths: [13, 16, 19] },
  { name: 'Mastercard', re: /^(5[1-5]|2(22[1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720))/, lengths: [16] },
  { name: 'Amex', re: /^3[47]/, lengths: [15] },
  { name: 'Discover', re: /^(6011|64[4-9]|65)/, lengths: [16, 17, 18, 19] },
  { name: 'Diners', re: /^3(0[0-5]|[689])/, lengths: [14, 15, 16, 17, 18, 19] },
  { name: 'JCB', re: /^35(2[89]|[3-8]\d)/, lengths: [16, 17, 18, 19] },
  { name: 'UnionPay', re: /^62/, lengths: [16, 17, 18, 19] },
  { name: 'Maestro', re: /^(5018|5020|5038|6304|6759|676[1-3])/, lengths: [13, 14, 15, 16, 17, 18, 19] },
];

function cardValid(number) {
  const digits = String(number).replace(/\D/g, '');
  const network = CARD_NETWORKS.some(
    (n) => n.re.test(digits) && n.lengths.includes(digits.length)
  );
  return network && luhnValid(digits);
}

// ISO 13616 mod-97 check — an IBAN-shaped run of characters is common in
// base64 and hex; a run that also checksums is not.
function ibanValid(value) {
  const s = String(value).replace(/[\s-]/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (let i = 0; i < rearranged.length; i++) {
    const ch = rearranged[i];
    const digits = ch >= 'A' ? String(ch.charCodeAt(0) - 55) : ch;
    for (let j = 0; j < digits.length; j++) {
      rem = (rem * 10 + Number(digits[j])) % 97;
    }
  }
  return rem === 1;
}

/*
 * Each detector returns match objects { type, sample } for reporting.
 *
 * `structural: true` marks a detector that recognizes a *shape* (a run of
 * digits, a country code followed by check digits) with no surrounding label
 * to corroborate it. Those run against text with URL hosts/paths and opaque
 * base64/hex runs stripped out, because inside such a run the shape means
 * nothing; URL query strings are still scanned. Detectors
 * without the flag carry their own context — a label, or a distinctive vendor
 * prefix — so they see the text as-is.
 */
const PII_DETECTORS = [
  {
    type: 'US Social Security Number',
    // 3-2-4 with separators; avoids 000/666/900-999 area and all-zero groups
    re: /\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g,
    structural: true,
    validate: (m) => !isPlaceholderSSN(m),
  },
  {
    type: 'Credit Card Number',
    re: /\b(?:\d[ -]*?){13,19}\b/g,
    structural: true,
    validate: (m) => cardValid(m),
  },
  {
    type: 'US Passport Number',
    re: /\bpassport\s*(?:no\.?|number|#)?\s*[:#]?\s*([A-Z]?\d{8,9})\b/gi,
    validate: () => true,
  },
  {
    type: 'US EIN (Employer ID)',
    // Guarded on both sides so we don't match a slice out of a longer run of
    // digits and dashes (part numbers, ISBNs, timestamps).
    re: /(?<![\d-])\d{2}-\d{7}(?![\d-])/g,
    structural: true,
    validate: () => true,
  },
  {
    type: "US Driver's License (labeled)",
    // The spelled-out label is specific enough to stand on its own. The "DL"
    // abbreviation is not: `\b` fires at every +, / and = in base64, so bare
    // `dl` matched tens of times in a single encoded image. Require an
    // explicit separator after the abbreviation.
    re: /\b(?:driver'?s?\s*licen[sc]e)\s*(?:no\.?|number|#)?\s*[:#]?\s*([A-Z0-9]{6,15})\b|\bDL\s*(?:no\.?|number)?\s*[:#]{1,2}\s*([A-Z0-9]{6,15})\b/gi,
    validate: () => true,
  },
  {
    type: 'IBAN',
    re: /(?<![A-Za-z0-9])[A-Z]{2}\d{2}[A-Z0-9]{11,30}(?![A-Za-z0-9])/g,
    structural: true,
    validate: (m) => ibanValid(m),
  },
  {
    type: 'Private Key Block',
    re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/g,
    validate: () => true,
  },
  {
    type: 'AWS Access Key ID',
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    validate: () => true,
  },
  {
    type: 'AWS Secret Access Key (labeled)',
    re: /aws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9\/+]{40}['"]?/gi,
    validate: () => true,
  },
  {
    type: 'Google API Key',
    re: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    validate: () => true,
  },
  {
    type: 'Slack Token',
    re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    validate: () => true,
  },
  {
    type: 'Generic Bearer/API secret (labeled)',
    re: /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|password|passwd)\s*[=:]\s*['"]?[A-Za-z0-9\-_\/+]{12,}['"]?/gi,
    validate: () => true,
  },
  {
    // A URL parameter whose NAME says what the value is. The name is the
    // label, so the value needs no particular shape, only some digits (which
    // rules out e.g. a mailto `cc=` address).
    type: 'Sensitive URL parameter',
    re: /[?&#;](?:ssn|social[_-]?security(?:[_-]?num(?:ber)?)?|cc|ccn|cc[_-]?num(?:ber)?|card[_-]?(?:no|num(?:ber)?)|pan|cvv2?|cvc|acct[_-]?(?:no|num(?:ber)?)|account[_-]?num(?:ber)?|routing(?:[_-]?num(?:ber)?)?|aba|iban|dob|birth[_-]?date|date[_-]?of[_-]?birth|tin|tax[_-]?id|ein|passport(?:[_-]?(?:no|num(?:ber)?))?|dl[_-]?(?:no|num(?:ber)?)|drivers?[_-]?licen[cs]e)=([^&#\s"'<>]+)/gi,
    validate: (m) => (m.match(/\d/g) || []).length >= 4,
  },
  {
    // Credentials that travel in URLs: Salesforce front-door `sid`, OAuth
    // `code`/`id_token`, AWS SigV4 and Azure SAS signatures, Zoom `pwd`, and
    // generic `token`/`key`/`secret`. Short values (`code=US`, `key=name`)
    // are not credentials, hence the 16-character floor. The generic labeled
    // detector above already covers access_token, api_key, client_secret and
    // password.
    type: 'Credential in URL parameter',
    re: /[?&#;](?:sid|session[_-]?id|jsessionid|id[_-]?token|refresh[_-]?token|auth[_-]?token|oauth[_-]?token|token|code|x-amz-signature|x-amz-credential|x-amz-security-token|sig|signature|key|secret|pwd|pass)=([A-Za-z0-9._~%+/=!:-]{16,})/gi,
    validate: () => true,
  },
  {
    // Salesforce access tokens and session IDs share one shape: the 15/18
    // character org ID, "!", then a long opaque string.
    type: 'Salesforce access token / session ID',
    re: /\b00D[A-Za-z0-9]{12,15}![A-Za-z0-9._]{40,}/g,
    validate: () => true,
  },
  {
    // `sf org display --verbose` prints this; it embeds a refresh token.
    type: 'Salesforce auth URL',
    re: /force:\/\/[^\s'"<>]*::[^\s'"<>@]{16,}@[^\s'"<>]+/g,
    validate: () => true,
  },
  {
    type: 'Salesforce refresh token',
    re: /\b5Aep8[0-9A-Za-z._]{50,}/g,
    validate: () => true,
  },
];

// ---------------------------------------------------------------------------
// 5. LABELED FIELDS  — PII identified by its column / field name
// ---------------------------------------------------------------------------
// The shape detectors above can't flag a bare 9-digit number as an SSN: on its
// own it could be anything. But query results carry their own labels. A pasted
// CSV or `sf data query` table with an `SSN__c` column, or JSON with
// "SSN__c":"...", says exactly what the digits are. This is the accident the
// guard most needs to catch: profiling a real org and pasting a SELECT of all
// fields back into the session.
//
// Field names are split into words (snake_case, camelCase, spaces, Salesforce
// namespace prefix and __c suffix), so `Contact_SSN__c` and `SocialSecurityNumber`
// match while `ClassName` (which merely contains the letters "ssn") does not.

function abaValid(digits) {
  if (!/^\d{9}$/.test(digits)) return false;
  const d = digits.split('').map(Number);
  const sum = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8]);
  return sum % 10 === 0;
}

const LABELED_FIELDS = [
  {
    type: 'SSN / tax ID (labeled field)',
    name: (w, j) =>
      w.includes('ssn') ||
      /socialsecurity/.test(j) ||
      ['tin', 'itin', 'taxid', 'taxidnumber', 'taxpayerid', 'federaltaxid'].includes(j),
    value: (v) => /^\d{3}[- ]?\d{2}[- ]?\d{4}$/.test(v) && !isPlaceholderSSN(v),
  },
  {
    type: 'Birthdate (labeled field)',
    name: (w, j) => w.includes('dob') || /birth/.test(j),
    value: (v) => /^(\d{4}-\d{1,2}-\d{1,2}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})([T ].*)?$/.test(v),
  },
  {
    type: 'Financial account number (labeled field)',
    // Bank and brokerage accounts. Needs a number word, so a lookup such as
    // Bank_Account__c (a record reference) doesn't count on its name alone.
    name: (w, j) =>
      w.some((x) => ['bank', 'brokerage', 'broker', 'checking', 'savings', 'investment'].includes(x)) &&
      /(account|acct)/.test(j) &&
      /(number|num|no)$/.test(j),
    value: (v) => /^\d{4,17}$/.test(v.replace(/[\s-]/g, '')),
  },
  {
    type: 'Bank routing number (labeled field)',
    name: (w, j) => w.includes('routing') || w.includes('aba'),
    value: (v) => abaValid(v.replace(/[\s-]/g, '')),
  },
];

// "Contact_SSN__c" -> ['contact', 'ssn'];  "SocialSecurityNumber" -> ['social', 'security', 'number']
function fieldWords(name) {
  return String(name)
    .replace(/__(c|r|pc)$/i, '')
    .replace(/^[a-z0-9]+__(?=[a-z])/i, '') // managed-package namespace
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

// The labeled-field rule for a header cell or key, or null. Only short,
// field-like names qualify, so a sentence that mentions an SSN is not a header.
function fieldRuleFor(name) {
  const s = String(name).trim().replace(/^["']|["']$/g, '');
  if (!/^[A-Za-z][\w .()-]{0,60}$/.test(s)) return null;
  const words = fieldWords(s);
  if (!words.length || words.length > 5) return null;
  const joined = words.join('');
  return LABELED_FIELDS.find((f) => f.name(words, joined)) || null;
}

function cleanCell(v) {
  return String(v == null ? '' : v).trim().replace(/^["']|["']$/g, '').trim();
}

// Minimal CSV/TSV splitter that respects double quotes ("Lee, Ann").
function splitRow(line, delim) {
  if (delim !== ',') return line.split(delim);
  const out = [];
  let cur = '';
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (q && line[i + 1] === '"') { cur += '"'; i++; } else q = !q;
    } else if (ch === ',' && !q) {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  out.push(cur);
  return out;
}

// Table borders and markdown separator rows: skip, don't end the table.
const RULE_LINE = /^[\s\-=+:|│┃─━┄┈┼├┤┌┐└┘┬┴╋╭╮╰╯]*$/;
const MAX_TABLE_ROWS = 5000;

function scanLabeledFields(text) {
  const hits = []; // { type, value }
  const lines = String(text).split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const header = lines[i];
    if (!/[A-Za-z]/.test(header) || header.length > 4000) continue;

    // 1. Delimited tables: sf box tables, TSV (spreadsheet paste), markdown, CSV.
    const delim = ['│', '\t', '|', ','].find((d) => header.includes(d));
    if (delim) {
      const cols = splitRow(header, delim)
        .map((c, idx) => ({ idx, rule: fieldRuleFor(c) }))
        .filter((c) => c.rule);
      if (!cols.length) continue;
      for (let r = i + 1; r < lines.length && r <= i + MAX_TABLE_ROWS; r++) {
        const row = lines[r];
        if (RULE_LINE.test(row)) {
          if (!row.trim()) break; // blank line ends the table
          continue;
        }
        if (!row.includes(delim)) break;
        const cells = splitRow(row, delim);
        for (const c of cols) {
          const v = cleanCell(cells[c.idx]);
          if (v && c.rule.value(v)) hits.push({ type: c.rule.type, value: v });
        }
      }
      continue;
    }

    // 2. Space-aligned tables (classic `sf data query` output): values start
    //    at the same character offset as their column header.
    const tokens = [...header.matchAll(/\S+/g)];
    if (tokens.length < 2) continue;
    const cols = tokens
      .map((t) => ({ at: t.index, rule: fieldRuleFor(t[0]) }))
      .filter((c) => c.rule);
    if (!cols.length) continue;
    for (let r = i + 1; r < lines.length && r <= i + MAX_TABLE_ROWS; r++) {
      const row = lines[r];
      if (!row.trim()) break;
      if (RULE_LINE.test(row)) continue;
      for (const c of cols) {
        const m = /^(\S+)/.exec(row.slice(c.at));
        if (m && c.rule.value(m[1])) hits.push({ type: c.rule.type, value: m[1] });
      }
    }
  }

  // 3. Key/value pairs: JSON records, YAML, `Field: value`, Apex `c.SSN__c = '...'`.
  const KV = /["']?([A-Za-z][\w.]{0,80})["']?\s*[:=]\s*["']?([^"',}\]\n]{1,40})/g;
  let m;
  while ((m = KV.exec(text)) !== null) {
    const rule = fieldRuleFor(m[1].split('.').pop());
    const v = cleanCell(m[2]);
    if (rule && v && rule.value(v)) hits.push({ type: rule.type, value: v });
  }

  // 4. Prose: "Ann's SSN is 123456789".
  const PROSE_SSN =
    /\b(?:ssn|social\s+security(?:\s+(?:number|no\.?|#))?|tax\s*id|itin|tin)\b[^\d\n]{0,20}?(\d{3}[- ]?\d{2}[- ]?\d{4})(?!\d)/gi;
  while ((m = PROSE_SSN.exec(text)) !== null) {
    if (!isPlaceholderSSN(m[1])) hits.push({ type: LABELED_FIELDS[0].type, value: m[1] });
  }

  return hits;
}

// Finding types that are credentials (can be rotated). Everything else the
// scan reports is personal data, which can't be.
const SECRET_TYPES = new Set([
  'Private Key Block',
  'AWS Access Key ID',
  'AWS Secret Access Key (labeled)',
  'Google API Key',
  'Slack Token',
  'Generic Bearer/API secret (labeled)',
  'Credential in URL parameter',
  'Salesforce access token / session ID',
  'Salesforce auth URL',
  'Salesforce refresh token',
]);

/*
 * Scan text for PII/secrets. Returns an array of findings:
 *   [{ type, count, sample }]
 * `sample` is masked so we never echo the raw secret back to the user.
 */
function scanForPII(text, { maxFindings = 25 } = {}) {
  if (!text) return [];
  const original = String(text);
  const findings = [];
  const seenTypes = new Map();

  // Computed only if a structural detector actually needs it.
  let stripped = null;
  const haystackFor = (det) => {
    if (!det.structural) return original;
    if (stripped === null) stripped = stripOpaqueRuns(original);
    return stripped;
  };

  for (const det of PII_DETECTORS) {
    const haystack = haystackFor(det);
    det.re.lastIndex = 0;
    let m;
    while ((m = det.re.exec(haystack)) !== null) {
      // Detectors with alternatives capture into different groups; take the
      // first group that participated, else the whole match.
      let raw = m[0];
      for (let g = 1; g < m.length; g++) {
        if (m[g] != null) {
          raw = m[g];
          break;
        }
      }
      if (det.validate && !det.validate(raw)) continue;
      const key = det.type;
      const entry = seenTypes.get(key) || { type: key, count: 0, sample: mask(raw) };
      entry.count += 1;
      seenTypes.set(key, entry);
      if (seenTypes.size >= maxFindings) break;
      // avoid pathological loops on zero-width matches
      if (m.index === det.re.lastIndex) det.re.lastIndex++;
    }
  }
  for (const hit of scanLabeledFields(original)) {
    if (!seenTypes.has(hit.type) && seenTypes.size >= maxFindings) break;
    const entry = seenTypes.get(hit.type) || { type: hit.type, count: 0, sample: mask(hit.value) };
    entry.count += 1;
    seenTypes.set(hit.type, entry);
  }
  for (const v of seenTypes.values()) findings.push(v);
  return findings;
}

function mask(value) {
  const s = String(value);
  if (s.length <= 4) return '*'.repeat(s.length);
  return s.slice(0, 2) + '*'.repeat(Math.max(0, s.length - 4)) + s.slice(-2);
}

module.exports = {
  isSensitiveFile,
  activeCode,
  stripHeredocs,
  commandTouchesSensitiveFile,
  findForbiddenCommand,
  scanForPII,
  luhnValid,
  isPlaceholderSSN,
  cardValid,
  ibanValid,
  abaValid,
  fieldWords,
  fieldRuleFor,
  scanLabeledFields,
  normalizePath,
  isBinaryPath,
  looksBinary,
  stripOpaqueRuns,
  // exported for testing / customization
  SENSITIVE_FILE_PATTERNS,
  FORBIDDEN_COMMANDS,
  PII_DETECTORS,
  SECRET_TYPES,
  BINARY_FILE_EXTENSIONS,
};
