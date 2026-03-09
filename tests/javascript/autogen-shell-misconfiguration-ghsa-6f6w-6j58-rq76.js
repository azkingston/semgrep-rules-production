# Semgrep test file — GHSA-6f6w-6j58-rq76
# Rule: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
# Generated: 2026-03-09T05:54:04.703Z

# ── TRUE POSITIVES ─────────────────────────────────────────

# TP-1: Express req.body input to exec
const { exec } = require('child_process');
const userInput = req.body.command;
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(userInput);

# TP-2: Express req.query input to exec
const { exec } = require('child_process');
let command = req.query.cmd;
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(command);

# TP-3: Express req.params input to exec
const { exec } = require('child_process');
const userCommand = req.params.command;
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(userCommand);

# TP-4: User input stored in variable then passed to exec
const { exec } = require('child_process');
let cmd = userInput;
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(cmd);

# TP-5: Async/await pattern with user input to exec
const { exec } = require('child_process');
async function runCommand() {
  const cmd = await getUserInput();
  exec(cmd);
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
}

# ── FALSE POSITIVES ────────────────────────────────────────

# FP-1: Hardcoded safe command
const { exec } = require('child_process');
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec('echo Hello World');

# FP-2: Stored hardcoded safe command
const { exec } = require('child_process');
let safeCommand = 'ls -la';
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(safeCommand);

# FP-3: Sanitized user input before exec
const { exec } = require('child_process');
const sanitizedInput = sanitize(userInput);
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(sanitizedInput);

# FP-4: Function with hardcoded safe command
const { exec } = require('child_process');
function runSafeCommand() {
  exec('date');
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
}

# FP-5: Variable with hardcoded safe command
const { exec } = require('child_process');
const command = 'uptime';
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(command);

# ── EDGE CASES (todo — does not fail CI) ───────────────────

# EDGE-1: Config-driven command execution
const { exec } = require('child_process');
const configCommand = config.get('defaultCommand');
# todoruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(configCommand);

# EDGE-2: Sanitized but still risky user input
const { exec } = require('child_process');
const userCommand = sanitize(req.body.command);
# todook: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(userCommand);