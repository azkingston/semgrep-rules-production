# Semgrep test file — GHSA-6f6w-6j58-rq76
# Rule: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
# Generated: 2026-03-09T05:23:20.655Z

# ── TRUE POSITIVES ─────────────────────────────────────────

# TP-1: Express req.body input to exec
const { exec } = require('child_process');
const userInput = req.body.command;
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(userInput);

# TP-2: User input stored in variable then passed to exec
const { exec } = require('child_process');
let command = userProvidedFunction();
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(command);

# TP-3: Express req.query input to exec
const { exec } = require('child_process');
const userCommand = req.query.cmd;
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(userCommand);

# TP-4: Async/await pattern with user input
const { exec } = require('child_process');
async function runCommand() {
  const cmd = await getUserCommand();
  exec(cmd);
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
}

# TP-5: Express req.params input to exec
const { exec } = require('child_process');
function executeCommand() {
  const cmd = req.params.command;
  exec(cmd);
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
}

# ── FALSE POSITIVES ────────────────────────────────────────

# FP-1: Hardcoded safe command
const { exec } = require('child_process');
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec('ls -la');

# FP-2: Hardcoded safe command stored in variable
const { exec } = require('child_process');
const safeCommand = 'echo Hello';
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(safeCommand);

# FP-3: Sanitized input before exec
const { exec } = require('child_process');
const sanitizedInput = sanitize(req.body.input);
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(sanitizedInput);

# FP-4: Function with hardcoded safe command
const { exec } = require('child_process');
function runSafeCommand() {
  const cmd = 'uptime';
  exec(cmd);
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
}

# FP-5: Simple hardcoded command
const { exec } = require('child_process');
const command = 'ls';
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(command);

# ── EDGE CASES (todo — does not fail CI) ───────────────────

# EDGE-1: Config-driven command — debatable
const { exec } = require('child_process');
const configCommand = config.get('shellCommand');
# todoruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(configCommand);

# EDGE-2: Sanitized but still risky if sanitize is incomplete
const { exec } = require('child_process');
const userInput = sanitize(req.body.command);
# todook: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(userInput);