# Semgrep test file — GHSA-6f6w-6j58-rq76
# Rule: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
# Generated: 2026-03-09T05:38:24.952Z

# ── TRUE POSITIVES ─────────────────────────────────────────

# TP-1: Express req.body input to exec
const { exec } = require('child_process');
const userInput = req.body.command;
exec(userInput, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
});

# TP-2: Express req.query input to exec
const { exec } = require('child_process');
const userCommand = req.query.cmd;
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(userCommand);

# TP-3: User input stored in variable then passed to exec
const { exec } = require('child_process');
let command = getUserInput();
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(command);

# TP-4: Async/await pattern with user input
const { exec } = require('child_process');
async function runCommand() {
  const cmd = await getUserInputAsync();
  exec(cmd);
}
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
runCommand();

# TP-5: Nested function call with Express req.params input
const { exec } = require('child_process');
function executeCommand(cmd) {
  exec(cmd);
}
const userCmd = req.params.command;
# ruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
executeCommand(userCmd);

# ── FALSE POSITIVES ────────────────────────────────────────

# FP-1: Hardcoded safe command
const { exec } = require('child_process');
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec('ls -la');

# FP-2: Hardcoded safe command stored in a variable
const { exec } = require('child_process');
const safeCommand = 'echo Hello World';
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(safeCommand);

# FP-3: Sanitized user input before exec
const { exec } = require('child_process');
const userInput = req.body.command;
const sanitizedInput = sanitize(userInput);
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(sanitizedInput);

# FP-4: Direct execution of a safe command variable
const { exec } = require('child_process');
const command = 'ls';
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(command);

# FP-5: Predefined command from a safe source
const { exec } = require('child_process');
const command = getPredefinedCommand();
# ok: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(command);

# ── EDGE CASES (todo — does not fail CI) ───────────────────

# EDGE-1: Config-driven command execution — debatable
const { exec } = require('child_process');
const config = require('./config');
# todoruleid: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(config.shellCommand);

# EDGE-2: Sanitized but still risky due to potential incomplete sanitization
const { exec } = require('child_process');
let userInput = req.body.command;
userInput = sanitize(userInput);
# todook: autogen-shell-misconfiguration-ghsa-6f6w-6j58-rq76
exec(userInput);