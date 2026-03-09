# Semgrep test file — GHSA-4j36-39gm-8vq8
# Rule: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
# Generated: 2026-03-09T05:37:18.170Z

# ── TRUE POSITIVES ─────────────────────────────────────────

# TP-1: Exec with user input from req.body
const { exec } = require('child_process');
const userInput = req.body.command;
exec(userInput, (error, stdout, stderr) => {
  console.log(stdout);
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-2: Exec with user input from req.query
const { exec } = require('child_process');
let command = req.query.cmd;
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(command);

# TP-3: Async/await with user input from req.params
const { exec } = require('child_process');
const command = req.params.command;
async function runCommand() {
  await exec(command);
}
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
runCommand();

# TP-4: Exec with user input stored in variable
const { exec } = require('child_process');
let userCommand = getUserInput();
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(userCommand);

# TP-5: Nested function call with user input
const { exec } = require('child_process');
function executeCommand(cmd) {
  exec(cmd);
}
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
executeCommand(req.body.cmd);

# ── FALSE POSITIVES ────────────────────────────────────────

# FP-1: Hardcoded safe command
const { exec } = require('child_process');
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec('echo Hello World');

# FP-2: Hardcoded safe command stored in variable
const { exec } = require('child_process');
const safeCommand = 'ls -la';
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(safeCommand);

# FP-3: Sanitized user input
const { exec } = require('child_process');
const sanitizedInput = sanitize(req.body.command);
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(sanitizedInput);

# FP-4: Nested function with hardcoded safe command
const { exec } = require('child_process');
function safeExecute() {
  exec('uptime');
}
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
safeExecute();

# FP-5: Hardcoded command in variable
const { exec } = require('child_process');
const command = 'date';
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(command);

# ── EDGE CASES (todo — does not fail CI) ───────────────────

# EDGE-1: Config-driven command execution
const { exec } = require('child_process');
const configCommand = config.get('defaultCommand');
# todoruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(configCommand);

# EDGE-2: Sanitized but still risky user input
const { exec } = require('child_process');
let userCommand = sanitizeInput(req.body.command);
# todook: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(userCommand);