# Semgrep test file — GHSA-4j36-39gm-8vq8
# Rule: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
# Generated: 2026-03-09T05:52:54.878Z

# ── TRUE POSITIVES ─────────────────────────────────────────

# TP-1: Direct execution of user input from request body
const { exec } = require('child_process');
const userInput = req.body.command;
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(userInput);

# TP-2: Using Playwright browser object with user input
const { browser } = require('playwright');
async function launchBrowser(userInput) {
  await browser.browserType().launch({ executablePath: userInput });
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
}

# TP-3: Execution of command from query parameter
const { exec } = require('child_process');
let command = req.query.cmd;
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(command);

# TP-4: Execution of command stored in a variable from a function
const { exec } = require('child_process');
let cmd = getUserInput();
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(cmd);

# TP-5: Async/await pattern with user input execution
const { exec } = require('child_process');
async function runCommand() {
  let userCommand = await getUserCommandAsync();
  exec(userCommand);
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
}

# ── FALSE POSITIVES ────────────────────────────────────────

# FP-1: Hardcoded safe command
const { exec } = require('child_process');
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec('echo Hello World');

# FP-2: Execution of a hardcoded safe command stored in a variable
const { exec } = require('child_process');
const safeCommand = 'ls -la';
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(safeCommand);

# FP-3: Execution with sanitized user input
const { exec } = require('child_process');
let sanitizedInput = sanitize(req.body.command);
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(sanitizedInput);

# FP-4: Execution of a hardcoded safe command within a function
const { exec } = require('child_process');
function safeFunction() {
  exec('uptime');
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
}

# FP-5: Execution of a static, safe command
const { exec } = require('child_process');
const cmd = 'date';
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(cmd);

# ── EDGE CASES (todo — does not fail CI) ───────────────────

# EDGE-1: Config-driven command execution — debatable safety
const { exec } = require('child_process');
const config = require('./config');
# todoruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(config.safeCommand);

# EDGE-2: Sanitized input but still risky due to inadequate sanitization
const { exec } = require('child_process');
let userInput = sanitize(req.body.command);
# todook: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(userInput);