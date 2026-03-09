# Semgrep test file — GHSA-4j36-39gm-8vq8
# Rule: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
# Generated: 2026-03-09T07:06:01.502Z

# ── TRUE POSITIVES ─────────────────────────────────────────

# TP-1: Express app executing user-provided script via Playwright
const express = require('express');
const app = express();
app.use(express.json());

app.post('/execute', (req, res) => {
  const userScript = req.body.script;
  // ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  browser.browserType().launch({ args: [userScript] });
  res.send('Executed');
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-2: Direct exec with user input
const { exec } = require('child_process');

function runCommand(userInput) {
  // ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  exec(userInput, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.error(`stderr: ${stderr}`);
  });
}

# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
runCommand(process.argv[2]);

# TP-3: Express app using req.params to execute command
const express = require('express');
const app = express();
app.use(express.json());

app.get('/run/:cmd', (req, res) => {
  const command = req.params.cmd;
  // ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  browser.browserType().launch({ args: [command] });
  res.send('Command executed');
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-4: Async/await pattern with user input
const { exec } = require('child_process');

async function executeCommand() {
  const userCommand = await getUserInput();
  // ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  exec(userCommand);
}

# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
executeCommand();

# TP-5: Nested function calls with user input
const { exec } = require('child_process');

function nestedExecution(userInput) {
  function execute(cmd) {
    // ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
    exec(cmd);
  }
  execute(userInput);
}

# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
nestedExecution('rm -rf /');

# ── FALSE POSITIVES ────────────────────────────────────────

# FP-1: Hardcoded safe command
const { exec } = require('child_process');

function safeExecution() {
  // ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  exec('echo Hello World');
}

# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
safeExecution();

# FP-2: Sanitized user input
const { exec } = require('child_process');

function sanitizedExecution(userInput) {
  const safeInput = sanitize(userInput);
  // ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  exec(safeInput);
}

# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
sanitizedExecution('ls');

# FP-3: Validated user input
const { exec } = require('child_process');

function executeWithValidation(userInput) {
  if (isValid(userInput)) {
    // ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
    exec(userInput);
  }
}

# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
executeWithValidation('ls');

# FP-4: Using execFile with hardcoded safe command
const { execFile } = require('child_process');

function safeExecFile() {
  // ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  execFile('ls', ['-la'], (error, stdout, stderr) => {
    if (error) {
      console.error(`execFile error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.error(`stderr: ${stderr}`);
  });
}

# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
safeExecFile();

# FP-5: Whitelisted user input
const { exec } = require('child_process');

function executeWithWhitelist(userInput) {
  const whitelist = ['ls', 'pwd'];
  if (whitelist.includes(userInput)) {
    // ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
    exec(userInput);
  }
}

# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
executeWithWhitelist('ls');

# ── EDGE CASES (todo — does not fail CI) ───────────────────

# EDGE-1: Config-driven command execution
const { exec } = require('child_process');

function configDrivenExecution(config) {
  const command = config.command;
  // todoruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  exec(command);
}

# todoruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
configDrivenExecution({ command: 'ls' });

# EDGE-2: Partially sanitized input
const { exec } = require('child_process');

function executeWithPartialSanitization(userInput) {
  const sanitizedInput = userInput.replace(/[^a-zA-Z0-9]/g, '');
  // todook: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  exec(sanitizedInput);
}

# todook: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
executeWithPartialSanitization('ls');