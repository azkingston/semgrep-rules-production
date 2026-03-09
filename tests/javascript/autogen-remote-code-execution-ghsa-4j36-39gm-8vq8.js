# Semgrep test file — GHSA-4j36-39gm-8vq8
# Rule: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
# Generated: 2026-03-09T06:04:44.975Z

# ── TRUE POSITIVES ─────────────────────────────────────────

# TP-1: Direct eval of user-provided script from request body
const express = require('express');
const app = express();
app.post('/execute', (req, res) => {
  const userScript = req.body.script;
  // ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  eval(userScript);
  res.send('Executed');
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-2: Command execution with user input from command line arguments
const { exec } = require('child_process');
const userInput = process.argv[2];
// ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(userInput, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-3: Command execution with user input from URL parameters
const express = require('express');
const app = express();
app.get('/run/:cmd', (req, res) => {
  const cmd = req.params.cmd;
  const { exec } = require('child_process');
  // ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      res.status(500).send('Error');
      return;
    }
    res.send(stdout);
  });
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-4: Command execution with environment variable input
const { exec } = require('child_process');
const userInput = 'ls ' + process.env.USER_INPUT;
// ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(userInput, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-5: Playwright script execution via eval with user input
const playwright = require('playwright');
async function run() {
  const browser = await playwright.chromium.launch();
  const page = await browser.newPage();
  const userScript = 'page.goto("http://example.com")';
  // ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  eval(userScript);
  await browser.close();
}
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
run();

# ── FALSE POSITIVES ────────────────────────────────────────

# FP-1: Hardcoded safe command execution
const { exec } = require('child_process');
// ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec('echo "Hello World"', (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# FP-2: Eval with hardcoded safe script
const express = require('express');
const app = express();
app.post('/safe', (req, res) => {
  const safeScript = 'console.log("Safe")';
  // ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  eval(safeScript);
  res.send('Executed safely');
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# FP-3: Execution with hardcoded safe input
const { exec } = require('child_process');
const safeInput = 'ls -la';
// ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(safeInput, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# FP-4: Function with hardcoded safe command
const { exec } = require('child_process');
function executeSafeCommand() {
  const command = 'echo "Safe execution"';
  // ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.error(`stderr: ${stderr}`);
  });
}
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
executeSafeCommand();

# FP-5: Sanitized user input for command execution
const { exec } = require('child_process');
const sanitizedInput = sanitizeInput(userInput);
// ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(sanitizedInput, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
});
function sanitizeInput(input) {
  return input.replace(/[^a-zA-Z0-9 ]/g, '');
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
}

# ── EDGE CASES (todo — does not fail CI) ───────────────────

# EDGE-1: Config-driven command execution — debatable
const { exec } = require('child_process');
const config = { command: 'ls -la' };
// todoruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(config.command, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# todoruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# EDGE-2: Sanitized but still risky due to incomplete sanitization
const { exec } = require('child_process');
const userInput = process.argv[2];
const sanitizedInput = userInput.replace(/[^a-zA-Z0-9 ]/g, '');
// todook: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(sanitizedInput, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# todook: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});