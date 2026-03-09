# Semgrep test file — GHSA-4j36-39gm-8vq8
# Rule: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
# Generated: 2026-03-09T07:12:22.626Z

# ── TRUE POSITIVES ─────────────────────────────────────────

# TP-1: Real vulnerable code from fix PR/commit (code_search:arkenfox/user.js)
# Code search reference from: arkenfox/user.js
# File: user.js
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
# (see file for full context)

# TP-2: User input from req.body directly passed to exec
const { exec } = require('child_process');
const userInput = req.body.command;
exec(userInput, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-3: Async/await pattern with user input from req.query
const { exec } = require('child_process');
const userCommand = req.query.cmd;
async function runCommand() {
  await exec(userCommand, (err, stdout, stderr) => {
    if (err) {
      console.error(`Error: ${err}`);
      return;
    }
    console.log(`Output: ${stdout}`);
  });
}
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
runCommand();

# TP-4: User input from req.params passed through a function
const { exec } = require('child_process');
function executeUserCommand(command) {
  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
  });
}
const userCommand = req.params.command;
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
executeUserCommand(userCommand);

# TP-5: User input stored in a variable then passed to exec
const { exec } = require('child_process');
const command = req.body.command;
function run(cmd) {
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
  });
}
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
run(command);

# TP-6: [BYPASS indirect_flow] indirect via function calls and variable assignments
const { exec } = require('child_process');

function getCommand(req) {
  return req.query.cmd;
}

function runCommand(cmd) {
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.error(`stderr: ${stderr}`);
  });
}

const userCommand = getCommand(request);
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
runCommand(userCommand);

# TP-7: [BYPASS indirect_flow] indirect via function abstraction and variable usage
const { exec } = require('child_process');

function fetchUserInput(req) {
  return req.body.command;
}

function executeUserCommand(command) {
  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.error(`stderr: ${stderr}`);
  });
}

const commandToExecute = fetchUserInput(request);
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
executeUserCommand(commandToExecute);

# TP-8: [BYPASS encoding_transformation] Base64 decode user input before passing to exec.
const { exec } = require('child_process');
const base64Decode = (str) => Buffer.from(str, 'base64').toString('utf8');
const data = base64Decode(req.query.cmd);
exec(data, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-9: [BYPASS encoding_transformation] Parse JSON input to extract command and execute.
const { exec } = require('child_process');
const parseJSON = (str) => JSON.parse(str);
const data = parseJSON(req.query.cmd).command;
exec(data, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-10: [BYPASS framework_variation] Using 'execFile' from 'child_process' with 'url.parse' for input access.
const { execFile } = require('child_process');
const url = require('url');

const query = url.parse(request.url, true).query;
execFile(query.cmd, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-11: [BYPASS framework_variation] Using 'fork' from 'child_process' with input from request headers.
const { fork } = require('child_process');

function executeCommand(command) {
  const child = fork(command, { stdio: 'inherit' });
  child.on('error', (err) => {
    console.error('Failed to start subprocess.', err);
  });
}

const userInput = request.headers['x-custom-cmd'];
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
executeCommand(userInput);

# ── FALSE POSITIVES ────────────────────────────────────────

# FP-1: Hardcoded safe command
const { exec } = require('child_process');
exec('ls -la', (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# FP-2: Hardcoded safe command stored in a variable
const { exec } = require('child_process');
const safeCommand = 'echo Hello World';
exec(safeCommand, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# FP-3: Sanitized user input
const { exec } = require('child_process');
const userInput = req.body.command;
const safeCommand = `echo ${userInput.replace(/[^a-zA-Z0-9]/g, '')}`;
exec(safeCommand, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# FP-4: Function with hardcoded safe command
const { exec } = require('child_process');
function executeSafeCommand() {
  const safeCommand = 'date';
  exec(safeCommand, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
  });
}
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
executeSafeCommand();

# FP-5: Direct execution of a safe command
const { exec } = require('child_process');
const command = 'uptime';
exec(command, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# ── EDGE CASES (todo — does not fail CI) ───────────────────

# EDGE-1: Config-driven command execution
const { exec } = require('child_process');
const configCommand = process.env.ALLOWED_COMMAND;
exec(configCommand, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
# todoruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# EDGE-2: Sanitized input but still risky
const { exec } = require('child_process');
const userInput = req.body.command;
const sanitizedCommand = userInput.replace(/[^a-zA-Z0-9]/g, '');
exec(sanitizedCommand, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
# todook: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});