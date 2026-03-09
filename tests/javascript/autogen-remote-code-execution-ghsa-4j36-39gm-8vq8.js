# Semgrep test file — GHSA-4j36-39gm-8vq8
# Rule: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
# Generated: 2026-03-09T06:58:52.733Z

# ── TRUE POSITIVES ─────────────────────────────────────────

# TP-1: Real vulnerable code from fix PR/commit (code_search:arkenfox/user.js)
# Code search reference from: arkenfox/user.js
# File: user.js
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
# (see file for full context)

# TP-2: Express JSON body with direct script execution
const express = require('express');
const app = express();
app.use(express.json());
app.post('/execute', (req, res) => {
  const userScript = req.body.script;
  const vm = require('vm');
  const script = new vm.Script(userScript);
  script.runInThisContext();
  res.send('Executed');
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-3: Command line input to exec
const { exec } = require('child_process');
const userInput = process.argv[2];
exec(userInput, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-4: Playwright with eval on user script
const playwright = require('playwright');
async function runScript(userScript) {
  const browser = await playwright.chromium.launch();
  eval(userScript);
  await browser.close();
}
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
runScript('console.log("Hello World")');

# TP-5: Express route parameter to exec
const express = require('express');
const app = express();
app.get('/run/:cmd', (req, res) => {
  const { exec } = require('child_process');
  exec(req.params.cmd, (error, stdout, stderr) => {
    if (error) {
      res.status(500).send('Error');
      return;
    }
    res.send(stdout);
  });
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-6: [BYPASS indirect_flow] Indirect flow through function calls and variable assignment.
const { exec } = require('child_process');

function getCommand() {
  return req.query.command;
}

function executeCommand(cmd) {
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.error(`stderr: ${stderr}`);
  });
}

const userCommand = getCommand();
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
executeCommand(userCommand);

# TP-7: [BYPASS indirect_flow] Indirect flow through a helper function and variable assignment.
const { exec } = require('child_process');

function fetchUserInput() {
  return req.body.cmd;
}

const runCommand = (command) => {
  exec(command, (err, stdout, stderr) => {
    if (err) {
      console.error(`exec error: ${err}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.error(`stderr: ${stderr}`);
  });
};

const commandToRun = fetchUserInput();
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
runCommand(commandToRun);

# TP-8: [BYPASS encoding_transformation] Bypasses the rule by encoding the command in base64, which is then decoded before execution.
const { exec } = require('child_process');
const base64 = require('base-64');
const userInput = req.query.cmd;
const decodedInput = base64.decode(userInput);
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(decodedInput);

# TP-9: [BYPASS encoding_transformation] Bypasses the rule by wrapping the command in a JSON object and then parsing it before execution.
const { exec } = require('child_process');
const userInput = req.query.cmd;
const parsedInput = JSON.parse(`{"cmd":"${userInput}"}`).cmd;
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
exec(parsedInput);

# TP-10: [BYPASS framework_variation] Using Node.js 'url' and 'querystring' modules to parse and execute commands from a URL query parameter.
const { exec } = require('child_process');
const url = require('url');
const querystring = require('querystring');

const reqUrl = 'http://example.com?cmd=ls';
const parsedUrl = url.parse(reqUrl);
const query = querystring.parse(parsedUrl.query);

exec(query.cmd, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# TP-11: [BYPASS framework_variation] Using Node.js 'http' module to receive and execute commands from HTTP POST body without sanitization.
const { spawn } = require('child_process');
const http = require('http');

http.createServer((req, res) => {
  let body = '';
  req.on('data', chunk => {
    body += chunk.toString();
  });
  req.on('end', () => {
    const command = JSON.parse(body).command;
    const child = spawn(command, { shell: true });

    child.stdout.on('data', (data) => {
      console.log(`stdout: ${data}`);
    });

    child.stderr.on('data', (data) => {
      console.error(`stderr: ${data}`);
    });

    child.on('close', (code) => {
      console.log(`child process exited with code ${code}`);
    });
  });
# ruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
}).listen(8080);

# ── FALSE POSITIVES ────────────────────────────────────────

# FP-1: Hardcoded safe command
const { exec } = require('child_process');
exec('ls -la', (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# FP-2: Sanitized user input before eval
const express = require('express');
const app = express();
app.use(express.json());
app.post('/safe', (req, res) => {
  const userScript = req.body.script;
  const safeScript = sanitize(userScript);
  eval(safeScript);
  res.send('Executed safely');
});
function sanitize(script) {
  return script.replace(/dangerousFunction/g, '');
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
}

# FP-3: Using execFile with hardcoded arguments
const { execFile } = require('child_process');
execFile('ls', ['-la'], (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# FP-4: Reading a file with fs.readFile
const fs = require('fs');
fs.readFile('/etc/passwd', 'utf8', (err, data) => {
  if (err) {
    console.error(err);
    return;
  }
  console.log(data);
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# FP-5: Simple express route with no user input execution
const express = require('express');
const app = express();
app.get('/safe', (req, res) => {
  res.send('This is safe');
# ok: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# ── EDGE CASES (todo — does not fail CI) ───────────────────

# EDGE-1: Config-driven command execution
const { exec } = require('child_process');
const config = require('./config');
exec(config.safeCommand, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
# todoruleid: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
});

# EDGE-2: Sanitized input but still risky
const { exec } = require('child_process');
const userInput = sanitizeInput(process.argv[2]);
exec(userInput, (error, stdout, stderr) => {
  if (error) {
    console.error(`exec error: ${error}`);
    return;
  }
  console.log(`stdout: ${stdout}`);
  console.error(`stderr: ${stderr}`);
});
function sanitizeInput(input) {
  return input.replace(/[^a-zA-Z0-9]/g, '');
# todook: autogen-remote-code-execution-ghsa-4j36-39gm-8vq8
}