# Semgrep test file — GHSA-h343-gg57-2q67
# Rule: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
# Generated: 2026-03-09T05:24:37.754Z

# ── TRUE POSITIVES ─────────────────────────────────────────

# TP-1: User input from req.body executed in vm
const vm = require('vm');
const userInput = req.body.code;
# ruleid: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(userInput);

# TP-2: Async/await pattern with user input from req.query
const vm = require('vm');
const userCode = req.query.script;
async function execute() {
  await vm.runInNewContext(userCode);
}
# ruleid: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
execute();

# TP-3: Nested function call with user input from req.params
const vm = require('vm');
const code = req.params.code;
function runCode() {
  vm.runInNewContext(code);
}
# ruleid: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
runCode();

# TP-4: User input stored in variable then passed to vm
const vm = require('vm');
let userScript = getUserScript();
# ruleid: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(userScript);

# TP-5: Direct user input from req.body executed in vm
const vm = require('vm');
const script = req.body.script;
# ruleid: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(script);

# ── FALSE POSITIVES ────────────────────────────────────────

# FP-1: Hardcoded safe code executed in vm
const vm = require('vm');
const safeCode = 'console.log("Hello, World!")';
# ok: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(safeCode);

# FP-2: Sanitized user input executed in vm
const vm = require('vm');
const sanitizedInput = sanitize(req.body.code);
# ok: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(sanitizedInput);

# FP-3: Predefined script executed in vm
const vm = require('vm');
const predefinedScript = getPredefinedScript();
# ok: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(predefinedScript);

# FP-4: Static code execution in vm
const vm = require('vm');
const code = 'console.log("Safe execution")';
# ok: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(code);

# FP-5: Another example of hardcoded safe code
const vm = require('vm');
const safeCode = 'console.log("Secure")';
# ok: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(safeCode);

# ── EDGE CASES (todo — does not fail CI) ───────────────────

# EDGE-1: Config-driven script execution — debatable
const vm = require('vm');
const configScript = getConfigScript();
# todoruleid: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(configScript);

# EDGE-2: Sanitized but still risky user input
const vm = require('vm');
let userCode = sanitize(req.query.code);
# todook: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(userCode);