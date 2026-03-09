# Semgrep test file — GHSA-h343-gg57-2q67
# Rule: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
# Generated: 2026-03-09T05:39:35.828Z

# ── TRUE POSITIVES ─────────────────────────────────────────

# TP-1: User input from req.body executed in vm.runInNewContext
const vm = require('vm');
const userCode = req.body.code;
# ruleid: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(userCode);

# TP-2: User input from req.query executed in vm.runInThisContext
const vm = require('vm');
const userInput = req.query.script;
# ruleid: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInThisContext(userInput);

# TP-3: User input from req.params executed in vm.runInContext
const vm = require('vm');
let code = req.params.code;
# ruleid: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInContext(code, vm.createContext({}));

# TP-4: Async function executing user code in vm.runInNewContext
const vm = require('vm');
async function executeUserCode() {
  const code = await getUserCode();
  vm.runInNewContext(code);
}
# ruleid: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
executeUserCode();

# TP-5: Nested function calls executing user code in vm.runInThisContext
const vm = require('vm');
function executeNested(userCode) {
  function innerExecute(code) {
    vm.runInThisContext(code);
  }
  innerExecute(userCode);
}
# ruleid: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
executeNested(req.body.code);

# ── FALSE POSITIVES ────────────────────────────────────────

# FP-1: Hardcoded safe code executed in vm.runInNewContext
const vm = require('vm');
const safeCode = 'console.log("Hello, World!")';
# ok: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(safeCode);

# FP-2: Sanitized user input executed in vm.runInNewContext
const vm = require('vm');
const userInput = req.body.code;
const sanitizedCode = sanitize(userInput);
# ok: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(sanitizedCode);

# FP-3: Hardcoded safe code executed in vm.runInThisContext
const vm = require('vm');
const safeCode = 'console.log("Secure Execution")';
# ok: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInThisContext(safeCode);

# FP-4: Static code executed in vm.runInContext
const vm = require('vm');
const code = 'console.log("Static Code")';
# ok: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInContext(code, vm.createContext({}));

# FP-5: Nested function calls executing hardcoded safe code
const vm = require('vm');
function executeSafe() {
  const safeCode = 'console.log("Nested Safe Execution")';
  vm.runInThisContext(safeCode);
}
# ok: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
executeSafe();

# ── EDGE CASES (todo — does not fail CI) ───────────────────

# EDGE-1: Config-driven execution — debatable
const vm = require('vm');
const config = { allowExecution: true };
if (config.allowExecution) {
  const userCode = req.body.code;
  vm.runInNewContext(userCode);
# todoruleid: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
}

# EDGE-2: Sanitized input but still risky
const vm = require('vm');
let userInput = req.body.code;
userInput = sanitize(userInput);
# todook: autogen-remote-code-execution-rce-ghsa-h343-gg57-2q67
vm.runInNewContext(userInput);