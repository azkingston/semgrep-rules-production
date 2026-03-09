# Semgrep test file — GHSA-c8m8-3jcr-6rj5
# Rule: autogen-hardcoded-secrets-ghsa-c8m8-3jcr-6rj5
# Generated: 2026-03-09T05:24:00.002Z

# ── TRUE POSITIVES ─────────────────────────────────────────

# TP-1: Hardcoded JWT secret used directly in sign function
const jwt = require('jsonwebtoken');
const secret = 'frangoteam751';
# ruleid: autogen-hardcoded-secrets-ghsa-c8m8-3jcr-6rj5
const token = jwt.sign({ user: 'admin' }, secret);

# TP-2: Hardcoded secret in Express route using req.body
const express = require('express');
const app = express();
app.post('/login', (req, res) => {
  const secret = 'frangoteam751';
  const token = jwt.sign(req.body, secret);
  res.send(token);
# ruleid: autogen-hardcoded-secrets-ghsa-c8m8-3jcr-6rj5
});

# TP-3: Hardcoded secret in async function
async function generateToken(user) {
  const secret = 'frangoteam751';
  return await jwt.sign({ user }, secret);
}
# ruleid: autogen-hardcoded-secrets-ghsa-c8m8-3jcr-6rj5
generateToken('admin');

# TP-4: Hardcoded secret in nested function call
function getToken(user) {
  const secret = 'frangoteam751';
  return jwt.sign({ user }, secret);
}
# ruleid: autogen-hardcoded-secrets-ghsa-c8m8-3jcr-6rj5
const token = getToken('admin');

# TP-5: Hardcoded secret stored in variable then used
const jwt = require('jsonwebtoken');
let secret = 'frangoteam751';
function createToken(data) {
  return jwt.sign(data, secret);
}
# ruleid: autogen-hardcoded-secrets-ghsa-c8m8-3jcr-6rj5
createToken({ user: 'admin' });

# ── FALSE POSITIVES ────────────────────────────────────────

# FP-1: Secret retrieved from environment variable
const jwt = require('jsonwebtoken');
const secret = process.env.JWT_SECRET;
# ok: autogen-hardcoded-secrets-ghsa-c8m8-3jcr-6rj5
const token = jwt.sign({ user: 'admin' }, secret);

# FP-2: Secret provided through request body
const express = require('express');
const app = express();
app.post('/login', (req, res) => {
  const secret = req.body.secret;
  const token = jwt.sign(req.body, secret);
  res.send(token);
# ok: autogen-hardcoded-secrets-ghsa-c8m8-3jcr-6rj5
});

# FP-3: Secret passed as function argument
async function generateToken(user, secret) {
  return await jwt.sign({ user }, secret);
}
# ok: autogen-hardcoded-secrets-ghsa-c8m8-3jcr-6rj5
generateToken('admin', process.env.JWT_SECRET);

# FP-4: Secret passed as parameter in nested function call
function getToken(user, secret) {
  return jwt.sign({ user }, secret);
}
# ok: autogen-hardcoded-secrets-ghsa-c8m8-3jcr-6rj5
const token = getToken('admin', process.env.JWT_SECRET);

# FP-5: Secret stored in variable from environment
const jwt = require('jsonwebtoken');
let secret = process.env.JWT_SECRET;
function createToken(data) {
  return jwt.sign(data, secret);
}
# ok: autogen-hardcoded-secrets-ghsa-c8m8-3jcr-6rj5
createToken({ user: 'admin' });

# ── EDGE CASES (todo — does not fail CI) ───────────────────

# EDGE-1: Config-driven fallback to hardcoded secret
const jwt = require('jsonwebtoken');
const secret = config.get('jwtSecret') || 'frangoteam751';
# todoruleid: autogen-hardcoded-secrets-ghsa-c8m8-3jcr-6rj5
const token = jwt.sign({ user: 'admin' }, secret);

# EDGE-2: Sanitized input with hardcoded fallback
const jwt = require('jsonwebtoken');
let secret = sanitizeInput(userInput) || 'frangoteam751';
function createToken(data) {
  return jwt.sign(data, secret);
}
# todook: autogen-hardcoded-secrets-ghsa-c8m8-3jcr-6rj5
createToken({ user: 'admin' });