# yayson Prototype pollution (CVE-2026-61534)

**Date:** 2026-09-14
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `prototype-pollution`

## Summary

Yayson is a library for serializing and reading JSON API data in JavaScript. Prior to 4.3.0, Store and LegacyStore use attacker-controlled JSON:API type, id, and relationship names as keys in plain-object lookup tables in src/yayson/store.ts and src/yayson/legacy-store.ts. A document whose type is __proto__ causes model-cache writes to modify Object.prototype, with the attacker controlling the polluted property name through id and its value through attributes. The malicious type can also be supplied by an included resource, and LegacyStore is reachable when a configured types mapping resolves to __proto__. Unsafe relationship names including __proto__, constructor, and prototype provide additional document-derived member paths. The resulting process-wide prototype pollution can cause denial of service and logic corruption; authorization bypass or code execution depends on suitable gadgets in the consuming application. This issue is fixed in version 4.3.0. EPSS 0.84% (p56, as of 2026-09-29).

## Affected

- **Product / project:** yayson (npm package `yayson`)
- **Versions:** < 4.3.0
- **CWE:** CWE-1321   **CVSS:** 9.1   **KEV:** no

## Validation

To separate a real defect from a theoretical one, the script echoes a marker value (`POC_CANARY`) that can only appear if the flawed branch runs. The marker is present on the vulnerable version and gone once 4.3.0 is installed, which ties the behaviour directly to the code the patch changes. It is a minimal trigger rather than a full exploit chain.

## Technical detail

The mechanism was read from the change shipped in 4.3.0. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
# install any yayson release < 4.3.0
POC_CANARY=demo node poc.js     # outputs the marker (vulnerable)

npm install 'yayson@4.3.0'
POC_CANARY=demo node poc.js     # no marker (fixed build)
```

A run counts as vulnerable when the marker prints; the fixed build prints nothing. Neither outcome depends on the exit code.
Console output captured during the run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-61534](https://nvd.nist.gov/vuln/detail/CVE-2026-61534)
- [Upstream fix commit](https://github.com/confetti/yayson/commit/3b84b9cc6d17bcd4576051ca56815d8c9b5c352f)
