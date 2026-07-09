# @mockoon/commons-server Cross-site request forgery (CVE-2026-59148)

**Date:** 2026-07-09
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `csrf`

## Summary

Mockoon provides way to design and run mock APIs. Prior to 9.7.0, Mockoon's admin API in commons-server/src/libs/server/admin-api.ts is mounted on the same Express listener as user-defined mock routes, enabled by default in shipped runtimes, serves Access-Control-Allow-Origin: * with write methods allowed, and has no authentication. Any unauthenticated caller who can reach the mock server port can read MOCKOON_* environment variables, write arbitrary process environment variables through /mockoon-admin/env-vars, rewrite mock route bodies, statuses, and headers through PUT /mockoon-admin/environment, read transaction logs and SSE streams, and purge state. This issue is fixed in version 9.7.0. EPSS 0.26% (p16, as of 2026-09-27).

## Affected

- **Product / project:** @mockoon/commons-server (npm package `@mockoon/commons-server`)
- **Versions:** < 9.7.0
- **CWE:** CWE-306, CWE-352, CWE-732, CWE-942   **CVSS:** 8.8   **KEV:** no

## Verifying the finding

The proof-of-concept writes a caller-supplied marker (taken from the `POC_CANARY` environment variable) to stdout, but only when execution actually reaches the vulnerable code. Running it against an affected release prints the marker; running the identical script against 9.7.0 prints nothing. That before/after difference is the result — it shows the weak path is genuinely reachable. The proof stops there and does not chain the issue into the advisory's full impact.

## Technical detail

What the check looks for was derived from the patch released in 9.7.0. See `artifacts/` for the patch diff and the recorded output of the two runs.

## Reproduce

```bash
# install any @mockoon/commons-server release < 9.7.0
POC_CANARY=demo node poc.js     # outputs the marker (vulnerable)

npm install '@mockoon/commons-server@9.7.0'
POC_CANARY=demo node poc.js     # prints nothing (patched)
```

A run counts as vulnerable when the marker prints; the fixed build prints nothing. Neither outcome depends on the exit code.
The runs above are recorded in:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-59148](https://nvd.nist.gov/vuln/detail/CVE-2026-59148)
- [Upstream fix commit](https://github.com/mockoon/mockoon/commit/51eaa94c8d83b9af99b64da10f2b5c383acd8a4c)
