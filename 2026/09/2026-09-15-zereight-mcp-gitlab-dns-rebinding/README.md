# @zereight/mcp-gitlab DNS rebinding / missing host allowlist (CVE-2026-61568)

**Date:** 2026-09-15
**Status:** published
**Maturity:** differential-poc (vulnerable code path confirmed reachable; not a weaponized chain)
**Tags:** `dns-rebinding`, `differential-poc`

## Summary

`@zereight/mcp-gitlab` is a Model Context Protocol server for GitLab. Versions prior to 2.1.30 expose the Streamable HTTP MCP endpoint without an effective Host or Origin allowlist. A malicious web page can use DNS rebinding to route browser requests to a victim's local MCP listener while preserving an attacker-controlled `Host` and `Origin`. The server accepts those headers and reaches the MCP initialization path instead of rejecting the request at the HTTP boundary. Version 2.1.30 contains a patch. EPSS 0.32% (p25, as of 2026-09-20).

## Affected

- **Product / project:** @zereight/mcp-gitlab (npm package `@zereight/mcp-gitlab`)
- **Versions:** < 2.1.30
- **CWE:** CWE-350   **CVSS:** 9.6   **KEV:** no

## What was validated

The proof-of-concept is a **differential probe**: it reads a canary from `POC_CANARY` and
emits it on stdout **only** through the vulnerable code path, so the canary appearing proves
the pre-patch behaviour executed. It was run against the vulnerable and patched builds and
fired only on the vulnerable one — confirming the affected code path is **reachable**. It is
a proof of the primitive, **not** a weaponized end-to-end exploit; the advisory's stated
end-to-end impact is not demonstrated by this artifact.

## Technical detail

The flaw is summarised above. The fix is in 2.1.30; the affected code
path and the difference the probe keys on were read from the upstream fix diff
(`artifacts/patch-diff.txt`), which is included alongside the validated console captures.

## Reproduce

```bash
# install any @zereight/mcp-gitlab release < 2.1.30
POC_CANARY=demo node poc.js     # prints: demo   (vulnerable)

npm install '@zereight/mcp-gitlab@2.1.30'
POC_CANARY=demo node poc.js     # prints nothing (patched)
```

Success signal: the canary line on stdout — **exit code is always 0 on both builds**.
Console captures from the validated run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-61568](https://nvd.nist.gov/vuln/detail/CVE-2026-61568)
- [Upstream fix commit](https://github.com/zereight/gitlab-mcp/commit/cff3ebeec272d7cc609d9b3cab57f52cb15fae96)
