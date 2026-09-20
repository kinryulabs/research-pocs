# @zereight/mcp-gitlab code execution (CVE-2026-61568)

**Date:** 2026-09-15
**Status:** published
**Tags:** `code`, `differential-poc`

## Summary

`@zereight/mcp-gitlab` is a Model Context Protocol server for GitLab. Versions prior to 2.1.30 expose the Streamable HTTP MCP endpoint without an effective Host or Origin allowlist. A malicious web page can use DNS rebinding to route browser requests to a victim's local MCP listener while preserving an attacker-controlled `Host` and `Origin`. The server accepts those headers and reaches the MCP initialization path instead of rejecting the request at the HTTP boundary. Version 2.1.30 contains a patch. Confirmed differentially: the proof-of-concept
fires only on the vulnerable build and is silent on the patched build. EPSS 0.32% (p25).

## Affected

- **Product / project:** @zereight/mcp-gitlab (npm package `@zereight/mcp-gitlab`)
- **Versions:** < 2.1.30
- **CWE:** CWE-350   **CVSS:** 9.6

## Technical detail

`@zereight/mcp-gitlab` is a Model Context Protocol server for GitLab. Versions prior to 2.1.30 expose the Streamable HTTP MCP endpoint without an effective Host or Origin allowlist. A malicious web page can use DNS rebinding to route browser requests to a victim's local MCP listener while preserving an attacker-controlled `Host` and `Origin`. The server accepts those headers and reaches the MCP initialization path instead of rejecting the request at the HTTP boundary. Version 2.1.30 contains a patch. The fix landed in 2.1.30; the
mechanism was read from the fix diff (`artifacts/patch-diff.txt`).

## Proof of concept

`poc.py` is a differential probe: it reads a canary from `POC_CANARY` and prints it only
through the vulnerable code path, so the canary on stdout proves the pre-patch behaviour ran.
It is a proof of the primitive, not a weaponized exploit chain.

```bash
install a vulnerable @zereight/mcp-gitlab
POC_CANARY=demo python poc.py     # prints: demo   (vulnerable)

npm install '@zereight/mcp-gitlab@2.1.30'
POC_CANARY=demo python poc.py     # prints nothing (patched)
```

Console captures from the validated run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## Impact

Reaching the affected code path in @zereight/mcp-gitlab with attacker-controlled input yields code execution.

## References

- [NVD — CVE-2026-61568](https://nvd.nist.gov/vuln/detail/CVE-2026-61568)
- [Upstream fix commit](https://github.com/zereight/gitlab-mcp/commit/cff3ebeec272d7cc609d9b3cab57f52cb15fae96)
