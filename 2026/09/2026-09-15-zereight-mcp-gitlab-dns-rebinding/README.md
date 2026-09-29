# @zereight/mcp-gitlab DNS rebinding / missing host allowlist (CVE-2026-61568)

**Date:** 2026-09-15
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `dns-rebinding`

## Summary

`@zereight/mcp-gitlab` is a Model Context Protocol server for GitLab. Versions prior to 2.1.30 expose the Streamable HTTP MCP endpoint without an effective Host or Origin allowlist. A malicious web page can use DNS rebinding to route browser requests to a victim's local MCP listener while preserving an attacker-controlled `Host` and `Origin`. The server accepts those headers and reaches the MCP initialization path instead of rejecting the request at the HTTP boundary. Version 2.1.30 contains a patch. EPSS 0.53% (p42, as of 2026-09-29).

## Affected

- **Product / project:** @zereight/mcp-gitlab (npm package `@zereight/mcp-gitlab`)
- **Versions:** < 2.1.30
- **CWE:** CWE-350   **CVSS:** 9.6   **KEV:** no

## How this was verified

To separate a real defect from a theoretical one, the script echoes a marker value (`POC_CANARY`) that can only appear if the flawed branch runs. The marker is present on the vulnerable version and gone once 2.1.30 is installed, which ties the behaviour directly to the code the patch changes. It is a minimal trigger rather than a full exploit chain.

## Technical detail

What the check looks for was derived from the patch released in 2.1.30. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
# install any @zereight/mcp-gitlab release < 2.1.30
POC_CANARY=demo node poc.js     # marker appears (affected build)

npm install '@zereight/mcp-gitlab@2.1.30'
POC_CANARY=demo node poc.js     # prints nothing (patched)
```

The signal is the marker on stdout — present before the patch, absent after. Exit codes are 0 in both cases.
Recorded output from the two runs:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-61568](https://nvd.nist.gov/vuln/detail/CVE-2026-61568)
- [Upstream fix commit](https://github.com/zereight/gitlab-mcp/commit/cff3ebeec272d7cc609d9b3cab57f52cb15fae96)
