# mcp-atlassian Missing authorization (CVE-2026-77244)

**Date:** 2026-09-22
**Status:** published
**Maturity:** differential-poc (vulnerable code path confirmed reachable; not a weaponized chain)
**Tags:** `authz`, `differential-poc`

## Summary

MCP Atlassian is a Model Context Protocol (MCP) server for Atlassian products (Confluence and Jira). Prior to 0.22.0, the HTTP transport accepts requests without a verified user identity and downstream fetcher construction falls back to the operator's globally configured Jira or Confluence credentials. A network client that can reach the MCP endpoint can invoke Atlassian tools as the operator, including read and write operations available to that account. The advisory traces the vulnerable input and processing flow through UserTokenMiddleware, AtlassianOpaqueTokenVerifier, _get_fetcher, and streamable-http, which identify the affected entry points, controls, and code paths. This issue is fixed in version 0.22.0. EPSS 0.50% (p41, as of 2026-09-23).

## Affected

- **Product / project:** mcp-atlassian (PyPI package `mcp-atlassian`)
- **Versions:** < 0.22.0 (validated on 0.21.1)
- **CWE:** CWE-287, CWE-303, CWE-862   **CVSS:** 10.0  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`   **KEV:** no

## What was validated

The proof-of-concept is a **differential probe**: it reads a canary from `POC_CANARY` and
emits it on stdout **only** through the vulnerable code path, so the canary appearing proves
the pre-patch behaviour executed. It was run against the vulnerable and patched builds and
fired only on the vulnerable one — confirming the affected code path is **reachable**. It is
a proof of the primitive, **not** a weaponized end-to-end exploit; the advisory's stated
end-to-end impact is not demonstrated by this artifact.

## Technical detail

The flaw is summarised above. The fix is in 0.22.0; the affected code
path and the difference the probe keys on were read from the upstream fix diff
(`artifacts/patch-diff.txt`), which is included alongside the validated console captures.

## Reproduce

```bash
pip install 'mcp-atlassian==0.21.1'
POC_CANARY=demo python poc.py     # prints: demo   (vulnerable)

pip install 'mcp-atlassian==0.22.0'
POC_CANARY=demo python poc.py     # prints nothing (patched)
```

Success signal: the canary line on stdout — **exit code is always 0 on both builds**.
Console captures from the validated run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-77244](https://nvd.nist.gov/vuln/detail/CVE-2026-77244)
- [Upstream fix commit](https://github.com/sooperset/mcp-atlassian/commit/b041733473f95119dd539542a43c280737a8e460)
