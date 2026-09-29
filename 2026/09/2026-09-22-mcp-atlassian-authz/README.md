# mcp-atlassian Missing authorization (CVE-2026-77244)

**Date:** 2026-09-22
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `authz`

## Summary

MCP Atlassian is a Model Context Protocol (MCP) server for Atlassian products (Confluence and Jira). Prior to 0.22.0, the HTTP transport accepts requests without a verified user identity and downstream fetcher construction falls back to the operator's globally configured Jira or Confluence credentials. A network client that can reach the MCP endpoint can invoke Atlassian tools as the operator, including read and write operations available to that account. The advisory traces the vulnerable input and processing flow through UserTokenMiddleware, AtlassianOpaqueTokenVerifier, _get_fetcher, and streamable-http, which identify the affected entry points, controls, and code paths. This issue is fixed in version 0.22.0. EPSS 0.28% (p18, as of 2026-09-29).

## Affected

- **Product / project:** mcp-atlassian (PyPI package `mcp-atlassian`)
- **Versions:** < 0.22.0 (validated on 0.21.1)
- **CWE:** CWE-287, CWE-303, CWE-862   **CVSS:** 10.0  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`   **KEV:** no

## Validation

Verification is done by comparison. The same program runs twice — once on the affected build, once on 0.22.0 — and prints a marker from `POC_CANARY` solely along the vulnerable path. Seeing the marker on the old build and not on the fixed one is what confirms the finding. It demonstrates that the flaw is reachable, not end-to-end impact.

## Technical detail

What the check looks for was derived from the patch released in 0.22.0. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
pip install 'mcp-atlassian==0.21.1'
POC_CANARY=demo python poc.py     # marker appears (affected build)

pip install 'mcp-atlassian==0.22.0'
POC_CANARY=demo python poc.py     # no marker (fixed build)
```

A run counts as vulnerable when the marker prints; the fixed build prints nothing. Neither outcome depends on the exit code.
The runs above are recorded in:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-77244](https://nvd.nist.gov/vuln/detail/CVE-2026-77244)
- [Upstream fix commit](https://github.com/sooperset/mcp-atlassian/commit/b041733473f95119dd539542a43c280737a8e460)
