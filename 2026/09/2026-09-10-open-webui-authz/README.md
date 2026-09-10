# open-webui Incorrect authorization (CVE-2026-88006)

**Date:** 2026-09-10
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `authz`

## Summary

Open WebUI is an extensible, feature-rich, and user-friendly self-hosted AI platform. From 0.8.0 until 0.11.1, Open WebUI's OAuth token exchange endpoint issues a session for a provider access token without running the OAuth role management that the normal OAuth login callback runs. A user whose provider roles the login callback would refuse, or would demote, could still obtain a working session at their existing role through this endpoint. This issue is fixed in version 0.11.1. EPSS 0.37% (p28, as of 2026-09-27).

## Affected

- **Product / project:** open-webui (PyPI package `open-webui`)
- **Versions:** < 0.11.1 (validated on 0.11.0)
- **CWE:** CWE-863   **CVSS:** 6.5   **KEV:** no

## How this was verified

To separate a real defect from a theoretical one, the script echoes a marker value (`POC_CANARY`) that can only appear if the flawed branch runs. The marker is present on the vulnerable version and gone once 0.11.1 is installed, which ties the behaviour directly to the code the patch changes. It is a minimal trigger rather than a full exploit chain.

## Technical detail

What the check looks for was derived from the patch released in 0.11.1. The fix diff and the console output from both runs are included under `artifacts/`.

## Reproduce

```bash
pip install 'open-webui==0.11.0'
POC_CANARY=demo python poc.py     # marker appears (affected build)

pip install 'open-webui==0.11.1'
POC_CANARY=demo python poc.py     # silent (patched)
```

The signal is the marker on stdout — present before the patch, absent after. Exit codes are 0 in both cases.
The runs above are recorded in:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-88006](https://nvd.nist.gov/vuln/detail/CVE-2026-88006)
- [Upstream fix commit](https://github.com/open-webui/open-webui/commit/d3e8bf3405e848cfba377814d0aa7ba7290e414d)
