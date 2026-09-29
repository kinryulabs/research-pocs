# httpx2 Data amplification denial of service (CVE-2026-84382)

**Date:** 2026-09-02
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `dos`

## Summary

HTTPX2 is a next generation HTTP client for Python. Prior to 2.12.0, the HTTPX2 content decoders in src/httpx2/httpx2/_decoders.py fully inflate each gzip, deflate, br, or zstd network chunk before iter_bytes() or aiter_bytes() yields bounded pieces to the application. A 64 KiB compressed chunk can expand to approximately 64 MiB in one intermediate allocation, so an attacker-controlled or compromised server can cause severe memory pressure or out-of-memory process termination even when the application streams the response. This issue is fixed in version 2.12.0. EPSS 0.63% (p48, as of 2026-09-29).

## Affected

- **Product / project:** httpx2 (PyPI package `httpx2`)
- **Versions:** < 2.12.0 (validated on 2.11.0)
- **CWE:** CWE-409   **CVSS:** 7.5   **KEV:** no

## Validation

The test keys on a single observable difference. A marker string (supplied through `POC_CANARY`) reaches stdout only if the vulnerable code executes; it shows up on the unpatched release and vanishes on 2.12.0. This confirms the affected path can be reached and exercised, without asserting the downstream impact described in the advisory.

## Technical detail

What the check looks for was derived from the patch released in 2.12.0. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
pip install 'httpx2==2.11.0'
POC_CANARY=demo python poc.py     # prints the marker (vulnerable)

pip install 'httpx2==2.12.0'
POC_CANARY=demo python poc.py     # prints nothing (patched)
```

Success is the marker line on stdout for the vulnerable build and its absence for the fixed one; both runs exit 0, so the exit code is not the signal.
Console output captured during the run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-84382](https://nvd.nist.gov/vuln/detail/CVE-2026-84382)
- [Upstream fix commit](https://github.com/pydantic/httpx2/commit/71ae23be5448f859c2b4e21d9972ddfa7b8d759d)
