# httpx2 Algorithmic-complexity denial of service (CVE-2026-84378)

**Date:** 2026-09-02
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `dos`

## Summary

HTTPX2 is a next generation HTTP client for Python. From 2.5.0 until 2.10.0, the HTTPX2 Server-Sent Events parser in src/httpx2/httpx2/_sse.py repeatedly copies and rescans buffered text in _SSELineDecoder.decode() when an attacker-controlled or compromised SSE endpoint splits one unterminated line across many response chunks. The behavior affects httpx2.Client.sse() and httpx2.AsyncClient.sse(), and the total processing work grows quadratically with the line length, allowing a crafted stream to consume excessive CPU and block a synchronous worker or asynchronous event loop. This issue is fixed in version 2.10.0. EPSS 0.53% (p42, as of 2026-09-27).

## Affected

- **Product / project:** httpx2 (PyPI package `httpx2`)
- **Versions:** < 2.10.0 (validated on 2.9.1)
- **CWE:** CWE-407   **CVSS:** 5.9   **KEV:** no

## Validation

The test keys on a single observable difference. A marker string (supplied through `POC_CANARY`) reaches stdout only if the vulnerable code executes; it shows up on the unpatched release and vanishes on 2.10.0. This confirms the affected path can be reached and exercised, without asserting the downstream impact described in the advisory.

## Technical detail

What the check looks for was derived from the patch released in 2.10.0. See `artifacts/` for the patch diff and the recorded output of the two runs.

## Reproduce

```bash
pip install 'httpx2==2.9.1'
POC_CANARY=demo python poc.py     # outputs the marker (vulnerable)

pip install 'httpx2==2.10.0'
POC_CANARY=demo python poc.py     # silent (patched)
```

A run counts as vulnerable when the marker prints; the fixed build prints nothing. Neither outcome depends on the exit code.
The runs above are recorded in:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-84378](https://nvd.nist.gov/vuln/detail/CVE-2026-84378)
- [Upstream fix commit](https://github.com/pydantic/httpx2/commit/a966320e75477b8c55ee78fdb8f57ead6a574cb0)
