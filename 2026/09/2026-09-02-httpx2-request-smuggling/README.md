# httpx2 HTTP request smuggling (CVE-2026-84380)

**Date:** 2026-09-02
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `request-smuggling`

## Summary

HTTPX2 is a next generation HTTP client for Python. Prior to 2.11.0, Request._prepare() in src/httpx2/httpx2/_models.py can add a body-derived Content-Length header to a request that already contains a caller-supplied Transfer-Encoding header because its setdefault() processing checks each default header independently rather than treating the two framing headers as mutually exclusive. Fixed-size byte, JSON, form, and known-length multipart bodies can therefore be serialized over HTTP/1.1 with both headers, allowing request smuggling or connection desynchronization when downstream intermediaries disagree about which framing header takes precedence. This issue is fixed in version 2.11.0. EPSS 0.36% (p26, as of 2026-09-27).

## Affected

- **Product / project:** httpx2 (PyPI package `httpx2`)
- **Versions:** < 2.11.0 (validated on 2.10.0)
- **CWE:** CWE-444   **CVSS:** 5.6   **KEV:** no

## Verifying the finding

The proof-of-concept writes a caller-supplied marker (taken from the `POC_CANARY` environment variable) to stdout, but only when execution actually reaches the vulnerable code. Running it against an affected release prints the marker; running the identical script against 2.11.0 prints nothing. That before/after difference is the result — it shows the weak path is genuinely reachable. The proof stops there and does not chain the issue into the advisory's full impact.

## Technical detail

The behaviour the test relies on was taken from the upstream fix in 2.11.0. See `artifacts/` for the patch diff and the recorded output of the two runs.

## Reproduce

```bash
pip install 'httpx2==2.10.0'
POC_CANARY=demo python poc.py     # outputs the marker (vulnerable)

pip install 'httpx2==2.11.0'
POC_CANARY=demo python poc.py     # no marker (fixed build)
```

A run counts as vulnerable when the marker prints; the fixed build prints nothing. Neither outcome depends on the exit code.
Console output captured during the run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-84380](https://nvd.nist.gov/vuln/detail/CVE-2026-84380)
- [Upstream fix commit](https://github.com/pydantic/httpx2/commit/2b13fa92e4181d5e0f56772205360b2aa12f109d)
