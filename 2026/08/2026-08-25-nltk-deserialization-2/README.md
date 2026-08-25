# NLTK Unsafe deserialization (CVE-2026-79657)

**Date:** 2026-08-25
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `deserialization`

## Summary

NLTK versions before 3.10.3 contain a remote code execution vulnerability in allowlisted pickle loaders that trust entire module namespaces instead of specific safe callables. Attackers can craft malicious pickle payloads invoking dangerous in-namespace functions like ReppTokenizer._execute and numpy.f2py.crackfortran.myeval through pickle REDUCE to execute arbitrary commands during model or tokenizer artifact loading. EPSS 1.27% (p68, as of 2026-09-27).

## Affected

- **Product / project:** NLTK (PyPI package `nltk`)
- **Versions:** < 3.10.3 (validated on 3.10.2)
- **CWE:** CWE-502   **CVSS:** 9.8   **KEV:** no

## Validation

The proof-of-concept writes a caller-supplied marker (taken from the `POC_CANARY` environment variable) to stdout, but only when execution actually reaches the vulnerable code. Running it against an affected release prints the marker; running the identical script against 3.10.3 prints nothing. That before/after difference is the result — it shows the weak path is genuinely reachable. The proof stops there and does not chain the issue into the advisory's full impact.

## Technical detail

The mechanism was read from the change shipped in 3.10.3. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
pip install 'nltk==3.10.2'
POC_CANARY=demo python poc.py     # marker appears (affected build)

pip install 'nltk==3.10.3'
POC_CANARY=demo python poc.py     # silent (patched)
```

Success is the marker line on stdout for the vulnerable build and its absence for the fixed one; both runs exit 0, so the exit code is not the signal.
Console output captured during the run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-79657](https://nvd.nist.gov/vuln/detail/CVE-2026-79657)
- [Upstream fix commit](https://github.com/nltk/nltk/commit/303f6e2ba8e4548a5f54fd65d86bb5c9a949f1db)
