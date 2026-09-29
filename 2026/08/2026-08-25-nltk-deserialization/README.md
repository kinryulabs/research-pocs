# NLTK Unsafe deserialization (CVE-2026-78683)

**Date:** 2026-08-25
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `deserialization`

## Summary

NLTK before 3.10.0 (affected versions <=3.9.4) contains an unsafe pickle deserialization vulnerability in the TransitionParser.parse() method (nltk/parse/transitionparser.py). The method calls pickle_load() with the default restricted=False, routing deserialization through WarningUnpickler, which does not override find_class() and therefore permits arbitrary class resolution. When an application loads an attacker-crafted model file, embedded pickle gadget chains execute arbitrary Python code with the privileges of the user running the application. NLTK provides a RestrictedUnpickler for safe deserialization, but it is not used by production code paths. Fixed in 3.10.0. EPSS 0.51% (p41, as of 2026-09-29).

## Affected

- **Product / project:** NLTK (PyPI package `nltk`)
- **Versions:** < 3.10.0 (validated on 3.9.4)
- **CWE:** CWE-502   **CVSS:** 9.6   **KEV:** no

## Validation

Verification is done by comparison. The same program runs twice — once on the affected build, once on 3.10.0 — and prints a marker from `POC_CANARY` solely along the vulnerable path. Seeing the marker on the old build and not on the fixed one is what confirms the finding. It demonstrates that the flaw is reachable, not end-to-end impact.

## Technical detail

What the check looks for was derived from the patch released in 3.10.0. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
pip install 'nltk==3.9.4'
POC_CANARY=demo python poc.py     # outputs the marker (vulnerable)

pip install 'nltk==3.10.0'
POC_CANARY=demo python poc.py     # prints nothing (patched)
```

A run counts as vulnerable when the marker prints; the fixed build prints nothing. Neither outcome depends on the exit code.
Console output captured during the run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-78683](https://nvd.nist.gov/vuln/detail/CVE-2026-78683)
- [Upstream fix commit](https://github.com/nltk/nltk/commit/bd49f9011d7dc8c6a36b3c4ae71f04060c9b3fb9)
