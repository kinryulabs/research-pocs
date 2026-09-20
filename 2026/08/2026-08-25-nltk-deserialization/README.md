# NLTK Unsafe deserialization (CVE-2026-78683)

**Date:** 2026-08-25
**Status:** published
**Maturity:** differential-poc (vulnerable code path confirmed reachable; not a weaponized chain)
**Tags:** `deserialization`, `differential-poc`

## Summary

NLTK before 3.10.0 (affected versions <=3.9.4) contains an unsafe pickle deserialization vulnerability in the TransitionParser.parse() method (nltk/parse/transitionparser.py). The method calls pickle_load() with the default restricted=False, routing deserialization through WarningUnpickler, which does not override find_class() and therefore permits arbitrary class resolution. When an application loads an attacker-crafted model file, embedded pickle gadget chains execute arbitrary Python code with the privileges of the user running the application. NLTK provides a RestrictedUnpickler for safe deserialization, but it is not used by production code paths. Fixed in 3.10.0. EPSS 0.29% (p21, as of 2026-09-20).

## Affected

- **Product / project:** NLTK (PyPI package `nltk`)
- **Versions:** < 3.10.0 (validated on 3.9.4)
- **CWE:** CWE-502   **CVSS:** 9.6   **KEV:** no

## What was validated

The proof-of-concept is a **differential probe**: it reads a canary from `POC_CANARY` and
emits it on stdout **only** through the vulnerable code path, so the canary appearing proves
the pre-patch behaviour executed. It was run against the vulnerable and patched builds and
fired only on the vulnerable one — confirming the affected code path is **reachable**. It is
a proof of the primitive, **not** a weaponized end-to-end exploit; the advisory's stated
end-to-end impact is not demonstrated by this artifact.

## Technical detail

The flaw is summarised above. The fix is in 3.10.0; the affected code
path and the difference the probe keys on were read from the upstream fix diff
(`artifacts/patch-diff.txt`), which is included alongside the validated console captures.

## Reproduce

```bash
pip install 'nltk==3.9.4'
POC_CANARY=demo python poc.py     # prints: demo   (vulnerable)

pip install 'nltk==3.10.0'
POC_CANARY=demo python poc.py     # prints nothing (patched)
```

Success signal: the canary line on stdout — **exit code is always 0 on both builds**.
Console captures from the validated run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-78683](https://nvd.nist.gov/vuln/detail/CVE-2026-78683)
- [Upstream fix commit](https://github.com/nltk/nltk/commit/bd49f9011d7dc8c6a36b3c4ae71f04060c9b3fb9)
