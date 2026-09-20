# NLTK Unsafe deserialization (CVE-2026-78683)

**Date:** 2026-08-25
**Status:** published
**Tags:** `unsafe`, `differential-poc`

## Summary

NLTK before 3.10.0 (affected versions <=3.9.4) contains an unsafe pickle deserialization vulnerability in the TransitionParser.parse() method (nltk/parse/transitionparser.py). The method calls pickle_load() with the default restricted=False, routing deserialization through WarningUnpickler, which does not override find_class() and therefore permits arbitrary class resolution. When an application loads an attacker-crafted model file, embedded pickle gadget chains execute arbitrary Python code with the privileges of the user running the application. NLTK provides a RestrictedUnpickler for safe deserialization, but it is not used by production code paths. Fixed in 3.10.0. Confirmed differentially: the proof-of-concept
fires only on the vulnerable build and is silent on the patched build. EPSS 0.29% (p21).

## Affected

- **Product / project:** NLTK (PyPI package `nltk`)
- **Versions:** < 3.10.0 (validated on 3.9.4)
- **CWE:** CWE-502   **CVSS:** 9.6

## Technical detail

NLTK before 3.10.0 (affected versions <=3.9.4) contains an unsafe pickle deserialization vulnerability in the TransitionParser.parse() method (nltk/parse/transitionparser.py). The method calls pickle_load() with the default restricted=False, routing deserialization through WarningUnpickler, which does not override find_class() and therefore permits arbitrary class resolution. When an application loads an attacker-crafted model file, embedded pickle gadget chains execute arbitrary Python code with the privileges of the user running the application. NLTK provides a RestrictedUnpickler for safe deserialization, but it is not used by production code paths. Fixed in 3.10.0. The fix landed in 3.10.0; the
mechanism was read from the fix diff (`artifacts/patch-diff.txt`).

## Proof of concept

`poc.py` is a differential probe: it reads a canary from `POC_CANARY` and prints it only
through the vulnerable code path, so the canary on stdout proves the pre-patch behaviour ran.
It is a proof of the primitive, not a weaponized exploit chain.

```bash
pip install 'nltk==3.9.4'
POC_CANARY=demo python poc.py     # prints: demo   (vulnerable)

pip install 'nltk==3.10.0'
POC_CANARY=demo python poc.py     # prints nothing (patched)
```

Console captures from the validated run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## Impact

Reaching the affected code path in NLTK with attacker-controlled input yields unsafe deserialization.

## References

- [NVD — CVE-2026-78683](https://nvd.nist.gov/vuln/detail/CVE-2026-78683)
- [Upstream fix commit](https://github.com/nltk/nltk/commit/bd49f9011d7dc8c6a36b3c4ae71f04060c9b3fb9)
