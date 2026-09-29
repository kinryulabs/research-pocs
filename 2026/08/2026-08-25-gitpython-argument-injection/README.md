# gitpython Argument injection (CVE-2026-78676)

**Date:** 2026-08-25
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `argument-injection`

## Summary

GitPython before 3.1.59 fails to safely re-serialize multi-line git-config values during write operations, corrupting dormant quoted values into injected directives like core.hooksPath. Attackers can craft config files with embedded newlines that become live git directives after any unrelated GitPython config write, enabling arbitrary code execution via hook invocation. EPSS 0.78% (p54, as of 2026-09-29).

## Affected

- **Product / project:** gitpython (PyPI package `gitpython`)
- **Versions:** < 3.1.59 (validated on 3.1.58)
- **CWE:** CWE-88   **CVSS:** 9.8   **KEV:** no

## Validation

Verification is done by comparison. The same program runs twice — once on the affected build, once on 3.1.59 — and prints a marker from `POC_CANARY` solely along the vulnerable path. Seeing the marker on the old build and not on the fixed one is what confirms the finding. It demonstrates that the flaw is reachable, not end-to-end impact.

## Technical detail

The mechanism was read from the change shipped in 3.1.59. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
pip install 'gitpython==3.1.58'
POC_CANARY=demo python poc.py     # outputs the marker (vulnerable)

pip install 'gitpython==3.1.59'
POC_CANARY=demo python poc.py     # prints nothing (patched)
```

A run counts as vulnerable when the marker prints; the fixed build prints nothing. Neither outcome depends on the exit code.
The runs above are recorded in:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-78676](https://nvd.nist.gov/vuln/detail/CVE-2026-78676)
- [Upstream fix commit](https://github.com/gitpython-developers/gitpython/commit/66340d77aab9a7468f4aed3681d4ef1e3c0ec931)
