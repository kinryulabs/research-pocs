# vllm Sensitive information exposure (CVE-2026-73555)

**Date:** 2026-08-13
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `info-disclosure`

## Summary

vLLM is an inference and serving engine for large language models. Prior to 0.26.0, the validation_exception_handler in vllm/entrypoints/openai/server_utils.py converts FastAPI RequestValidationError objects with str(exc), and sanitize_message in vllm/entrypoints/utils.py does not remove traceback-style file paths, allowing unauthenticated malformed JSON requests to /v1/chat/completions, /v1/completions, /tokenize, and /detokenize to disclose the OS username, home and virtual-environment paths, Python version, internal package structure, line numbers, and endpoint handler names. This issue is fixed in version 0.26.0. EPSS 0.42% (p33, as of 2026-09-29).

## Affected

- **Product / project:** vllm (PyPI package `vllm`)
- **Versions:** < 0.26.0 (validated on 0.25.1)
- **CWE:** CWE-209   **CVSS:** 5.3   **KEV:** no

## Validation

Verification is done by comparison. The same program runs twice — once on the affected build, once on 0.26.0 — and prints a marker from `POC_CANARY` solely along the vulnerable path. Seeing the marker on the old build and not on the fixed one is what confirms the finding. It demonstrates that the flaw is reachable, not end-to-end impact.

## Technical detail

What the check looks for was derived from the patch released in 0.26.0. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
pip install 'vllm==0.25.1'
POC_CANARY=demo python poc.py     # marker appears (affected build)

pip install 'vllm==0.26.0'
POC_CANARY=demo python poc.py     # prints nothing (patched)
```

The signal is the marker on stdout — present before the patch, absent after. Exit codes are 0 in both cases.
Recorded output from the two runs:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-73555](https://nvd.nist.gov/vuln/detail/CVE-2026-73555)
- [Upstream fix commit](https://github.com/vllm-project/vllm/commit/ffd46bfab2128bb84146050e98b51a617c6575ab)
