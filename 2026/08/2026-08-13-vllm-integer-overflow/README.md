# vllm Integer overflow (CVE-2026-73558)

**Date:** 2026-08-13
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `integer-overflow`

## Summary

vLLM is an inference and serving engine for large language models. Prior to 0.27.0, an integer overflow in blockIdx.x * 2 * d in activation_kernels.cu can cause act_and_mul_kernel to consume another batched user's input, allowing a request processed in the same inference batch to receive a partial or complete copy of another user's inference result. This issue is fixed in version 0.27.0. EPSS 0.41% (p33, as of 2026-09-29).

## Affected

- **Product / project:** vllm (PyPI package `vllm`)
- **Versions:** < 0.27.0 (validated on 0.26.0)
- **CWE:** CWE-190   **CVSS:** 5.3   **KEV:** no

## What the proof-of-concept shows

The test keys on a single observable difference. A marker string (supplied through `POC_CANARY`) reaches stdout only if the vulnerable code executes; it shows up on the unpatched release and vanishes on 0.27.0. This confirms the affected path can be reached and exercised, without asserting the downstream impact described in the advisory.

## Technical detail

What the check looks for was derived from the patch released in 0.27.0. See `artifacts/` for the patch diff and the recorded output of the two runs.

## Reproduce

```bash
pip install 'vllm==0.26.0'
POC_CANARY=demo python poc.py     # outputs the marker (vulnerable)

pip install 'vllm==0.27.0'
POC_CANARY=demo python poc.py     # no marker (fixed build)
```

A run counts as vulnerable when the marker prints; the fixed build prints nothing. Neither outcome depends on the exit code.
The runs above are recorded in:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-73558](https://nvd.nist.gov/vuln/detail/CVE-2026-73558)
- [Upstream fix commit](https://github.com/vllm-project/vllm/commit/4bdc8a788d2e2ce9165d552b3d4d8b72604626bf)
