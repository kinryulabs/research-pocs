# vllm Race condition (CVE-2026-73557)

**Date:** 2026-08-13
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `race-condition`

## Summary

vLLM is an inference and serving engine for large language models. From 0.20.2rc0 until 0.26.0, safe_load_prompt_embeds in vllm/renderers/embed_utils.py uses torch.sparse.check_sparse_tensor_invariants, whose process-global save, enable, and restore state can be raced by concurrent prompt_embeds parts submitted to POST /v1/chat/completions through AsyncMultiModalItemTracker.resolve_items, asyncio.gather, and the default executor, allowing an invalid sparse tensor to reach tensor.to_dense despite the CVE-2025-62164 guard when enable_prompt_embeds is enabled. This issue is fixed in version 0.26.0. EPSS 0.40% (p32, as of 2026-09-27).

## Affected

- **Product / project:** vllm (PyPI package `vllm`)
- **Versions:** < 0.26.0 (validated on 0.25.1)
- **CWE:** CWE-362   **CVSS:** 6.3   **KEV:** no

## How this was verified

The test keys on a single observable difference. A marker string (supplied through `POC_CANARY`) reaches stdout only if the vulnerable code executes; it shows up on the unpatched release and vanishes on 0.26.0. This confirms the affected path can be reached and exercised, without asserting the downstream impact described in the advisory.

## Technical detail

The relevant code path and the fix that closes it land in 0.26.0. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
pip install 'vllm==0.25.1'
POC_CANARY=demo python poc.py     # marker appears (affected build)

pip install 'vllm==0.26.0'
POC_CANARY=demo python poc.py     # prints nothing (patched)
```

Success is the marker line on stdout for the vulnerable build and its absence for the fixed one; both runs exit 0, so the exit code is not the signal.
Console output captured during the run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-73557](https://nvd.nist.gov/vuln/detail/CVE-2026-73557)
- [Upstream fix commit](https://github.com/vllm-project/vllm/commit/ffd46bfab2128bb84146050e98b51a617c6575ab)
