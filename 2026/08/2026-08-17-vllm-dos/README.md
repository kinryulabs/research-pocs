# vllm Uncontrolled resource consumption (CVE-2026-71486)

**Date:** 2026-08-17
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `dos`

## Summary

vLLM is an inference and serving engine for large language models. Prior to 0.26.0, the /v1/completions/derender and /v1/chat/completions/derender endpoints accept caller-supplied GenerateResponse objects whose generate_responses, choices, token_ids, prompt_logprobs, logprobs.content, top_logprobs, and routed_experts structures are processed by OnlineDerenderer and tokenizer.decode before max_model_len, max_tokens, max_num_seqs, or response-size limits are enforced, allowing an authenticated API client to consume excessive CPU and memory and produce oversized responses. This issue is fixed in version 0.26.0. EPSS 0.47% (p37, as of 2026-09-27).

## Affected

- **Product / project:** vllm (PyPI package `vllm`)
- **Versions:** < 0.26.0 (validated on 0.25.1)
- **CWE:** CWE-400, CWE-770   **CVSS:** 4.3   **KEV:** no

## How this was verified

Verification is done by comparison. The same program runs twice — once on the affected build, once on 0.26.0 — and prints a marker from `POC_CANARY` solely along the vulnerable path. Seeing the marker on the old build and not on the fixed one is what confirms the finding. It demonstrates that the flaw is reachable, not end-to-end impact.

## Technical detail

The relevant code path and the fix that closes it land in 0.26.0. The fix diff and the console output from both runs are included under `artifacts/`.

## Reproduce

```bash
pip install 'vllm==0.25.1'
POC_CANARY=demo python poc.py     # outputs the marker (vulnerable)

pip install 'vllm==0.26.0'
POC_CANARY=demo python poc.py     # silent (patched)
```

A run counts as vulnerable when the marker prints; the fixed build prints nothing. Neither outcome depends on the exit code.
Recorded output from the two runs:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-71486](https://nvd.nist.gov/vuln/detail/CVE-2026-71486)
- [Upstream fix commit](https://github.com/vllm-project/vllm/commit/ffd46bfab2128bb84146050e98b51a617c6575ab)
