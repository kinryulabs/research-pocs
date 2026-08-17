# vllm Server-side request forgery (CVE-2026-73560)

**Date:** 2026-08-17
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `ssrf`

## Summary

vLLM is an inference and serving engine for large language models. Prior to 0.26.0, the MiMoV2OmniMultiModalProcessor in vllm/transformers_utils/processors/mimo_v2_omni.py passes attacker-controlled image and audio strings through _fetch_image, requests.get, and Image.open instead of MediaConnector, bypassing allowed_media_domains and allowed_local_media_path protections and allowing server-side requests and reads of arbitrary files accessible to the vLLM process. This issue is fixed in version 0.26.0. EPSS 0.44% (p35, as of 2026-09-27).

## Affected

- **Product / project:** vllm (PyPI package `vllm`)
- **Versions:** < 0.26.0 (validated on 0.25.1)
- **CWE:** CWE-918   **CVSS:** 6.5   **KEV:** no

## Validation

The proof-of-concept writes a caller-supplied marker (taken from the `POC_CANARY` environment variable) to stdout, but only when execution actually reaches the vulnerable code. Running it against an affected release prints the marker; running the identical script against 0.26.0 prints nothing. That before/after difference is the result — it shows the weak path is genuinely reachable. The proof stops there and does not chain the issue into the advisory's full impact.

## Technical detail

What the check looks for was derived from the patch released in 0.26.0. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
pip install 'vllm==0.25.1'
POC_CANARY=demo python poc.py     # marker appears (affected build)

pip install 'vllm==0.26.0'
POC_CANARY=demo python poc.py     # no marker (fixed build)
```

The signal is the marker on stdout — present before the patch, absent after. Exit codes are 0 in both cases.
Recorded output from the two runs:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-73560](https://nvd.nist.gov/vuln/detail/CVE-2026-73560)
- [Upstream fix commit](https://github.com/vllm-project/vllm/commit/ffd46bfab2128bb84146050e98b51a617c6575ab)
