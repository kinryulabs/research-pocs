# lmdeploy Uncontrolled resource consumption (CVE-2026-33625)

**Date:** 2026-09-18
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `dos`

## Summary

LMDeploy is a toolkit for compressing, deploying, and serving large language models. Versions 012.1 through 0.12.2 contain a code injection vulnerability in `lmdeploy/pytorch/config.py` line 620 that allows an attacker to execute arbitrary Python code by publishing a malicious HuggingFace model with a crafted `quantization_config.quant_dtype` value. When a user loads the model with lmdeploy, the `quant_dtype` is passed to `eval(f'torch.{quant_dtype}')` without any validation. Version 0.12.3 contains a patch. EPSS 0.44% (p35, as of 2026-09-29).

## Affected

- **Product / project:** lmdeploy (PyPI package `lmdeploy`)
- **Versions:** < 0.12.3 (validated on 0.12.2)
- **CWE:** CWE-400   **CVSS:** 8.8  `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`   **KEV:** no

## Validation

The test keys on a single observable difference. A marker string (supplied through `POC_CANARY`) reaches stdout only if the vulnerable code executes; it shows up on the unpatched release and vanishes on 0.12.3. This confirms the affected path can be reached and exercised, without asserting the downstream impact described in the advisory.

## Technical detail

The mechanism was read from the change shipped in 0.12.3. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
pip install 'lmdeploy==0.12.2'
POC_CANARY=demo python poc.py     # prints the marker (vulnerable)

pip install 'lmdeploy==0.12.3'
POC_CANARY=demo python poc.py     # no marker (fixed build)
```

A run counts as vulnerable when the marker prints; the fixed build prints nothing. Neither outcome depends on the exit code.
Console output captured during the run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-33625](https://nvd.nist.gov/vuln/detail/CVE-2026-33625)
- [Upstream fix commit](https://github.com/internlm/lmdeploy/commit/8ea459f49ed9cd943481073011424919e31e3e3b)
