# lmdeploy Unsafe deserialization (CVE-2025-66455)

**Date:** 2026-09-18
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `deserialization`

## Summary

LMDeploy is a toolkit for compressing, deploying, and serving large language models. Starting in version 0.9.2 and prior to version 0.16.0, LMDeploy's PyTorch DistServe/PD-disaggregation control plane used `recv_pyobj()` to deserialize messages received through a ZeroMQ PULL socket. PyZMQ implements `recv_pyobj()` using Python pickle deserialization, which can execute arbitrary code while reconstructing an object. The peer address used by the receiver was supplied through the `POST /distserve/p2p_connect` HTTP endpoint. An attacker who could reach an affected DistServe API server could cause the server to connect to an attacker-controlled ZeroMQ endpoint and deserialize a crafted pickle payload. API-key authentication is not enabled unless the operator explicitly configures it. As a result, affected DistServe deployments without API keys allowed unauthenticated remote code execution with the privileges of the LMDeploy serving process. This issue affects the PyTorch backend when PD-disaggregation/DistServe is enabled. Ordinary deployments that do not use the affected disaggregated-serving path do not expose this data flow. The fix was released in LMDeploy 0.16.0. Users who cannot upgrade immediately should prevent untrusted clients from reaching `/distserve/*` endpoints, restrict the DistServe HTTP and ZeroMQ control planes to trusted cluster networks, configure API-key authentication, and block arbitrary outbound ZeroMQ connections from serving nodes. These measures reduce exposure but do not make pickle deserialization safe. EPSS 0.69% (p50, as of 2026-09-27).

## Affected

- **Product / project:** lmdeploy (PyPI package `lmdeploy`)
- **Versions:** < 0.16.0 (validated on 0.15.0)
- **CWE:** CWE-502   **CVSS:** 9.8  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`   **KEV:** no

## What the proof-of-concept shows

Verification is done by comparison. The same program runs twice — once on the affected build, once on 0.16.0 — and prints a marker from `POC_CANARY` solely along the vulnerable path. Seeing the marker on the old build and not on the fixed one is what confirms the finding. It demonstrates that the flaw is reachable, not end-to-end impact.

## Technical detail

The relevant code path and the fix that closes it land in 0.16.0. The fix diff and the console output from both runs are included under `artifacts/`.

## Reproduce

```bash
pip install 'lmdeploy==0.15.0'
POC_CANARY=demo python poc.py     # prints the marker (vulnerable)

pip install 'lmdeploy==0.16.0'
POC_CANARY=demo python poc.py     # silent (patched)
```

A run counts as vulnerable when the marker prints; the fixed build prints nothing. Neither outcome depends on the exit code.
Recorded output from the two runs:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2025-66455](https://nvd.nist.gov/vuln/detail/CVE-2025-66455)
- [Upstream fix commit](https://github.com/internlm/lmdeploy/commit/1208bf006bbac69f1f012ceafeeeb70f623b632c)
