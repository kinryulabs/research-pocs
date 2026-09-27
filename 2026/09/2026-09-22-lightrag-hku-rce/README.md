# lightrag-hku code execution (CVE-2026-85734)

**Date:** 2026-09-22
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `rce`

## Summary

LightRAG provides simple and fast retrieval-augmented generation. Prior to 1.5.5, the POST /login endpoint in lightrag/api/lightrag_server.py does not impose a rate limit, account lockout, delay, or counter for failed authentication attempts. A network attacker can submit password guesses at full request speed until a valid account password is found. Successful credential recovery grants authenticated access to documents, the knowledge graph, and administrative operations. This issue is fixed in version 1.5.5. EPSS 0.36% (p26, as of 2026-09-27).

## Affected

- **Product / project:** lightrag-hku (PyPI package `lightrag-hku`)
- **Versions:** < 1.5.5 (validated on 1.5.4)
- **CWE:** CWE-307   **CVSS:** 9.1  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`   **KEV:** no

## Verifying the finding

The proof-of-concept writes a caller-supplied marker (taken from the `POC_CANARY` environment variable) to stdout, but only when execution actually reaches the vulnerable code. Running it against an affected release prints the marker; running the identical script against 1.5.5 prints nothing. That before/after difference is the result — it shows the weak path is genuinely reachable. The proof stops there and does not chain the issue into the advisory's full impact.

## Technical detail

The relevant code path and the fix that closes it land in 1.5.5. The fix diff and the console output from both runs are included under `artifacts/`.

## Reproduce

```bash
pip install 'lightrag-hku==1.5.4'
POC_CANARY=demo python poc.py     # marker appears (affected build)

pip install 'lightrag-hku==1.5.5'
POC_CANARY=demo python poc.py     # silent (patched)
```

The signal is the marker on stdout — present before the patch, absent after. Exit codes are 0 in both cases.
Recorded output from the two runs:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-85734](https://nvd.nist.gov/vuln/detail/CVE-2026-85734)
- [Upstream fix commit](https://github.com/hkuds/lightrag/commit/22ea2d0cbfa2b7002aa118bd0bf1780a69d489bc)
