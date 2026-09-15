# org.http4s:http4s-ember-core_2.12 HTTP request smuggling (CVE-2026-69204)

**Date:** 2026-09-15
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `request-smuggling`

## Summary

Http4s is a Scala interface for HTTP services. Prior to 0.23.35 and 1.0.0-M47, Ember HTTP/1.1 does not reject messages containing both Transfer-Encoding and Content-Length, so an intermediary and Ember can select different body framing rules. When ember-server is behind a keep-alive intermediary that forwards both headers and frames by Content-Length, an unauthenticated attacker can smuggle a second request, bypass intermediary access controls, poison caches, or cause a victim request to be joined to an attacker-controlled prefix. The shared response parser can also desynchronize an ember-client connection when a malicious or compromised upstream sends both headers. This issue is fixed in versions 0.23.35 and 1.0.0-M47. EPSS 0.57% (p45, as of 2026-09-27).

## Affected

- **Product / project:** org.http4s:http4s-ember-core_2.12 (Maven package `org.http4s:http4s-ember-core_2.12`)
- **Versions:** < 0.23.35 (validated on 0.23.34)
- **CWE:** CWE-444   **CVSS:** 9.2  `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X`   **KEV:** no

## Validation

The proof-of-concept writes a caller-supplied marker (taken from the `POC_CANARY` environment variable) to stdout, but only when execution actually reaches the vulnerable code. Running it against an affected release prints the marker; running the identical script against 0.23.35 prints nothing. That before/after difference is the result — it shows the weak path is genuinely reachable. The proof stops there and does not chain the issue into the advisory's full impact.

## Technical detail

The mechanism was read from the change shipped in 0.23.35. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
org.http4s:http4s-ember-core_2.12:0.23.34
POC_CANARY=demo java Poc.java     # prints the marker (vulnerable)

org.http4s:http4s-ember-core_2.12:0.23.35
POC_CANARY=demo java Poc.java     # silent (patched)
```

Success is the marker line on stdout for the vulnerable build and its absence for the fixed one; both runs exit 0, so the exit code is not the signal.
The runs above are recorded in:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-69204](https://nvd.nist.gov/vuln/detail/CVE-2026-69204)
- [Upstream fix commit](https://github.com/http4s/http4s/commit/9feaf8677951a52af906ae9664ff6f0543d9d810)
