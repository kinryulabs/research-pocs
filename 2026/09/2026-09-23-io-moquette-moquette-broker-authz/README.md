# io.moquette:moquette-broker Incorrect authorization (CVE-2026-85724)

**Date:** 2026-09-23
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `authz`

## Summary

Moquette is a lightweight Java MQTT broker. Prior to 0.18.1, when pattern-based ACL rules are configured, AuthorizationsCollector.canDoOperation substitutes client ID and username values directly into rules containing %c or %u and then treats the result as an MQTT topic filter. A client that uses + or # in either identity can broaden the substituted filter and gain cross-tenant read and write access. A # identity can also produce an invalid filter that triggers a NullPointerException in Topic.match and disrupts session processing. This issue is fixed in version 0.18.1. EPSS 0.27% (p17, as of 2026-09-29).

## Affected

- **Product / project:** io.moquette:moquette-broker (Maven package `io.moquette:moquette-broker`)
- **Versions:** < 0.18.1 (validated on 0.17)
- **CWE:** CWE-155, CWE-863   **CVSS:** 9.6  `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`   **KEV:** no

## Validation

The proof-of-concept writes a caller-supplied marker (taken from the `POC_CANARY` environment variable) to stdout, but only when execution actually reaches the vulnerable code. Running it against an affected release prints the marker; running the identical script against 0.18.1 prints nothing. That before/after difference is the result — it shows the weak path is genuinely reachable. The proof stops there and does not chain the issue into the advisory's full impact.

## Technical detail

The relevant code path and the fix that closes it land in 0.18.1. See `artifacts/` for the patch diff and the recorded output of the two runs.

## Reproduce

```bash
io.moquette:moquette-broker:0.17
POC_CANARY=demo java Poc.java     # marker appears (affected build)

io.moquette:moquette-broker:0.18.1
POC_CANARY=demo java Poc.java     # prints nothing (patched)
```

The signal is the marker on stdout — present before the patch, absent after. Exit codes are 0 in both cases.
Console output captured during the run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-85724](https://nvd.nist.gov/vuln/detail/CVE-2026-85724)
- [Upstream fix commit](https://github.com/moquette-io/moquette/commit/b4a98bb3f3425ece476ed073aa080c627c1239af)
