# org.opencastproject:opencast-engage-paella-player-7 Cross-site scripting (CVE-2026-77615)

**Date:** 2026-09-17
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `xss`

## Summary

Paella Player is a set of libraries to create a multi stream video player. Prior to Paella Player 2.12.11 (as used in Opencast prior to 19.7 and 20.2), there is a potential XSS attack though closed captions cue text. This vulnerability is fixed in 2.12.11. EPSS 0.56% (p44, as of 2026-09-29).

## Affected

- **Product / project:** org.opencastproject:opencast-engage-paella-player-7 (Maven package `org.opencastproject:opencast-engage-paella-player-7`)
- **Versions:** < 19.7 (validated on 18.5)
- **CWE:** CWE-79   **CVSS:** 8.7  `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N`   **KEV:** no

## How this was verified

To separate a real defect from a theoretical one, the script echoes a marker value (`POC_CANARY`) that can only appear if the flawed branch runs. The marker is present on the vulnerable version and gone once 19.7 is installed, which ties the behaviour directly to the code the patch changes. It is a minimal trigger rather than a full exploit chain.

## Technical detail

The mechanism was read from the change shipped in 19.7. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
org.opencastproject:opencast-engage-paella-player-7:18.5
POC_CANARY=demo java Poc.java     # marker appears (affected build)

org.opencastproject:opencast-engage-paella-player-7:19.7
POC_CANARY=demo java Poc.java     # prints nothing (patched)
```

The signal is the marker on stdout — present before the patch, absent after. Exit codes are 0 in both cases.
Recorded output from the two runs:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-77615](https://nvd.nist.gov/vuln/detail/CVE-2026-77615)
- [Upstream fix commit](https://github.com/opencast/opencast/commit/701682c635f668228c3e8fb7b4564b3294788e40)
