# morgan code execution (CVE-2026-87859)

**Date:** 2026-09-11
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `rce`

## Summary

morgan is an HTTP request logger middleware for Node.js. In versions before 1.12.1, its escapeLogField() function does not escape the double quote character, which delimits the quoted fields of the Apache combined log format that morgan emits. An unauthenticated remote attacker who controls a value written to a quoted field, such as the User-Agent or Referer header, can include a double quote to close that field early, so a log consumer that parses the log by field position reads attacker-supplied text as the following field. In the built-in formats this makes the recorded value differ from the value that was sent, and in custom formats that quote an attacker-controlled token before a server-controlled one it can forge values such as the response status. No newline is injected, so record separation stays intact. The issue is fixed in morgan 1.12.1, which escapes the double quote. Users should upgrade to morgan 1.12.1 or later. EPSS 0.41% (p32, as of 2026-10-01).

## Affected

- **Product / project:** morgan (npm package `morgan`)
- **Versions:** < 1.12.1
- **CWE:** CWE-117   **CVSS:** 5.3  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`   **KEV:** no

## Verifying the finding

Verification is done by comparison. The same program runs twice — once on the affected build, once on 1.12.1 — and prints a marker from `POC_CANARY` solely along the vulnerable path. Seeing the marker on the old build and not on the fixed one is what confirms the finding. It demonstrates that the flaw is reachable, not end-to-end impact.

## Technical detail

The relevant code path and the fix that closes it land in 1.12.1. The fix diff and the console output from both runs are included under `artifacts/`.

## Reproduce

```bash
# install any morgan release < 1.12.1
POC_CANARY=demo node poc.js     # marker appears (affected build)

npm install 'morgan@1.12.1'
POC_CANARY=demo node poc.js     # silent (patched)
```

Success is the marker line on stdout for the vulnerable build and its absence for the fixed one; both runs exit 0, so the exit code is not the signal.
The runs above are recorded in:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-87859](https://nvd.nist.gov/vuln/detail/CVE-2026-87859)
- [Upstream fix commit](https://github.com/expressjs/morgan/commit/b1272e70812dbc504321eeb5a43d14b0822c150d)
