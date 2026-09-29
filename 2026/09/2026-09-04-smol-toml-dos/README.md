# smol-toml Infinite-loop denial of service (CVE-2026-85730)

**Date:** 2026-09-04
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `dos`

## Summary

smol-toml is a small, fast, and correct TOML parser and serializer. Prior to 1.7.1, parse() can enter an infinite loop when a value inside an array or inline table is followed by a comment with no trailing newline. In src/util.ts, skipUntil() calls indexOfNewline(), receives -1 at the end of input, and resets the cursor to the beginning of the string instead of leaving the structure scan. The parser then hangs indefinitely and can consume a service's processing capacity when an application parses attacker-controlled TOML. This issue is fixed in version 1.7.1. EPSS 0.52% (p42, as of 2026-09-29).

## Affected

- **Product / project:** smol-toml (npm package `smol-toml`)
- **Versions:** < 1.7.1
- **CWE:** CWE-606, CWE-835   **CVSS:** 8.2   **KEV:** no

## Validation

The proof-of-concept writes a caller-supplied marker (taken from the `POC_CANARY` environment variable) to stdout, but only when execution actually reaches the vulnerable code. Running it against an affected release prints the marker; running the identical script against 1.7.1 prints nothing. That before/after difference is the result — it shows the weak path is genuinely reachable. The proof stops there and does not chain the issue into the advisory's full impact.

## Technical detail

The relevant code path and the fix that closes it land in 1.7.1.

## Reproduce

```bash
# install any smol-toml release < 1.7.1
POC_CANARY=demo node poc.js     # outputs the marker (vulnerable)

npm install 'smol-toml@1.7.1'
POC_CANARY=demo node poc.js     # silent (patched)
```

The signal is the marker on stdout — present before the patch, absent after. Exit codes are 0 in both cases.


## References

- [NVD — CVE-2026-85730](https://nvd.nist.gov/vuln/detail/CVE-2026-85730)
- [Upstream fix commit](https://github.com/squirrelchat/smol-toml/commit/3e978a945ef9b15056d55f6ad92dd48fb05fe28e)
