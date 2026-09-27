# org.http4s:http4s-scala-xml_2.12 XML external entity injection (CVE-2026-61741)

**Date:** 2026-09-24
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `xxe`

## Summary

http4s-scala-xml provides `EntityDecoder[F, scala.xml.Elem]` instances that parse XML message bodies. Prior to versions 0.24.1 and 1.0.0-M39, these decoders used a `javax.xml.parsers.SAXParserFactory` obtained from `SAXParserFactory.newInstance` without any security configuration.  With the JDK's default settings, the parser resolves DOCTYPE declarations, external general and parameter entities, and external DTDs.An application that uses these decoders to parse untrusted XML is vulnerable to XML External Entity (XXE) attacks.  An attacker can craft a request that discloses local files readable by the service process, performs server-side request forgery (SSRF) against internal network resources, and/or causes denial of service through entity expansion. Versions 0.24.1 and 1.0.0-M39 fix the issue. EPSS 0.29% (p19, as of 2026-09-27).

## Affected

- **Product / project:** org.http4s:http4s-scala-xml_2.12 (Maven package `org.http4s:http4s-scala-xml_2.12`)
- **Versions:** < 0.24.1 (validated on 0.24.0)
- **CWE:** CWE-611   **CVSS:** 9.3  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:L`   **KEV:** no

## Verifying the finding

Verification is done by comparison. The same program runs twice — once on the affected build, once on 0.24.1 — and prints a marker from `POC_CANARY` solely along the vulnerable path. Seeing the marker on the old build and not on the fixed one is what confirms the finding. It demonstrates that the flaw is reachable, not end-to-end impact.

## Technical detail

The behaviour the test relies on was taken from the upstream fix in 0.24.1. See `artifacts/` for the patch diff and the recorded output of the two runs.

## Reproduce

```bash
org.http4s:http4s-scala-xml_2.12:0.24.0
POC_CANARY=demo java Poc.java     # outputs the marker (vulnerable)

org.http4s:http4s-scala-xml_2.12:0.24.1
POC_CANARY=demo java Poc.java     # no marker (fixed build)
```

A run counts as vulnerable when the marker prints; the fixed build prints nothing. Neither outcome depends on the exit code.
Console output captured during the run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-61741](https://nvd.nist.gov/vuln/detail/CVE-2026-61741)
- [Upstream fix commit](https://github.com/http4s/http4s-scala-xml/commit/49dbbcef3ffeab6102aa061f3e409bfb2d12cbaa)
