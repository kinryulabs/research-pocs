# @vendure/core Improper authentication (CVE-2026-63472)

**Date:** 2026-09-17
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `authn`

## Summary

Vendure is an open-source headless commerce platform. Prior to 3.7.0, ExternalAuthenticationService.createCustomerAndUser in packages/core/src/service/helpers/external-authentication/external-authentication.service.ts selects an existing customer user by emailAddress and attaches a newly presented ExternalAuthenticationMethod without requiring verified to be true. In deployments with a custom external AuthenticationStrategy that forwards an email whose ownership the provider has not verified, an attacker can authenticate with a victim's email and bind the attacker's external identity to the victim's existing account. This can expose orders, addresses, and personal information and permit account changes or orders as the victim. Native-only email and password deployments and external strategies that always require provider-verified email ownership are unaffected, and new-account creation for an unused email remains permitted. This issue is fixed in version 3.7.0. EPSS 0.59% (p46, as of 2026-09-29).

## Affected

- **Product / project:** @vendure/core (npm package `@vendure/core`)
- **Versions:** < 3.7.0
- **CWE:** CWE-287   **CVSS:** 9.1  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`   **KEV:** no

## Verifying the finding

To separate a real defect from a theoretical one, the script echoes a marker value (`POC_CANARY`) that can only appear if the flawed branch runs. The marker is present on the vulnerable version and gone once 3.7.0 is installed, which ties the behaviour directly to the code the patch changes. It is a minimal trigger rather than a full exploit chain.

## Technical detail

The relevant code path and the fix that closes it land in 3.7.0. See `artifacts/` for the patch diff and the recorded output of the two runs.

## Reproduce

```bash
# install any @vendure/core release < 3.7.0
POC_CANARY=demo node poc.js     # marker appears (affected build)

npm install '@vendure/core@3.7.0'
POC_CANARY=demo node poc.js     # prints nothing (patched)
```

Success is the marker line on stdout for the vulnerable build and its absence for the fixed one; both runs exit 0, so the exit code is not the signal.
The runs above are recorded in:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-63472](https://nvd.nist.gov/vuln/detail/CVE-2026-63472)
- [Upstream fix commit](https://github.com/vendurehq/vendure/commit/a2b8ff8b33b1d241b244b0072870569feae80135)
