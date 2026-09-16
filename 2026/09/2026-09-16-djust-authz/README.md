# djust Missing authorization (CVE-2026-61594)

**Date:** 2026-09-16
**Status:** published
**Maturity:** proof-of-concept — confirms the vulnerable code path is reachable; not a full exploit chain
**Tags:** `authz`

## Summary

djust provides Phoenix LiveView-style reactive server-side rendering for Django with Rust-powered performance. Prior to version 1.0.7, the live (WebSocket) transport authorizes a mount via `check_view_auth`, not Django's `View.dispatch()` chain. As a result, standard Django authorization — `LoginRequiredMixin`, `PermissionRequiredMixin`, `UserPassesTestMixin`, `@method_decorator(login_required, name="dispatch")`, and custom `dispatch()` guards — and the djust admin extension's staff gate (applied only in the HTTP `as_view` wrapper) were enforced on the initial HTTP GET but silently bypassed over WebSocket, where all events and state flow. An anonymous or under-privileged client could open a WebSocket and mount such a view — including admin list/create/change/delete — and dispatch its handlers. This is fixed in djust 1.0.7. `check_view_auth` now honors the Django `AccessMixin` family on every transport; a new system check S004 fails loud at startup on auth patterns the runtime cannot safely replay (decorator/overridden-`dispatch` forms); and the admin base mixin declares `login_required = True` + an active-staff `check_permissions` gate. As a workaround, gate views using djust's `login_required` / `permission_required` / `check_permissions` attributes (honored on all transports) rather than HTTP-only mixins/decorators. EPSS 0.48% (p39, as of 2026-09-27).

## Affected

- **Product / project:** djust (PyPI package `djust`)
- **Versions:** < 1.0.7 (validated on 1.0.6)
- **CWE:** CWE-306, CWE-862   **CVSS:** 9.1  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`   **KEV:** no

## How this was verified

To separate a real defect from a theoretical one, the script echoes a marker value (`POC_CANARY`) that can only appear if the flawed branch runs. The marker is present on the vulnerable version and gone once 1.0.7 is installed, which ties the behaviour directly to the code the patch changes. It is a minimal trigger rather than a full exploit chain.

## Technical detail

The mechanism was read from the change shipped in 1.0.7. The patch diff and the captured console output are kept in `artifacts/` for review.

## Reproduce

```bash
pip install 'djust==1.0.6'
POC_CANARY=demo python poc.py     # outputs the marker (vulnerable)

pip install 'djust==1.0.7'
POC_CANARY=demo python poc.py     # no marker (fixed build)
```

A run counts as vulnerable when the marker prints; the fixed build prints nothing. Neither outcome depends on the exit code.
Console output captured during the run:
- `artifacts/vuln-output.txt`
- `artifacts/patched-output.txt`
- `artifacts/patch-diff.txt`

## References

- [NVD — CVE-2026-61594](https://nvd.nist.gov/vuln/detail/CVE-2026-61594)
- [Upstream fix commit](https://github.com/djust-org/djust/commit/e7f6751723e76219d3062f3391231fec3c736ab3)
