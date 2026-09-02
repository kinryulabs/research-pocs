import os
import sys

import httpx2


def has_both_framing_headers(headers):
    keys = {k.lower() for k in headers.keys()}
    return "content-length" in keys and "transfer-encoding" in keys


def build_request_with_te_and_body():
    """
    Construct a request that carries a caller-supplied Transfer-Encoding header
    together with a fixed-size body. Request._prepare() runs during construction.

    Pre-patch: setdefault() adds a body-derived Content-Length independently of the
    existing Transfer-Encoding, so BOTH framing headers end up on the request.

    Post-patch: the two framing headers are treated as mutually exclusive, so the
    caller-supplied Transfer-Encoding suppresses the Content-Length and only ONE
    framing header survives.
    """
    method = "POST"
    url = "http://127.0.0.1/smuggle"
    te_headers = {"Transfer-Encoding": "chunked"}

    # A fixed-size byte body: known length -> _prepare() would derive Content-Length.
    body = b"0123456789"

    attempts = (
        lambda: httpx2.Request(method, url, headers=te_headers, content=body),
        lambda: httpx2.Request(method, url, headers=te_headers, data=body),
        lambda: httpx2.Request(
            method=method, url=url, headers=te_headers, content=body
        ),
    )

    last_exc = None
    for make in attempts:
        try:
            return make()
        except Exception as exc:  # try the next constructor spelling
            last_exc = exc
    raise last_exc


def main():
    request = build_request_with_te_and_body()

    # The vulnerability manifests as the coexistence of Content-Length and
    # Transfer-Encoding on a single HTTP/1.1 request (CWE-444). This is only
    # true on the vulnerable build; the patch removes the Content-Length here.
    if has_both_framing_headers(request.headers):
        sys.stdout.write(os.environ["POC_CANARY"] + "\n")
    else:
        sys.stderr.write(
            "Not vulnerable: framing headers are mutually exclusive "
            f"({dict(request.headers)!r})\n"
        )


if __name__ == "__main__":
    main()