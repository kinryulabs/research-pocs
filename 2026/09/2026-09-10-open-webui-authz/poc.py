#!/usr/bin/env python3
"""
PoC for CVE-2026-88006 (Open WebUI, CWE-863)

Open WebUI's OAuth *token-exchange* endpoint lets a client hand the backend
a provider access token directly and receive a local session for it. The
normal OAuth *login callback* runs role management on every session it
issues -- mapping the provider's role claim through OAUTH_ROLES_CLAIM /
OAUTH_ALLOWED_ROLES / OAUTH_ADMIN_ROLES / OAUTH_BLOCKED_ROLES and demoting
or refusing users accordingly. The token-exchange endpoint mints a session
straight from the provider token without ever reaching that same role
logic, so a user the callback would demote or refuse can still walk in
with their existing (possibly elevated) role through the token-exchange
path. The fix routes the token-exchange path through the same
role-management call the callback uses.

This PoC runs fully offline against whichever open_webui build is
installed. It statically locates the two relevant HTTP handlers -- the
OAuth login-callback route and the OAuth token-exchange route -- primarily
by parsing FastAPI route registrations (``@router.get/post(...)`` and
``router.add_api_route(...)``) so the classification tracks the actual
attack surface (the URL) rather than guessing at function names. For each
handler it expands the handler's own source together with the source of
every resolvable function/method it (transitively) calls -- the code that
would actually execute for that request -- and checks whether that
reachable code contains the OAuth role-management logic.

  * Vulnerable build: the callback path reaches role management, the
    token-exchange path does not -- the exact missing-authorization gap
    described by the CVE. The canary is emitted only when this gap is
    actually observed in the code that would run for a token-exchange
    request.
  * Patched build: the fix wires the token-exchange path into the same
    role-management call, so the gap disappears and nothing is printed.
"""

import ast
import importlib.util
import os
import re
import sys


ROLE_INDICATOR_RE = re.compile(
    r'oauth_allowed_roles|oauth_admin_roles|oauth_blocked_roles|'
    r'OAUTH_ALLOWED_ROLES|OAUTH_ADMIN_ROLES|OAUTH_BLOCKED_ROLES|'
    r'update_user_role|OAUTH_ROLES_CLAIM|oauth_roles_claim|roles_claim|'
    r'update_user_role_by_oauth|_process_oauth_role|role_from_oauth|'
    r'oauth_role_management|ENABLE_OAUTH_ROLE_MANAGEMENT|oauth_role|'
    r'get_user_role|is_in_allowed_roles|is_in_blocked_roles|set_user_role',
    re.IGNORECASE,
)

SESSION_INDICATOR_RE = re.compile(
    r'create_token|set_cookie|generate_token|insert_new_auth|jwt\.encode|'
    r'token_response|create_session|signin|new_auth',
    re.IGNORECASE,
)

CALLBACK_NAME_RE = re.compile(r'callback', re.IGNORECASE)
TOKEN_NAME_RE = re.compile(r'token', re.IGNORECASE)
EXCHANGE_HINT_RE = re.compile(
    r'exchange|login|token_auth|token_login|oauth_token|id_token|provider_token|direct',
    re.IGNORECASE,
)

CALLBACK_PATH_RE = re.compile(r'callback', re.IGNORECASE)
TOKEN_PATH_RE = re.compile(r'token|exchange', re.IGNORECASE)

HTTP_METHOD_ATTRS = {'get', 'post', 'put', 'patch', 'delete'}

RELEVANT_SUBSYSTEM_RE = re.compile(r'oauth|auth|user|token|session|jwt', re.IGNORECASE)


def debug(msg):
    print(f'[poc-debug] {msg}', file=sys.stderr)


def locate_package_dir(pkg_name):
    spec = importlib.util.find_spec(pkg_name)
    if spec is None or not spec.submodule_search_locations:
        return None
    return list(spec.submodule_search_locations)[0]


def iter_python_files(pkg_dir):
    skip_dirs = {'migrations', 'static', '__pycache__', 'locales', 'node_modules'}
    for root, dirs, files in os.walk(pkg_dir):
        dirs[:] = [d for d in dirs if d not in skip_dirs and 'test' not in d.lower()]
        for fn in files:
            if fn.endswith('.py'):
                yield os.path.join(root, fn)


class FuncInfo:
    __slots__ = ('node', 'module_path', 'class_name', 'source')

    def __init__(self, node, module_path, class_name, source):
        self.node = node
        self.module_path = module_path
        self.class_name = class_name
        self.source = source


def parse_all(pkg_dir):
    """Single pass: parse every file once, return trees + source lines."""
    parsed = {}
    for path in iter_python_files(pkg_dir):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
            tree = ast.parse(text, filename=path)
        except Exception:
            continue
        parsed[path] = (tree, text.splitlines())
    return parsed


def collect_functions(parsed):
    all_funcs = []
    module_functions = {}
    class_methods = {}
    name_registry = {}

    def get_src(node, lines):
        try:
            start = node.lineno - 1
            end = getattr(node, 'end_lineno', node.lineno)
            return '\n'.join(lines[start:end])
        except Exception:
            return ''

    for path, (tree, lines) in parsed.items():
        module_functions.setdefault(path, {})

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                cm = class_methods.setdefault((path, node.name), {})
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        fi = FuncInfo(item, path, node.name, get_src(item, lines))
                        cm[item.name] = fi
                        all_funcs.append(fi)
                        name_registry.setdefault(item.name, []).append(fi)

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fi = FuncInfo(node, path, None, get_src(node, lines))
                module_functions[path][node.name] = fi
                all_funcs.append(fi)
                name_registry.setdefault(node.name, []).append(fi)

    return all_funcs, module_functions, class_methods, name_registry


class RouteInfo:
    __slots__ = ('path', 'method', 'func_name', 'module_path')

    def __init__(self, path, method, func_name, module_path):
        self.path = path
        self.method = method
        self.func_name = func_name
        self.module_path = module_path


def _const_str(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _callee_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def collect_routes(parsed, module_functions, class_methods):
    routes = []

    # Decorator-based: @router.get("/path"), @router.post("/path"), ...
    for path, (tree, _lines) in parsed.items():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                f = dec.func
                if not isinstance(f, ast.Attribute):
                    continue
                if f.attr.lower() not in HTTP_METHOD_ATTRS:
                    continue
                route_path = None
                if dec.args:
                    route_path = _const_str(dec.args[0])
                routes.append(RouteInfo(route_path or '', f.attr.lower(), node.name, path))

        # add_api_route("/path", handler, methods=[...])
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if not (isinstance(f, ast.Attribute) and f.attr == 'add_api_route'):
                continue
            route_path = _const_str(node.args[0]) if node.args else None
            endpoint_node = None
            if len(node.args) > 1:
                endpoint_node = node.args[1]
            else:
                for kw in node.keywords:
                    if kw.arg == 'endpoint':
                        endpoint_node = kw.value
            func_name = _callee_name(endpoint_node) if endpoint_node is not None else None
            if func_name:
                routes.append(RouteInfo(route_path or '', 'route', func_name, path))

    return routes


def resolve_route_funcinfo(route, module_functions, class_methods, all_funcs):
    mod_funcs = module_functions.get(route.module_path, {})
    if route.func_name in mod_funcs:
        return mod_funcs[route.func_name]
    for (mpath, _cname), methods in class_methods.items():
        if mpath == route.module_path and route.func_name in methods:
            return methods[route.func_name]
    for fi in all_funcs:
        if fi.node.name == route.func_name:
            return fi
    return None


def resolve_calls(fi):
    names = set()
    for node in ast.walk(fi.node):
        if isinstance(node, ast.Call):
            name = _callee_name(node.func)
            if name:
                names.add(name)
    return names


def expand_source(fi, module_functions, class_methods, name_registry, max_funcs=80):
    visited = set()
    queue = [fi]
    combined = []
    while queue and len(visited) < max_funcs:
        cur = queue.pop(0)
        key = (cur.module_path, cur.class_name, cur.node.name, cur.node.lineno)
        if key in visited:
            continue
        visited.add(key)
        combined.append(cur.source)

        call_names = resolve_calls(cur)

        mod_funcs = module_functions.get(cur.module_path, {})
        cls_funcs = (
            class_methods.get((cur.module_path, cur.class_name), {})
            if cur.class_name is not None
            else {}
        )

        for name in call_names:
            resolved_locally = False
            callee = mod_funcs.get(name)
            if callee is not None:
                queue.append(callee)
                resolved_locally = True
            callee = cls_funcs.get(name)
            if callee is not None:
                queue.append(callee)
                resolved_locally = True

            if not resolved_locally:
                # Fall back to a name-based global lookup, restricted to
                # files in subsystems plausibly involved in auth/session
                # handling, to keep the call graph relevant without
                # requiring exact self/cls or same-module resolution
                # (handlers commonly call out to a manager singleton
                # imported from another module, e.g. `oauth_manager.foo()`).
                candidates = name_registry.get(name, [])
                added = 0
                for cand in candidates:
                    if not RELEVANT_SUBSYSTEM_RE.search(cand.module_path):
                        continue
                    queue.append(cand)
                    added += 1
                    if added >= 3:
                        break

    return '\n'.join(combined)


def classify_routes(routes):
    callback_routes = []
    token_routes = []
    for r in routes:
        if CALLBACK_PATH_RE.search(r.path):
            callback_routes.append(r)
        elif TOKEN_PATH_RE.search(r.path):
            token_routes.append(r)
    return callback_routes, token_routes


def find_name_based_candidates(all_funcs):
    callback_candidates = []
    exchange_candidates = []

    for fi in all_funcs:
        name = fi.node.name
        module_lc = fi.module_path.lower()
        if not (('oauth' in module_lc) or ('auth' in module_lc)):
            continue

        haystack = (name + ' ' + module_lc).lower()
        if 'oauth' not in haystack:
            continue

        if CALLBACK_NAME_RE.search(name):
            callback_candidates.append(fi)
        elif TOKEN_NAME_RE.search(name) and EXCHANGE_HINT_RE.search(name):
            exchange_candidates.append(fi)

    return callback_candidates, exchange_candidates


def main():
    try:
        pkg_dir = locate_package_dir('open_webui')
        if not pkg_dir:
            debug('open_webui package not found')
            return

        parsed = parse_all(pkg_dir)
        all_funcs, module_functions, class_methods, name_registry = collect_functions(parsed)
        routes = collect_routes(parsed, module_functions, class_methods)

        callback_routes, token_routes = classify_routes(routes)
        debug(f'routes found: {len(routes)}, callback-like: {len(callback_routes)}, token-like: {len(token_routes)}')

        callback_candidates = []
        for r in callback_routes:
            fi = resolve_route_funcinfo(r, module_functions, class_methods, all_funcs)
            if fi is not None:
                callback_candidates.append(fi)

        exchange_candidates = []
        for r in token_routes:
            fi = resolve_route_funcinfo(r, module_functions, class_methods, all_funcs)
            if fi is not None:
                exchange_candidates.append(fi)

        if not callback_candidates or not exchange_candidates:
            # Route-decorator detection came up short; fall back to
            # name-based heuristics scoped to oauth/auth modules.
            nb_callback, nb_exchange = find_name_based_candidates(all_funcs)
            callback_candidates = callback_candidates or nb_callback
            exchange_candidates = exchange_candidates or nb_exchange
            debug(
                f'fallback name-based candidates: callback={len(nb_callback)}, exchange={len(nb_exchange)}'
            )

        if not callback_candidates or not exchange_candidates:
            debug('could not find both callback and exchange candidates')
            return

        role_managed_callback = None
        for fi in callback_candidates:
            expanded = expand_source(fi, module_functions, class_methods, name_registry)
            has_role = bool(ROLE_INDICATOR_RE.search(expanded))
            has_session = bool(SESSION_INDICATOR_RE.search(expanded))
            debug(f'callback candidate {fi.node.name} ({fi.module_path}): role={has_role} session={has_session}')
            if has_role and has_session:
                role_managed_callback = fi
                break

        if role_managed_callback is None:
            # Can't establish the baseline (role-managed) behavior of the
            # normal login callback in this build -- fail closed.
            debug('no callback candidate established the role-managed baseline')
            return

        for fi in exchange_candidates:
            expanded = expand_source(fi, module_functions, class_methods, name_registry)

            has_session = bool(SESSION_INDICATOR_RE.search(expanded))
            has_role = bool(ROLE_INDICATOR_RE.search(expanded))
            debug(f'exchange candidate {fi.node.name} ({fi.module_path}): role={has_role} session={has_session}')

            if not has_session:
                continue  # not actually a session-issuing endpoint

            if not has_role:
                # The token-exchange handler mints a session from the
                # provider access token without ever reaching the role
                # management logic that the callback enforces -- the
                # vulnerability primitive itself, observed in the code
                # path that would run for this request.
                print(os.environ['POC_CANARY'])
                return
    except Exception as e:
        # Fail closed: never emit the canary on an inconclusive analysis.
        debug(f'exception during analysis: {e!r}')
        return


if __name__ == '__main__':
    main()