"""Explainable Python source-to-sink analysis."""

from __future__ import annotations

import ast
from copy import deepcopy
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any, Iterable

from .models import AnalysisSupport


_IGNORED_DIRECTORIES = frozenset(
    {".git", ".hg", ".svn", ".tox", ".venv", "venv", "node_modules", "vendor"}
)
_SOURCE_PREFIXES = (
    "request.args",
    "request.form",
    "request.json",
    "request.values",
    "request.query_params",
    "request.headers",
    "request.cookies",
)
_SOURCE_CALLS = frozenset({"input"})
_SANITIZERS = frozenset(
    {
        "escape",
        "html.escape",
        "quote",
        "quote_plus",
        "shlex.quote",
        "clean",
        "sanitize",
        "validate",
    }
)
_SINKS = frozenset(
    {
        "execute",
        "executemany",
        "eval",
        "exec",
        "system",
        "popen",
        "run",
        "render_template_string",
        "loads",
        "load",
    }
)
_AUTHENTICATION_DECORATORS = frozenset(
    {"login_required", "auth_required", "requires_auth", "authenticated"}
)
_AUTHORIZATION_DECORATORS = frozenset(
    {"roles_required", "permission_required", "requires_role", "authorize"}
)
_LIMITATION = (
    "Python AST analysis cannot resolve runtime metaprogramming, reflection, "
    "dynamic dispatch, generated code, native extensions, or all framework hooks."
)


@dataclass(frozen=True)
class _Function:
    key: str
    module: str
    file: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    imports: dict[str, str]
    route: dict[str, Any] | None
    authentication_required: bool
    authorization_checks: tuple[str, ...]


@dataclass
class _Collector:
    sources: list[dict[str, Any]]
    sanitizers: list[dict[str, Any]]
    sinks: list[dict[str, Any]]
    paths: list[dict[str, Any]]


def analyze_python_source_to_sink(repository_root: Path) -> dict[str, Any]:
    """Build a bounded project-wide Python data-flow report."""

    root = Path(repository_root).resolve()
    functions: dict[str, _Function] = {}
    parse_failures: list[str] = []
    analysed_files: list[str] = []
    routes: list[dict[str, Any]] = []
    for path in _python_files(root):
        relative = path.relative_to(root).as_posix()
        analysed_files.append(relative)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (OSError, SyntaxError, UnicodeError):
            parse_failures.append(relative)
            continue
        module = _module_name(relative)
        imports = _imports(tree)
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            route = _route(node, relative)
            if route:
                routes.append(route)
            decorators = {_decorator_name(item) for item in node.decorator_list}
            authorization = tuple(
                sorted(decorators & _AUTHORIZATION_DECORATORS)
            )
            key = f"{module}:{node.name}"
            functions[key] = _Function(
                key=key,
                module=module,
                file=relative,
                node=node,
                imports=imports,
                route=route,
                authentication_required=bool(
                    decorators & _AUTHENTICATION_DECORATORS
                ),
                authorization_checks=authorization,
            )

    collector = _Collector([], [], [], [])
    for function in functions.values():
        _analyse_function(
            function,
            functions=functions,
            collector=collector,
            initial_taint={},
            route=function.route,
            authentication_required=function.authentication_required,
            authorization_checks=function.authorization_checks,
            chain=(),
        )
    paths = _unique(
        collector.paths,
        lambda item: (
            item["source"]["file"],
            item["source"]["line"],
            item["sink"]["file"],
            item["sink"]["line"],
            (item.get("framework_route") or {}).get("endpoint"),
        ),
    )
    support = (
        AnalysisSupport.INCOMPLETE
        if parse_failures
        else AnalysisSupport.SUPPORTED
    )
    limitations = [_LIMITATION]
    if parse_failures:
        limitations.append(
            "Files that could not be parsed: " + ", ".join(sorted(parse_failures))
        )
    return {
        "support": support.value,
        "analysis_incomplete": bool(parse_failures),
        "analysed_files": sorted(analysed_files),
        "parse_failures": sorted(parse_failures),
        "identified_sources": _unique(
            collector.sources, lambda item: (item["file"], item["line"], item["symbol"])
        ),
        "identified_sanitizers": _unique(
            collector.sanitizers,
            lambda item: (item["file"], item["line"], item["symbol"]),
        ),
        "identified_sinks": _unique(
            collector.sinks, lambda item: (item["file"], item["line"], item["symbol"])
        ),
        "framework_routes": _unique(
            routes, lambda item: (item["file"], item["line"], item["endpoint"])
        ),
        "paths": paths,
        "limitations": limitations,
    }


def apply_source_to_sink_analysis(
    findings: Iterable[dict[str, Any]],
    repository_root: Path,
) -> list[dict[str, Any]]:
    """Attach the best matching trace or an explicit support state."""

    report = analyze_python_source_to_sink(repository_root)
    analyzed = []
    for original in findings:
        finding = deepcopy(original)
        file_name = str(finding.get("file") or "")
        if Path(file_name).suffix.lower() != ".py":
            finding["source_to_sink_analysis"] = _unsupported_metadata()
            analyzed.append(finding)
            continue
        candidates = [
            path
            for path in report["paths"]
            if path["sink"]["file"] == file_name
            and _line_matches(finding, path["sink"]["line"])
        ]
        if not candidates:
            candidates = [
                path
                for path in report["paths"]
                if path["sink"]["file"] == file_name
                and _finding_matches_path(finding, path)
            ]
        if candidates:
            path = candidates[0]
            finding["data_flow"] = deepcopy(path["data_flow"])
            finding["reachability"] = "reachable"
            finding["source_to_sink_analysis"] = {
                "support": "supported",
                "status": "path-found",
                "analysis_incomplete": report["analysis_incomplete"],
                "identified_sources": [deepcopy(path["source"])],
                "identified_sanitizers": deepcopy(path["sanitizers"]),
                "identified_sinks": [deepcopy(path["sink"])],
                "intra_file": path["intra_file"],
                "cross_file": path["cross_file"],
                "framework_routes": (
                    [deepcopy(path["framework_route"])]
                    if path["framework_route"]
                    else []
                ),
                "authentication_required": path["authentication_required"],
                "authorization_checks": list(path["authorization_checks"]),
                "path_confidence": path["path_confidence"],
                "evidence": deepcopy(path["data_flow"]),
                "limitations": list(report["limitations"]),
            }
        else:
            finding["source_to_sink_analysis"] = {
                "support": report["support"],
                "status": "no-path-found",
                "analysis_incomplete": report["analysis_incomplete"],
                "identified_sources": [],
                "identified_sanitizers": [],
                "identified_sinks": [],
                "intra_file": False,
                "cross_file": False,
                "framework_routes": [],
                "authentication_required": None,
                "authorization_checks": [],
                "path_confidence": 0.0,
                "evidence": [],
                "limitations": list(report["limitations"]),
            }
        analyzed.append(finding)
    return analyzed


def _analyse_function(
    function: _Function,
    *,
    functions: dict[str, _Function],
    collector: _Collector,
    initial_taint: dict[str, list[dict[str, Any]]],
    route: dict[str, Any] | None,
    authentication_required: bool,
    authorization_checks: tuple[str, ...],
    chain: tuple[str, ...],
) -> None:
    if function.key in chain or len(chain) >= 8:
        return
    state = {name: deepcopy(trace) for name, trace in initial_taint.items()}
    sanitized: set[str] = set()
    for statement in _statements(function.node.body):
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
            )
            target_names = [
                name for target in targets for name in _assigned_names(target)
            ]
            sanitizer = _sanitizer_call(value)
            trace = (
                _first_tainted_argument(
                    value, state, function=function, collector=collector
                )
                if sanitizer and isinstance(value, ast.Call)
                else _taint_trace(
                    value, state, function=function, collector=collector
                )
            )
            if sanitizer and trace:
                evidence = _evidence(
                    function.file,
                    value.lineno,
                    sanitizer,
                    "Sanitizer applied to tainted data.",
                )
                collector.sanitizers.append(evidence)
                sanitized.update(target_names)
                for name in target_names:
                    state.pop(name, None)
            elif trace:
                propagation = _flow_step(
                    "propagation",
                    function.file,
                    statement.lineno,
                    target_names[0] if target_names else None,
                    "Tainted value assigned.",
                )
                for name in target_names:
                    state[name] = deepcopy(trace) + [propagation]
                    sanitized.discard(name)
        for call in [node for node in ast.walk(statement) if isinstance(node, ast.Call)]:
            call_name = _expression_name(call.func)
            sink_name = call_name.rsplit(".", 1)[-1]
            if sink_name in _SINKS:
                sink = _evidence(
                    function.file,
                    call.lineno,
                    call_name,
                    "Potentially dangerous sink.",
                )
                collector.sinks.append(sink)
                trace = _first_tainted_argument(
                    call, state, function=function, collector=collector
                )
                if trace:
                    flow = deepcopy(trace) + [
                        _flow_step(
                            "sink", function.file, call.lineno, call_name,
                            "Tainted data reaches a dangerous sink.",
                        )
                    ]
                    source = _flow_as_evidence(flow[0])
                    files = {step["file"] for step in flow if step["file"]}
                    collector.paths.append(
                        {
                            "source": source,
                            "sanitizers": [],
                            "sink": sink,
                            "intra_file": len(files) == 1,
                            "cross_file": len(files) > 1,
                            "framework_route": deepcopy(route),
                            "authentication_required": authentication_required,
                            "authorization_checks": list(authorization_checks),
                            "path_confidence": 0.8 if len(files) > 1 else 0.95,
                            "data_flow": flow,
                        }
                    )
            target = _resolve_call(function, call_name, functions)
            if target is None:
                continue
            parameter_taint: dict[str, list[dict[str, Any]]] = {}
            parameters = [argument.arg for argument in target.node.args.args]
            for parameter, argument in zip(parameters, call.args):
                trace = _taint_trace(
                    argument, state, function=function, collector=collector
                )
                if trace:
                    parameter_taint[parameter] = deepcopy(trace) + [
                        _flow_step(
                            "propagation",
                            function.file,
                            call.lineno,
                            call_name,
                            f"Tainted argument passed to {target.key}.",
                        )
                    ]
            if parameter_taint:
                _analyse_function(
                    target,
                    functions=functions,
                    collector=collector,
                    initial_taint=parameter_taint,
                    route=route or target.route,
                    authentication_required=(
                        authentication_required or target.authentication_required
                    ),
                    authorization_checks=tuple(
                        sorted(
                            set(authorization_checks)
                            | set(target.authorization_checks)
                        )
                    ),
                    chain=chain + (function.key,),
                )


def _taint_trace(
    expression: ast.AST | None,
    state: dict[str, list[dict[str, Any]]],
    *,
    function: _Function,
    collector: _Collector,
) -> list[dict[str, Any]] | None:
    if expression is None:
        return None
    source_name = _source_name(expression)
    if source_name:
        evidence = _evidence(
            function.file,
            getattr(expression, "lineno", function.node.lineno),
            source_name,
            "Untrusted request or process input.",
        )
        collector.sources.append(evidence)
        return [
            _flow_step(
                "source",
                evidence["file"],
                evidence["line"],
                evidence["symbol"],
                evidence["description"],
            )
        ]
    if isinstance(expression, ast.Name) and expression.id in state:
        return deepcopy(state[expression.id])
    if _sanitizer_call(expression):
        return None
    for child in ast.iter_child_nodes(expression):
        trace = _taint_trace(
            child, state, function=function, collector=collector
        )
        if trace:
            return trace
    return None


def _first_tainted_argument(
    call: ast.Call,
    state: dict[str, list[dict[str, Any]]],
    *,
    function: _Function,
    collector: _Collector,
) -> list[dict[str, Any]] | None:
    for argument in [*call.args, *(item.value for item in call.keywords)]:
        trace = _taint_trace(
            argument, state, function=function, collector=collector
        )
        if trace:
            return trace
    return None


def _source_name(expression: ast.AST) -> str | None:
    name = _expression_name(expression)
    if any(name.startswith(prefix) for prefix in _SOURCE_PREFIXES):
        return _request_source_name(expression, name)
    if isinstance(expression, ast.Call) and name in _SOURCE_CALLS:
        return name
    return None


def _request_source_name(expression: ast.AST, fallback: str) -> str:
    """Preserve a statically visible request parameter in source evidence."""

    if isinstance(expression, ast.Call) and isinstance(expression.func, ast.Attribute):
        collection = _expression_name(expression.func.value)
        if (
            expression.func.attr == "get"
            and expression.args
            and isinstance(expression.args[0], ast.Constant)
            and isinstance(expression.args[0].value, str)
        ):
            return f"{collection}[{expression.args[0].value!r}]"
    if isinstance(expression, ast.Subscript):
        key = expression.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            return f"{_expression_name(expression.value)}[{key.value!r}]"
    return fallback


def _sanitizer_call(expression: ast.AST | None) -> str | None:
    if not isinstance(expression, ast.Call):
        return None
    name = _expression_name(expression.func)
    return name if name in _SANITIZERS or name.rsplit(".", 1)[-1] in _SANITIZERS else None


def _resolve_call(
    function: _Function,
    call_name: str,
    functions: dict[str, _Function],
) -> _Function | None:
    local_key = f"{function.module}:{call_name}"
    if local_key in functions:
        return functions[local_key]
    first, separator, remainder = call_name.partition(".")
    imported = function.imports.get(first)
    if imported:
        if ":" in imported and not separator:
            return functions.get(imported)
        module = imported.split(":", 1)[0]
        target_name = remainder if separator else imported.partition(":")[2]
        return functions.get(f"{module}:{target_name}")
    return None


def _imports(tree: ast.Module) -> dict[str, str]:
    imports: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports[alias.asname or alias.name.split(".", 1)[0]] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                imports[alias.asname or alias.name] = f"{node.module}:{alias.name}"
    return imports


def _route(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    file_name: str,
) -> dict[str, Any] | None:
    for decorator in function.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        name = _expression_name(decorator.func)
        method = name.rsplit(".", 1)[-1].upper()
        if method not in {"ROUTE", "GET", "POST", "PUT", "PATCH", "DELETE"}:
            continue
        endpoint = (
            decorator.args[0].value
            if decorator.args
            and isinstance(decorator.args[0], ast.Constant)
            and isinstance(decorator.args[0].value, str)
            else None
        )
        methods = [method] if method != "ROUTE" else ["ANY"]
        for keyword in decorator.keywords:
            if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                methods = [
                    str(item.value).upper()
                    for item in keyword.value.elts
                    if isinstance(item, ast.Constant)
                ]
        return {
            "endpoint": endpoint,
            "methods": methods,
            "file": file_name,
            "line": decorator.lineno,
            "handler": function.name,
        }
    return None


def _decorator_name(decorator: ast.expr) -> str:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return _expression_name(target).rsplit(".", 1)[-1]


def _statements(statements: list[ast.stmt]) -> list[ast.stmt]:
    flattened: list[ast.stmt] = []
    for statement in statements:
        flattened.append(statement)
        for field in ("body", "orelse", "finalbody"):
            nested = getattr(statement, field, None)
            if isinstance(nested, list):
                flattened.extend(_statements(nested))
    return flattened


def _assigned_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        return [name for item in target.elts for name in _assigned_names(item)]
    return []


def _expression_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _expression_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _expression_name(node.func)
    if isinstance(node, ast.Subscript):
        return _expression_name(node.value)
    return ""


def _module_name(relative: str) -> str:
    path = relative.removesuffix(".py").replace("/", ".")
    return path.removesuffix(".__init__")


def _python_files(root: Path) -> tuple[Path, ...]:
    files = []
    for current, directories, names in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories if name not in _IGNORED_DIRECTORIES
        )
        for name in sorted(names):
            path = Path(current) / name
            if name.endswith(".py") and not path.is_symlink():
                files.append(path)
    return tuple(files)


def _evidence(
    file: str,
    line: int | None,
    symbol: str | None,
    description: str,
) -> dict[str, Any]:
    return {
        "file": file,
        "line": line,
        "symbol": symbol,
        "description": description,
    }


def _flow_step(
    kind: str,
    file: str | None,
    line: int | None,
    symbol: str | None,
    description: str,
) -> dict[str, Any]:
    return {
        "order": 0,
        "kind": kind,
        "file": file,
        "line": line,
        "symbol": symbol,
        "description": description,
    }


def _flow_as_evidence(step: dict[str, Any]) -> dict[str, Any]:
    return {
        "file": step["file"],
        "line": step["line"],
        "symbol": step["symbol"],
        "description": step["description"],
    }


def _unique(items: list[dict[str, Any]], key) -> list[dict[str, Any]]:
    unique: dict[object, dict[str, Any]] = {}
    for item in items:
        unique.setdefault(key(item), item)
    values = list(unique.values())
    for item in values:
        if "data_flow" in item:
            for order, step in enumerate(item["data_flow"]):
                step["order"] = order
    return values


def _line_matches(finding: dict[str, Any], line: int | None) -> bool:
    if line is None:
        return False
    start = finding.get("start_line")
    end = finding.get("end_line") or start
    return isinstance(start, int) and isinstance(end, int) and start <= line <= end


def _finding_matches_path(
    finding: dict[str, Any], path: dict[str, Any]
) -> bool:
    """Require scanner symbols to agree before using a non-line fallback."""

    checks: list[bool] = []
    source = str(finding.get("source") or "").strip().lower()
    if source:
        path_source = str(path["source"].get("symbol") or "").lower()
        checks.append(source in path_source or path_source in source)
    sink = str(finding.get("sink") or "").strip().lower()
    if sink:
        path_sink = str(path["sink"].get("symbol") or "").lower()
        checks.append(
            sink == path_sink
            or sink.rsplit(".", 1)[-1] == path_sink.rsplit(".", 1)[-1]
        )
    return bool(checks) and all(checks)


def _unsupported_metadata() -> dict[str, Any]:
    return {
        "support": "unsupported",
        "status": "not-analysed",
        "analysis_incomplete": True,
        "identified_sources": [],
        "identified_sanitizers": [],
        "identified_sinks": [],
        "intra_file": False,
        "cross_file": False,
        "framework_routes": [],
        "authentication_required": None,
        "authorization_checks": [],
        "path_confidence": 0.0,
        "evidence": [],
        "limitations": [
            "Python is the only source-to-sink language supported in Phase 8."
        ],
    }
