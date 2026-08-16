"""Narrow, deterministic source-to-source remediation transformations."""

from __future__ import annotations

import ast
from collections.abc import Callable, Mapping
import re
import shlex
from typing import Any

from .engine import RemediationError


Transformer = Callable[[str, Mapping[str, Any]], str]
_SUBPROCESS_APIS = frozenset(
    {"call", "check_call", "check_output", "Popen", "run"}
)
_SHELL_SYNTAX = re.compile(r"[|&;<>()$`\n\r*?\[\]{}~]")
_DIGEST = re.compile(r"^[0-9a-fA-F]{64}$")
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+!-]*$")


def _tree(source: str) -> ast.Module:
    try:
        return ast.parse(source)
    except SyntaxError as error:
        raise RemediationError(f"Python source is not parseable: {error}") from error


def _offset(source: str, line: int, byte_column: int) -> int:
    lines = source.splitlines(keepends=True)
    if line == len(lines) + 1 and byte_column == 0:
        return len(source)
    prefix = sum(len(value) for value in lines[: line - 1])
    current = lines[line - 1]
    column = len(current.encode("utf-8")[:byte_column].decode("utf-8"))
    return prefix + column


def _span(source: str, node: ast.AST) -> tuple[int, int]:
    if not all(
        hasattr(node, field)
        for field in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ):
        raise RemediationError("selected syntax has no stable source span")
    return (
        _offset(source, node.lineno, node.col_offset),
        _offset(source, node.end_lineno, node.end_col_offset),
    )


def _replace(source: str, replacements: list[tuple[int, int, str]]) -> str:
    result = source
    last_start = len(source) + 1
    for start, end, value in sorted(replacements, reverse=True):
        if start > end or end > last_start:
            raise RemediationError("overlapping or empty transformation span")
        result = result[:start] + value + result[end:]
        last_start = start
    return result


def _single(matches: list[Any], *, label: str) -> Any:
    if not matches:
        raise RemediationError(f"no supported {label} was found")
    if len(matches) != 1:
        raise RemediationError(f"multiple supported {label} instances are ambiguous")
    return matches[0]


def parameterise_sql(source: str, parameters: Mapping[str, Any]) -> str:
    if parameters:
        raise RemediationError("TG-PY-SQL-001 does not accept parameters")
    tree = _tree(source)
    matches: list[ast.Call] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
            and len(node.args) == 1
            and not node.keywords
            and isinstance(node.args[0], ast.JoinedStr)
        ):
            matches.append(node)
    call = _single(matches, label="SQLite f-string query")
    query_parts: list[str] = []
    values: list[str] = []
    for part in call.args[0].values:
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            query_parts.append(part.value)
        elif (
            isinstance(part, ast.FormattedValue)
            and part.conversion == -1
            and part.format_spec is None
        ):
            expression = ast.get_source_segment(source, part.value)
            if not expression:
                raise RemediationError("SQL value has no stable source expression")
            query_parts.append("?")
            values.append(expression)
        else:
            raise RemediationError(
                "SQL f-string conversions and format specifications are unsupported"
            )
    query = "".join(query_parts)
    if not re.match(r"^\s*(?:SELECT|INSERT|UPDATE|DELETE)\b", query, re.I):
        raise RemediationError("supported SQL must start with a data query statement")
    if not values:
        raise RemediationError("SQL f-string contains no value to parameterise")
    tuple_source = "(" + ", ".join(values) + ("," if len(values) == 1 else "") + ")"
    replacement = f"{query!r}, {tuple_source}"
    start, end = _span(source, call.args[0])
    return _replace(source, [(start, end, replacement)])


def remove_shell(source: str, parameters: Mapping[str, Any]) -> str:
    if parameters:
        raise RemediationError("TG-PY-SHELL-001 does not accept parameters")
    tree = _tree(source)
    matches: list[tuple[ast.Call, ast.keyword]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if not (
            isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr in _SUBPROCESS_APIS
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            continue
        shell = [
            keyword
            for keyword in node.keywords
            if keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
        ]
        if shell:
            matches.append((node, shell[0]))
    call, _ = _single(matches, label="shell=True subprocess call")
    command = str(call.args[0].value)
    if _SHELL_SYNTAX.search(command):
        raise RemediationError("command uses unsupported shell syntax")
    try:
        argv = shlex.split(command, posix=True)
    except ValueError as error:
        raise RemediationError(f"command has invalid shell quoting: {error}") from error
    if (
        not argv
        or argv[0] in {"cd", "exec", "export", "set", "source", "unset"}
        or "=" in argv[0]
    ):
        raise RemediationError("command uses unsupported shell syntax")
    if any(keyword.arg is None for keyword in call.keywords):
        raise RemediationError("subprocess **kwargs are unsupported")
    function = ast.get_source_segment(source, call.func)
    if not function:
        raise RemediationError("subprocess function has no stable source expression")
    arguments = [repr(argv)]
    arguments.extend(
        ast.get_source_segment(source, argument) or "" for argument in call.args[1:]
    )
    arguments.extend(
        f"{keyword.arg}={ast.get_source_segment(source, keyword.value)}"
        for keyword in call.keywords
        if keyword.arg != "shell"
    )
    if any(not argument or argument.endswith("=None") for argument in arguments):
        raise RemediationError("subprocess argument has no stable source expression")
    replacement = f"{function}({', '.join(arguments)})"
    start, end = _span(source, call)
    return _replace(source, [(start, end, replacement)])


def safe_yaml(source: str, parameters: Mapping[str, Any]) -> str:
    if parameters:
        raise RemediationError("TG-PY-YAML-001 does not accept parameters")
    tree = _tree(source)
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "yaml"
        and node.func.attr == "load"
        and len(node.args) == 1
        and not node.keywords
    ]
    call = _single(matches, label="yaml.load call")
    start, end = _span(source, call.func)
    return _replace(source, [(start, end, "yaml.safe_load")])


def strong_hash(source: str, parameters: Mapping[str, Any]) -> str:
    if parameters != {"purpose": "security"}:
        raise RemediationError(
            "weak-hash replacement requires purpose='security'"
        )
    tree = _tree(source)
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "hashlib"
        and node.func.attr in {"md5", "sha1"}
    ]
    call = _single(matches, label="weak hashlib call")
    start, end = _span(source, call.func)
    return _replace(source, [(start, end, "hashlib.sha256")])


def upgrade_dependency(source: str, parameters: Mapping[str, Any]) -> str:
    required = {"name", "from_version", "to_version"}
    parameter_fields = set(parameters)
    if parameter_fields != required and parameter_fields != required | {"hashes"}:
        raise RemediationError("dependency-upgrade parameters are incomplete")
    name = parameters["name"]
    from_version = parameters["from_version"]
    to_version = parameters["to_version"]
    if not isinstance(name, str) or not _PACKAGE.fullmatch(name):
        raise RemediationError("dependency name is invalid")
    if not all(
        isinstance(value, str) and _VERSION.fullmatch(value)
        for value in (from_version, to_version)
    ):
        raise RemediationError("dependency version is invalid")
    lines = source.splitlines(keepends=True)
    starts = [
        index
        for index, line in enumerate(lines)
        if re.match(
            rf"^{re.escape(name)}=={re.escape(from_version)}(?:\s|$)",
            line,
            re.I,
        )
    ]
    start = _single(starts, label="exact dependency pin")
    end = start
    while lines[end].rstrip("\r\n").endswith("\\"):
        end += 1
        if end >= len(lines):
            raise RemediationError("requirement continuation is incomplete")
    block = lines[start : end + 1]
    if any(";" in line or " #" in line for line in block):
        raise RemediationError("requirement markers and comments are unsupported")
    hashed = any("--hash=" in line for line in block)
    newline = "\r\n" if any(line.endswith("\r\n") for line in block) else "\n"
    terminated = block[-1].endswith(("\n", "\r"))
    if hashed:
        if set(parameters) != required | {"hashes"}:
            raise RemediationError("hash-locked dependency requires replacement hashes")
        hashes = parameters["hashes"]
        if (
            not isinstance(hashes, list)
            or not hashes
            or any(
                not isinstance(value, str) or not _DIGEST.fullmatch(value)
                for value in hashes
            )
        ):
            raise RemediationError("replacement hashes must be SHA-256 hex digests")
        if not re.fullmatch(
            rf"{re.escape(name)}=={re.escape(from_version)}[ \t]*\\\r?\n",
            block[0],
            re.I,
        ):
            raise RemediationError(
                "hash-locked requirement contains unsupported options"
            )
        if any(
            index > 0 and not re.fullmatch(
                r"\s*--hash=sha256:[0-9a-fA-F]{64}\s*\\?\r?\n?",
                line,
            )
            for index, line in enumerate(block)
        ):
            raise RemediationError(
                "hash-locked requirement contains unsupported options"
            )
        ordered = sorted(set(hashes))
        replacement_lines = [f"{name}=={to_version} \\{newline}"]
        replacement_lines.extend(
            f"    --hash=sha256:{value}"
            + (f" \\{newline}" if index < len(ordered) - 1 else "")
            for index, value in enumerate(ordered)
        )
        if terminated:
            replacement_lines[-1] += newline
        replacement = "".join(replacement_lines)
    else:
        if len(block) != 1 or set(parameters) != required:
            raise RemediationError("simple dependency pin has unsupported options")
        replacement = f"{name}=={to_version}" + (newline if terminated else "")
    return "".join(lines[:start]) + replacement + "".join(lines[end + 1 :])


def docker_user(source: str, parameters: Mapping[str, Any]) -> str:
    if set(parameters) != {"uid"}:
        raise RemediationError("Docker user remediation requires one numeric uid")
    uid = parameters["uid"]
    if isinstance(uid, bool) or not isinstance(uid, int) or uid < 10000 or uid > 65535:
        raise RemediationError("Docker uid must be between 10000 and 65535")
    lines = source.splitlines(keepends=True)
    instructions = [
        (index, match.group(1).upper())
        for index, line in enumerate(lines)
        if (match := re.match(r"^\s*([A-Za-z]+)\b", line))
    ]
    if sum(instruction == "FROM" for _, instruction in instructions) != 1:
        raise RemediationError("Dockerfile must contain exactly one build stage")
    if any(instruction == "USER" for _, instruction in instructions):
        raise RemediationError("Dockerfile already configures USER")
    entrypoints = [
        index
        for index, instruction in instructions
        if instruction in {"CMD", "ENTRYPOINT"}
    ]
    insertion = _single(entrypoints, label="final Docker CMD or ENTRYPOINT")
    newline = "\r\n" if any(line.endswith("\r\n") for line in lines) else "\n"
    lines.insert(insertion, f"USER {uid}{newline}")
    return "".join(lines)


def environment_secret(source: str, parameters: Mapping[str, Any]) -> str:
    if set(parameters) != {"symbol", "environment_variable"}:
        raise RemediationError("secret remediation parameters are incomplete")
    symbol = parameters["symbol"]
    environment = parameters["environment_variable"]
    if not isinstance(symbol, str) or not _NAME.fullmatch(symbol):
        raise RemediationError("secret symbol is invalid")
    if not isinstance(environment, str) or not _NAME.fullmatch(environment):
        raise RemediationError("environment variable is invalid")
    tree = _tree(source)
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
        and (
            (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == symbol
            )
            or (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == symbol
            )
        )
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        and bool(node.value.value)
    ]
    assignment = _single(matches, label="module-level literal secret")
    value = assignment.value
    replacements = [(*_span(source, value), f'os.environ["{environment}"]')]
    has_import = any(
        isinstance(node, ast.Import)
        and any(
            alias.name == "os" and alias.asname in {None, "os"}
            for alias in node.names
        )
        for node in tree.body
    )
    if not has_import:
        anchor: ast.stmt | None = None
        if (
            tree.body
            and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
            and isinstance(tree.body[0].value.value, str)
        ):
            anchor = tree.body[0]
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                anchor = node
        if anchor is None:
            lines = source.splitlines(keepends=True)
            prefix_lines = 1 if lines and lines[0].startswith("#!") else 0
            for index, line in enumerate(lines[:2]):
                if re.search(r"coding[:=][ \t]*[-\w.]+", line):
                    prefix_lines = max(prefix_lines, index + 1)
            insertion = sum(len(line) for line in lines[:prefix_lines])
            if prefix_lines:
                import_source = (
                    "import os\n"
                    if source[insertion:].startswith(("\n", "\r\n"))
                    else "import os\n\n"
                )
            else:
                import_source = "import os\n\n"
        else:
            insertion = _offset(source, anchor.end_lineno + 1, 0)
            import_source = "\nimport os\n"
        replacements.append((insertion, insertion, import_source))
    return _replace(source, replacements)


_HEADER_HOOK = "\n".join(
    [
        "",
        "@{application}.after_request",
        "def _trustgate_security_headers(response):",
        "    response.headers.setdefault("
        "\"Content-Security-Policy\", "
        "\"default-src 'self'; frame-ancestors 'none'\")",
        "    response.headers.setdefault("
        "\"Permissions-Policy\", "
        "\"camera=(), geolocation=(), microphone=()\")",
        "    response.headers.setdefault("
        "\"Referrer-Policy\", \"strict-origin-when-cross-origin\")",
        "    response.headers.setdefault("
        "\"X-Content-Type-Options\", \"nosniff\")",
        "    response.headers.setdefault("
        "\"X-Frame-Options\", \"DENY\")",
        "    return response",
        "",
    ]
)


def flask_headers(source: str, parameters: Mapping[str, Any]) -> str:
    if set(parameters) != {"application"}:
        raise RemediationError("Flask header remediation requires application")
    application = parameters["application"]
    if not isinstance(application, str) or not _NAME.fullmatch(application):
        raise RemediationError("Flask application symbol is invalid")
    if "_trustgate_security_headers" in source:
        raise RemediationError("Trust Gate security-header hook already exists")
    tree = _tree(source)
    matches = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == application
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "Flask"
    ]
    assignment = _single(matches, label="module-level Flask application")
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute) or node.attr != "after_request":
            continue
        if isinstance(node.value, ast.Name) and node.value.id == application:
            raise RemediationError(
                "Flask application already has an after_request hook"
            )
    insertion = _offset(source, assignment.end_lineno + 1, 0)
    return _replace(
        source,
        [(insertion, insertion, _HEADER_HOOK.format(application=application))],
    )


TRANSFORMERS: dict[str, Transformer] = {
    "TG-DEP-PY-001": upgrade_dependency,
    "TG-DOCKER-USER-001": docker_user,
    "TG-FLASK-HEADERS-001": flask_headers,
    "TG-PY-HASH-001": strong_hash,
    "TG-PY-SECRET-001": environment_secret,
    "TG-PY-SHELL-001": remove_shell,
    "TG-PY-SQL-001": parameterise_sql,
    "TG-PY-YAML-001": safe_yaml,
}


__all__ = ["TRANSFORMERS", "Transformer"]
