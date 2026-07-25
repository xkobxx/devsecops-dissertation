"""Built-in scanner adapter catalogue."""

from __future__ import annotations

from abc import abstractmethod
from datetime import datetime, timezone
from pathlib import Path
import shutil
from typing import Any, Callable, ClassVar, Iterable, Mapping

from trustgate.adapters import (
    AdapterCapability,
    AdapterContext,
    AdapterMetadata,
    AdapterRegistry,
    RepositoryContext,
    ScannerAdapter,
)
from trustgate.scanners.execution import execute_scanner, record_external_scanner
from trustgate.scanners.models import ScannerResult

from .legacy import (
    parse_bandit,
    parse_gitleaks,
    parse_pip_audit,
    parse_semgrep,
    parse_trivy,
)
from .parsers import (
    parse_brakeman,
    parse_checkov,
    parse_codeql_sarif,
    parse_eslint_security,
    parse_gosec,
    parse_grype,
    parse_hadolint,
    parse_osv_scanner,
    parse_spotbugs,
    parse_syft,
    parse_trufflehog,
    parse_zap,
)

Parser = Callable[..., list[dict[str, Any]]]


class BuiltinCommandAdapter(ScannerAdapter):
    """Shared lifecycle implementation for local command-line scanners."""

    adapter_name: ClassVar[str]
    adapter_category: ClassVar[str]
    languages: ClassVar[tuple[str, ...]] = ()
    file_patterns: ClassVar[tuple[str, ...]] = ()
    runtime: ClassVar[tuple[str, ...]]
    timeout: ClassVar[float] = 300.0
    report_format: ClassVar[str] = "json"
    capabilities: ClassVar[tuple[AdapterCapability, ...]]
    licence: ClassVar[str] = "Apache-2.0"
    globally_applicable: ClassVar[bool] = False
    finding_exit_codes: ClassVar[frozenset[int]] = frozenset()
    report_from_stdout: ClassVar[bool] = False
    report_filename: ClassVar[str | None] = None
    parser: ClassVar[Parser]

    def metadata(self) -> AdapterMetadata:
        return AdapterMetadata(
            name=self.adapter_name,
            version="1.0.0",
            category=self.adapter_category,
            supported_languages=self.languages,
            supported_files=self.file_patterns,
            required_runtime=self.runtime,
            default_timeout=self.timeout,
            licence=self.licence,
            data_leaves_runner=False,
            report_format=self.report_format,
            capabilities=self.capabilities,
        )

    def is_applicable(self, repository_context: RepositoryContext) -> bool:
        if self.globally_applicable:
            return bool(repository_context.root)
        return bool(
            set(self.languages).intersection(repository_context.languages)
            or repository_context.matches(self.file_patterns)
        )

    @property
    def native_report_filename(self) -> str:
        return self.report_filename or f"{self.adapter_name}_report.{self.report_format}"

    @abstractmethod
    def build_command(
        self, target: Path, report_path: Path, context: AdapterContext
    ) -> tuple[str, ...]:
        """Return a no-shell command for this scanner."""

    def execute(self, target: Path, context: AdapterContext) -> ScannerResult:
        report_path = context.reports_dir / self.native_report_filename
        metadata_path = (
            context.reports_dir / f"{self.adapter_name}_execution.json"
        )
        return execute_scanner(
            scanner=self.adapter_name,
            command=self.build_command(target, report_path, context),
            report_path=report_path,
            metadata_path=metadata_path,
            logs_dir=context.reports_dir / "logs",
            timeout_seconds=context.timeout_seconds,
            finding_exit_codes=self.finding_exit_codes,
            report_from_stdout=self.report_from_stdout,
        )

    def parse(
        self, report: Path, context: AdapterContext
    ) -> Iterable[Mapping[str, Any]]:
        return self.parser(
            report,
            redact_sensitive_content=bool(
                context.config.options.get("redact_sensitive_content", False)
            ),
            repository_root=context.repository.root,
        )


class BanditAdapter(BuiltinCommandAdapter):
    adapter_name = "bandit"
    adapter_category = "sast"
    languages = ("python",)
    file_patterns = ("*.py",)
    runtime = ("bandit",)
    capabilities = (AdapterCapability.SAST,)
    finding_exit_codes = frozenset({1})
    report_filename = "bandit_report.json"
    parser = staticmethod(parse_bandit)

    def build_command(self, target, report_path, context):
        return (
            "bandit", "-r", str(target), "-f", "json", "-o", str(report_path)
        )


class SemgrepAdapter(BuiltinCommandAdapter):
    adapter_name = "semgrep"
    adapter_category = "sast"
    languages = (
        "c", "cpp", "csharp", "go", "java", "javascript", "kotlin",
        "php", "python", "ruby", "rust", "typescript",
    )
    file_patterns = ()
    runtime = ("semgrep",)
    licence = "LGPL-2.1-or-later"
    capabilities = (AdapterCapability.SAST,)
    report_filename = "semgrep_report.json"
    parser = staticmethod(parse_semgrep)

    def build_command(self, target, report_path, context):
        rules = str(context.config.options.get("config", "auto"))
        return (
            "semgrep", "scan", "--config", rules, "--json", "--output",
            str(report_path), str(target),
        )


class PipAuditAdapter(BuiltinCommandAdapter):
    adapter_name = "pip-audit"
    adapter_category = "sca"
    file_patterns = (
        "requirements*.txt",
    )
    runtime = ("pip-audit",)
    capabilities = (AdapterCapability.SCA,)
    finding_exit_codes = frozenset({1})
    report_filename = "pip_audit_report.json"
    parser = staticmethod(parse_pip_audit)

    def build_command(self, target, report_path, context):
        configured = context.config.options.get("requirements")
        requirements = (
            Path(configured)
            if configured
            else next(
                (
                    target / name
                    for name in sorted(context.repository.files)
                    if Path(name).name.startswith("requirements")
                    and Path(name).suffix == ".txt"
                ),
                None,
            )
        )
        if requirements is None:
            raise ValueError("pip-audit requires a requirements*.txt file")
        return (
            "pip-audit", "--format", "json", "--output", str(report_path),
            "--requirement", str(requirements),
        )


class TrivyAdapter(BuiltinCommandAdapter):
    adapter_name = "trivy"
    adapter_category = "multi"
    globally_applicable = True
    runtime = ("trivy",)
    capabilities = (
        AdapterCapability.SCA,
        AdapterCapability.IAC,
        AdapterCapability.SECRETS,
    )
    report_filename = "trivy_report.json"
    parser = staticmethod(parse_trivy)

    def build_command(self, target, report_path, context):
        return (
            "trivy", "fs", "--format", "json", "--output", str(report_path),
            str(target),
        )


class GitleaksAdapter(BuiltinCommandAdapter):
    adapter_name = "gitleaks"
    adapter_category = "secrets"
    globally_applicable = True
    runtime = ("gitleaks",)
    licence = "MIT"
    capabilities = (AdapterCapability.SECRETS,)
    finding_exit_codes = frozenset({3})
    report_filename = "gitleaks_report.json"
    parser = staticmethod(parse_gitleaks)

    def build_command(self, target, report_path, context):
        return (
            "gitleaks", "detect", "--source", str(target), "--report-format",
            "json", "--report-path", str(report_path), "--exit-code", "3",
        )


class ZapAdapter(BuiltinCommandAdapter):
    adapter_name = "zap"
    adapter_category = "dast"
    file_patterns = (
        "openapi*.json", "openapi*.yaml", "openapi*.yml",
        "swagger*.json", "swagger*.yaml", "swagger*.yml",
    )
    runtime = ("zap-api-scan.py",)
    timeout = 600.0
    capabilities = (AdapterCapability.DAST,)
    report_filename = "zap_report.json"
    parser = staticmethod(parse_zap)

    def build_command(self, target, report_path, context):
        specification = context.config.options.get("specification")
        if specification is None:
            specification = next(
                (
                    target / name
                    for name in sorted(context.repository.files)
                    if context.repository.matches((name,))
                    and Path(name).name.lower().startswith(
                        ("openapi", "swagger")
                    )
                ),
                None,
            )
        if specification is None:
            raise ValueError("ZAP requires an OpenAPI or Swagger specification")
        return (
            "zap-api-scan.py", "-t", str(specification), "-f", "openapi",
            "-J", str(report_path),
        )


class OsvScannerAdapter(BuiltinCommandAdapter):
    adapter_name = "osv-scanner"
    adapter_category = "sca"
    file_patterns = (
        "Cargo.lock", "Gemfile.lock", "go.mod", "package-lock.json",
        "pnpm-lock.yaml", "poetry.lock", "requirements*.txt", "yarn.lock",
    )
    runtime = ("osv-scanner",)
    capabilities = (AdapterCapability.SCA,)
    report_filename = "osv_scanner_report.json"
    parser = staticmethod(parse_osv_scanner)

    def build_command(self, target, report_path, context):
        return (
            "osv-scanner", "scan", "source", "--format=json",
            f"--output-file={report_path}", "--recursive", str(target),
        )


class SyftAdapter(BuiltinCommandAdapter):
    adapter_name = "syft"
    adapter_category = "sbom"
    globally_applicable = True
    runtime = ("syft",)
    capabilities = (AdapterCapability.SBOM,)
    report_filename = "syft_report.json"
    parser = staticmethod(parse_syft)

    def build_command(self, target, report_path, context):
        return ("syft", "scan", str(target), "-o", f"syft-json={report_path}")


class GrypeAdapter(BuiltinCommandAdapter):
    adapter_name = "grype"
    adapter_category = "sca"
    globally_applicable = True
    runtime = ("grype",)
    capabilities = (AdapterCapability.SCA,)
    report_from_stdout = True
    report_filename = "grype_report.json"
    parser = staticmethod(parse_grype)

    def build_command(self, target, report_path, context):
        return ("grype", str(target), "-o", "json")


class CheckovAdapter(BuiltinCommandAdapter):
    adapter_name = "checkov"
    adapter_category = "iac"
    file_patterns = (
        "*.tf", "*.tf.json", "Dockerfile", "*.yaml", "*.yml",
        "template.json", "template.yaml", "template.yml",
    )
    runtime = ("checkov",)
    capabilities = (AdapterCapability.IAC,)
    report_from_stdout = True
    report_filename = "checkov_report.json"
    parser = staticmethod(parse_checkov)

    def build_command(self, target, report_path, context):
        return ("checkov", "-d", str(target), "-o", "json", "--quiet")


class HadolintAdapter(BuiltinCommandAdapter):
    adapter_name = "hadolint"
    adapter_category = "container"
    file_patterns = ("Dockerfile", "Dockerfile.*", "*.Dockerfile")
    runtime = ("hadolint",)
    licence = "GPL-3.0-only"
    capabilities = (AdapterCapability.IAC,)
    report_from_stdout = True
    report_filename = "hadolint_report.json"
    parser = staticmethod(parse_hadolint)

    def build_command(self, target, report_path, context):
        dockerfile = context.config.options.get("dockerfile")
        if dockerfile is None:
            dockerfile = next(
                (
                    target / name
                    for name in sorted(context.repository.files)
                    if Path(name).name == "Dockerfile"
                    or Path(name).name.startswith("Dockerfile.")
                    or Path(name).name.endswith(".Dockerfile")
                ),
                None,
            )
        if dockerfile is None:
            raise ValueError("Hadolint requires a Dockerfile")
        return ("hadolint", "--format", "json", str(dockerfile))


class GosecAdapter(BuiltinCommandAdapter):
    adapter_name = "gosec"
    adapter_category = "sast"
    languages = ("go",)
    file_patterns = ("go.mod", "*.go")
    runtime = ("gosec",)
    capabilities = (AdapterCapability.SAST,)
    finding_exit_codes = frozenset({1})
    report_filename = "gosec_report.json"
    parser = staticmethod(parse_gosec)

    def build_command(self, target, report_path, context):
        return (
            "gosec", "-fmt=json", f"-out={report_path}", f"{target}/..."
        )


class BrakemanAdapter(BuiltinCommandAdapter):
    adapter_name = "brakeman"
    adapter_category = "sast"
    languages = ("ruby",)
    file_patterns = ("Gemfile", "config/application.rb")
    runtime = ("brakeman",)
    licence = "Brakeman-Public-Use-1.0"
    capabilities = (AdapterCapability.SAST,)
    report_filename = "brakeman_report.json"
    parser = staticmethod(parse_brakeman)

    def is_applicable(self, repository_context):
        return (
            "Gemfile" in repository_context.files
            and "config/application.rb" in repository_context.files
        )

    def build_command(self, target, report_path, context):
        return (
            "brakeman", "-p", str(target), "-f", "json", "-o",
            str(report_path),
        )


class SpotBugsAdapter(BuiltinCommandAdapter):
    adapter_name = "spotbugs"
    adapter_category = "sast"
    languages = ("java",)
    file_patterns = ("pom.xml", "build.gradle", "build.gradle.kts", "*.class")
    runtime = ("spotbugs",)
    licence = "LGPL-2.1-or-later"
    capabilities = (AdapterCapability.SAST,)
    report_format = "xml"
    report_filename = "spotbugs_report.xml"
    parser = staticmethod(parse_spotbugs)

    def build_command(self, target, report_path, context):
        classes = context.config.options.get("classes", target)
        return (
            "spotbugs", "-textui", "-xml:withMessages", "-output",
            str(report_path), str(classes),
        )


class EslintSecurityAdapter(BuiltinCommandAdapter):
    adapter_name = "eslint-security"
    adapter_category = "sast"
    languages = ("javascript", "typescript")
    file_patterns = ("package.json", "*.js", "*.jsx", "*.ts", "*.tsx")
    runtime = ("npx", "eslint")
    licence = "MIT"
    capabilities = (AdapterCapability.SAST,)
    finding_exit_codes = frozenset({1})
    report_filename = "eslint_security_report.json"
    parser = staticmethod(parse_eslint_security)

    def build_command(self, target, report_path, context):
        return (
            "npx", "--no-install", "eslint", str(target), "--format", "json",
            "--output-file", str(report_path),
        )


class TruffleHogAdapter(BuiltinCommandAdapter):
    adapter_name = "trufflehog"
    adapter_category = "secrets"
    globally_applicable = True
    runtime = ("trufflehog",)
    licence = "AGPL-3.0-only"
    capabilities = (AdapterCapability.SECRETS,)
    report_format = "jsonl"
    report_from_stdout = True
    report_filename = "trufflehog_report.jsonl"
    parser = staticmethod(parse_trufflehog)

    def is_applicable(self, repository_context):
        return bool(repository_context.root) and bool(
            self._optional_enabled(repository_context)
        )

    @staticmethod
    def _optional_enabled(repository_context):
        # Optionality is enforced by AdapterConfig.enabled during planning.
        return True

    def build_command(self, target, report_path, context):
        return (
            "trufflehog", "filesystem", str(target), "--json", "--no-update"
        )


class CodeQlSarifAdapter(BuiltinCommandAdapter):
    adapter_name = "codeql-sarif"
    adapter_category = "sast"
    file_patterns = ("*.sarif", "*.sarif.json")
    runtime = ()
    licence = "GitHub-CodeQL-Terms"
    capabilities = (AdapterCapability.SARIF_IMPORT, AdapterCapability.SAST)
    report_format = "sarif"
    report_filename = "codeql_report.sarif"
    parser = staticmethod(parse_codeql_sarif)

    def build_command(self, target, report_path, context):
        return ()

    def execute(self, target: Path, context: AdapterContext) -> ScannerResult:
        configured = context.config.options.get("sarif")
        source = (
            Path(configured)
            if configured
            else next(
                (
                    target / name
                    for name in sorted(context.repository.files)
                    if name.endswith((".sarif", ".sarif.json"))
                ),
                None,
            )
        )
        if source is None or not source.is_file():
            raise ValueError("CodeQL SARIF import requires an existing SARIF file")
        report_path = context.reports_dir / self.native_report_filename
        report_path.parent.mkdir(parents=True, exist_ok=True)
        if source.resolve() != report_path.resolve():
            shutil.copyfile(source, report_path)
        started_at = datetime.now(timezone.utc)
        return record_external_scanner(
            scanner=self.adapter_name,
            outcome="success",
            report_path=report_path,
            metadata_path=(
                context.reports_dir / f"{self.adapter_name}_execution.json"
            ),
            started_at=started_at,
            version=str(context.config.options.get("scanner_version") or "unknown"),
        )


BUILTIN_ADAPTERS: tuple[type[BuiltinCommandAdapter], ...] = (
    BanditAdapter,
    BrakemanAdapter,
    CheckovAdapter,
    CodeQlSarifAdapter,
    EslintSecurityAdapter,
    GitleaksAdapter,
    GosecAdapter,
    GrypeAdapter,
    HadolintAdapter,
    OsvScannerAdapter,
    PipAuditAdapter,
    SemgrepAdapter,
    SpotBugsAdapter,
    SyftAdapter,
    TrivyAdapter,
    TruffleHogAdapter,
    ZapAdapter,
)
BUILTIN_ADAPTER_NAMES = tuple(
    sorted(adapter().metadata().name for adapter in BUILTIN_ADAPTERS)
)


def builtin_registry(*, discover_plugins: bool = False) -> AdapterRegistry:
    registry = AdapterRegistry()
    for adapter in BUILTIN_ADAPTERS:
        registry.register(adapter)
    if discover_plugins:
        registry.discover()
    return registry


__all__ = [
    "BUILTIN_ADAPTER_NAMES",
    "BUILTIN_ADAPTERS",
    "BuiltinCommandAdapter",
    "builtin_registry",
]
