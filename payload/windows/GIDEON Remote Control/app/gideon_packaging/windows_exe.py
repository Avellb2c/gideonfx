from __future__ import annotations

"""Native Windows EXE packaging orchestration.

Preferred production path: Inno Setup -> EXE -> Authenticode.
Cross-platform path: verified precompiled GIDEON SFX stub + per-build payload.
Last-resort Windows path: IExpress -> EXE -> Authenticode.
No MSI is generated or consumed by either backend.
"""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import sys
import zipfile

from gideon_branding import BrandProfile, BrandingRepository
from gideon_agent_archive import AgentArchiveError, write_verified_deflated_zip
from gideon_agent_windows_runtime import validate_windows_private_runtime_payload
from gideon_agent_installer_contract import refresh_installer_contract, verify_installer_contract
from gideon_infrastructure.subprocess_utils import run_hidden
from .signing import SigningResult, WindowsCodeSigningService


PREBUILT_SFX_MAGIC = b"GIDEON_AGENT_SFX_TRAILER_V1"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class WindowsExeBuildError(RuntimeError):
    """Windows EXE build failure with an optional redacted support bundle."""

    def __init__(self, message: str, *, support_bundle: Path | None = None) -> None:
        super().__init__(message)
        self.support_bundle = Path(support_bundle).resolve() if support_bundle else None


class WindowsExePackager:
    def __init__(self, app_root: Path, *, signer: WindowsCodeSigningService | None = None) -> None:
        self.app_root = Path(app_root).resolve()
        self.signer = signer or WindowsCodeSigningService()
        self.last_signing_result: SigningResult | None = None
        self.last_backend: str = ""

    @staticmethod
    def _inno_registry_candidates() -> list[Path]:
        """Return ISCC candidates registered by Inno Setup on Windows.

        Inno Setup is not guaranteed to be added to PATH and winget can install it
        per-machine or per-user.  Keep discovery here so dependency validation and
        packaging use exactly the same source of truth.
        """
        if os.name != "nt":
            return []
        try:
            import winreg
        except ImportError:
            return []

        candidates: list[Path] = []
        uninstall_keys = (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 6_is1",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 5_is1",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 5_is1",
        )
        views = [0]
        for flag_name in ("KEY_WOW64_64KEY", "KEY_WOW64_32KEY"):
            flag = getattr(winreg, flag_name, 0)
            if flag and flag not in views:
                views.append(flag)

        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for key_name in uninstall_keys:
                for view in views:
                    try:
                        with winreg.OpenKey(hive, key_name, 0, winreg.KEY_READ | view) as key:
                            for value_name in ("InstallLocation", "DisplayIcon"):
                                try:
                                    value, _ = winreg.QueryValueEx(key, value_name)
                                except OSError:
                                    continue
                                raw = str(value or "").strip().strip('"')
                                if not raw:
                                    continue
                                # DisplayIcon may include ",0" and may point at Compil32.exe.
                                raw = raw.split(",", 1)[0].strip().strip('"')
                                path = Path(raw)
                                base = path if path.is_dir() else path.parent
                                candidates.append(base / "ISCC.exe")
                    except OSError:
                        continue
        return candidates

    @classmethod
    def inno_executable(cls) -> str | None:
        explicit = os.environ.get("GIDEON_INNO_ISCC_PATH")
        if explicit and Path(explicit).is_file():
            return str(Path(explicit).resolve())
        found = shutil.which("ISCC.exe") or shutil.which("ISCC") or shutil.which("iscc")
        if found:
            return found
        if os.name != "nt":
            return None

        local_app_data = os.environ.get("LOCALAPPDATA")
        roots = [
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
            os.environ.get("ProgramFiles", r"C:\Program Files"),
        ]
        if local_app_data:
            roots.extend([
                str(Path(local_app_data) / "Programs"),
                str(Path(local_app_data)),
            ])

        candidates: list[Path] = []
        for root in roots:
            for name in ("Inno Setup 6", "Inno Setup 5"):
                candidates.append(Path(root) / name / "ISCC.exe")
        candidates.extend(cls._inno_registry_candidates())

        seen: set[str] = set()
        for candidate in candidates:
            key = str(candidate).casefold()
            if key in seen:
                continue
            seen.add(key)
            if candidate.is_file():
                return str(candidate.resolve())
        return None

    @staticmethod
    def iexpress_executable() -> str | None:
        value = shutil.which("iexpress.exe") or shutil.which("iexpress")
        if value:
            return value
        if os.name == "nt":
            candidate = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "iexpress.exe"
            if candidate.is_file():
                return str(candidate)
        return None

    @staticmethod
    def csc_executable() -> str | None:
        explicit = os.environ.get("GIDEON_CSC_PATH")
        if explicit and Path(explicit).is_file():
            return str(Path(explicit).resolve())
        found = shutil.which("csc.exe") or shutil.which("csc")
        if found:
            return found
        if os.name != "nt":
            return None
        windir = Path(os.environ.get("WINDIR", os.environ.get("SystemRoot", r"C:\Windows")))
        for candidate in (
            windir / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe",
            windir / "Microsoft.NET" / "Framework" / "v4.0.30319" / "csc.exe",
        ):
            if candidate.is_file():
                return str(candidate.resolve())
        return None

    def _validated_prebuilt(self, tool: str, *, expected_version: str = "") -> Path:
        root = self.app_root / "deploy" / "agent" / "windows" / "prebuilt"
        manifest_path = root / "manifest.json"
        # The source bundle is authored on Windows, where ``MANIFEST.json`` and
        # ``manifest.json`` name the same file.  A release is built on Linux in
        # production, however, where a ZIP/TAR copied from a Windows workstation
        # can preserve the uppercase spelling.  Resolve that one legacy spelling
        # deterministically instead of silently reading an older neighbouring
        # manifest or failing the release build.
        if not manifest_path.is_file():
            try:
                manifest_path = next(
                    candidate for candidate in root.iterdir()
                    if candidate.is_file() and candidate.name.casefold() == "manifest.json"
                )
            except (OSError, StopIteration):
                pass
        try:
            document = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            raise WindowsExeBuildError(f"WINDOWS_PREBUILT_MANIFEST_INVALID: {exc}") from exc
        if not isinstance(document, dict) or document.get("schema") != "gideon-windows-prebuilt-tools/v1":
            raise WindowsExeBuildError("WINDOWS_PREBUILT_MANIFEST_SCHEMA_INVALID")
        if expected_version and str(document.get("agent_version") or "") != str(expected_version):
            raise WindowsExeBuildError(
                "WINDOWS_PREBUILT_VERSION_MISMATCH: "
                f"prebuilt={document.get('agent_version')} requested={expected_version}"
            )
        definitions = {
            "sfx_stub": (
                "GIDEONAgentSfxStub.exe",
                root / "GIDEONAgentSfxStub.cs",
                root / "GIDEONAgentSfxStub.manifest",
            ),
            "service_host": (
                "GIDEONAgentServiceHost.exe",
                self.app_root / "deploy" / "agent" / "windows" / "GIDEONAgentServiceHost.cs",
                None,
            ),
        }
        if tool not in definitions:
            raise WindowsExeBuildError(f"WINDOWS_PREBUILT_TOOL_UNKNOWN: {tool}")
        filename, source, resource_manifest = definitions[tool]
        row = (document.get("tools") or {}).get(tool)
        if not isinstance(row, dict) or str(row.get("binary") or "") != filename:
            raise WindowsExeBuildError(f"WINDOWS_PREBUILT_ENTRY_INVALID: {tool}")
        binary = root / filename
        checks = (
            (binary, str(row.get("binary_sha256") or ""), "binary"),
            (source, str(row.get("source_sha256") or ""), "source"),
        )
        for path, expected, label in checks:
            if not path.is_file() or not expected or _sha256_file(path) != expected.casefold():
                raise WindowsExeBuildError(f"WINDOWS_PREBUILT_{label.upper()}_INVALID: {tool}")
        if resource_manifest is not None:
            expected_manifest = str(row.get("manifest_sha256") or "")
            if not resource_manifest.is_file() or not expected_manifest or _sha256_file(resource_manifest) != expected_manifest.casefold():
                raise WindowsExeBuildError(f"WINDOWS_PREBUILT_RESOURCE_MANIFEST_INVALID: {tool}")
        with binary.open("rb") as stream:
            if stream.read(2) != b"MZ":
                raise WindowsExeBuildError(f"WINDOWS_PREBUILT_PE_MAGIC_INVALID: {tool}")
        return binary.resolve()

    @classmethod
    def prebuilt_sfx_executable(cls) -> str | None:
        try:
            app_root = Path(__file__).resolve().parents[1]
            return str(cls(app_root)._validated_prebuilt("sfx_stub"))
        except (OSError, ValueError, WindowsExeBuildError):
            return None

    def _build_agent_service_host(
        self, *, payload_dir: Path, source_dir: Path, version: str, brand: BrandProfile
    ) -> Path:
        """Compile the native Windows SCM host which supervises gideon_agent.py."""
        payload_dir = Path(payload_dir).resolve()
        source_dir = Path(source_dir).resolve()
        source = self.app_root / "deploy" / "agent" / "windows" / "GIDEONAgentServiceHost.cs"
        if not source.is_file():
            raise WindowsExeBuildError(
                f"AGENT_SERVICE_HOST_SOURCE_MISSING: {source}"
            )

        output = payload_dir / "GIDEONAgentServiceHost.exe"
        output.unlink(missing_ok=True)
        csc = self.csc_executable()
        if not csc:
            prebuilt = self._validated_prebuilt("service_host", expected_version=version)
            shutil.copy2(prebuilt, output)
            signing_result = self.signer.sign(output, brand, self.app_root)
            if brand.signing.required and not signing_result.signed:
                raise WindowsExeBuildError(
                    "AGENT_SERVICE_HOST_SIGNING_FAILED: la política exige firma Authenticode."
                )
            return output

        private_temp = source_dir / "service-host-csc-temp"
        private_temp.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["TEMP"] = str(private_temp)
        env["TMP"] = str(private_temp)

        args = [
            csc,
            "/nologo",
            "/target:winexe",
            "/optimize+",
            "/platform:anycpu",
            "/reference:System.dll",
            "/reference:System.Core.dll",
            "/reference:System.ServiceProcess.dll",
            f"/out:{output}",
            str(source),
        ]
        icon = brand.icon_file(self.app_root)
        if icon and icon.suffix.casefold() == ".ico":
            args.insert(-1, f"/win32icon:{icon}")

        result = run_hidden(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(source_dir),
            env=env,
        )
        if result.returncode != 0 or not output.is_file():
            detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            raise WindowsExeBuildError(
                "AGENT_SERVICE_HOST_BUILD_FAILED: "
                f"csc exit={result.returncode}\n{detail[-8000:]}"
            )

        signing_result = self.signer.sign(output, brand, self.app_root)
        if brand.signing.required and not signing_result.signed:
            raise WindowsExeBuildError(
                "AGENT_SERVICE_HOST_SIGNING_FAILED: la política exige firma Authenticode."
            )
        return output

    @classmethod
    def preferred_backend(cls) -> tuple[str, str | None]:
        inno = cls.inno_executable()
        if inno:
            return "inno", inno
        csc = cls.csc_executable()
        if csc:
            return "gideon_sfx", csc
        prebuilt = cls.prebuilt_sfx_executable()
        if prebuilt:
            return "prebuilt_sfx", prebuilt
        iexpress = cls.iexpress_executable()
        if iexpress:
            return "iexpress", iexpress
        return "none", None

    @staticmethod
    def _numeric_version(version: str) -> str:
        parts = [int(x) for x in re.findall(r"\d+", str(version))[:4]]
        while len(parts) < 4:
            parts.append(0)
        return ".".join(str(x) for x in parts)

    @staticmethod
    def _iss_quote(value: str) -> str:
        return str(value).replace('"', '""')

    @staticmethod
    def _validate_bootstrap_contract(payload_dir: Path) -> None:
        payload_dir = Path(payload_dir).resolve()
        marker = payload_dir / "bootstrap.required.json"
        bootstrap = payload_dir / "bootstrap.enrollment"
        if not marker.is_file():
            return
        try:
            doc = json.loads(marker.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            raise RuntimeError(f"BOOTSTRAP_CONTRACT_INVALID: {exc}") from exc
        if not bool(doc.get("required")):
            return
        if not bootstrap.is_file():
            raise RuntimeError("BOOTSTRAP_REQUIRED_MISSING: bootstrap.enrollment no existe.")
        if not bootstrap.read_text(encoding="utf-8-sig").strip():
            raise RuntimeError("BOOTSTRAP_REQUIRED_EMPTY: bootstrap.enrollment está vacío.")

    @staticmethod
    def _validate_csharp_source_literals(source_text: str) -> None:
        """Fail closed when generated C# contains an unterminated regular string.

        Python template escapes can accidentally materialize CR/LF or path backslashes
        inside C# string literals.  Catch that deterministically before invoking csc so
        WebAdmin returns an actionable builder error instead of publishing/burying a bad EXE.
        """
        text = str(source_text)
        state = "code"
        line = 1
        i = 0
        while i < len(text):
            ch = text[i]
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if state == "code":
                if ch == "/" and nxt == "/":
                    state = "line_comment"; i += 2; continue
                if ch == "/" and nxt == "*":
                    state = "block_comment"; i += 2; continue
                if ch == "@" and nxt == '"':
                    state = "verbatim"; i += 2; continue
                if ch == '"':
                    state = "string"; i += 1; continue
                if ch == "'":
                    state = "char"; i += 1; continue
            elif state == "line_comment":
                if ch in "\r\n":
                    state = "code"
            elif state == "block_comment":
                if ch == "*" and nxt == "/":
                    state = "code"; i += 2; continue
            elif state == "string":
                if ord(ch) < 32 and ch not in "\t\r\n":
                    raise WindowsExeBuildError(
                        f"WINDOWS_CSC_SOURCE_INVALID: control char U+{ord(ch):04X} in C# string at line {line}"
                    )
                if ch in "\r\n":
                    raise WindowsExeBuildError(
                        f"WINDOWS_CSC_SOURCE_INVALID: literal newline in regular C# string at line {line}"
                    )
                if ch == "\\":
                    if not nxt or nxt not in "'\"\\0abfnrtvuxU":
                        raise WindowsExeBuildError(
                            f"WINDOWS_CSC_SOURCE_INVALID: unsupported C# escape \\{nxt or '<eof>'} at line {line}"
                        )
                    i += 2; continue
                if ch == '"':
                    state = "code"
            elif state == "verbatim":
                if ord(ch) < 32 and ch not in "\t\r\n":
                    raise WindowsExeBuildError(
                        f"WINDOWS_CSC_SOURCE_INVALID: control char U+{ord(ch):04X} in verbatim C# string at line {line}"
                    )
                if ch == '"' and nxt == '"':
                    i += 2; continue
                if ch == '"':
                    state = "code"
            elif state == "char":
                if ord(ch) < 32 and ch not in "\t\r\n":
                    raise WindowsExeBuildError(
                        f"WINDOWS_CSC_SOURCE_INVALID: control char U+{ord(ch):04X} in C# char literal at line {line}"
                    )
                if ch in "\r\n":
                    raise WindowsExeBuildError(
                        f"WINDOWS_CSC_SOURCE_INVALID: literal newline in C# char literal at line {line}"
                    )
                if ch == "\\":
                    if not nxt or nxt not in "'\"\\0abfnrtvuxU":
                        raise WindowsExeBuildError(
                            f"WINDOWS_CSC_SOURCE_INVALID: unsupported C# escape \\{nxt or '<eof>'} in char literal at line {line}"
                        )
                    i += 2; continue
                if ch == "'":
                    state = "code"
            if ch == "\n":
                line += 1
            i += 1
        if state in {"string", "char", "verbatim", "block_comment"}:
            raise WindowsExeBuildError(
                f"WINDOWS_CSC_SOURCE_INVALID: unterminated C# lexical state={state} at EOF"
            )

    def _validate_visible_recovery_wrapper_contract(self, *, version: str, brand: BrandProfile) -> None:
        bootstrap = self._bootstrap_script("0" * 64, version)
        missing_bootstrap = [
            marker for marker in (
                "BOOTSTRAP_TRANSACTIONAL_STAGING",
                "installer-staging-",
                "New-GideonBootstrapDiagnostic",
                "Stop-GideonOldRuntime",
                "BOOTSTRAP_STAGED_PAYLOAD_VALIDATED",
                "installer-backup-",
                "BOOTSTRAP_ROLLBACK_PASS",
            ) if marker not in bootstrap
        ]
        if missing_bootstrap:
            raise WindowsExeBuildError(
                "WINDOWS_BOOTSTRAP_RECOVERY_CONTRACT_MISSING:" + ",".join(missing_bootstrap)
            )
        sfx = self._csc_sfx_source(
            expected_payload_sha256="0" * 64, version=version, brand=brand
        )
        self._validate_csharp_source_literals(sfx)
        missing_sfx = [
            marker for marker in (
                "FindLatestDiagnostic",
                "WriteWrapperDiagnostic",
                "MessageBox.Show",
                "bootstrap-install.log",
                "Se mostrará el diagnóstico",
            ) if marker not in sfx
        ]
        if missing_sfx:
            raise WindowsExeBuildError(
                "WINDOWS_VISIBLE_FAILURE_CONTRACT_MISSING:" + ",".join(missing_sfx)
            )

    @staticmethod
    def _postinstall_script() -> str:
        return r'''$ErrorActionPreference='Stop'
$Root=$PSScriptRoot
$Setup=Join-Path $Root 'gideon-agent-setup.ps1'
if(-not (Test-Path -LiteralPath $Setup)){ throw "El paquete no contiene gideon-agent-setup.ps1" }
$preseed = -not [string]::IsNullOrWhiteSpace($env:GIDEON_AGENT_SITE_CODE) -and -not [string]::IsNullOrWhiteSpace($env:GIDEON_AGENT_SITE_NAME)
$bootstrapPath=Join-Path $Root 'bootstrap.enrollment'
$contractPath=Join-Path $Root 'bootstrap.required.json'
$bootstrapRequired=$false
if(Test-Path -LiteralPath $contractPath){
  try{$bootstrapRequired=[bool]((Get-Content -LiteralPath $contractPath -Raw -Encoding UTF8|ConvertFrom-Json).required)}catch{}
}
if([string]::IsNullOrWhiteSpace($env:GIDEON_AGENT_ENROLL_SECRET) -and (Test-Path -LiteralPath $bootstrapPath)){
  try{$env:GIDEON_AGENT_ENROLL_SECRET=([string](Get-Content -LiteralPath $bootstrapPath -Raw -Encoding UTF8)).Trim()}catch{}
}
if($bootstrapRequired -and [string]::IsNullOrWhiteSpace($env:GIDEON_AGENT_ENROLL_SECRET)){
  throw 'BOOTSTRAP_REQUIRED_MISSING_AFTER_EXTRACTION: el instalador perdió la credencial temporal.'
}
$args=@('-NoLogo','-NoProfile','-STA','-WindowStyle','Hidden','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $Setup),'-InstallRoot',('"{0}"' -f $Root))
if($preseed){
  $args += @('-SiteCode',('"{0}"' -f $env:GIDEON_AGENT_SITE_CODE),'-SiteName',('"{0}"' -f $env:GIDEON_AGENT_SITE_NAME),'-Silent')
  if($env:GIDEON_AGENT_NAME){$args += @('-AgentName',('"{0}"' -f $env:GIDEON_AGENT_NAME))}
  if($env:GIDEON_AGENT_GATEWAY){$args += @('-Gateway',('"{0}"' -f $env:GIDEON_AGENT_GATEWAY))}
}
try{
  $proc=Start-Process -FilePath 'powershell.exe' -ArgumentList $args -WindowStyle Hidden -Wait -PassThru
  exit $proc.ExitCode
}finally{
  Remove-Item Env:GIDEON_AGENT_ENROLL_SECRET -ErrorAction SilentlyContinue
}
'''

    def _build_inno(
        self,
        *,
        compiler: str,
        payload_dir: Path,
        source_dir: Path,
        version: str,
        brand: BrandProfile,
    ) -> Path:
        payload_dir = Path(payload_dir).resolve()
        # The script is part of the compiled payload only and never touches source tree.
        postinstall = payload_dir / "gideon-agent-postinstall.ps1"
        postinstall.write_text(self._postinstall_script(), encoding="utf-8-sig", newline="\r\n")

        icon = brand.icon_file(self.app_root)
        output_base = f"{brand.package_basename()}-build"
        setup_lines = [
            "[Setup]",
            f"AppId={self._iss_quote(brand.bundle_id)}",
            f"AppName={self._iss_quote(brand.agent_product_name)}",
            f"AppVersion={self._iss_quote(version)}",
            f"AppVerName={self._iss_quote(brand.agent_product_name + ' ' + version)}",
            f"AppPublisher={self._iss_quote(brand.publisher_name)}",
            f"AppPublisherURL={self._iss_quote(brand.website_url)}",
            f"AppSupportURL={self._iss_quote(brand.support_url)}",
            f"AppCopyright={self._iss_quote(brand.copyright)}",
            "DefaultDirName={autopf}\\GIDEONAgent",
            "DisableProgramGroupPage=yes",
            "PrivilegesRequired=admin",
            "OutputDir=" + self._iss_quote(str(source_dir.resolve())),
            "OutputBaseFilename=" + self._iss_quote(output_base),
            "Compression=lzma2/fast",
            "SolidCompression=no",
            "WizardStyle=modern",
            "DisableWelcomePage=no",
            "DisableReadyPage=no",
            "DisableFinishedPage=no",
            "ArchitecturesAllowed=x64compatible",
            "ArchitecturesInstallIn64BitMode=x64compatible",
            "Uninstallable=yes",
            "UsePreviousAppDir=yes",
            "DirExistsWarning=no",
            "UninstallDisplayName=" + self._iss_quote(brand.agent_product_name),
            "CloseApplications=no",
            "RestartApplications=no",
            f"VersionInfoCompany={self._iss_quote(brand.company_name)}",
            f"VersionInfoDescription={self._iss_quote(brand.agent_description)}",
            f"VersionInfoProductName={self._iss_quote(brand.agent_product_name)}",
            f"VersionInfoProductVersion={self._iss_quote(version)}",
            f"VersionInfoVersion={self._numeric_version(version)}",
        ]
        if icon and icon.suffix.casefold() == ".ico":
            setup_lines.append(f"SetupIconFile={self._iss_quote(str(icon))}")
            setup_lines.append("UninstallDisplayIcon={app}\\gideon_agent_tray.ico")

        setup_lines += ["", "[Files]"]
        for path in sorted(payload_dir.rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(payload_dir)
            dest = "{app}" if rel.parent == Path(".") else "{app}\\" + str(rel.parent).replace("/", "\\")
            setup_lines.append(
                f'Source: "{self._iss_quote(str(path))}"; DestDir: "{self._iss_quote(dest)}"; Flags: ignoreversion'
            )
        setup_lines += [
            "",
            "[UninstallRun]",
            'Filename: "{sys}\\WindowsPowerShell\\v1.0\\powershell.exe"; Parameters: "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File ""{app}\\gideon-agent-uninstall.ps1"" -InstallRoot ""{app}"" -RemoveData -RemoveLegacy -Quiet"; Flags: runhidden waituntilterminated; RunOnceId: "GIDEONAgentCleanup"',
            "",
            "[Code]",
            "function PrepareToInstall(var NeedsRestart: Boolean): String;",
            "var ResultCode: Integer;",
            "begin",
            "  Exec(ExpandConstant('{sys}\\WindowsPowerShell\\v1.0\\powershell.exe'),",
            "    '-NoProfile -NonInteractive -WindowStyle Hidden -Command \"sc.exe stop GIDEONAgent 2>$null | Out-Null; Stop-ScheduledTask -TaskName ''GIDEONAgent'' -ErrorAction SilentlyContinue; Remove-Item -LiteralPath (Join-Path (Get-Location) ''gideon_common'') -Recurse -Force -ErrorAction SilentlyContinue; Remove-Item -LiteralPath (Join-Path (Get-Location) ''__pycache__'') -Recurse -Force -ErrorAction SilentlyContinue\"',",
            "    ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode);",
            "  Result := '';",
            "end;",
            "",
            "procedure CurStepChanged(CurStep: TSetupStep);",
            "var ResultCode: Integer; Ok: Boolean;",
            "begin",
            "  if CurStep = ssPostInstall then",
            "  begin",
            "    Ok := Exec(ExpandConstant('{sys}\\WindowsPowerShell\\v1.0\\powershell.exe'),",
            "      '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"' + ExpandConstant('{app}\\gideon-agent-postinstall.ps1') + '\"',",
            "      ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode);",
            "    if (not Ok) or (ResultCode <> 0) then",
            "      RaiseException('La instalación del agente no completó identificación/enrolamiento. Código: ' + IntToStr(ResultCode));",
            "  end;",
            "end;",
        ]
        iss = source_dir / "gideon-agent.iss"
        iss.write_text("\r\n".join(setup_lines) + "\r\n", encoding="utf-8-sig")
        proc = run_hidden([compiler, "/Qp", str(iss)], check=False, capture_output=True, text=True, timeout=600)
        built = source_dir / f"{output_base}.exe"
        if proc.returncode != 0 or not built.is_file():
            detail = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
            raise RuntimeError(f"Inno Setup no pudo generar el EXE (exit {proc.returncode}).\n{detail[-6000:]}")
        return built

    @staticmethod
    def _zip_payload(payload_dir: Path, output: Path) -> None:
        try:
            write_verified_deflated_zip(payload_dir, output)
        except AgentArchiveError as exc:
            raise WindowsExeBuildError(str(exc)) from exc

    @staticmethod
    def _bootstrap_script(expected_payload_sha256: str, expected_agent_version: str) -> str:
        script = r'''$ErrorActionPreference='Stop'
$Root='C:\Program Files\GIDEONAgent'
$DataRoot=Join-Path $env:ProgramData 'GIDEONAgent'
$Payload=Join-Path $PSScriptRoot 'payload.zip'
$ExpectedPayloadSha256='__PAYLOAD_SHA256__'
$TargetAgentVersion='__AGENT_VERSION__'
$Stamp=Get-Date -Format 'yyyyMMdd_HHmmss'
$BootstrapLog=Join-Path $DataRoot 'bootstrap-install.log'
$DiagDir=Join-Path $DataRoot 'diagnostics'
$Stage=Join-Path $DataRoot ('installer-staging-'+[guid]::NewGuid().ToString('N'))
$PreviousRoot=$Root+'.previous-'+$Stamp
$IdentityBackup=Join-Path $DataRoot ('installer-backup-'+$Stamp)
$script:MovedOldRoot=$false
$script:PostInstallStarted=$false

function Write-BootstrapLog([string]$Message){
  try{
    New-Item -ItemType Directory -Path $DataRoot -Force|Out-Null
    $line='[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'),$Message
    Add-Content -LiteralPath $BootstrapLog -Value $line -Encoding UTF8
  }catch{}
}
function New-GideonBootstrapDiagnostic([string]$Reason,[string]$StageName){
  New-Item -ItemType Directory -Path $DiagDir -Force|Out-Null
  $path=Join-Path $DiagDir ('bootstrap-error-'+(Get-Date -Format 'yyyyMMdd_HHmmss')+'.txt')
  $lines=New-Object System.Collections.Generic.List[string]
  $lines.Add('============================================================')
  $lines.Add('GIDEON RX AGENT - WINDOWS BOOTSTRAP DIAGNOSTIC')
  $lines.Add('============================================================')
  $lines.Add('Timestamp: '+(Get-Date).ToString('o'))
  $lines.Add('Stage: '+$StageName)
  $lines.Add('Reason: '+$Reason)
  $lines.Add('Target: '+$TargetAgentVersion)
  $lines.Add('InstallRoot: '+$Root)
  $lines.Add('Staging: '+$Stage)
  $lines.Add('PreviousRoot: '+$PreviousRoot)
  $lines.Add('IdentityBackup: '+$IdentityBackup)
  $lines.Add('')
  $lines.Add('=== SERVICE ===')
  try{$svc=Get-Service GIDEONAgent -ErrorAction Stop;$lines.Add(('GIDEONAgent Status={0}; StartType={1}' -f $svc.Status,$svc.StartType))}catch{$lines.Add('GIDEONAgent: '+$_.Exception.Message)}
  $lines.Add('')
  $lines.Add('=== FILES ===')
  foreach($f in @('gideon_agent.py','agent.template.json','installer.contract.json','runtime.contract.json','GIDEONAgentServiceHost.exe')){
    $fp=Join-Path $Root $f;$lines.Add(($f+': '+(Test-Path -LiteralPath $fp)))
  }
  $lines.Add('')
  $lines.Add('=== BOOTSTRAP LOG (LAST 120) ===')
  if(Test-Path -LiteralPath $BootstrapLog){foreach($l in @(Get-Content -LiteralPath $BootstrapLog -Tail 120 -ErrorAction SilentlyContinue)){$lines.Add([string]$l)}}
  $lines.Add('')
  $lines.Add('============================================================')
  $lines.Add('END DIAGNOSTIC')
  $lines.Add('============================================================')
  [IO.File]::WriteAllLines($path,$lines,(New-Object Text.UTF8Encoding($false)))
  return $path
}
function Test-Admin {
  $id=[Security.Principal.WindowsIdentity]::GetCurrent()
  $p=New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Stop-GideonOldRuntime {
  Write-BootstrapLog 'BOOTSTRAP_TRANSACTIONAL_STAGING: deteniendo runtime anterior.'
  try{Stop-ScheduledTask -TaskName 'GIDEONAgent' -ErrorAction SilentlyContinue}catch{}
  $sc=Join-Path $env:WINDIR 'System32\sc.exe'
  try{& $sc stop GIDEONAgent 2>$null|Out-Null}catch{}
  for($i=0;$i-lt 30;$i++){
    $svc=Get-Service GIDEONAgent -ErrorAction SilentlyContinue
    if($null-eq $svc -or $svc.Status-eq 'Stopped'){break}
    Start-Sleep -Milliseconds 300
  }
  try{
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue|Where-Object{
      ([string]$_.ExecutablePath).Equals((Join-Path $Root 'GIDEONAgentServiceHost.exe'),[StringComparison]::OrdinalIgnoreCase) -or
      (([string]$_.CommandLine) -like ('*'+$Root+'*gideon_agent.py*'))
    }|ForEach-Object{try{Stop-Process -Id ([int]$_.ProcessId) -Force -ErrorAction SilentlyContinue}catch{}}
  }catch{}
  Start-Sleep -Milliseconds 500
}
function Copy-GideonIdentityBackup {
  New-Item -ItemType Directory -Path $IdentityBackup -Force|Out-Null
  foreach($source in @(
    (Join-Path $Root 'agent.json'),
    (Join-Path $DataRoot 'agent.runtime.json'),
    (Join-Path $DataRoot 'agent.status.json')
  )){
    if(Test-Path -LiteralPath $source){Copy-Item -LiteralPath $source -Destination (Join-Path $IdentityBackup ([IO.Path]::GetFileName($source))) -Force}
  }
  Write-BootstrapLog ('Identity backup: '+$IdentityBackup)
}
function Test-StagedPayload([string]$StageRoot){
  foreach($rel in @('gideon-agent-postinstall.ps1','gideon-agent-setup.ps1','gideon_agent.py','agent.template.json','installer.contract.json','runtime.contract.json','GIDEONAgentServiceHost.exe')){
    if(-not(Test-Path -LiteralPath (Join-Path $StageRoot $rel) -PathType Leaf)){throw ('BOOTSTRAP_STAGED_PAYLOAD_MISSING: '+$rel)}
  }
  $contract=Get-Content -LiteralPath (Join-Path $StageRoot 'installer.contract.json') -Raw -Encoding UTF8|ConvertFrom-Json
  if([string]$contract.schema-ne'gideon-agent-installer-contract/v2'){throw 'BOOTSTRAP_CONTRACT_SCHEMA_MISMATCH'}
  if([string]$contract.status-ne'PASS'){throw 'BOOTSTRAP_CONTRACT_STATUS_NOT_PASS'}
  if([string]$contract.agent_version-ne$TargetAgentVersion){throw ('BOOTSTRAP_CONTRACT_VERSION_MISMATCH: '+[string]$contract.agent_version)}
  Write-BootstrapLog ('BOOTSTRAP_STAGED_PAYLOAD_VALIDATED: contract PASS version='+$TargetAgentVersion+'.')
}

if(-not (Test-Admin)){
  $args=@('-NoProfile','-NonInteractive','-WindowStyle','Hidden','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath))
  $proc=Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $args -WindowStyle Hidden -Wait -PassThru
  exit $proc.ExitCode
}

try{
  New-Item -ItemType Directory -Path $DataRoot,$DiagDir -Force|Out-Null
  Write-BootstrapLog ('BOOTSTRAP_START target='+$TargetAgentVersion)
  if(-not (Test-Path -LiteralPath $Payload)){throw "No existe payload.zip en $PSScriptRoot"}
  $ActualPayloadSha256=(Get-FileHash -LiteralPath $Payload -Algorithm SHA256).Hash.ToLowerInvariant()
  if($ActualPayloadSha256 -ne $ExpectedPayloadSha256){throw 'BOOTSTRAP_PAYLOAD_SHA256_MISMATCH'}

  New-Item -ItemType Directory -Path $Stage -Force|Out-Null
  Expand-Archive -LiteralPath $Payload -DestinationPath $Stage -Force
  Test-StagedPayload $Stage
  Copy-GideonIdentityBackup
  Stop-GideonOldRuntime

  if(Test-Path -LiteralPath $Root){
    try{
      Move-Item -LiteralPath $Root -Destination $PreviousRoot -Force
      $script:MovedOldRoot=$true
      Write-BootstrapLog ('BOOTSTRAP_OLD_ROOT_MOVED: '+$PreviousRoot)
    }catch{
      Write-BootstrapLog ('BOOTSTRAP_OLD_ROOT_MOVE_FAILED: '+[string]$_.Exception.Message+'; intentando limpieza controlada.')
      Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction Stop
    }
  }
  New-Item -ItemType Directory -Path $Root -Force|Out-Null
  Get-ChildItem -LiteralPath $Stage -Force|Copy-Item -Destination $Root -Recurse -Force
  Remove-Item -LiteralPath $Stage -Recurse -Force -ErrorAction SilentlyContinue
  Write-BootstrapLog 'BOOTSTRAP_NEW_ROOT_ACTIVATED: payload copiado con ACL heredada de Program Files.'

  $oldConfig=Join-Path $IdentityBackup 'agent.json'
  if(Test-Path -LiteralPath $oldConfig){
    Copy-Item -LiteralPath $oldConfig -Destination (Join-Path $Root 'agent.json') -Force
    Write-BootstrapLog 'BOOTSTRAP_IDENTITY_CONFIG_RESTORED_FOR_MIGRATION.'
  }

  $script:PostInstallStarted=$true
  & (Join-Path $Root 'gideon-agent-postinstall.ps1')
  $postCode=$LASTEXITCODE
  if($postCode-ne 0){throw ('BOOTSTRAP_POSTINSTALL_FAILED exit='+$postCode)}
  Write-BootstrapLog 'BOOTSTRAP_POSTINSTALL_PASS.'
  if($script:MovedOldRoot -and (Test-Path -LiteralPath $PreviousRoot)){
    Remove-Item -LiteralPath $PreviousRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
  Write-BootstrapLog 'BOOTSTRAP_COMPLETE PASS.'
  exit 0
}catch{
  $message=[string]$_.Exception.Message
  Write-BootstrapLog ('BOOTSTRAP_ERROR: '+$message)
  if($script:MovedOldRoot -and -not $script:PostInstallStarted -and (Test-Path -LiteralPath $PreviousRoot)){
    try{
      if(Test-Path -LiteralPath $Root){Remove-Item -LiteralPath $Root -Recurse -Force -ErrorAction SilentlyContinue}
      Move-Item -LiteralPath $PreviousRoot -Destination $Root -Force
      Write-BootstrapLog 'BOOTSTRAP_ROLLBACK_PASS: root anterior restaurado porque el fallo ocurrió antes del postinstall.'
      $sc=Join-Path $env:WINDIR 'System32\sc.exe'
      try{& $sc start GIDEONAgent 2>$null|Out-Null}catch{}
    }catch{Write-BootstrapLog ('BOOTSTRAP_ROLLBACK_FAILED: '+[string]$_.Exception.Message)}
  }
  $diag=New-GideonBootstrapDiagnostic $message 'transactional-bootstrap'
  Write-Output ('GIDEON_DIAGNOSTIC_FILE='+$diag)
  Write-BootstrapLog ('GIDEON_DIAGNOSTIC_FILE='+$diag)
  exit 97
}
'''
        return (
            script.replace('__PAYLOAD_SHA256__', expected_payload_sha256.lower())
            .replace('__AGENT_VERSION__', str(expected_agent_version))
        )

    @staticmethod
    def _sed(*, final: Path, source_dir: Path, version: str, brand: BrandProfile) -> str:
        target = str(final.resolve())
        source = str(source_dir.resolve()) + "\\"
        friendly = brand.metadata_text(f"{brand.agent_product_name} {version}").replace('"', "'")
        return (
            "[Version]\nClass=IEXPRESS\nSEDVersion=3\n[Options]\n"
            "PackagePurpose=InstallApp\nShowInstallProgramWindow=0\nHideExtractAnimation=1\n"
            "UseLongFileName=1\nInsideCompressed=0\nCAB_FixedSize=0\nCAB_ResvCodeSigning=0\n"
            "RebootMode=N\nInstallPrompt=\nDisplayLicense=\nFinishMessage=\n"
            f"TargetName={target}\nFriendlyName={friendly}\n"
            "AppLaunched=powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File bootstrap.ps1\n"
            "PostInstallCmd=<None>\nAdminQuietInstCmd=<None>\nUserQuietInstCmd=<None>\n"
            "SourceFiles=SourceFiles\n[SourceFiles]\n"
            f"SourceFiles0={source}\n[SourceFiles0]\n%FILE0%=\n%FILE1%=\n"
            "[Strings]\nFILE0=\"payload.zip\"\nFILE1=\"bootstrap.ps1\"\n"
        )

    @staticmethod
    def _csc_sfx_source(*, expected_payload_sha256: str, version: str, brand: BrandProfile) -> str:
        company = brand.metadata_text(brand.company_name).replace('"', '\\"')
        product = brand.metadata_text(brand.agent_product_name).replace('"', '\\"')
        description = brand.metadata_text(brand.agent_description).replace('"', '\\"')
        numeric = WindowsExePackager._numeric_version(version)
        return f'''using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Drawing;
using System.Windows.Forms;
[assembly: AssemblyTitle("{product}")]
[assembly: AssemblyProduct("{product}")]
[assembly: AssemblyCompany("{company}")]
[assembly: AssemblyDescription("{description}")]
[assembly: AssemblyVersion("{numeric}")]
[assembly: AssemblyFileVersion("{numeric}")]
namespace GIDEON.AgentSfx {{
  internal static class Program {{
    const string ExpectedSha256 = "{expected_payload_sha256.lower()}";
    [STAThread]
    static int Main() {{
      Application.EnableVisualStyles();
      Application.SetCompatibleTextRenderingDefault(false);
      Form progress = new Form();
      progress.Text = "{product} · Preparando instalación";
      progress.StartPosition = FormStartPosition.CenterScreen;
      progress.FormBorderStyle = FormBorderStyle.FixedDialog;
      progress.MaximizeBox = false;
      progress.MinimizeBox = false;
      progress.ControlBox = false;
      progress.ClientSize = new Size(520, 118);
      Label title = new Label();
      title.Text = "Gideon Rx Agent · Instalación / reparación";
      title.Font = new Font("Segoe UI", 11.0f, FontStyle.Bold);
      title.AutoSize = true;
      title.Location = new Point(22, 18);
      progress.Controls.Add(title);
      Label detail = new Label();
      detail.Text = "Validando y extrayendo el runtime seguro. Esto puede tardar unos segundos.";
      detail.AutoSize = false;
      detail.Size = new Size(470, 36);
      detail.Location = new Point(22, 47);
      progress.Controls.Add(detail);
      ProgressBar bar = new ProgressBar();
      bar.Style = ProgressBarStyle.Marquee;
      bar.MarqueeAnimationSpeed = 22;
      bar.Location = new Point(22, 86);
      bar.Size = new Size(470, 14);
      progress.Controls.Add(bar);
      progress.Show();
      Application.DoEvents();

      string root = Path.Combine(Path.GetTempPath(), "GIDEONAgentSetup-" + Guid.NewGuid().ToString("N"));
      try {{
        Directory.CreateDirectory(root);
        string payload = Path.Combine(root, "payload.zip");
        string bootstrap = Path.Combine(root, "bootstrap.ps1");
        detail.Text = "Extrayendo archivos del instalador…";
        Application.DoEvents();
        Extract("GIDEON.Payload", payload);
        Extract("GIDEON.Bootstrap", bootstrap);
        detail.Text = "Validando integridad…";
        Application.DoEvents();
        if (!String.Equals(Sha256(payload), ExpectedSha256, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Payload SHA-256 mismatch");
        string systemRoot = Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\\Windows";
        string powershell = Path.Combine(systemRoot, @"System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        if (!File.Exists(powershell)) powershell = "powershell.exe";
        detail.Text = "Abriendo identificación del Agent…";
        Application.DoEvents();
        ProcessStartInfo psi = new ProcessStartInfo();
        psi.FileName = powershell;
        psi.Arguments = "-NoLogo -NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File \\\"" + bootstrap + "\\\"";
        psi.WorkingDirectory = root;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        Process child = Process.Start(psi);
        if (child == null) throw new InvalidOperationException("No se pudo iniciar el bootstrap PowerShell");
        System.Threading.Thread.Sleep(250);
        detail.Text = "Configurando, reparando y validando el Agent…";
        Application.DoEvents();
        while (!child.HasExited) {{
          Application.DoEvents();
          System.Threading.Thread.Sleep(120);
        }}
        if (child.ExitCode == 0) {{
          bar.Style = ProgressBarStyle.Continuous;
          bar.Value = 100;
          detail.Text = "Instalación validada correctamente.";
          Application.DoEvents();
          System.Threading.Thread.Sleep(450);
          return 0;
        }}
        bar.Style = ProgressBarStyle.Continuous;
        bar.Value = 100;
        detail.Text = "La instalación terminó con errores. Se mostrará el diagnóstico.";
        Application.DoEvents();
        string diag = FindLatestDiagnostic();
        string msg = "Gideon Rx Agent no pudo completar la instalación." + Environment.NewLine + Environment.NewLine + "Código: " + child.ExitCode.ToString();
        if (!String.IsNullOrWhiteSpace(diag)) msg += Environment.NewLine + Environment.NewLine + "Diagnóstico: " + diag;
        else msg += Environment.NewLine + Environment.NewLine + "Revise " + Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GIDEONAgent", "bootstrap-install.log");
        MessageBox.Show(msg, "Gideon Rx Agent · Error de instalación", MessageBoxButtons.OK, MessageBoxIcon.Error);
        return child.ExitCode;
      }} catch (Exception ex) {{
        string diag = WriteWrapperDiagnostic(ex);
        MessageBox.Show("El instalador falló antes de completar el Agent." + Environment.NewLine + Environment.NewLine + ex.Message + Environment.NewLine + Environment.NewLine + "Diagnóstico: " + diag,
          "Gideon Rx Agent · Error de bootstrap", MessageBoxButtons.OK, MessageBoxIcon.Error);
        return 93;
      }} finally {{
        try {{ progress.Close(); progress.Dispose(); }} catch {{ }}
        try {{ Directory.Delete(root, true); }} catch {{ }}
      }}
    }}
    static string FindLatestDiagnostic() {{
      try {{
        string data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GIDEONAgent");
        string diagDir = Path.Combine(data, "diagnostics");
        if (Directory.Exists(diagDir)) {{
          FileInfo[] files = new DirectoryInfo(diagDir).GetFiles("*.txt");
          Array.Sort(files, delegate(FileInfo a, FileInfo b) {{ return b.LastWriteTimeUtc.CompareTo(a.LastWriteTimeUtc); }});
          if (files.Length > 0) return files[0].FullName;
        }}
        string log = Path.Combine(data, "bootstrap-install.log");
        if (File.Exists(log)) return log;
      }} catch {{ }}
      return "";
    }}
    static string WriteWrapperDiagnostic(Exception ex) {{
      try {{
        string data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "GIDEONAgent");
        string diagDir = Path.Combine(data, "diagnostics");
        Directory.CreateDirectory(diagDir);
        string path = Path.Combine(diagDir, "wrapper-error-" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".txt");
        File.WriteAllText(path, "Gideon Rx Agent - Wrapper Diagnostic" + Environment.NewLine + "Timestamp: " + DateTime.Now.ToString("o") + Environment.NewLine + "Reason: " + ex.ToString(), Encoding.UTF8);
        return path;
      }} catch {{ return @"C:\\ProgramData\\GIDEONAgent"; }}
    }}
    static void Extract(string resourceName, string target) {{
      Assembly assembly = Assembly.GetExecutingAssembly();
      using (Stream input = assembly.GetManifestResourceStream(resourceName)) {{
        if (input == null) throw new InvalidOperationException("Missing resource: " + resourceName);
        using (FileStream output = new FileStream(target, FileMode.Create, FileAccess.Write, FileShare.None)) input.CopyTo(output);
      }}
    }}
    static string Sha256(string path) {{
      using (SHA256 sha = SHA256.Create())
      using (FileStream stream = File.OpenRead(path)) {{
        byte[] hash = sha.ComputeHash(stream);
        StringBuilder sb = new StringBuilder(hash.Length * 2);
        foreach (byte b in hash) sb.Append(b.ToString("x2"));
        return sb.ToString();
      }}
    }}
  }}
}}
'''

    def _build_csc_sfx(
        self, *, compiler: str, payload_dir: Path, source_dir: Path, version: str, brand: BrandProfile,
    ) -> Path:
        payload_dir = Path(payload_dir).resolve()
        source_dir = Path(source_dir).resolve()
        source_dir.mkdir(parents=True, exist_ok=True)
        (payload_dir / "gideon-agent-postinstall.ps1").write_text(
            self._postinstall_script(), encoding="utf-8-sig", newline="\r\n"
        )
        payload_zip = source_dir / "payload.zip"
        self._zip_payload(payload_dir, payload_zip)
        payload_sha256 = hashlib.sha256(payload_zip.read_bytes()).hexdigest()
        bootstrap = source_dir / "bootstrap.ps1"
        bootstrap.write_text(self._bootstrap_script(payload_sha256, version), encoding="utf-8-sig", newline="\r\n")
        source = source_dir / "GIDEONAgentSfx.cs"
        source_text = self._csc_sfx_source(
            expected_payload_sha256=payload_sha256, version=version, brand=brand
        )
        self._validate_csharp_source_literals(source_text)
        source.write_text(source_text, encoding="utf-8-sig", newline="\r\n")
        manifest = source_dir / "GIDEONAgentSfx.manifest"
        manifest.write_text(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">\n"
            "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges>\n"
            "<requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\" />\n"
            "</requestedPrivileges></security></trustInfo></assembly>\n",
            encoding="utf-8",
        )
        built = source_dir / f"{brand.package_basename()}-build.exe"
        built.unlink(missing_ok=True)
        private_temp = source_dir / "csc-temp"
        private_temp.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["TEMP"] = str(private_temp)
        env["TMP"] = str(private_temp)
        args = [
            compiler, "/nologo", "/target:winexe", "/optimize+", "/platform:anycpu",
            "/reference:System.Windows.Forms.dll", "/reference:System.Drawing.dll",
            f"/win32manifest:{manifest}",
            f"/out:{built}", f"/resource:{payload_zip},GIDEON.Payload",
            f"/resource:{bootstrap},GIDEON.Bootstrap", str(source),
        ]
        icon = brand.icon_file(self.app_root)
        if icon and icon.suffix.casefold() == ".ico":
            args.insert(-1, f"/win32icon:{icon}")
        result = run_hidden(
            args, check=False, capture_output=True, text=True, timeout=300,
            cwd=str(source_dir), env=env,
        )
        if result.returncode != 0 or not built.is_file():
            detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            raise RuntimeError(
                f"GIDEON SFX (.NET csc) no pudo generar el instalador EXE (exit {result.returncode}).\n{detail[-8000:]}"
            )
        return built

    def _build_prebuilt_sfx(
        self,
        *,
        stub: str,
        payload_dir: Path,
        source_dir: Path,
        version: str,
        brand: BrandProfile,
    ) -> Path:
        """Append a verified payload to the immutable Windows SFX launcher."""
        payload_dir = Path(payload_dir).resolve()
        source_dir = Path(source_dir).resolve()
        source_dir.mkdir(parents=True, exist_ok=True)
        expected_stub = self._validated_prebuilt("sfx_stub", expected_version=version)
        if Path(stub).resolve() != expected_stub:
            raise WindowsExeBuildError("WINDOWS_PREBUILT_SFX_SELECTION_INVALID")

        (payload_dir / "gideon-agent-postinstall.ps1").write_text(
            self._postinstall_script(), encoding="utf-8-sig", newline="\r\n"
        )
        payload_zip = source_dir / "payload.zip"
        self._zip_payload(payload_dir, payload_zip)
        payload_sha256 = _sha256_file(payload_zip)
        bootstrap = source_dir / "bootstrap.ps1"
        bootstrap.write_text(
            self._bootstrap_script(payload_sha256, version), encoding="utf-8-sig", newline="\r\n"
        )
        bootstrap_sha256 = _sha256_file(bootstrap)

        built = source_dir / f"{brand.package_basename()}-build.exe"
        built.unlink(missing_ok=True)
        with built.open("wb") as output:
            for part in (expected_stub, payload_zip, bootstrap):
                with part.open("rb") as source:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
            output.write(struct.pack("<QQ", payload_zip.stat().st_size, bootstrap.stat().st_size))
            output.write(payload_sha256.encode("ascii"))
            output.write(bootstrap_sha256.encode("ascii"))
            output.write(PREBUILT_SFX_MAGIC)
            output.flush()
        return built

    @staticmethod
    def _payload_diagnostic_manifest(payload_dir: Path) -> list[dict[str, object]]:
        """Describe payload files without copying bootstrap credentials into support bundles."""
        rows: list[dict[str, object]] = []
        sensitive_tokens = ("secret", "password", "token", "enrollment", "private")
        for path in sorted(Path(payload_dir).rglob("*")):
            if not path.is_file():
                continue
            rel = path.relative_to(payload_dir).as_posix()
            lowered = rel.casefold()
            sensitive = any(token in lowered for token in sensitive_tokens) or path.suffix.casefold() in {".key", ".p12", ".pfx"}
            row: dict[str, object] = {"path": rel, "size_bytes": path.stat().st_size}
            if sensitive:
                row["content"] = "REDACTED"
            else:
                row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            rows.append(row)
        return rows

    def _write_iexpress_support_bundle(
        self, *, support_dir: Path | None, source_dir: Path, payload_dir: Path,
        compiler: str, private_temp: Path, result: object, built: Path, sed: Path,
    ) -> Path | None:
        if support_dir is None:
            return None
        try:
            target_dir = Path(support_dir).resolve()
            target_dir.mkdir(parents=True, exist_ok=True)
            target = target_dir / "GIDEON-AGENT-BUILD-SUPPORT-IEXPRESS.zip"
            safe = source_dir / "support-redacted"
            if safe.exists():
                shutil.rmtree(safe, ignore_errors=True)
            safe.mkdir(parents=True, exist_ok=True)
            stdout = str(getattr(result, "stdout", "") or "")
            stderr = str(getattr(result, "stderr", "") or "")
            compiler_path = Path(compiler)
            system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
            makecab = system_root / "System32" / "makecab.exe"
            diag = {
                "schema": "gideon-agent-builder-support/v1",
                "backend": "IExpress",
                "returncode": int(getattr(result, "returncode", -999)),
                "built_exists": built.is_file(),
                "compiler": str(compiler_path),
                "compiler_exists": compiler_path.is_file(),
                "makecab": str(makecab),
                "makecab_exists": makecab.is_file(),
                "working_directory": str(source_dir),
                "private_temp": str(private_temp),
                "sed_file": sed.name,
                "platform": platform.platform(),
                "python_version": sys.version,
                "python_executable": sys.executable,
                "service_identity_hint": str(os.environ.get("USERNAME") or ""),
                "stdout": stdout[-12000:],
                "stderr": stderr[-12000:],
            }
            (safe / "builder-diagnostics.json").write_text(
                json.dumps(diag, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            (safe / "payload-manifest.redacted.json").write_text(
                json.dumps(self._payload_diagnostic_manifest(payload_dir), ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            if sed.is_file():
                shutil.copy2(sed, safe / "gideon-agent.sed")
            bootstrap = source_dir / "bootstrap.ps1"
            if bootstrap.is_file():
                shutil.copy2(bootstrap, safe / "bootstrap.ps1")
            (safe / "LEAME.txt").write_text(
                "GIDEON Agent Builder - diagnóstico IExpress\n"
                "Este ZIP no contiene payload.zip, bootstrap.enrollment, claves privadas ni grants.\n",
                encoding="utf-8",
            )
            with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                for path in sorted(safe.rglob("*")):
                    if path.is_file():
                        archive.write(path, path.relative_to(safe).as_posix())
            shutil.rmtree(safe, ignore_errors=True)
            return target
        except Exception:
            return None

    def _build_iexpress(
        self,
        *,
        compiler: str,
        payload_dir: Path,
        source_dir: Path,
        version: str,
        brand: BrandProfile,
        support_dir: Path | None = None,
    ) -> Path:
        payload_dir = Path(payload_dir).resolve()
        source_dir = Path(source_dir).resolve()
        source_dir.mkdir(parents=True, exist_ok=True)
        (payload_dir / "gideon-agent-postinstall.ps1").write_text(
            self._postinstall_script(), encoding="utf-8-sig", newline="\r\n"
        )
        payload_zip = source_dir / "payload.zip"
        self._zip_payload(payload_dir, payload_zip)
        payload_sha256 = hashlib.sha256(payload_zip.read_bytes()).hexdigest()
        (source_dir / "bootstrap.ps1").write_text(
            self._bootstrap_script(payload_sha256, version), encoding="utf-8-sig", newline="\r\n"
        )
        built = source_dir / f"{brand.package_basename()}-build.exe"
        built.unlink(missing_ok=True)
        sed = source_dir / "gideon-agent.sed"
        sed_encoding = "mbcs" if os.name == "nt" else "cp1252"
        sed.write_text(
            self._sed(final=built, source_dir=source_dir, version=version, brand=brand),
            encoding=sed_encoding, errors="replace", newline="\r\n"
        )

        # IExpress is a legacy Windows component. When WebAdmin runs as LocalService,
        # never rely on an interactive user's TEMP/profile or current directory.
        private_temp = source_dir / "iex-temp"
        private_temp.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["TEMP"] = str(private_temp)
        env["TMP"] = str(private_temp)
        env["TMPDIR"] = str(private_temp)
        result = run_hidden(
            [compiler, "/N", "/Q", sed.name],
            check=False, capture_output=True, text=True, timeout=300,
            cwd=str(source_dir), env=env,
        )
        if result.returncode != 0 or not built.is_file():
            support = self._write_iexpress_support_bundle(
                support_dir=support_dir, source_dir=source_dir, payload_dir=payload_dir,
                compiler=compiler, private_temp=private_temp, result=result, built=built, sed=sed,
            )
            detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            suffix = f" Diagnóstico: {support.name}." if support else ""
            raise WindowsExeBuildError(
                f"IExpress no pudo generar el instalador EXE (exit {result.returncode}).{suffix}\n{detail[-5000:]}",
                support_bundle=support,
            )
        return built

    def build(
        self,
        *,
        payload_dir: Path,
        final: Path,
        stage: Path,
        version: str,
        brand: BrandProfile | None = None,
        diagnostics_dir: Path | None = None,
    ) -> Path:
        # Last fail-closed gates.
        validate_windows_private_runtime_payload(Path(payload_dir))
        self._validate_bootstrap_contract(Path(payload_dir))
        runtime_contract_path = Path(payload_dir) / "runtime.contract.json"
        if not runtime_contract_path.is_file():
            raise RuntimeError("RUNTIME_CONTRACT_FILE_MISSING: runtime.contract.json no existe.")
        try:
            runtime_contract = json.loads(runtime_contract_path.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            raise RuntimeError(f"RUNTIME_CONTRACT_FILE_INVALID: {exc}") from exc
        if int(runtime_contract.get("reverse_tunnel_api_required") or 0) != int(runtime_contract.get("reverse_tunnel_api_provided") or -1):
            raise RuntimeError("RUNTIME_CONTRACT_FILE_MISMATCH: BUILD BLOCKED.")
        for required in (
            "gideon-agent-setup.ps1", "gideon-agent-uninstall.ps1", "gideon_agent.py", "gideon_agent_http.py",
            "gideon_agent_security.py", "gideon_agent_worker.py", "gideon_agent_job_contract.py",
            "gideon_agent_connectivity.py", "gideon_agent_config.py", "gideon_reverse_tunnel.py",
            "gideon_script_host.ps1", "requirements-agent.txt",
        ):
            if not (Path(payload_dir) / required).is_file():
                raise WindowsExeBuildError(f"AGENT_INSTALLER_INCOMPLETE: falta {required}")
        if not (Path(payload_dir) / "gideon_common" / "__init__.py").is_file():
            raise WindowsExeBuildError("AGENT_INSTALLER_INCOMPLETE: falta gideon_common/__init__.py")
        brand = brand or BrandingRepository(self.app_root).load()
        # RC30.95.21: WebAdmin must never publish a Windows installer whose
        # bootstrap can fail silently or overwrite a live runtime in place.
        self._validate_visible_recovery_wrapper_contract(version=version, brand=brand)

        # RC30.95.5: every NEW Windows Agent runs under the native Windows SCM.
        # No Scheduled Task is created by the generated installer.
        service_host = self._build_agent_service_host(
            payload_dir=Path(payload_dir),
            source_dir=Path(stage) / "windows-service-host",
            version=version,
            brand=brand,
        )
        if not service_host.is_file():
            raise WindowsExeBuildError("AGENT_SERVICE_HOST_BUILD_FAILED: output missing.")

        # The native SCM host is compiled during the Windows build. Refresh the
        # embedded installer contract now, before Inno/SFX enumerates payload
        # files, so GIDEONAgentServiceHost.exe is itself covered by SHA-256.
        refreshed = refresh_installer_contract(
            Path(payload_dir), extra_required=("GIDEONAgentServiceHost.exe",)
        )
        verified = verify_installer_contract(
            Path(payload_dir), expected_version=version, expected_target_id=str(refreshed.get("target_id") or "")
        )
        if str(verified.get("status") or "") != "PASS":
            raise WindowsExeBuildError("AGENT_INSTALLER_CONTRACT_NOT_PASS")

        backend, compiler = self.preferred_backend()
        if not compiler:
            raise RuntimeError(
                "No hay backend EXE disponible. Instale Inno Setup 6 o valide .NET Framework csc.exe / iexpress.exe."
            )
        source_dir = Path(stage) / "windows-exe"
        source_dir.mkdir(parents=True, exist_ok=True)
        if backend == "inno":
            built = self._build_inno(
                compiler=compiler, payload_dir=payload_dir, source_dir=source_dir, version=version, brand=brand
            )
            self.last_backend = "Inno Setup"
        elif backend == "gideon_sfx":
            built = self._build_csc_sfx(
                compiler=compiler, payload_dir=payload_dir, source_dir=source_dir, version=version, brand=brand
            )
            self.last_backend = "GIDEON SFX (.NET Framework csc)"
        elif backend == "prebuilt_sfx":
            built = self._build_prebuilt_sfx(
                stub=compiler, payload_dir=payload_dir, source_dir=source_dir, version=version, brand=brand
            )
            self.last_backend = "GIDEON SFX precompilado verificado"
        else:
            built = self._build_iexpress(
                compiler=compiler, payload_dir=payload_dir, source_dir=source_dir, version=version, brand=brand,
                support_dir=diagnostics_dir,
            )
            self.last_backend = "IExpress (last-resort fallback)"

        # Resource/metadata generation is complete before signing.  Any mutation
        # after Authenticode would invalidate the signature.
        staged_final = built
        self.last_signing_result = self.signer.sign(staged_final, brand, self.app_root)
        if brand.signing.required and not self.last_signing_result.signed:
            raise RuntimeError("La política exige un EXE firmado y no se obtuvo firma Authenticode válida.")
        final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staged_final, final)
        return final
