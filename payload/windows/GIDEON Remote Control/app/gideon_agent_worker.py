#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import datetime as dt
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from gideon_agent_job_contract import validate_job_envelope

VERSION = "2.2.0"


def windows_hidden_kwargs() -> dict[str, Any]:
    if os.name != "nt":
        return {}
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
    return {
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0),
        "startupinfo": startup,
    }


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="milliseconds")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_platform_name(value: str) -> str:
    raw = str(value or "").strip().lower()
    if raw.startswith("win"):
        return "windows"
    if raw in {"darwin", "mac", "macos"}:
        return "darwin"
    if raw in {"linux", "gnu/linux"}:
        return "linux"
    return raw


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}.{time.time_ns()}")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    os.replace(tmp, path)


def find_executable(candidates: list[str]) -> str | None:
    for name in candidates:
        if not name:
            continue
        if os.path.isabs(name) and Path(name).exists():
            return name
        found = shutil.which(name)
        if found:
            return found
    return None


def _preferred(profile: dict[str, Any], kind: str) -> list[str]:
    values = [str(x) for x in profile.get("preferred_executors", [])]
    def name(value: str) -> str:
        return Path(value).name.lower()
    if kind == "powershell":
        return [x for x in values if name(x) in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}]
    if kind == "python":
        return [x for x in values if name(x).startswith("python") or name(x).startswith("py.exe")]
    if kind == "shell":
        return [x for x in values if name(x) in {"bash", "bash.exe", "sh", "sh.exe", "zsh", "zsh.exe"}]
    return []


def command_for(script: Path, profile: dict[str, Any]) -> list[str]:
    ext = script.suffix.lower()
    if ext == ".ps1":
        exe = find_executable(_preferred(profile, "powershell") + (["powershell.exe", "pwsh"] if os.name == "nt" else ["pwsh"]))
        if not exe:
            raise RuntimeError("EXECUTOR_NOT_AVAILABLE: .ps1 requiere PowerShell/pwsh en este host")
        if Path(exe).name.lower().startswith("powershell"):
            return [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)]
        return [exe, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(script)]
    if ext in {".sh", ".command"}:
        exe = find_executable(_preferred(profile, "shell") + ["bash", "sh"])
        if not exe:
            raise RuntimeError("EXECUTOR_NOT_AVAILABLE: bash/sh no está disponible")
        return [exe, str(script)]
    if ext == ".py":
        exe = find_executable(_preferred(profile, "python") + [sys.executable, "python3", "python"])
        if not exe:
            raise RuntimeError("EXECUTOR_NOT_AVAILABLE: Python no está disponible")
        return [exe, str(script)]
    if ext in {".cmd", ".bat"} and os.name == "nt":
        return [os.environ.get("COMSPEC", "cmd.exe"), "/D", "/C", str(script)]
    raise RuntimeError(f"SCRIPT_EXTENSION_NOT_ALLOWED: {ext or '<sin extensión>'}")


def powershell_host_command(script: Path, profile: dict[str, Any], host_script: Path, params_path: Path, result_path: Path) -> list[str]:
    exe = find_executable(_preferred(profile, "powershell") + (["powershell.exe", "pwsh"] if os.name == "nt" else ["pwsh"]))
    if not exe:
        raise RuntimeError("EXECUTOR_NOT_AVAILABLE: .ps1 requiere PowerShell/pwsh en este host")
    base = [exe, "-NoLogo", "-NoProfile", "-NonInteractive"]
    if Path(exe).name.lower().startswith("powershell"):
        base += ["-ExecutionPolicy", "Bypass"]
    return base + [
        "-File", str(host_script),
        "-ScriptPath", str(script),
        "-ParametersPath", str(params_path),
        "-ResultPath", str(result_path),
    ]


def terminate_process(proc: subprocess.Popen, grace: float = 3.0) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(["taskkill.exe", "/PID", str(proc.pid), "/T"], capture_output=True, timeout=4, **windows_hidden_kwargs())
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception as exc:
            print(f"[GIDEON][WARN] terminate() fallback falló PID {proc.pid}: {exc}", file=sys.stderr, flush=True)
    deadline = time.monotonic() + grace
    while proc.poll() is None and time.monotonic() < deadline:
        time.sleep(.1)
    if proc.poll() is None:
        try:
            if os.name == "nt":
                subprocess.run(["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, timeout=4, **windows_hidden_kwargs())
            else:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception as exc:
                print(f"[GIDEON][WARN] kill() fallback falló PID {proc.pid}: {exc}", file=sys.stderr, flush=True)


def safe_result_name(item: dict[str, Any], index: int, script: Path) -> str:
    raw = str(item.get("ResultName") or f"{index:02d}_{script.stem}.json").strip()
    name = Path(raw).name
    if not name.lower().endswith(".json"):
        name += ".json"
    return name


def normalize_stdout_data(text: str) -> list[dict[str, Any]]:
    value = text.strip()
    if not value:
        return []
    try:
        parsed = json.loads(value)
        if isinstance(parsed, list):
            return [x if isinstance(x, dict) else {"Value": x} for x in parsed]
        if isinstance(parsed, dict):
            # If a non-PowerShell script already emits the GIDEON result envelope,
            # preserve its Data instead of nesting the envelope in one row.
            if "Data" in parsed:
                data = parsed.get("Data")
                if data is None:
                    return []
                if not isinstance(data, list):
                    data = [data]
                return [x if isinstance(x, dict) else {"Value": x} for x in data]
            return [parsed]
        return [{"Value": parsed}]
    except Exception:
        # Text-producing scripts still deserve visible output in the final
        # Excel. Each non-empty line becomes a row instead of being discarded.
        return [{"Value": line} for line in value.splitlines() if line.strip()]


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def run_job(job_root: Path) -> int:
    job_root = job_root.resolve()
    raw_job = json.loads((job_root / "agent_job.json").read_text(encoding="utf-8-sig"))
    if not isinstance(raw_job, dict):
        raise RuntimeError("JOB_ENVELOPE_INVALID")
    job = validate_job_envelope(
        raw_job,
        expected_job_id=str(raw_job.get("JobId") or ""),
        expected_agent_id=str(raw_job.get("AgentId") or ""),
        expected_site_code=str(raw_job.get("SiteCode") or ""),
        expected_host_profile=str(((raw_job.get("HostProfile") or {}) if isinstance(raw_job.get("HostProfile"), dict) else {}).get("id") or ""),
        freshness_required=True,
    )
    profile = job.get("HostProfile") or {}
    allowed = {str(x).lower() for x in profile.get("allowed_extensions", [])}
    scripts = job.get("Scripts") or []

    expected_platform = normalize_platform_name(str(profile.get("platform") or ""))
    current_platform = normalize_platform_name(platform.system())
    if expected_platform and expected_platform != current_platform:
        raise RuntimeError(f"HOST_PROFILE_PLATFORM_MISMATCH: profile={expected_platform} host={current_platform}")

    # Verify every script descriptor before executing the first payload. Script
    # jobs bind SHA-256 per asset; FILE_TRANSFER binds its payload through the
    # Artifact descriptor and validates it again inside transfer_payload.py.
    if str(job.get("JobType") or "").upper() == "SCRIPT_EXECUTION":
        for index, item in enumerate(scripts, 1):
            rel = str(item.get("Path") or "")
            script = (job_root / rel).resolve()
            if job_root not in script.parents or not script.is_file():
                raise RuntimeError(f"JOB_SCRIPT_MISSING: index={index} path={rel}")
            expected_sha = str(item.get("Sha256") or "").lower()
            actual_sha = sha256_file(script).lower()
            if expected_sha != actual_sha:
                raise RuntimeError(f"JOB_SCRIPT_SHA256_MISMATCH: index={index}")

    cancel_path = job_root / "cancel.request"
    status_path = job_root / "status.json"
    progress_path = job_root / "progress.json"
    collection = job_root / "collection"
    result_scripts_dir = collection / "scripts"
    params_dir = job_root / "script_parameters"
    collection.mkdir(parents=True, exist_ok=True)
    result_scripts_dir.mkdir(parents=True, exist_ok=True)
    params_dir.mkdir(parents=True, exist_ok=True)

    atomic_json(progress_path, {
        "Type": "JOB_PRECHECK",
        "CurrentScriptIndex": 0,
        "CurrentScriptName": "",
        "ScriptCount": len(scripts),
        "Phase": "PRECHECK_OK",
        "UpdatedAt": now_iso(),
    })

    status = {
        "State": "RUNNING",
        "JobId": job.get("JobId"),
        "AgentId": job.get("AgentId"),
        "SiteCode": job.get("SiteCode"),
        "HostProfile": profile.get("id"),
        "AgentWorkerVersion": VERSION,
        "Platform": platform.system(),
        "Architecture": platform.machine(),
        "StartedAt": now_iso(),
        "UpdatedAt": now_iso(),
    }
    atomic_json(status_path, status)

    results: list[dict[str, Any]] = []
    failed = 0
    skipped = 0
    for index, item in enumerate(scripts, 1):
        if cancel_path.exists():
            status.update({"State": "CANCELLED", "UpdatedAt": now_iso()})
            atomic_json(status_path, status)
            break

        rel = str(item.get("Path") or item.get("FileName") or "")
        script = (job_root / rel).resolve()
        if job_root not in script.parents:
            raise RuntimeError("Unsafe script path")
        ext = script.suffix.lower()
        result_name = safe_result_name(item, index, script)
        result_path = result_scripts_dir / result_name
        stdout_path = collection / f"{index:02d}_{script.stem}.stdout.log"
        stderr_path = collection / f"{index:02d}_{script.stem}.stderr.log"
        started_at = now_iso()

        if allowed and ext not in allowed:
            failed += 1
            payload = {
                "Success": False,
                "Error": f"Extension {ext} no permitida por host profile",
                "StartedAt": started_at,
                "FinishedAt": now_iso(),
                "ElapsedSec": 0,
                "Data": [],
            }
            atomic_json(result_path, payload)
            results.append({
                "Index": index, "Name": script.name, "ResultName": result_name,
                "ResultFile": f"scripts/{result_name}", "Success": False,
                "DataCount": 0, "Error": payload["Error"],
            })
            if not bool(job.get("ContinueOnError", True)):
                break
            continue

        timeout = int(item.get("TimeoutSeconds") or job.get("DefaultTimeoutSeconds") or 1800)
        atomic_json(progress_path, {
            "Type": "SCRIPT_RUNNING",
            "CurrentScriptIndex": index,
            "CurrentScriptName": script.name,
            "ScriptCount": len(scripts),
            "Phase": "SCRIPT_RUNNING",
            "StartedAt": started_at,
            "UpdatedAt": now_iso(),
        })

        try:
            parameters = item.get("Parameters") if isinstance(item.get("Parameters"), dict) else {}
            params_path = params_dir / f"{index:02d}.json"
            atomic_json(params_path, parameters)

            if ext == ".ps1":
                host_script = job_root / "gideon_script_host.ps1"
                if not host_script.exists():
                    raise RuntimeError("SCRIPT_HOST_MISSING: gideon_script_host.ps1 no fue incluido en el package")
                cmd = powershell_host_command(script, profile, host_script, params_path, result_path)
                # Positional Arguments remain supported after the host parameters,
                # but structured Parameters are the preferred contract.
                cmd += [str(x) for x in item.get("Arguments", [])]
            else:
                cmd = command_for(script, profile) + [str(x) for x in item.get("Arguments", [])]

            env = os.environ.copy()
            env.update({str(k): str(v) for k, v in (item.get("Environment") or {}).items()})
            env["GIDEON_JOB_ID"] = str(job.get("JobId") or "")
            env["GIDEON_AGENT_ID"] = str(job.get("AgentId") or "")
            env["GIDEON_SITE_CODE"] = str(job.get("SiteCode") or "")
            env["GIDEON_HOST_PROFILE"] = str(profile.get("id") or "")
            kwargs: dict[str, Any] = {"cwd": str(job_root), "stdin": subprocess.DEVNULL, "env": env}
            if os.name == "nt":
                kwargs.update(windows_hidden_kwargs())
                kwargs["creationflags"] = int(kwargs.get("creationflags", 0)) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            else:
                kwargs["start_new_session"] = True

            start = time.monotonic()
            with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
                proc = subprocess.Popen(cmd, stdout=out, stderr=err, **kwargs)
                cancelled = False
                timed_out = False
                while proc.poll() is None:
                    if cancel_path.exists():
                        cancelled = True
                        terminate_process(proc)
                        break
                    if timeout > 0 and time.monotonic() - start >= timeout:
                        timed_out = True
                        terminate_process(proc)
                        break
                    time.sleep(.25)
                exit_code = proc.poll()
            elapsed = round(time.monotonic() - start, 3)
            stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else ""
            stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""

            if ext == ".ps1":
                payload = load_json_object(result_path)
                if not payload:
                    payload = {
                        "Success": False,
                        "Error": stderr_text.strip() or stdout_text.strip() or "SCRIPT_RESULT_NOT_CREATED",
                        "StartedAt": started_at,
                        "FinishedAt": now_iso(),
                        "ElapsedSec": elapsed,
                        "Data": [],
                    }
                    atomic_json(result_path, payload)
                data = payload.get("Data")
                if data is None:
                    data = []
                if not isinstance(data, list):
                    data = [data]
                payload_success = bool(payload.get("Success"))
                success = bool(exit_code == 0 and payload_success and not cancelled and not timed_out)
                error = payload.get("Error")
            else:
                data = normalize_stdout_data(stdout_text)
                success = bool(exit_code == 0 and not cancelled and not timed_out)
                error = None if success else (stderr_text.strip() or ("SCRIPT_TIMEOUT" if timed_out else "SCRIPT_CANCELLED" if cancelled else f"ExitCode={exit_code}"))
                payload = {
                    "Success": success,
                    "ExitCode": exit_code,
                    "Error": error,
                    "StartedAt": started_at,
                    "FinishedAt": now_iso(),
                    "ElapsedSec": elapsed,
                    "Data": data,
                    "StdoutLog": stdout_path.name,
                    "StderrLog": stderr_path.name,
                }
                atomic_json(result_path, payload)

            if not success:
                failed += 1
            results.append({
                "Index": index,
                "Name": script.name,
                "ResultName": result_name,
                "ResultFile": f"scripts/{result_name}",
                "Success": success,
                "ExitCode": exit_code,
                "Cancelled": cancelled,
                "TimedOut": timed_out,
                "Executor": cmd[0],
                "Command": cmd,
                "StdoutLog": stdout_path.name,
                "StderrLog": stderr_path.name,
                "DataCount": len(data),
                "Error": error,
                "CompletedAt": now_iso(),
            })
            if cancelled:
                status["State"] = "CANCELLED"
                break
            if not success and not bool(job.get("ContinueOnError", True)):
                break
        except Exception as exc:
            failed += 1
            error = f"{type(exc).__name__}: {exc}"
            if not result_path.exists():
                atomic_json(result_path, {
                    "Success": False,
                    "Error": error,
                    "StartedAt": started_at,
                    "FinishedAt": now_iso(),
                    "ElapsedSec": 0,
                    "Data": [],
                })
            results.append({
                "Index": index,
                "Name": script.name,
                "ResultName": result_name,
                "ResultFile": f"scripts/{result_name}",
                "Success": False,
                "DataCount": 0,
                "Error": error,
            })
            if not bool(job.get("ContinueOnError", True)):
                break

    attempted = len(results)
    if attempted < len(scripts) and status.get("State") != "CANCELLED":
        skipped = len(scripts) - attempted
    success_all = failed == 0 and status.get("State") != "CANCELLED"
    if status.get("State") != "CANCELLED":
        status["State"] = "RESULT_READY" if success_all else "RESULT_READY_WITH_ERRORS"
    status.update({
        "UpdatedAt": now_iso(),
        "CompletedAt": now_iso(),
        "ScriptsFailed": failed,
        "ScriptsSkipped": skipped,
    })
    atomic_json(status_path, status)
    atomic_json(progress_path, {
        "Type": "JOB_COMPLETE",
        "CurrentScriptIndex": attempted,
        "CurrentScriptName": results[-1]["Name"] if results else "",
        "ScriptCount": len(scripts),
        "Phase": status["State"],
        "UpdatedAt": now_iso(),
    })
    atomic_json(collection / "job_result.json", {
        "JobId": job.get("JobId"),
        "AgentId": job.get("AgentId"),
        "AgentName": job.get("AgentName"),
        "Hostname": job.get("Hostname"),
        "SiteCode": job.get("SiteCode"),
        "SiteName": job.get("SiteName"),
        "HostProfile": profile,
        "Success": success_all,
        "Cancelled": status.get("State") == "CANCELLED",
        "ScriptsTotal": len(scripts),
        "ScriptsFailed": failed,
        "ScriptsSkipped": skipped,
        "Results": results,
        "Platform": platform.system(),
        "Architecture": platform.machine(),
        "AgentWorkerVersion": VERSION,
        "CompletedAt": now_iso(),
    })
    atomic_json(collection / "status.final.json", status)
    return 0 if success_all else (40 if status.get("State") == "CANCELLED" else 20)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--job-root", type=Path, required=True)
    a = p.parse_args()
    try:
        return run_job(a.job_root)
    except Exception as exc:
        try:
            atomic_json(a.job_root / "status.json", {
                "State": "FAILED",
                "Error": f"{type(exc).__name__}: {exc}",
                "UpdatedAt": now_iso(),
            })
        except Exception as persist_exc:
            print(f"[GIDEON][ERROR] No se pudo persistir status FAILED: {persist_exc}", file=sys.stderr, flush=True)
        return 30


if __name__ == "__main__":
    raise SystemExit(main())
