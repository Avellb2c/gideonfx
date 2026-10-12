from __future__ import annotations

"""Write-ahead transaction journal for in-place GIDEON code updates.

Every destination is backed up and journaled *before* replacement.  If the host
is interrupted between files, the next updater invocation can deterministically
restore the previous release before accepting another package.
"""

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


class TransactionError(RuntimeError):
    pass


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def _copy_atomic(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.gideon-tx-", dir=str(destination.parent))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        shutil.copy2(source, tmp)
        os.replace(tmp, destination)
    finally:
        tmp.unlink(missing_ok=True)


@dataclass(slots=True)
class PlannedFile:
    source: Path
    destination: Path
    backup_key: str


class UpdateTransaction:
    def __init__(self, tx_root: Path, *, tx_id: str, from_version: str, to_version: str, package_id: str) -> None:
        self.root = Path(tx_root) / tx_id
        self.root.mkdir(parents=True, exist_ok=False)
        self.staging = self.root / "staging"
        self.backups = self.root / "backups"
        self.staging.mkdir()
        self.backups.mkdir()
        self.journal_path = self.root / "journal.json"
        self.journal = {
            "schema": "gideon-update-transaction/v1",
            "tx_id": tx_id,
            "package_id": package_id,
            "from_version": from_version,
            "to_version": to_version,
            "status": "PREPARING",
            "operations": [],
        }
        self._persist()

    def _persist(self) -> None:
        _atomic_json(self.journal_path, self.journal)

    def prepare(self, plan: Iterable[PlannedFile]) -> list[PlannedFile]:
        prepared: list[PlannedFile] = []
        operations = []
        for index, item in enumerate(plan):
            staged = self.staging / f"{index:04d}-{item.source.name}"
            shutil.copy2(item.source, staged)
            destination = Path(item.destination).resolve()
            backup = self.backups / item.backup_key
            existed = destination.exists()
            operations.append({
                "index": index,
                "destination": str(destination),
                "staged": str(staged),
                "backup": str(backup),
                "existed": bool(existed),
                "backup_ready": False,
                "replacement_started": False,
                "replacement_done": False,
            })
            prepared.append(PlannedFile(staged, destination, item.backup_key))
        self.journal["operations"] = operations
        self.journal["status"] = "PREPARED"
        self._persist()
        return prepared

    def commit(self, *, mode_hook: Callable[[Path], None] | None = None) -> int:
        self.journal["status"] = "COMMITTING"
        self._persist()
        for op in self.journal["operations"]:
            destination = Path(op["destination"])
            staged = Path(op["staged"])
            backup = Path(op["backup"])
            if op["existed"]:
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(destination, backup)
            op["backup_ready"] = True
            self._persist()  # WAL boundary: recovery is safe after this point.
            op["replacement_started"] = True
            self._persist()
            _copy_atomic(staged, destination)
            if mode_hook is not None:
                mode_hook(destination)
            op["replacement_done"] = True
            self._persist()
        self.journal["status"] = "FILES_COMMITTED"
        self._persist()
        return len(self.journal["operations"])

    def mark_applied(self, result: dict) -> None:
        self.journal["status"] = "APPLIED"
        self.journal["result"] = result
        self._persist()

    def rollback(self, *, reason: str = "") -> list[str]:
        errors = _rollback_journal(self.journal)
        self.journal["status"] = "ROLLED_BACK" if not errors else "ROLLBACK_PARTIAL"
        self.journal["rollback_reason"] = reason
        self.journal["rollback_errors"] = errors
        self._persist()
        return errors


def _rollback_journal(journal: dict) -> list[str]:
    errors: list[str] = []
    for op in reversed(list(journal.get("operations") or [])):
        if not op.get("backup_ready"):
            continue
        destination = Path(str(op.get("destination") or ""))
        backup = Path(str(op.get("backup") or ""))
        try:
            if bool(op.get("existed")):
                if not backup.is_file():
                    raise TransactionError(f"Falta backup requerido: {backup}")
                _copy_atomic(backup, destination)
            else:
                destination.unlink(missing_ok=True)
        except Exception as exc:
            errors.append(f"{destination}: {exc}")
    return errors


def recover_incomplete_transactions(tx_root: Path) -> list[dict]:
    root = Path(tx_root)
    if not root.exists():
        return []
    recovered: list[dict] = []
    terminal = {"APPLIED", "ROLLED_BACK", "ROLLBACK_PARTIAL"}
    for journal_path in sorted(root.glob("*/journal.json")):
        try:
            journal = json.loads(journal_path.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            raise TransactionError(f"Journal de update ilegible: {journal_path}: {exc}") from exc
        if str(journal.get("status") or "") in terminal:
            continue
        errors = _rollback_journal(journal)
        journal["status"] = "RECOVERED_ROLLBACK" if not errors else "RECOVERY_PARTIAL"
        journal["rollback_errors"] = errors
        _atomic_json(journal_path, journal)
        recovered.append({"tx_id": journal.get("tx_id"), "status": journal["status"], "errors": errors})
        if errors:
            raise TransactionError(
                f"RECOVERY_PARTIAL: no se pudo recuperar completamente la transacción {journal.get('tx_id')}: {errors}"
            )
    return recovered
