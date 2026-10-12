from __future__ import annotations

"""Small, deterministic safeguards for generated Agent ZIP archives.

The Agent payload is source-controlled and signed after it is built.  This
module keeps the archive writer deliberately narrow: it uses maximum Deflate
compression without changing the bytes extracted by an installer, rejects
development caches, and verifies the resulting ZIP CRCs before it can be
hashed or signed.
"""

from pathlib import Path
import zipfile


ARCHIVE_COMPRESSION_LEVEL = 9
_NON_RUNTIME_NAMES = frozenset({".DS_Store", "Thumbs.db"})
_NON_RUNTIME_SUFFIXES = frozenset({".pyc", ".pyo"})


class AgentArchiveError(RuntimeError):
    """Raised when a generated Agent archive would contain unsafe junk."""


def _is_nonruntime_member(relative: Path, candidate: Path) -> bool:
    return (
        "__pycache__" in relative.parts
        or candidate.name in _NON_RUNTIME_NAMES
        or candidate.suffix.lower() in _NON_RUNTIME_SUFFIXES
    )


def prune_generated_nonruntime_files(source_root: Path) -> tuple[str, ...]:
    """Remove only generated cache/desktop metadata from a temporary stage.

    Callers use this before a manifest is hashed and signed.  It never follows
    or removes symlinks, and it is deliberately limited to files that cannot
    be runtime dependencies.  Symlinks still fail closed in the archive writer.
    """

    root = Path(source_root).resolve()
    if not root.is_dir():
        raise AgentArchiveError(f"AGENT_ARCHIVE_SOURCE_MISSING: {root}")
    removed: list[str] = []
    candidates = sorted(root.rglob("*"), key=lambda value: len(value.parts), reverse=True)
    for candidate in candidates:
        if candidate.is_symlink() or not candidate.is_file():
            continue
        relative = candidate.relative_to(root)
        if _is_nonruntime_member(relative, candidate):
            candidate.unlink()
            removed.append(relative.as_posix())
    for directory in sorted(root.rglob("__pycache__"), key=lambda value: len(value.parts), reverse=True):
        if not directory.is_symlink() and directory.is_dir():
            try:
                directory.rmdir()
            except OSError:
                # If an unexpected file remains, the archive writer reports it
                # rather than silently changing a possible runtime asset.
                pass
    return tuple(sorted(removed))


def _member_name(source_root: Path, candidate: Path) -> str:
    relative = candidate.relative_to(source_root)
    if candidate.is_symlink():
        raise AgentArchiveError(
            f"AGENT_ARCHIVE_SYMLINK_MEMBER: {relative.as_posix()}"
        )
    if _is_nonruntime_member(relative, candidate):
        raise AgentArchiveError(
            f"AGENT_ARCHIVE_NONRUNTIME_MEMBER: {relative.as_posix()}"
        )
    return relative.as_posix()


def write_verified_deflated_zip(source_root: Path, output: Path) -> tuple[str, ...]:
    """Archive regular runtime files with maximum compatible Deflate.

    The function intentionally does not strip or transform payload bytes: the
    installer contract, SHA-256 manifest and Ed25519 signature continue to
    describe exactly what will be extracted.  Rejecting caches and symlinks
    prevents accidental debug payloads and path-indirection from entering a
    signed installer.
    """

    root = Path(source_root).resolve()
    target = Path(output).resolve()
    if not root.is_dir():
        raise AgentArchiveError(f"AGENT_ARCHIVE_SOURCE_MISSING: {root}")
    try:
        target.relative_to(root)
    except ValueError:
        pass
    else:
        raise AgentArchiveError("AGENT_ARCHIVE_OUTPUT_INSIDE_SOURCE")

    members: list[tuple[Path, str]] = []
    names_casefolded: set[str] = set()
    for candidate in sorted(root.rglob("*")):
        if candidate.is_symlink():
            # A symlinked directory is not traversed by pathlib, so reject it
            # before the directory fast-path as well.
            _member_name(root, candidate)
        if candidate.is_dir():
            continue
        name = _member_name(root, candidate)
        if not candidate.is_file():
            raise AgentArchiveError(f"AGENT_ARCHIVE_NONREGULAR_MEMBER: {name}")
        normalized = name.casefold()
        if normalized in names_casefolded:
            raise AgentArchiveError(f"AGENT_ARCHIVE_CASE_COLLISION: {name}")
        names_casefolded.add(normalized)
        members.append((candidate, name))

    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        target,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=ARCHIVE_COMPRESSION_LEVEL,
        strict_timestamps=False,
    ) as archive:
        for candidate, name in members:
            archive.write(candidate, name)

    with zipfile.ZipFile(target, "r") as archive:
        corrupt = archive.testzip()
        if corrupt:
            raise AgentArchiveError(f"AGENT_ARCHIVE_CRC_INVALID: {corrupt}")
        if tuple(archive.namelist()) != tuple(name for _, name in members):
            raise AgentArchiveError("AGENT_ARCHIVE_MEMBER_LIST_MISMATCH")
    return tuple(name for _, name in members)
