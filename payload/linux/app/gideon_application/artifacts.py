from __future__ import annotations

from pathlib import Path

from gideon_application.ports import HashPort
from gideon_domain import ArtifactDescriptor, ArtifactKind, ValidationError


VIDEO_EXTENSIONS: frozenset[str] = frozenset({
    ".mp4", ".mkv", ".mov", ".avi", ".webm", ".m4v", ".mpeg", ".mpg"
})


class ArtifactService:
    def __init__(self, hash_provider: HashPort) -> None:
        self._hash_provider: HashPort = hash_provider

    def build(self, path: Path, remote_path: str) -> ArtifactDescriptor:
        source: Path = Path(path).resolve()
        if not source.is_file():
            raise ValidationError(f"Archivo inexistente: {source}")
        destination: str = str(remote_path).strip()
        if not destination:
            raise ValidationError("La ruta remota de destino es obligatoria.")

        kind: ArtifactKind = (
            ArtifactKind.VIDEO
            if source.suffix.lower() in VIDEO_EXTENSIONS
            else ArtifactKind.FILE
        )
        return ArtifactDescriptor(
            local_path=source,
            remote_path=destination,
            kind=kind,
            size_bytes=source.stat().st_size,
            sha256=self._hash_provider.sha256_file(source),
        )
