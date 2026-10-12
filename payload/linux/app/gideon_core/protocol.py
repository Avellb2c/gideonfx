from __future__ import annotations

from gideon_version import (
    EVENT_SCHEMA_VERSION,
    FANOUT_PROTOCOL_VERSION,
    MANIFEST_SCHEMA_VERSION,
    PRODUCT_VERSION,
    REMOTE_PACKAGE_SCHEMA_VERSION,
)

APP_VERSION = PRODUCT_VERSION
PROTOCOL_VERSION = FANOUT_PROTOCOL_VERSION
ARCHITECTURE_ID = "MULTI_TRANSPORT_AGENTLESS_PLUS_AGENT_V2"

CONTROL_ARTIFACTS = (
    "job.definition.json",
    "job_result.json",
    "status.final.json",
    "progress.final.json",
    "worker.log",
)


def protocol_metadata() -> dict[str, object]:
    return {
        "ApplicationVersion": APP_VERSION,
        "ProtocolVersion": PROTOCOL_VERSION,
        "ManifestSchemaVersion": MANIFEST_SCHEMA_VERSION,
        "RemotePackageSchemaVersion": REMOTE_PACKAGE_SCHEMA_VERSION,
        "Architecture": ARCHITECTURE_ID,
    }
