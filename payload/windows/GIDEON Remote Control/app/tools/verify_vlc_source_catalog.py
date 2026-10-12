from __future__ import annotations

"""Verify the separately retained VLC source closure before component builds."""

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gideon_agent_vlc_offline import (  # noqa: E402
    OfflineVlcCatalogError,
    validate_offline_vlc_source_baseline,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--full", action="store_true", help="hash every reviewed source byte once")
    parser.add_argument("--required", action="store_true", help="fail when the source closure is not provisioned")
    args = parser.parse_args()
    try:
        report = validate_offline_vlc_source_baseline(
            args.root.resolve(), verify_payload=bool(args.full),
        )
        if args.required and report.get("State") != "VERIFIED":
            raise OfflineVlcCatalogError("VLC_OFFLINE_SOURCE_REQUIRED_BUT_NOT_PROVISIONED")
    except OfflineVlcCatalogError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
