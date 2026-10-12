from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BandwidthPolicy:
    normal_workers: int = 4
    large_file_workers: int = 2
    critical_workers: int = 1
    large_file_threshold_bytes: int = 500 * 1024 * 1024
    critical_file_threshold_bytes: int = 2 * 1024 * 1024 * 1024

    def workers_for(self, file_size_bytes: int, vpn_workers: int | None = None) -> int:
        if file_size_bytes >= self.critical_file_threshold_bytes:
            base: int = self.critical_workers
        elif file_size_bytes >= self.large_file_threshold_bytes:
            base = self.large_file_workers
        else:
            base = self.normal_workers

        if vpn_workers is None:
            return max(1, base)
        return max(1, min(base, int(vpn_workers)))


@dataclass(frozen=True, slots=True)
class ConnectivityRecoveryPolicy:
    retry_seconds: int = 15
    max_wait_seconds: int = 3600
