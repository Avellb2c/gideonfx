from __future__ import annotations

from enum import Enum

from gideon_domain.enums import JobState


class SiteState(str, Enum):
    PENDING = "PENDING"
    DISPATCHED = "DISPATCHED"
    WAITING_CONNECTION = "WAITING_CONNECTION"
    RUNNING = "RUNNING"
    RESULT_READY = "RESULT_READY"
    RESULT_READY_WITH_ERRORS = "RESULT_READY_WITH_ERRORS"
    COLLECTED = "COLLECTED"
    COLLECTED_WITH_ERRORS = "COLLECTED_WITH_ERRORS"
    FAILED = "FAILED"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    CANCELLING = "CANCELLING"
    CANCELLED = "CANCELLED"
    CANCELLED_NOT_STARTED = "CANCELLED_NOT_STARTED"
    CANCEL_FAILED = "CANCEL_FAILED"
    INTERRUPTED = "INTERRUPTED"
    DISPATCH_FAILED = "DISPATCH_FAILED"
    PENDING_RETRY = "PENDING_RETRY"
    IGNORED = "IGNORED"


JOB_TERMINAL_STATES = frozenset({
    JobState.COMPLETED.value,
    JobState.COMPLETED_WITH_WARNINGS.value,
    JobState.COMPLETED_WITH_ERRORS.value,
    JobState.PARTIAL.value,
    JobState.CANCELLED.value,
    JobState.CANCELLED_WITH_ERRORS.value,
    JobState.FAILED.value,
    JobState.LAUNCH_FAILED.value,
    JobState.INTERRUPTED.value,
    JobState.COMPLETED_WITH_SKIPPED.value,
})

JOB_CANCEL_STATES = frozenset({
    JobState.CANCEL_REQUESTED.value,
    JobState.CANCELLING.value,
    JobState.CANCELLED.value,
    JobState.CANCELLED_WITH_ERRORS.value,
})

SITE_SUCCESS_STATES = frozenset({
    SiteState.COLLECTED.value,
    SiteState.CANCELLED.value,
    SiteState.CANCELLED_NOT_STARTED.value,
})

SITE_WARNING_STATES = frozenset({
    SiteState.COLLECTED_WITH_ERRORS.value,
    SiteState.IGNORED.value,
})

SITE_ERROR_STATES = frozenset({
    SiteState.FAILED.value,
    SiteState.CANCEL_FAILED.value,
    SiteState.INTERRUPTED.value,
    SiteState.DISPATCH_FAILED.value,
})

SITE_TERMINAL_STATES = frozenset(
    set(SITE_SUCCESS_STATES) | set(SITE_WARNING_STATES) | set(SITE_ERROR_STATES)
)

SITE_ACTIVE_STATES = frozenset({
    SiteState.DISPATCHED.value,
    SiteState.WAITING_CONNECTION.value,
    SiteState.RUNNING.value,
    SiteState.RESULT_READY.value,
    SiteState.RESULT_READY_WITH_ERRORS.value,
    SiteState.CANCEL_REQUESTED.value,
    SiteState.CANCELLING.value,
})


def norm(value: object) -> str:
    return str(value or "").strip().upper()


def is_job_terminal(value: object) -> bool:
    return norm(value) in JOB_TERMINAL_STATES


def is_site_terminal(value: object) -> bool:
    return norm(value) in SITE_TERMINAL_STATES


def preserve_terminal_job(old: object, new: object) -> str:
    old_s, new_s = norm(old), norm(new)
    if old_s in JOB_TERMINAL_STATES and new_s not in JOB_TERMINAL_STATES:
        return old_s
    return new_s


def preserve_terminal_site(old: object, new: object) -> str:
    old_s, new_s = norm(old), norm(new)
    if old_s in SITE_TERMINAL_STATES and new_s not in SITE_TERMINAL_STATES:
        return old_s
    return new_s
