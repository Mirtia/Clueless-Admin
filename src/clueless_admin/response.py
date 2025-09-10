import time
from datetime import datetime, timezone
from enum import Enum, IntEnum
from typing import Any, Dict, Optional


class TaskType(str, Enum):
    """Task type enum mirroring the C enum task_type (STATE=0, EVENT=1, INTERRUPT=2)."""

    # The only available task type currently is STATE, since the tool only does periodic sampling.
    STATE = "STATE"


class ErrorCode(IntEnum):
    """Error codes aligned to the C enum error_code."""

    MEMORY_ALLOCATION_FAILURE = 0
    INVALID_ARGUMENTS = 1
    VMI_OP_FAILURE = 2
    ERROR_CODE_MAX = 3
    # Extended / Python-side specific mappings
    TOOL_NOT_AVAILABLE = 1000  # bpftool/BCC missing
    EXECUTION_FAILURE = 1001  # bpftool exec error
    IO_FAILURE = 1002  # file I/O error


def iso_utc_timestamp() -> str:
    """
    Generate an ISO 8601 UTC timestamp with microsecond precision, matching
    the C function's intended format, suffixed with 'Z'.
    Example: '2025-09-10T09:42:13.123456Z'
    """
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def make_success_response(
    task_type: TaskType, subtype: Optional[str], data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Create a schema-compliant SUCCESS response.

    {
      "timestamp": "...",
      "status": "SUCCESS",
      "metadata": { "task_type": "...", "subtype": "..." },
      "data": { ... }
    }
    """
    return {
        "timestamp": iso_utc_timestamp(),
        "status": "SUCCESS",
        "metadata": {
            "task_type": task_type,
            "subtype": subtype or "",
        },
        "data": data,
    }


def make_error_response(
    task_type: TaskType, subtype: Optional[str], code: int, message: str
) -> Dict[str, Any]:
    """
    Create a schema-compliant FAILURE response.

    {
      "timestamp": "...",
      "status": "FAILURE",
      "metadata": { "task_type": "...", "subtype": "..." },
      "error": { "code": <int>, "message": "<string>" }
    }
    """
    return {
        "timestamp": iso_utc_timestamp(),
        "status": "FAILURE",
        "metadata": {
            "task_type": task_type,
            "subtype": subtype or "",
        },
        "error": {
            "code": int(code),
            "message": str(message),
        },
    }
