"""AgentKernel Canonical JSON profile AK-CJ-1 and SHA-256 content identity."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping, Sequence, Set
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from agentkernel.errors import AgentKernelError, ErrorCode


def _normalized_string(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _normalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="python"))
    if isinstance(value, Enum):
        return _normalize(value.value)
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, str):
        return _normalized_string(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Canonical JSON rejects non-finite floating-point values",
            )
        return 0.0 if value == 0.0 else value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Canonical JSON rejects non-finite decimal values",
            )
        sign, raw_digits, exponent_value = value.as_tuple()
        if not isinstance(exponent_value, int):
            raise AgentKernelError(ErrorCode.VALIDATION_ERROR, "Decimal exponent is not finite")
        exponent = exponent_value
        digits = list(raw_digits)
        while digits and digits[-1] == 0:
            digits.pop()
            exponent += 1
        if not digits:
            return "0"
        coefficient = "".join(str(digit) for digit in digits)
        if exponent >= 0:
            rendered = coefficient + ("0" * exponent)
        else:
            point = len(coefficient) + exponent
            rendered = (
                f"0.{('0' * -point)}{coefficient}"
                if point <= 0
                else f"{coefficient[:point]}.{coefficient[point:]}"
            )
        return f"-{rendered}" if sign else rendered
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Canonical timestamps must be timezone-aware",
            )
        utc_value = value.astimezone(UTC)
        rendered = utc_value.isoformat(timespec="microseconds")
        return rendered.replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, bytes):
        encoded = base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
        return {"$bytes_base64url": encoded}
    if isinstance(value, Path):
        raise AgentKernelError(
            ErrorCode.VALIDATION_ERROR,
            "Raw platform paths are not canonical resources; normalize them before hashing",
        )
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            if not isinstance(raw_key, str):
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Canonical JSON object keys must be strings",
                )
            key = _normalized_string(raw_key)
            if key in normalized:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Unicode normalization produced a duplicate object key",
                    details={"key": key},
                )
            normalized[key] = _normalize(raw_value)
        return normalized
    if isinstance(value, Set):
        items = [_normalize(item) for item in value]
        return sorted(items, key=lambda item: canonical_json_text(item))
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_normalize(item) for item in value]
    raise AgentKernelError(
        ErrorCode.VALIDATION_ERROR,
        "Value is not supported by the canonical JSON profile",
        details={"type": type(value).__qualname__},
    )


def canonical_json_text(value: Any) -> str:
    """Serialize a value using the documented deterministic AK-CJ-1 profile."""

    return json.dumps(
        _normalize(value),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return UTF-8 bytes for the AK-CJ-1 representation."""

    return canonical_json_text(value).encode("utf-8")


def sha256_digest(value: bytes) -> str:
    """Return the repository's prefixed SHA-256 identifier."""

    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def canonical_digest(value: Any) -> str:
    """Hash the AK-CJ-1 serialization of a value."""

    return sha256_digest(canonical_json_bytes(value))
