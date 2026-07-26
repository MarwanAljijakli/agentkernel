"""AgentKernel Canonical JSON profile AK-CJ-1 and SHA-256 content identity."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import unicodedata
from collections.abc import Mapping, Sequence, Set
from datetime import UTC, date, datetime, timezone
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel
from pydantic_core import TzInfo

from agentkernel.errors import AgentKernelError, ErrorCode

_PYDANTIC_UTC = TzInfo(0)


def _is_trusted_utc_timezone(value: object) -> bool:
    """Recognize fixed UTC implementations without calling an untrusted tzinfo object."""

    return (type(value) is timezone and value == UTC) or (
        type(value) is TzInfo and value == _PYDANTIC_UTC
    )


def validate_canonical_input_bounds(
    value: Any,
    *,
    max_depth: int,
    max_container_items: int,
    max_nodes: int,
    max_string_characters: int,
    max_total_string_characters: int,
    max_integer_bits: int,
) -> None:
    """Bound unvalidated material before canonicalization can copy or normalize it.

    The traversal is iterative, counts repeated aliases each time they are serialized, and
    rejects cycles.  Callers still perform their normal schema validation afterwards.
    """

    stack: list[tuple[Any, int, bool]] = [(value, 0, False)]
    active_containers: set[int] = set()
    nodes = 0
    string_characters = 0
    while stack:
        current, depth, leaving = stack.pop()
        if leaving:
            active_containers.remove(id(current))
            continue
        nodes += 1
        if nodes > max_nodes:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Canonical input exceeds the node bound",
            )
        if depth > max_depth:
            raise AgentKernelError(
                ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                "Canonical input exceeds the nesting-depth bound",
            )
        if isinstance(current, Enum):
            children = (object.__getattribute__(current, "_value_"),)
        elif type(current) in {str, bytes, bytearray}:
            length = len(current)
            if length > max_string_characters:
                raise AgentKernelError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "Canonical input contains an oversized scalar",
                )
            string_characters += length
            if string_characters > max_total_string_characters:
                raise AgentKernelError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "Canonical input exceeds the aggregate text bound",
                )
            if type(current) is str:
                try:
                    current.encode("utf-8", errors="strict")
                except UnicodeEncodeError as error:
                    raise AgentKernelError(
                        ErrorCode.VALIDATION_ERROR,
                        "Pre-hash canonical input must contain valid UTF-8 text",
                    ) from error
            continue
        elif isinstance(current, str | bytes | bytearray):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Pre-hash canonical input requires a built-in scalar",
            )
        elif current is None or type(current) is bool:
            continue
        elif type(current) is int:
            if current.bit_length() > max_integer_bits:
                raise AgentKernelError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "Canonical input contains an oversized integer",
                )
            continue
        elif isinstance(current, int):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Pre-hash canonical input requires a built-in scalar",
            )
        elif type(current) is float:
            continue
        elif isinstance(current, float):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Pre-hash canonical input requires a built-in scalar",
            )
        elif type(current) is Decimal:
            decimal_tuple = current.as_tuple()
            exponent = decimal_tuple.exponent
            if not isinstance(exponent, int):
                continue
            digit_count = len(decimal_tuple.digits)
            if (
                digit_count > max_string_characters
                or abs(exponent) > max_string_characters
                or digit_count + abs(exponent) + 3 > max_string_characters
            ):
                raise AgentKernelError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "Canonical input contains an oversized decimal",
                )
            continue
        elif isinstance(current, Decimal):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Pre-hash canonical input requires a built-in scalar",
            )
        elif type(current) is datetime:
            if not _is_trusted_utc_timezone(current.tzinfo):
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Pre-hash timestamps require a built-in timezone",
                )
            continue
        elif type(current) in {date, UUID}:
            continue
        elif isinstance(current, datetime | date | UUID):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Pre-hash canonical input requires a built-in scalar",
            )
        else:
            children = None
        if isinstance(current, BaseModel):
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Pre-hash canonical input cannot contain an unvalidated model",
            )
        if isinstance(current, Mapping):
            if type(current) is not dict:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Pre-hash canonical input requires a built-in mapping",
                )
            if len(current) > max_container_items:
                raise AgentKernelError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "Canonical input mapping exceeds the item bound",
                )
            children = tuple(item for pair in current.items() for item in pair)
        elif isinstance(current, Set | Sequence) and not isinstance(
            current, str | bytes | bytearray
        ):
            if type(current) not in {list, tuple, set, frozenset}:
                raise AgentKernelError(
                    ErrorCode.VALIDATION_ERROR,
                    "Pre-hash canonical input requires a built-in sequence or set",
                )
            if len(current) > max_container_items:
                raise AgentKernelError(
                    ErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    "Canonical input sequence exceeds the item bound",
                )
            children = tuple(current)
        if children is None:
            continue
        identity = id(current)
        if identity in active_containers:
            raise AgentKernelError(
                ErrorCode.VALIDATION_ERROR,
                "Canonical input cannot contain a reference cycle",
            )
        active_containers.add(identity)
        stack.append((current, depth, True))
        stack.extend((child, depth + 1, False) for child in reversed(children))


def _normalized_string(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _normalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="python"))
    if isinstance(value, Enum):
        return _normalize(object.__getattribute__(value, "_value_"))
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
