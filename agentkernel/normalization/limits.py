"""Bounded, allocation-safe sizing for admitted JSON action arguments."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import cast

from agentkernel.errors import AgentKernelError, ErrorCode

MAX_ARGUMENT_DEPTH = 32
MAX_ARGUMENT_NODES = 10_000
MAX_COLLECTION_ITEMS = 4_096


@dataclass(frozen=True, slots=True)
class _ValueFrame:
    value: object
    depth: int


@dataclass(frozen=True, slots=True)
class _ExitContainerFrame:
    identity: int


type _Frame = _ValueFrame | _ExitContainerFrame


def _resource_limit(subject: str, limit: str, maximum: int) -> AgentKernelError:
    return AgentKernelError(
        ErrorCode.RESOURCE_LIMIT_EXCEEDED,
        f"{subject} exceed the admitted {limit} limit",
        details={"limit": limit, "maximum": maximum},
    )


def _invalid_json(subject: str) -> AgentKernelError:
    return AgentKernelError(
        ErrorCode.VALIDATION_ERROR,
        f"{subject} cannot be represented as bounded UTF-8 JSON",
    )


def _bounded_string_size(value: str, *, remaining: int, subject: str) -> int:
    """Return exact ``json.dumps(..., ensure_ascii=False)`` bytes for one string.

    The cheap one-byte-per-code-point lower bound rejects large strings before scanning
    or allocating an encoded copy. Accepted strings are then counted one code point at a
    time, so a multimegabyte UTF-8 buffer is never materialized merely to measure it.
    """

    if len(value) + 2 > remaining:
        raise _resource_limit(subject, "encoded bytes", remaining)
    size = 2  # surrounding JSON quotes
    for character in value:
        codepoint = ord(character)
        if character in {'"', "\\"} or character in {"\b", "\t", "\n", "\f", "\r"}:
            increment = 2
        elif codepoint < 0x20:
            increment = 6
        elif 0xD800 <= codepoint <= 0xDFFF:
            raise _invalid_json(subject)
        elif codepoint <= 0x7F:
            increment = 1
        elif codepoint <= 0x7FF:
            increment = 2
        elif codepoint <= 0xFFFF:
            increment = 3
        else:
            increment = 4
        if size > remaining - increment:
            raise _resource_limit(subject, "encoded bytes", remaining)
        size += increment
    return size


def bounded_json_size(
    value: object,
    *,
    max_bytes: int,
    subject: str = "Action arguments",
    max_depth: int = MAX_ARGUMENT_DEPTH,
    max_nodes: int = MAX_ARGUMENT_NODES,
    max_collection_items: int = MAX_COLLECTION_ITEMS,
) -> int:
    """Measure strict JSON input exactly while enforcing structural limits early.

    For accepted JSON values, the result matches the UTF-8 length of ``json.dumps`` with
    ``ensure_ascii=False``, ``allow_nan=False``, compact separators, and sorted keys.
    Object ordering does not affect byte length, so this walker never sorts or renders the
    complete payload. Direct model construction that bypasses Pydantic is still contained.
    """

    if min(max_bytes, max_depth, max_nodes, max_collection_items) < 1:
        raise ValueError("Bounded JSON limits must be positive")

    total = 0
    node_count = 1
    active_containers: set[int] = set()
    stack: list[_Frame] = [_ValueFrame(value=value, depth=0)]

    def add_size(increment: int) -> None:
        nonlocal total
        if increment < 0 or total > max_bytes - increment:
            raise _resource_limit(subject, "encoded bytes", max_bytes)
        total += increment

    def reserve_nodes(count: int) -> None:
        nonlocal node_count
        if node_count > max_nodes - count:
            raise _resource_limit(subject, "node count", max_nodes)
        node_count += count

    while stack:
        frame = stack.pop()
        if isinstance(frame, _ExitContainerFrame):
            active_containers.remove(frame.identity)
            continue

        item = frame.value
        depth = frame.depth
        if depth > max_depth:
            raise _resource_limit(subject, "nesting depth", max_depth)

        if item is None:
            add_size(4)
        elif type(item) is bool:
            add_size(4 if item else 5)
        elif type(item) is str:
            add_size(_bounded_string_size(item, remaining=max_bytes - total, subject=subject))
        elif type(item) is int:
            integer = item
            bit_length = integer.bit_length()
            # log10(2) > 0.301, giving a safe allocation-free lower bound.
            minimum_digits = 1 if bit_length == 0 else ((bit_length - 1) * 301) // 1000 + 1
            minimum_size = minimum_digits + int(integer < 0)
            if minimum_size > max_bytes - total:
                raise _resource_limit(subject, "encoded bytes", max_bytes)
            try:
                rendered = str(integer)
            except ValueError as error:
                raise _invalid_json(subject) from error
            add_size(len(rendered))
        elif type(item) is float:
            if not math.isfinite(item):
                raise _invalid_json(subject)
            add_size(len(repr(item)))
        elif type(item) in {bytes, bytearray}:
            # Bytes are not JSON, but an oversized bypass value is rejected by the byte
            # budget before any attempt to copy or encode it.
            raw_bytes = cast("bytes | bytearray", item)
            if len(raw_bytes) + 2 > max_bytes - total:
                raise _resource_limit(subject, "encoded bytes", max_bytes)
            raise _invalid_json(subject)
        elif type(item) is dict:
            identity = id(item)
            if identity in active_containers:
                raise _invalid_json(subject)
            count = len(item)
            if count > max_collection_items:
                raise _resource_limit(subject, "collection size", max_collection_items)
            reserve_nodes(count * 2)
            if count and depth == max_depth:
                raise _resource_limit(subject, "nesting depth", max_depth)
            add_size(2 + max(0, count - 1) + count)  # braces, commas, and colons
            active_containers.add(identity)
            stack.append(_ExitContainerFrame(identity=identity))
            for key, child in item.items():
                if type(key) is not str:
                    raise _invalid_json(subject)
                add_size(_bounded_string_size(key, remaining=max_bytes - total, subject=subject))
                stack.append(_ValueFrame(value=child, depth=depth + 1))
        elif type(item) in {list, tuple}:
            sequence = cast("list[object] | tuple[object, ...]", item)
            identity = id(item)
            if identity in active_containers:
                raise _invalid_json(subject)
            count = len(sequence)
            if count > max_collection_items:
                raise _resource_limit(subject, "collection size", max_collection_items)
            reserve_nodes(count)
            if count and depth == max_depth:
                raise _resource_limit(subject, "nesting depth", max_depth)
            add_size(2 + max(0, count - 1))  # brackets and commas
            active_containers.add(identity)
            stack.append(_ExitContainerFrame(identity=identity))
            stack.extend(_ValueFrame(value=child, depth=depth + 1) for child in sequence)
        else:
            raise _invalid_json(subject)

    return total
