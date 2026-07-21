"""Non-semantic identifier generation."""

from __future__ import annotations

from uuid import UUID, uuid4


def new_id(prefix: str, *, value: UUID | None = None) -> str:
    """Create an opaque identifier; callers must not derive meaning from its suffix."""

    if not prefix or not prefix[0].isalpha() or not prefix.replace("_", "").isalnum():
        raise ValueError("Identifier prefixes must start with a letter and be alphanumeric")
    return f"{prefix}_{(value or uuid4()).hex}"
