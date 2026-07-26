from __future__ import annotations

import pytest
from agentkernel.domain.models import CanonicalResource
from pydantic import TypeAdapter, ValidationError

_RESOURCE = TypeAdapter(CanonicalResource)


@pytest.mark.security
@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("fs://workspace/file%", "invalid percent escape"),
        ("fs://workspace/file%0", "invalid percent escape"),
        ("fs://workspace/file%GG", "invalid percent escape"),
        ("fs://workspace/file%2fpart", "uppercase hex"),
        ("fs://workspace/%41", "must not encode an unreserved"),
        ("fs://workspace/", "path is not in canonical form"),
        ("fs://workspace/a//b", "path is not in canonical form"),
        ("fs://workspace/%FF", "path is not valid UTF-8"),
        ("fs://workspace/.", "path contains an alias"),
        ("fs://workspace/..", "path contains an alias"),
        ("fs://workspace/%2F", "path contains an alias"),
        ("fs://workspace/%5C", "path contains an alias"),
        ("fs://workspace/%3A", "path contains an alias"),
        ("fs://workspace/%00", "path contains an alias"),
        ("fs://workspace/%3C", "path contains an alias"),
        ("fs://workspace/CON", "OS-reserved alias"),
        ("fs://workspace/name.", "OS-reserved alias"),
        ("fs://workspace/(name)", "not safely percent-encoded"),
        ("https://user:password@example.com/path", "credential-bearing authority"),
        ("https://example.com./path", "lowercase without a trailing dot"),
        ("https://example.com:abc/path", "invalid port"),
        ("https://example.com:70000/path", "invalid port"),
        ("https://[2001:0db8::1]/path", "IPv6 address is not compressed"),
        ("https://bad_host/path", "invalid DNS or IPv4 authority"),
        ("https://999.999.999.999/path", "invalid IPv4 address"),
        ("https://EXAMPLE.com/path", "authority is not in canonical form"),
        ("https://example.com", "path is not in canonical form"),
        ("https://example.com/path/", "path is not in canonical form"),
        ("https://example.com/a//b", "path is not in canonical form"),
        ("https://example.com/%FF", "path is not valid UTF-8"),
        ("https://example.com/.", "path contains an alias"),
        ("https://example.com/%2F", "path contains an alias"),
        ("https://example.com/%5C", "path contains an alias"),
        ("https://example.com/%00", "path contains an alias"),
        ("https://example.com/(name)", "not safely percent-encoded"),
        ("fs://workspace/cafe\u0301", "must be Unicode NFC"),
        ("fs://workspace/café", "must percent-encode non-ASCII"),
        ("fs://workspace/a\x01b", "control character"),
        ("fs://workspace/a b", "non-canonical character"),
        ("fs://workspace/a\\b", "non-canonical character"),
        ("fs://workspace/a?", "cannot contain a query or fragment"),
        ("fs://workspace/a#", "cannot contain a query or fragment"),
        ("HTTPS://example.com/path", "lowercase scheme"),
        ("https:/path", "requires an authority"),
        ("fs://bad_host/path", "invalid authority or suffix"),
        ("http://example.com:80/path", "must omit its scheme's default port"),
        ("https://example.com:443/path", "must omit its scheme's default port"),
    ],
)
def test_canonical_resource_uri_rejects_aliases_and_credential_surfaces(
    value: str,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        _RESOURCE.validate_python(value)


@pytest.mark.security
@pytest.mark.parametrize(
    "value",
    [
        "fs://workspace",
        "fs://workspace/**",
        "fs://workspace/reports/result.json",
        "https://example.com/",
        "https://example.com:8443/api/v1",
        "https://[2001:db8::1]/api",
        "process://allowlist/pytest%408.3.5",
    ],
)
def test_canonical_resource_uri_accepts_one_unambiguous_spelling(value: str) -> None:
    assert _RESOURCE.validate_python(value) == value
