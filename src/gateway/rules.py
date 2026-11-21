<<<<<<< Updated upstream
"""Gateway-specific rules and filters."""

from __future__ import annotations


DEFAULT_RULES = {
    "scope": "in_scope_hosts",
    "undocumented_policy": "block",
    "allowlist": "generated",
}
=======
"""Pure matching helpers for the gateway engine: hosts, paths and route templates.

Nothing here has a policy default. ``undocumented_policy`` lives in the config
and has none (DR6).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_PARAM = re.compile(r"^\{[^{}/]+\}$")


class MalformedPath(ValueError):
    """The request path cannot be matched safely and must be blocked."""


def host_key(host: str, port: int) -> str:
    """Canonical ``host:port`` used for scope comparison (no wildcards)."""
    name = host.strip().lower().rstrip(".")
    if ":" in name and not name.startswith("["):
        name = f"[{name}]"
    return f"{name}:{int(port)}"


def split_path(path: str) -> tuple[str, ...]:
    """Split a request path into decoded segments, rejecting anything ambiguous.

    A gateway that matches on a different string than the upstream resolves can
    be bypassed, so dot segments, empty segments, encoded separators, NUL and
    backslashes are rejected instead of normalized.
    """
    if not path.startswith("/") or "\\" in path or "\x00" in path:
        raise MalformedPath("path must start with '/' and contain no backslash or NUL")
    if path == "/":
        return ()
    segments = path[1:].split("/")
    decoded: list[str] = []
    for index, raw in enumerate(segments):
        value = unquote(raw)
        if raw == "" and index < len(segments) - 1:
            raise MalformedPath("empty path segment")
        if value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
            raise MalformedPath("dot segment or encoded separator in path")
        decoded.append(value)
    return tuple(decoded)


@dataclass(frozen=True)
class CompiledTemplate:
    """A route template such as ``/orders/{order_id}`` split into segments."""

    segments: tuple[str, ...]

    @property
    def literal_count(self) -> int:
        return sum(1 for s in self.segments if not _PARAM.match(s))

    def matches(self, request_segments: tuple[str, ...]) -> bool:
        if len(request_segments) != len(self.segments):
            return False
        for template_segment, actual in zip(self.segments, request_segments):
            if _PARAM.match(template_segment):
                if actual == "":
                    return False
            elif template_segment != actual:
                return False
        return True


def compile_template(template: str) -> CompiledTemplate:
    if not template.startswith("/"):
        raise ValueError(f"path template must start with '/': {template!r}")
    if template == "/":
        return CompiledTemplate(())
    return CompiledTemplate(tuple(template[1:].split("/")))
>>>>>>> Stashed changes
