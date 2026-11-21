"""Proxy operating modes: capture and reverse test."""

from __future__ import annotations


CAPTURE = "capture"
REVERSE_TEST = "reverse_test"


def supported_modes() -> tuple[str, ...]:
    return (CAPTURE, REVERSE_TEST)
