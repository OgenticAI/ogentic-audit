"""Smoke test that the native extension loads and exposes version metadata."""

from __future__ import annotations

import pytest


def test_format_version() -> None:
    pytest.importorskip("ogentic_audit", reason="native extension not built yet")

    import ogentic_audit

    assert ogentic_audit.format_version() == 0x0001
    assert isinstance(ogentic_audit.core_version(), str)
    assert ogentic_audit.core_version().startswith("0.")
