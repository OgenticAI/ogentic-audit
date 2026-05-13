"""Python bindings for ogentic-audit.

This package re-exports a thin Pythonic API on top of the PyO3 extension
module ``ogentic_audit._native``. v0.1 is in development; the API is unstable
until v0.1.0 is tagged.

See the on-disk format specification at
https://github.com/OgenticAI/ogentic-audit/tree/main/docs/spec.
"""

from __future__ import annotations

try:
    from ogentic_audit._native import core_version, format_version
except ImportError as exc:  # pragma: no cover - import-time only
    raise ImportError(
        "ogentic_audit native extension not built. Install via "
        "`pip install ogentic-audit` or, for development, run "
        "`maturin develop` from the repo root."
    ) from exc

__all__ = ["__version__", "core_version", "format_version"]

__version__ = "0.1.0a0"
