# ogentic-audit (Python)

PyO3 bindings for the [`ogentic-audit`](https://github.com/OgenticAI/ogentic-audit) HMAC-SHA256 chained, append-only audit log.

```{toctree}
:maxdepth: 2
:caption: Contents

quickstart
api
```

## Installation

```sh
pip install ogentic-audit
```

Wheels ship for Linux (manylinux_2_28, x86_64 + aarch64), macOS (arm64 + x86_64), and Windows (x86_64), CPython 3.9+.

## Status

v0.1 is in development (alpha). The Python API is unstable until v0.1.0 is tagged. The underlying on-disk format is pinned by [golden vectors](https://github.com/OgenticAI/ogentic-audit/tree/main/tests/vectors/v0.1) and is the stable surface.

See the [project README](https://github.com/OgenticAI/ogentic-audit#status--versioning) for the full versioning posture.
