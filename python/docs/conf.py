"""Sphinx configuration for the ogentic-audit Python docs.

Renders to https://ogentic-audit.readthedocs.io once the
corresponding Read the Docs project is linked to this repo. The
build is triggered automatically on every tag.
"""

from __future__ import annotations

# -- Project information -----------------------------------------------------

project = "ogentic-audit"
copyright = "2026, OgenticAI"
author = "OgenticAI"
release = "0.1.0a0"

# -- General configuration ---------------------------------------------------

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx.ext.viewcode",
    "myst_parser",
]
templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

autosummary_generate = True
autodoc_typehints = "description"
autodoc_member_order = "bysource"
napoleon_google_docstring = True
napoleon_numpy_docstring = False

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
}

# Source suffix — .md (via myst) + .rst.
source_suffix = {
    ".rst": "restructuredtext",
    ".md": "markdown",
}

# -- HTML output options -----------------------------------------------------

html_theme = "furo"
html_static_path = ["_static"]
html_title = f"ogentic-audit {release}"
