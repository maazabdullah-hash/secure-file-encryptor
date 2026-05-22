"""Entry point for the Secure File Encryptor desktop application."""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_project_root_on_path() -> None:
    """Add project root to sys.path so `src` imports work when run as a script."""
    project_root = Path(__file__).resolve().parent.parent
    root_str = str(project_root)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)


def main() -> None:
    """Launch the GUI application."""
    _ensure_project_root_on_path()
    from src.gui import run_gui

    run_gui()


if __name__ == "__main__":
    main()
