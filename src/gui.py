"""Tkinter GUI for the Secure File Encryptor."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Optional

from cryptography.exceptions import InvalidTag

from .crypto import (
    CryptoError,
    FileFormatError,
    FileNotFoundCryptoError,
    decrypt_file,
    encrypt_file,
)


class EncryptorApp:
    """Main application window."""

    def __init__(self, root: tk.Tk) -> None:
        """Initialize widgets and layout.

        Args:
            root: Tk root window.
        """
        self._root = root
        self._selected_file: Optional[Path] = None

        root.title("Secure File Encryptor")
        root.geometry("520x280")
        root.resizable(False, False)

        self._build_ui()

    def _build_ui(self) -> None:
        """Create and place all GUI components."""
        padding = {"padx": 12, "pady": 6}

        file_frame = ttk.LabelFrame(self._root, text="File", padding=10)
        file_frame.pack(fill=tk.X, **padding)

        self._file_var = tk.StringVar(value="No file selected")
        ttk.Label(file_frame, textvariable=self._file_var, wraplength=460).pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )
        ttk.Button(file_frame, text="Browse…", command=self._browse_file).pack(
            side=tk.RIGHT, padx=(8, 0)
        )

        pwd_frame = ttk.LabelFrame(self._root, text="Password", padding=10)
        pwd_frame.pack(fill=tk.X, **padding)

        self._password_var = tk.StringVar()
        self._password_entry = ttk.Entry(
            pwd_frame, textvariable=self._password_var, show="•", width=40
        )
        self._password_entry.pack(fill=tk.X)

        btn_frame = ttk.Frame(self._root, padding=10)
        btn_frame.pack(fill=tk.X)

        ttk.Button(btn_frame, text="Encrypt", command=self._on_encrypt).pack(
            side=tk.LEFT, padx=(0, 8)
        )
        ttk.Button(btn_frame, text="Decrypt", command=self._on_decrypt).pack(
            side=tk.LEFT
        )

        self._status_var = tk.StringVar(value="Ready.")
        status_frame = ttk.Frame(self._root, padding=(12, 0, 12, 12))
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        ttk.Label(status_frame, text="Status:").pack(side=tk.LEFT)
        ttk.Label(
            status_frame, textvariable=self._status_var, foreground="#333333"
        ).pack(side=tk.LEFT, padx=(6, 0))

    def _browse_file(self) -> None:
        """Open file picker and store the selected path."""
        path = filedialog.askopenfilename(
            title="Select a file",
            filetypes=[("All files", "*.*")],
        )
        if path:
            self._selected_file = Path(path)
            self._file_var.set(str(self._selected_file))
            self._set_status("File selected.")

    def _get_password(self) -> Optional[str]:
        """Return password or show validation message.

        Returns:
            Password string, or None if empty.
        """
        password = self._password_var.get()
        if not password.strip():
            messagebox.showwarning(
                "Password required",
                "Please enter a password before encrypting or decrypting.",
            )
            return None
        return password

    def _get_selected_file(self) -> Optional[Path]:
        """Return selected file or warn the user.

        Returns:
            Path to selected file, or None if missing.
        """
        if self._selected_file is None or not self._selected_file.is_file():
            messagebox.showwarning(
                "No file",
                "Please choose a file using Browse.",
            )
            return None
        return self._selected_file

    def _on_encrypt(self) -> None:
        """Encrypt the selected file to a new path."""
        self._run_operation(
            operation_name="Encrypt",
            default_extension=".enc",
            handler=self._do_encrypt,
        )

    def _on_decrypt(self) -> None:
        """Decrypt the selected encrypted file."""
        self._run_operation(
            operation_name="Decrypt",
            default_extension="",
            handler=self._do_decrypt,
        )

    def _run_operation(
        self,
        operation_name: str,
        default_extension: str,
        handler: Callable[[Path, Path, str], None],
    ) -> None:
        """Validate inputs, ask for output path, and run encrypt/decrypt.

        Args:
            operation_name: Label for dialogs (Encrypt / Decrypt).
            default_extension: Suggested suffix for save dialog.
            handler: Callable that performs encrypt_file or decrypt_file.
        """
        source = self._get_selected_file()
        password = self._get_password()
        if source is None or password is None:
            return

        initial = source.stem + "_decrypted" if operation_name == "Decrypt" else source.name
        if operation_name == "Encrypt" and not str(source).endswith(".enc"):
            initial = source.name + ".enc"

        dest = filedialog.asksaveasfilename(
            title=f"{operation_name} — save as",
            initialfile=initial,
            defaultextension=default_extension,
            filetypes=[("All files", "*.*")],
        )
        if not dest:
            self._set_status("Cancelled.")
            return

        output_path = Path(dest)
        try:
            handler(source, output_path, password)
        except (
            FileNotFoundCryptoError,
            FileFormatError,
            InvalidTag,
            ValueError,
            CryptoError,
            OSError,
        ) as exc:
            self._handle_error(exc)
            return

        self._set_status(f"{operation_name} completed: {output_path.name}")
        messagebox.showinfo(
            operation_name,
            f"{operation_name} successful.\nSaved to:\n{output_path}",
        )

    @staticmethod
    def _do_encrypt(source: Path, dest: Path, password: str) -> None:
        """Delegate to crypto layer."""
        encrypt_file(source, dest, password)

    @staticmethod
    def _do_decrypt(source: Path, dest: Path, password: str) -> None:
        """Delegate to crypto layer."""
        decrypt_file(source, dest, password)

    def _handle_error(self, exc: BaseException) -> None:
        """Map exceptions to user-friendly status and dialog messages.

        Args:
            exc: Exception raised during encrypt or decrypt.
        """
        if isinstance(exc, FileNotFoundCryptoError):
            title, msg = "File not found", str(exc)
        elif isinstance(exc, FileFormatError):
            title, msg = "Corrupted file", (
                "This file does not look like a valid encrypted file "
                "or it has been truncated."
            )
        elif isinstance(exc, InvalidTag):
            title, msg = "Decryption failed", (
                "Wrong password or the file has been modified. "
                "Authentication failed."
            )
        elif isinstance(exc, ValueError):
            title, msg = "Invalid input", str(exc)
        elif isinstance(exc, CryptoError):
            title, msg = "Error", str(exc)
        elif isinstance(exc, OSError):
            title, msg = "File error", f"Could not read or write the file: {exc}"
        else:
            title, msg = "Unexpected error", str(exc)

        self._set_status(f"Error: {msg}")
        messagebox.showerror(title, msg)

    def _set_status(self, message: str) -> None:
        """Update the status label.

        Args:
            message: Short status text for the user.
        """
        self._status_var.set(message)


def run_gui() -> None:
    """Create the main window and start the Tk event loop."""
    root = tk.Tk()
    # Use themed widgets on Windows/macOS where available.
    try:
        ttk.Style().theme_use("clam")
    except tk.TclError:
        pass
    EncryptorApp(root)
    root.mainloop()
