"""Permite `python -m atalaya`, útil cuando el ejecutable no está disponible."""

from .cli import main_cli

if __name__ == "__main__":
    main_cli()
