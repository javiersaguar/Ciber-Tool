"""Bloqueo de instancia liberado por el SO incluso tras una caída."""

import os
from contextlib import contextmanager

from .storage import private_directory, private_file


@contextmanager
def state_lock(directory):
    private_directory(directory)
    path = directory / "instance.lock"
    private_file(path, b"0")
    with path.open("r+b") as stream:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)
