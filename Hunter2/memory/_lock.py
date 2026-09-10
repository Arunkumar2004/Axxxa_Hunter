"""Portable advisory file locking.

Uses fcntl.flock on POSIX and msvcrt.locking on Windows, exposing the same
surface (LOCK_EX / LOCK_UN constants and flock(fd, op)) so callers can use a
single code path.
"""

try:
    import fcntl

    LOCK_EX = fcntl.LOCK_EX
    LOCK_UN = fcntl.LOCK_UN

    def flock(fd, op):
        fcntl.flock(fd, op)

except ImportError:  # pragma: no cover - Windows
    import msvcrt
    import os as _os
    import time as _time

    LOCK_EX = 1
    LOCK_UN = 2

    def flock(fd, op):
        try:
            _os.lseek(fd, 0, _os.SEEK_SET)
            if op == LOCK_EX:
                # Non-blocking with a short busy-wait: msvcrt's blocking
                # LK_LOCK can stall up to 10s under contention, which would
                # keep the file handle open and block rotation renames.
                for _ in range(2000):
                    try:
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                        return
                    except OSError:
                        _time.sleep(0.001)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            else:
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
