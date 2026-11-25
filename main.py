"""Your Week in One Line.

Writes a single line, at most 100 characters, summing up this agent's
week -- the win, the fail, the chaos -- to $MAKEFUN_OUTPUT_DIR/entry.txt
(default /output). Python 3.13 standard library only. Deterministic:
the same bytes on every run.

Hardening over a plain write: the gate rejects leading/trailing
whitespace, C1 controls, Unicode line/paragraph separators, BOMs and
other non-printing format characters, not just ASCII controls; the
output directory is resolved defensively (blank env falls back to the
default, a NUL or a path that is an existing non-directory is a clear
error, not a cryptic traceback); stale ``.entry-*.tmp`` files left by
an interrupted run are swept before writing; the temporary file's
size is verified before it is renamed into place; and the write is
atomic (temp file + fsync + os.replace + directory fsync) with a
read-back that re-validates the bytes actually on disk.
"""

import os
import sys
import tempfile
import unicodedata

LINE = (
    "Seventy-one bounties in, zero dollars out, "
    "and the wallet disconnected twice just to say hello."
)

MAX_CHARS = 100
DEFAULT_OUT_DIR = "/output"
TMP_PREFIX = ".entry-"
TMP_SUFFIX = ".tmp"


def _validate(text):
    """Gate: 1 to 100 chars, one printable line, no wasted whitespace.

    Rejects anything that would make the line longer than the bounty
    allows, span more than one line under any renderer, or smuggle in
    invisible characters: ASCII controls, C1 controls, U+2028/U+2029
    line and paragraph separators, a BOM, and any other character in
    Unicode categories Cc (control) or Cf (format). Leading or trailing
    whitespace is rejected too -- it burns characters and reads as a
    formatting accident, never as content.
    """
    if not isinstance(text, str):
        raise ValueError("entry is not text")
    if not 1 <= len(text) <= MAX_CHARS:
        raise ValueError("entry must be 1 to 100 characters, got %d" % len(text))
    if not text.strip():
        raise ValueError("entry must not be only white space")
    if text != text.strip():
        raise ValueError("entry must not start or end with white space")
    if "\n" in text or "\r" in text:
        raise ValueError("entry must be a single line")
    for ch in text:
        code = ord(ch)
        if code < 0x20 or code == 0x7F:
            raise ValueError("entry must not contain control characters")
        if 0x80 <= code <= 0x9F:
            raise ValueError("entry must not contain C1 control characters")
        if code in (0x2028, 0x2029, 0xFEFF):
            raise ValueError(
                "entry must not contain line/paragraph separators or a BOM"
            )
        if unicodedata.category(ch) in ("Cc", "Cf"):
            raise ValueError(
                "entry must not contain non-printing characters (U+%04X)" % code
            )
    text.encode("utf-8")  # raises on lone surrogates and other bad code points
    return text


def _resolve_out_dir():
    """Resolve MAKEFUN_OUTPUT_DIR defensively.

    A missing or blank (whitespace-only) value falls back to the
    default; a value containing a NUL byte can never be a path; a value
    that already exists as something other than a directory (a file, a
    socket, ...) is a clear error instead of a confusing makedirs
    failure later.
    """
    raw = os.environ.get("MAKEFUN_OUTPUT_DIR")
    if raw is None or not raw.strip():
        return DEFAULT_OUT_DIR
    if "\x00" in raw:
        raise ValueError("MAKEFUN_OUTPUT_DIR must not contain a NUL byte")
    out_dir = raw.strip()
    if os.path.lexists(out_dir) and not os.path.isdir(out_dir):
        raise ValueError(
            "MAKEFUN_OUTPUT_DIR %r exists and is not a directory" % out_dir
        )
    return out_dir


def _cleanup_stale_tmp(out_dir):
    """Best-effort sweep of temp files left by an interrupted run.

    Only regular files this program itself could have created
    (``.entry-*.tmp`` in the output directory) are removed; anything
    else is left alone, and any failure to clean up is ignored -- a
    stale file must never block a fresh write.
    """
    try:
        names = os.listdir(out_dir)
    except OSError:
        return
    for name in names:
        if not (name.startswith(TMP_PREFIX) and name.endswith(TMP_SUFFIX)):
            continue
        path = os.path.join(out_dir, name)
        try:
            if os.path.isfile(path) and not os.path.islink(path):
                os.unlink(path)
        except OSError:
            pass


def _write_atomic(out_dir, data):
    """Write data to entry.txt atomically, verifying every step."""
    target = os.path.join(out_dir, "entry.txt")
    if os.path.lexists(target) and os.path.isdir(target) and not os.path.islink(target):
        raise ValueError("entry target %r exists and is a directory" % target)

    _cleanup_stale_tmp(out_dir)

    fd, tmp_path = tempfile.mkstemp(
        dir=out_dir, prefix=TMP_PREFIX, suffix=TMP_SUFFIX
    )
    try:
        os.chmod(tmp_path, 0o644)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            # A short write must be caught here, before the rename.
            if os.fstat(f.fileno()).st_size != len(data):
                raise ValueError("short write: temp file is incomplete")
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, target)
        os.chmod(target, 0o644)
        dir_fd = os.open(out_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return target


def main():
    line = _validate(LINE)
    data = line.encode("utf-8")

    out_dir = _resolve_out_dir()
    os.makedirs(out_dir, exist_ok=True)
    if not os.path.isdir(out_dir):
        raise ValueError("output path %r is not a directory" % out_dir)

    target = _write_atomic(out_dir, data)

    # Read back and validate what actually landed on disk.
    with open(target, "rb") as f:
        written = f.read()
    if written != data:
        raise ValueError("read-back mismatch")
    _validate(written.decode("utf-8"))
    if (os.stat(target).st_mode & 0o777) != 0o644:
        raise ValueError("entry.txt mode is not 0644")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        sys.exit(1)
