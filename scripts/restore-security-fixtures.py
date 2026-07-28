#!/usr/bin/env python3
"""Fixture builder for scripts/selftest-restore-security.sh (#218).

Builds one raw (uncompressed) tar archive per "shape" using the stdlib `tarfile`
module — the `tar` CLI itself will refuse to CREATE most of these entries on request
(path traversal, an absolute member name, a hardlink/symlink whose target escapes the
tree, FIFO/device nodes), so this constructs the tar header bytes directly instead.
These are exactly the entry kinds restore.ts's inspectRestoreArchive()/
validateRestoreEntries() must reject before extraction ever starts, plus a few
legitimate shapes (a plain file tree, a standalone dangling symlink, an in-tree
hardlink) that must NOT be rejected.

Invoked with CB_TAR_OUT (output path) and CB_TAR_SHAPE (which fixture to build) set in
the environment, and CB_SYMLINK_TARGET for the 'symlink-traverse' shape.
"""
import os
import tarfile
import io

out_path = os.environ["CB_TAR_OUT"]
shape = os.environ["CB_TAR_SHAPE"]


def add_file(tf, name, data=b"data"):
    ti = tarfile.TarInfo(name=name)
    ti.size = len(data)
    tf.addfile(ti, io.BytesIO(data))


def add_symlink(tf, name, linkname):
    ti = tarfile.TarInfo(name=name)
    ti.type = tarfile.SYMTYPE
    ti.linkname = linkname
    tf.addfile(ti)


def add_hardlink(tf, name, linkname):
    ti = tarfile.TarInfo(name=name)
    ti.type = tarfile.LNKTYPE
    ti.linkname = linkname
    tf.addfile(ti)


with tarfile.open(out_path, "w") as tf:
    if shape == "traversal":
        add_file(tf, "../../etc/evil.txt", b"path-traversal-payload")
    elif shape == "absolute":
        add_file(tf, "/tmp/abs-evil-marker.txt", b"absolute-path-payload")
    elif shape == "fifo":
        ti = tarfile.TarInfo(name="myfifo")
        ti.type = tarfile.FIFOTYPE
        tf.addfile(ti)
    elif shape == "device":
        ti = tarfile.TarInfo(name="mydev")
        ti.type = tarfile.CHRTYPE
        ti.devmajor = 1
        ti.devminor = 3
        tf.addfile(ti)
    elif shape == "hardlink-escape":
        add_hardlink(tf, "hardlink-evil.txt", "../../etc/passwd")
    elif shape == "symlink-traverse":
        target = os.environ["CB_SYMLINK_TARGET"]
        add_symlink(tf, "link", target)
        add_file(tf, "link/pwned.txt", b"PWNED")
    elif shape == "plain":
        add_file(tf, "note.txt", b"plain-ok")
    elif shape == "symlink-standalone":
        add_symlink(tf, "dangling-link", "/this/path/does/not/exist")
    elif shape == "hardlink-safe":
        add_file(tf, "target.txt", b"hardlink-ok")
        add_hardlink(tf, "link.txt", "target.txt")
    else:
        raise SystemExit(f"unknown CB_TAR_SHAPE: {shape}")
