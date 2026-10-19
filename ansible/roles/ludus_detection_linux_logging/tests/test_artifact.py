import hashlib
import importlib.util
import io
import sys
import tarfile
from pathlib import Path

import pytest

INSTALLER_PATH = Path(__file__).resolve().parents[1] / "files" / "install_laurel_artifact.py"
SPEC = importlib.util.spec_from_file_location("install_laurel_artifact", INSTALLER_PATH)
installer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = installer
SPEC.loader.exec_module(installer)


LAYOUT = [
    ("laurel", "file", 0o755),
    ("laurel2audit", "file", 0o755),
    ("INSTALL.md", "file", 0o664),
    ("README.md", "file", 0o664),
    ("performance.md", "file", 0o664),
    ("man", "dir", 0o775),
    ("man/laurel.8", "file", 0o644),
    ("man/.gitignore", "file", 0o664),
    ("man/laurel-about.7", "file", 0o644),
    ("man/laurel2audit.8", "file", 0o644),
    ("man/laurel.8.md", "file", 0o664),
    ("man/laurel2audit.8.md", "file", 0o664),
    ("man/Makefile", "file", 0o664),
    ("man/laurel-about.7.md", "file", 0o664),
]
PAYLOAD = b"synthetic Laurel payload; never executed\n"


def make_archive(path, entries=None, *, corrupt=False):
    with tarfile.open(path, "w:gz") as archive:
        for name, kind, mode in entries if entries is not None else LAYOUT:
            info = tarfile.TarInfo(name)
            info.mode = mode
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "laurel"
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = "laurel"
                archive.addfile(info)
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
                archive.addfile(info)
            elif kind == "device":
                info.type = tarfile.CHRTYPE
                archive.addfile(info)
            else:
                content = PAYLOAD if name == "laurel" else b"harmless companion\n"
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
    if corrupt:
        path.write_bytes(path.read_bytes()[:-24])
    return hashlib.sha256(path.read_bytes()).hexdigest()


def call_main(monkeypatch, archive, digest, *, destination=None, check_only=False):
    args = ["installer", "--archive", str(archive), "--sha256", digest]
    if destination is not None:
        args += ["--destination", str(destination)]
    if check_only:
        args.append("--check-only")
    monkeypatch.setattr("sys.argv", args)
    return installer.main()


def test_accepts_release_layout_installs_only_laurel(tmp_path, monkeypatch, capsys):
    archive = tmp_path / "release.tar.gz"
    digest = make_archive(archive)
    destination = tmp_path / "installed/laurel"

    call_main(monkeypatch, archive, digest, destination=destination, check_only=True)
    assert not destination.parent.exists()
    assert capsys.readouterr().out.strip() == "OK safe archive"

    call_main(monkeypatch, archive, digest, destination=destination)
    assert capsys.readouterr().out.strip() == "CHANGED content"
    assert destination.read_bytes() == PAYLOAD
    assert destination.stat().st_mode & 0o777 == 0o755
    assert list(destination.parent.iterdir()) == [destination]

    call_main(monkeypatch, archive, digest, destination=destination)
    assert capsys.readouterr().out.strip() == "OK"
    assert destination.read_bytes() == PAYLOAD
    assert destination.stat().st_mode & 0o777 == 0o755


@pytest.mark.parametrize("case", [
    "checksum", "missing", "duplicate-laurel", "nonregular-laurel",
    "absolute", "traversal", "ambiguous", "duplicate-companion",
    "symlink", "hardlink", "fifo", "device", "corrupt",
    "laurel-ancestor-child", "laurel-ancestor-child-reverse",
    "docs-ancestor-child", "docs-ancestor-child-reverse",
])
def test_rejects_unsafe_archive_without_mutation(tmp_path, monkeypatch, case):
    entries = list(LAYOUT)
    corrupt = case == "corrupt"
    if case == "missing":
        entries = [entry for entry in entries if entry[0] != "laurel"]
    elif case == "duplicate-laurel":
        entries.append(("laurel", "file", 0o755))
    elif case == "nonregular-laurel":
        entries[0] = ("laurel", "symlink", 0o755)
    elif case == "absolute":
        entries.append(("/outside", "file", 0o644))
    elif case == "traversal":
        entries.append(("../outside", "file", 0o644))
    elif case == "ambiguous":
        entries.append(("man//other", "file", 0o644))
    elif case == "duplicate-companion":
        entries.append(("README.md", "file", 0o644))
    elif case in {"symlink", "hardlink", "fifo", "device"}:
        entries.append(("unselected", case, 0o644))
    elif case.startswith("laurel-ancestor-child"):
        entries.append(("laurel/child", "file", 0o644))
        if case.endswith("reverse"):
            entries.reverse()
    elif case.startswith("docs-ancestor-child"):
        entries.extend([("docs", "file", 0o644), ("docs/readme", "file", 0o644)])
        if case.endswith("reverse"):
            entries.reverse()

    archive = tmp_path / "bad.tar.gz"
    digest = make_archive(archive, entries, corrupt=corrupt)
    if case == "checksum":
        digest = "0" * 64
    destination = tmp_path / "existing/laurel"
    destination.parent.mkdir()
    destination.write_bytes(b"old bytes")
    destination.chmod(0o751)
    sentinel = destination.parent / "sentinel"
    sentinel.write_text("retain")

    if case == "corrupt":
        with pytest.raises(EOFError, match="Compressed file ended before"):
            call_main(monkeypatch, archive, digest, destination=destination)
    else:
        messages = {
            "checksum": "Laurel archive checksum changed after download",
            "missing": "archive must contain one regular root member named laurel",
            "duplicate-laurel": "archive contains duplicate member paths",
            "nonregular-laurel": "archive contains an unsupported member type",
            "absolute": "archive contains an unsafe member path",
            "traversal": "archive contains an unsafe member path",
            "ambiguous": "archive contains an unsafe member path",
            "duplicate-companion": "archive contains duplicate member paths",
            "symlink": "archive contains an unsupported member type",
            "hardlink": "archive contains an unsupported member type",
            "fifo": "archive contains an unsupported member type",
            "device": "archive contains an unsupported member type",
            "laurel-ancestor-child": "regular member is an ancestor of another archive path",
            "laurel-ancestor-child-reverse": "regular member is an ancestor of another archive path",
            "docs-ancestor-child": "regular member is an ancestor of another archive path",
            "docs-ancestor-child-reverse": "regular member is an ancestor of another archive path",
        }
        with pytest.raises(ValueError, match=messages[case]):
            call_main(monkeypatch, archive, digest, destination=destination)

    assert destination.read_bytes() == b"old bytes"
    assert destination.stat().st_mode & 0o777 == 0o751
    assert sentinel.read_text() == "retain"
    assert sorted(item.name for item in destination.parent.iterdir()) == ["laurel", "sentinel"]


def test_rejection_does_not_create_absent_destination_parent(tmp_path, monkeypatch):
    archive = tmp_path / "unsafe.tar.gz"
    digest = make_archive(archive, LAYOUT + [("../escape", "file", 0o644)])
    destination = tmp_path / "absent/nested/laurel"
    with pytest.raises(ValueError, match="archive contains an unsafe member path"):
        call_main(monkeypatch, archive, digest, destination=destination)
    assert not destination.parent.exists()


def test_replace_failure_preserves_destination(tmp_path, monkeypatch):
    archive = tmp_path / "release.tar.gz"
    digest = make_archive(archive)
    destination = tmp_path / "existing/laurel"
    destination.parent.mkdir()
    destination.write_bytes(b"old bytes")
    destination.chmod(0o751)
    sentinel = destination.parent / "sentinel"
    sentinel.write_text("retain")

    def fail_replace(_source, _target):
        raise OSError("injected replace failure")

    monkeypatch.setattr(installer.os, "replace", fail_replace)
    with pytest.raises(OSError, match="injected replace failure"):
        call_main(monkeypatch, archive, digest, destination=destination)
    assert destination.read_bytes() == b"old bytes"
    assert destination.stat().st_mode & 0o777 == 0o751
    assert sentinel.read_text() == "retain"
    assert sorted(item.name for item in destination.parent.iterdir()) == ["laurel", "sentinel"]
