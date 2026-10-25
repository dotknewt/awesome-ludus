"""Read-only inspection of the role-owned pip-only Python 3.12 venv."""

import base64
import csv
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TREE_FILES = 12000
MAX_TOTAL_BYTES = 128 * 1024 * 1024
REASONS = set()
DETAILS = []
OBSERVED_DISTRIBUTIONS = []


def reject(reason, path, expected, actual):
    REASONS.add(reason)
    if len(DETAILS) < 40:
        DETAILS.append({"reason": reason, "path": path, "expected": expected, "actual": actual})


def generated_cache_source(relative):
    match = re.fullmatch(r"pip/(?:((?:[^/]+/)*))__pycache__/([^/]+)\.cpython-312(?:\.opt-[0-9]+)?\.pyc", relative)
    if not match:
        return None
    return "pip/" + match.group(1) + match.group(2) + ".py"


def valid_generated_cache(relative, target, hash_verified_sources):
    source = generated_cache_source(relative)
    if source is None or source not in hash_verified_sources:
        return False
    try:
        with open(target, "rb") as stream:
            header = stream.read(16)
        return len(header) == 16 and header[:4] == importlib.util.MAGIC_NUMBER
    except OSError:
        return False


def lstat(path):
    try:
        return os.lstat(path)
    except OSError:
        return None


def owned_safe(st, kind=None):
    if st is None or st.st_uid != 0 or st.st_gid != 0:
        return False
    if st.st_mode & 0o6022:
        return False
    if kind == "directory":
        return stat.S_ISDIR(st.st_mode)
    if kind == "file":
        return stat.S_ISREG(st.st_mode)
    return stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)


def metadata(st):
    if st is None:
        return "missing"
    return {"type": stat.filemode(st.st_mode), "uid": st.st_uid, "gid": st.st_gid,
            "mode": oct(stat.S_IMODE(st.st_mode)), "size": st.st_size}


def record_target(site_packages, relative):
    rel = PurePosixPath(relative)
    if rel.is_absolute() or not relative or "\\" in relative:
        return None
    candidate = os.path.abspath(os.path.join(site_packages, *rel.parts))
    try:
        if os.path.commonpath((venv, candidate)) != venv:
            return None
        if os.path.commonpath((venv, os.path.realpath(candidate))) != venv:
            return None
    except ValueError:
        return None
    current = venv
    for component in os.path.relpath(candidate, venv).split(os.sep):
        current = os.path.join(current, component)
        st = lstat(current)
        if st is not None and stat.S_ISLNK(st.st_mode):
            return None
    return candidate


def hash_matches(path, encoded):
    if "=" not in encoded:
        return False
    algorithm, expected = encoded.split("=", 1)
    if algorithm not in ("sha256", "sha384", "sha512"):
        return f"unsupported hash algorithm: {algorithm[:32]}"
    try:
        digest = hashlib.new(algorithm)
        with open(path, "rb") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        actual = base64.urlsafe_b64encode(digest.digest()).decode("ascii").rstrip("=")
        return actual
    except (OSError, ValueError) as exc:
        return f"{type(exc).__name__}: {exc}"[:256]


def inspect():
    if os.geteuid() != 0:
        reject("not_root", "process", "effective uid 0", os.geteuid())
    if len(sys.argv) != 2:
        reject("arguments", "argv", "one venv path argument", sys.argv[1:4])
        return

    global venv
    venv = os.path.abspath(sys.argv[1])
    if venv != "/opt/ludus-k3s/python":
        reject("unexpected_venv_path", "argv[1]", "/opt/ludus-k3s/python", venv[:256])
        return
    if sys.version_info[:2] != (3, 12):
        reject("trusted_python_version", sys.executable, "Python 3.12", sys.version[:128])

    root_stat = lstat(venv)
    if not owned_safe(root_stat, "directory") or stat.S_IMODE(root_stat.st_mode) != 0o755:
        reject("venv_root_metadata", venv, "root-owned directory mode 0755", metadata(root_stat))
        return

    config_path = os.path.join(venv, "pyvenv.cfg")
    config_stat = lstat(config_path)
    if not owned_safe(config_stat, "file") or stat.S_IMODE(config_stat.st_mode) != 0o644:
        reject("pyvenv_cfg_metadata", config_path, "root-owned regular file mode 0644", metadata(config_stat))
        return
    try:
        config_bytes = Path(config_path).read_bytes()
        if len(config_bytes) > 65536:
            reject("pyvenv_cfg_size", config_path, "<= 65536 bytes", len(config_bytes))
            return
        config = {}
        for line in config_bytes.decode("utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if "=" not in line:
                reject("pyvenv_cfg_format", config_path, "key=value line", line[:160])
                continue
            key, value = (piece.strip() for piece in line.split("=", 1))
            if key in config:
                reject("pyvenv_cfg_duplicate", config_path, "unique config keys", key[:128])
            config[key] = value
    except (OSError, UnicodeError):
        reject("pyvenv_cfg_read", config_path, "readable UTF-8 config", "read/decode failure")
        return
    if config.get("include-system-site-packages", "").lower() != "true":
        reject("system_site_packages", config_path, "include-system-site-packages=true", config.get("include-system-site-packages"))
    if not config.get("version", "").startswith("3.12."):
        reject("venv_python_version", config_path, "version 3.12.x", config.get("version"))
    if os.path.realpath(config.get("home", "")) != os.path.realpath(os.path.dirname(sys.executable)):
        reject("venv_python_home", config_path, os.path.dirname(sys.executable), config.get("home"))
    configured_interpreter = config.get("executable")
    if configured_interpreter and os.path.realpath(configured_interpreter) != os.path.realpath(sys.executable):
        reject("venv_python_executable", config_path, os.path.realpath(sys.executable), configured_interpreter)

    bin_dir = os.path.join(venv, "bin")
    include_dir = os.path.join(venv, "include")
    lib_dir = os.path.join(venv, "lib")
    site_packages = os.path.join(lib_dir, "python3.12", "site-packages")
    include_version_dir = os.path.join(include_dir, "python3.12")
    for directory in (bin_dir, include_dir, lib_dir, os.path.join(lib_dir, "python3.12"), site_packages):
        st = lstat(directory)
        if not owned_safe(st, "directory") or stat.S_IMODE(st.st_mode) != 0o755:
            reject("venv_layout_directory", directory, "root-owned directory mode 0755", metadata(st))
    include_version_stat = lstat(include_version_dir)
    if include_version_stat is not None and stat.S_ISLNK(include_version_stat.st_mode):
        try:
            include_target = os.path.realpath(include_version_dir)
            expected_include = "/usr/include/python3.12"
            include_safe = os.path.commonpath((expected_include, include_target)) == expected_include
        except ValueError:
            include_safe = False
        if include_version_stat.st_uid != 0 or include_version_stat.st_gid != 0 or not include_safe:
            reject("venv_include_link", include_version_dir, "root-owned link into /usr/include/python3.12", os.path.realpath(include_version_dir))
    elif not owned_safe(include_version_stat, "directory"):
        reject("venv_layout_directory", include_version_dir, "root-owned directory or approved system include symlink", metadata(include_version_stat))

    system_interpreter = os.path.realpath(sys.executable)
    allowed_links = {
        "bin/python", "bin/python3", "bin/python3.12",
    }
    for rel in allowed_links:
        path = os.path.join(venv, rel)
        st = lstat(path)
        if st is None or not stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_gid != 0:
            reject("venv_interpreter_link", path, "root-owned symlink", metadata(st))
            continue
        if os.path.realpath(path) != system_interpreter:
            reject("venv_interpreter_target", path, system_interpreter, os.path.realpath(path))
        target_stat = lstat(os.path.realpath(path))
        if not owned_safe(target_stat, "file") or not target_stat.st_mode & 0o111:
            reject("venv_interpreter_metadata", os.path.realpath(path), "root-owned executable regular file", metadata(target_stat))

    lib64 = os.path.join(venv, "lib64")
    lib64_stat = lstat(lib64)
    if lib64_stat is not None:
        if stat.S_ISLNK(lib64_stat.st_mode):
            if lib64_stat.st_uid != 0 or lib64_stat.st_gid != 0 or os.readlink(lib64) != "lib":
                reject("venv_lib64_link", lib64, "root-owned symlink to lib", os.readlink(lib64))
        elif not owned_safe(lib64_stat, "directory") or stat.S_IMODE(lib64_stat.st_mode) != 0o755:
            reject("venv_lib64_metadata", lib64, "root-owned directory mode 0755", metadata(lib64_stat))

    root_entries = set(os.listdir(venv))
    if root_entries - {"bin", "include", "lib", "lib64", "pyvenv.cfg"}:
        reject("venv_root_payload", venv, "only bin/include/lib/lib64/pyvenv.cfg", sorted(root_entries - {"bin", "include", "lib", "lib64", "pyvenv.cfg"})[:20])
    if not {"bin", "include", "lib", "pyvenv.cfg"} <= root_entries:
        reject("venv_root_layout", venv, "bin/include/lib/pyvenv.cfg present", sorted({"bin", "include", "lib", "pyvenv.cfg"} - root_entries))

    dist_info = os.path.join(site_packages, "pip-24.0.dist-info")
    metadata_dirs = []
    try:
        metadata_dirs = [
            entry.name for entry in os.scandir(site_packages)
            if entry.name.endswith((".dist-info", ".egg-info"))
        ]
    except OSError:
        reject("site_packages_read", site_packages, "readable directory", "scandir failed")
    if metadata_dirs != ["pip-24.0.dist-info"]:
        reject("unknown_distribution_metadata", site_packages, ["pip-24.0.dist-info"], metadata_dirs[:20])
    metadata_stat = lstat(dist_info)
    if not owned_safe(metadata_stat, "directory") or stat.S_IMODE(metadata_stat.st_mode) != 0o755:
        reject("pip_metadata_directory", dist_info, "root-owned directory mode 0755", metadata(metadata_stat))

    metadata_path = os.path.join(dist_info, "METADATA")
    record_path = os.path.join(dist_info, "RECORD")
    for path in (metadata_path, record_path):
        st = lstat(path)
        if not owned_safe(st, "file"):
            reject("pip_metadata_file", path, "root-owned regular file", metadata(st))
            return
    try:
        metadata_text = Path(metadata_path).read_text(encoding="utf-8")
        names = re.findall(r"(?m)^Name:\s*(.*?)\s*$", metadata_text)
        versions = re.findall(r"(?m)^Version:\s*(.*?)\s*$", metadata_text)
        if names != ["pip"] or versions != ["24.0"]:
            reject("pip_metadata_identity", metadata_path, "Name=pip, Version=24.0", {"names": names[:4], "versions": versions[:4]})
        else:
            OBSERVED_DISTRIBUTIONS[:] = ["pip==24.0"]
        record_bytes = Path(record_path).read_bytes()
        if len(record_bytes) > MAX_RECORD_BYTES:
            reject("record_size", record_path, f"<= {MAX_RECORD_BYTES} bytes", len(record_bytes))
            return
        rows = list(csv.reader(record_bytes.decode("utf-8").splitlines()))
    except (OSError, UnicodeError, csv.Error):
        reject("record_read", record_path, "valid UTF-8 CSV RECORD", "read/decode/CSV failure")
        return

    indexed_rows = {}
    record_self = os.path.relpath(record_path, site_packages).replace(os.sep, "/")
    total_bytes = 0
    for row in rows:
        if len(row) != 3:
            reject("record_row", record_path, "three-column row", row[:4])
            continue
        relative, encoded_hash, encoded_size = row
        target = record_target(site_packages, relative)
        if target is None:
            reject("record_path", record_path, "safe relative path under site-packages", relative[:256])
            continue
        if relative in indexed_rows:
            reject("record_duplicate", target, "one RECORD row", "duplicate row")
            continue
        indexed_rows[relative] = (target, encoded_hash, encoded_size)
        st = lstat(target)
        if not owned_safe(st, "file"):
            reject("record_file_metadata", target, "root-owned regular file without unsafe permissions", metadata(st))
            continue
        if st.st_size > MAX_FILE_BYTES:
            reject("record_file_size", target, f"<= {MAX_FILE_BYTES} bytes", st.st_size)
            continue
        total_bytes += st.st_size
    if total_bytes > MAX_TOTAL_BYTES:
        reject("record_total_size", record_path, f"<= {MAX_TOTAL_BYTES} bytes total", total_bytes)
        return

    hash_verified_python_sources = set()
    pending_caches = []
    verified_paths = set(indexed_rows)
    for relative, (target, encoded_hash, encoded_size) in indexed_rows.items():
        st = lstat(target)
        if not owned_safe(st, "file") or st.st_size > MAX_FILE_BYTES:
            continue
        if relative == record_self:
            if encoded_hash or encoded_size:
                reject("record_self_hash", target, "empty hash and size", {"hash": encoded_hash, "size": encoded_size})
            continue
        try:
            if encoded_size and int(encoded_size) != st.st_size:
                reject("record_size_mismatch", target, int(encoded_size), st.st_size)
            if encoded_hash:
                actual_digest = hash_matches(target, encoded_hash)
                expected_digest = encoded_hash.split("=", 1)[1] if "=" in encoded_hash else "invalid encoding"
                if actual_digest != expected_digest:
                    reject("record_hash_mismatch", target, encoded_hash, actual_digest)
                elif relative.startswith("pip/") and relative.endswith(".py"):
                    hash_verified_python_sources.add(relative)
            cache_source = generated_cache_source(relative)
            if cache_source and not encoded_hash:
                pending_caches.append((relative, target))
            elif not encoded_hash and relative not in {
                "pip-24.0.dist-info/INSTALLER", "pip-24.0.dist-info/REQUESTED",
            }:
                reject("record_missing_integrity", target, "RECORD hash", "empty hash")
            if relative == "pip-24.0.dist-info/INSTALLER":
                if Path(target).read_text(encoding="utf-8").strip() != "pip":
                    reject("pip_installer_metadata", target, "pip", Path(target).read_text(encoding="utf-8")[:128])
            if relative == "pip-24.0.dist-info/REQUESTED" and Path(target).read_bytes():
                reject("pip_requested_metadata", target, "empty file", st.st_size)
        except ValueError:
            reject("record_size_format", target, "integer byte size", encoded_size)
        except (OSError, UnicodeError) as exc:
            reject("record_file_read", target, "readable file", f"{type(exc).__name__}: {exc}"[:256])

    for relative, target in pending_caches:
        if not valid_generated_cache(relative, target, hash_verified_python_sources):
            reject("pyc_source_unverified", target, "Python 3.12 cache with hash-verified pip .py source", generated_cache_source(relative))

    if record_self not in verified_paths:
        reject("record_self_missing", record_path, "RECORD self-row", "missing")

    expected_files = set()
    expected_dirs = {
        "bin", "include", "include/python3.12", "lib", "lib/python3.12",
        "lib/python3.12/site-packages",
    }
    for relative in verified_paths:
        target = record_target(site_packages, relative)
        if target is None:
            continue
        rel = os.path.relpath(target, venv).replace(os.sep, "/")
        expected_files.add(rel)
        parent = PurePosixPath(rel).parent
        while str(parent) not in (".", ""):
            expected_dirs.add(str(parent))
            parent = parent.parent
    allowed_files = expected_files | {
        "pyvenv.cfg", "bin/activate", "bin/activate.csh", "bin/activate.fish", "bin/Activate.ps1",
    }
    for activation in ("bin/activate", "bin/activate.csh", "bin/activate.fish"):
        path = os.path.join(venv, activation)
        st = lstat(path)
        if not owned_safe(st, "file") or stat.S_IMODE(st.st_mode) != 0o644 or st.st_size > 65536:
                reject("venv_activation_file", path, "root-owned regular mode 0644 <= 65536 bytes", metadata(st))
    activation = os.path.join(venv, "bin", "Activate.ps1")
    activation_stat = lstat(activation)
    if activation_stat is not None and (
        not owned_safe(activation_stat, "file")
        or stat.S_IMODE(activation_stat.st_mode) != 0o644
        or activation_stat.st_size > 65536
    ):
        reject("venv_activation_file", activation, "root-owned regular mode 0644 <= 65536 bytes", metadata(activation_stat))

    allowed_links.update({"lib64"} if lib64_stat is not None and stat.S_ISLNK(lib64_stat.st_mode) else set())
    if include_version_stat is not None and stat.S_ISLNK(include_version_stat.st_mode):
        allowed_links.add("include/python3.12")

    file_count = 0
    for directory, dirnames, filenames in os.walk(venv, topdown=True, followlinks=False):
        relative_dir = os.path.relpath(directory, venv).replace(os.sep, "/")
        if relative_dir != ".":
            st = lstat(directory)
            if not owned_safe(st, "directory") or stat.S_IMODE(st.st_mode) != 0o755:
                reject("venv_directory_metadata", directory, "root-owned directory mode 0755", metadata(st))
        for name in list(dirnames):
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, venv).replace(os.sep, "/")
            st = lstat(path)
            if st is not None and stat.S_ISLNK(st.st_mode):
                if relative not in allowed_links:
                    reject("venv_unknown_symlink", path, "allowlisted symlink", os.readlink(path))
                dirnames.remove(name)
                continue
            if (relative not in expected_dirs and relative != "lib64" and
                    not (relative.startswith("lib/python3.12/site-packages/pip/") and
                         name == "__pycache__")):
                reject("venv_unmanaged_directory", path, "listed package directory or expected venv directory", relative)
        for name in filenames:
            path = os.path.join(directory, name)
            relative = os.path.relpath(path, venv).replace(os.sep, "/")
            file_count += 1
            if file_count > MAX_TREE_FILES:
                reject("venv_tree_limit", venv, f"<= {MAX_TREE_FILES} files", file_count)
                break
            st = lstat(path)
            if st is not None and stat.S_ISLNK(st.st_mode):
                if relative in allowed_links:
                    if os.path.realpath(path) != system_interpreter:
                        reject("venv_interpreter_target", path, system_interpreter, os.path.realpath(path))
                    continue
                reject("venv_unknown_symlink", path, "allowlisted symlink", os.readlink(path))
                continue
            if st is None or not owned_safe(st, "file") or st.st_size > MAX_FILE_BYTES:
                reject("venv_file_metadata", path, "root-owned regular file <= size limit", metadata(st))
                continue
            if name.endswith(".pth"):
                reject("python_startup_injection", path, "no .pth startup injection", "unexpected .pth file")
            if relative in allowed_files:
                continue
            cache_relative = os.path.relpath(path, site_packages).replace(os.sep, "/")
            if os.path.commonpath((site_packages, os.path.abspath(path))) == site_packages and generated_cache_source(cache_relative) and valid_generated_cache(cache_relative, path, hash_verified_python_sources):
                continue
            reject("venv_unmanaged_payload", path, "RECORD-listed file or verified generated pip cache", relative)

    if file_count > MAX_TREE_FILES:
        reject("venv_tree_limit", venv, f"<= {MAX_TREE_FILES} files", file_count)


def main():
    try:
        inspect()
    except Exception as exc:
        reject("inspection_error", venv if "venv" in globals() else "inspector", "successful read-only inspection", f"{type(exc).__name__}: {exc}"[:256])
    print(json.dumps({
        "ok": not REASONS,
        "reasons": sorted(REASONS)[:40],
        "details": DETAILS[:40],
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "local_distributions": OBSERVED_DISTRIBUTIONS,
    }, sort_keys=True))


main()
