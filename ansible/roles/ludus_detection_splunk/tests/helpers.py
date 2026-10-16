from __future__ import annotations

import getpass
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from support import run_production_include


ROLE = "ludus_detection_splunk"


def _executable(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/sh\nset -eu\n{body}\n", encoding="utf-8")
    path.chmod(0o755)


def make_fixture(tmp_path: Path) -> dict[str, Any]:
    root = tmp_path / "target"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    root.mkdir()
    artifact = root / "splunk.deb"
    artifact.write_bytes(b"explicitly synthetic splunk package fixture\n")
    calls = root / "calls.jsonl"
    calls.touch()
    package_state = root / "package-state"
    service_state = root / "service-state"
    service_enabled = root / "service-enabled"

    logger = f"printf '%s\\n' \"$*\" >> {calls}"
    _executable(
        fake_bin / "dpkg-deb",
        f"{logger}\n"
        "case \"$3\" in\n"
        "  Package) printf '%s\\n' splunk ;;\n"
        "  Version) printf '%s\\n' 10.6.1.1 ;;\n"
        "  Architecture) printf '%s\\n' amd64 ;;\n"
        "  *) exit 2 ;;\n"
        "esac",
    )
    _executable(
        fake_bin / "dpkg-query",
        f"{logger}\n"
        "expected=$(printf '%s%s\\t%s' '--showformat=' '${Status}' '${Version}')\n"
        "[ \"$2\" = \"$expected\" ] || exit 64\n"
        f"if [ -f {package_state} ]; then cat {package_state}; else exit 1; fi",
    )
    _executable(
        fake_bin / "dpkg",
        f"{logger}\nprintf 'install ok installed\\t%s\\n' 10.6.1.1 > {package_state}",
    )
    _executable(
        fake_bin / "systemctl",
        f"{logger}\n"
        "case \"$1\" in\n"
        f"  restart|start) printf running > {service_state} ;;\n"
        f"  enable) printf enabled > {service_enabled} ;;\n"
        f"  is-active) [ -f {service_state} ] && [ \"$(cat {service_state})\" = running ] ;;\n"
        f"  is-enabled) [ -f {service_enabled} ] && [ \"$(cat {service_enabled})\" = enabled ] ;;\n"
        "esac",
    )
    _executable(
        fake_bin / "splunk",
        f"{logger}\n"
        "case \"${1:-}\" in\n"
        f"  start) printf running > {service_state} ;;\n"
        f"  enable) printf enabled > {service_enabled} ;;\n"
        f"  status) [ -f {service_state} ] && [ \"$(cat {service_state})\" = running ] && printf '%s\\n' 'splunkd is running' ;;\n"
        "esac",
    )

    config_root = root / "opt/splunk/etc"
    variables = {
        "range_id": "synthetic-range",
        "detection_splunk_artifact": {
            "version": "10.6.1.1",
            "build": "b2ae2962645c",
            "url": "https://fixtures.invalid/splunk-10.6.1.1-b2ae2962645c-linux-amd64.deb",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "download_auth_required": False,
        },
        "detection_splunk_download_auth_path": None,
        "detection_splunk_license": {
            "initial_mode": "ENTERPRISE_60_DAY_TRIAL",
            "trial_days_user_confirmed": 60,
            "terms_confirmation": "USER_CONFIRMED_NOT_INDEPENDENTLY_VERIFIED",
            "expiry_behavior": "synthetic fixture: verified separately before deployment",
            "hec": True,
            "search_api": True,
            "auth_behavior": "synthetic fixture: verified separately before deployment",
        },
        "detection_splunk_hec_supported": True,
        "detection_splunk_search_api_supported": True,
        "detection_splunk_bind_ip": "10.77.10.14",
        "detection_splunk_admin_password": "ADMIN-CANARY-never-in-process-output",
        "detection_splunk_restore_authorized": False,
        "detection_splunk_maintenance_state_path": str(root / "state/maintenance.json"),
        "detection_splunk_artifact_path": str(artifact),
        "detection_splunk_provenance_path": str(root / "etc/install-provenance.yml"),
        "detection_splunk_secret_dir": str(root / "etc/secrets"),
        "detection_splunk_hec_token_path": str(root / "etc/secrets/hec-workload.token"),
        "detection_splunk_bootstrap_state_path": str(root / "state/bootstrap-complete"),
        "detection_splunk_seed_path": str(config_root / "system/local/user-seed.conf"),
        "detection_splunk_indexes_path": str(config_root / "system/local/indexes.conf"),
        "detection_splunk_inputs_path": str(config_root / "system/local/inputs.conf"),
        "detection_splunk_web_path": str(config_root / "system/local/web.conf"),
        "detection_splunk_hec_input_path": str(config_root / "apps/detection_hec/local/inputs.conf"),
        "detection_splunk_cli": str(fake_bin / "splunk"),
        "detection_splunk_dpkg": str(fake_bin / "dpkg"),
        "detection_splunk_dpkg_query": str(fake_bin / "dpkg-query"),
        "detection_splunk_dpkg_deb": str(fake_bin / "dpkg-deb"),
        "detection_splunk_systemctl": str(fake_bin / "systemctl"),
        "detection_splunk_python": os.sys.executable,
        "detection_splunk_file_owner": getpass.getuser(),
        "detection_splunk_file_group": getpass.getuser(),
        "detection_splunk_root_owner": getpass.getuser(),
        "detection_splunk_root_group": getpass.getuser(),
    }
    return {
        "root": root,
        "fake_bin": fake_bin,
        "calls": calls,
        "package_state": package_state,
        "service_state": service_state,
        "service_enabled": service_enabled,
        "variables": variables,
    }


def run_role(fixture: dict[str, Any], **updates: Any):
    variables = dict(fixture["variables"])
    variables.update(updates)
    return run_production_include(ROLE, "main", variables, fixture["fake_bin"])


def command_calls(fixture: dict[str, Any]) -> list[str]:
    return [line for line in fixture["calls"].read_text(encoding="utf-8").splitlines() if line]


def maintenance_manifest(fixture: dict[str, Any]) -> dict[str, Any]:
    return json.loads(Path(fixture["variables"]["detection_splunk_maintenance_state_path"]).read_text(encoding="utf-8"))


def write_manifest(fixture: dict[str, Any], state: str) -> dict[str, Any]:
    artifact = fixture["variables"]["detection_splunk_artifact"]
    manifest = {
        "schema_version": 1,
        "range_id": "synthetic-range",
        "state": state,
        "operation_id": "7740b94c-301d-4a0a-8854-cc2a7828372e",
        "package": {
            "name": "splunk",
            "version": artifact["version"],
            "build": artifact["build"],
            "architecture": "amd64",
            "sha256": artifact["sha256"],
        },
        "startup_paths": ["Splunkd.service"],
        "baseline": {
            "captured_at": "2026-10-16T12:00:00Z",
            "writers_stopped": True,
            "paths": [],
        },
        "journal": [
            {
                "at": "2026-10-16T12:00:00Z",
                "from": "HEALTHY",
                "to": state,
                "result": "synthetic fixture",
                "limitation": "not live evidence",
            }
        ],
        "acceptance": {
            "run_id": "prior-run",
            "summary_sha256": "a" * 64,
            "accepted_at": "2026-10-16T11:00:00Z",
        },
    }
    path = Path(fixture["variables"]["detection_splunk_maintenance_state_path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest
