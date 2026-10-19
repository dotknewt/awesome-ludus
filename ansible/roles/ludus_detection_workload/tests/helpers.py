from __future__ import annotations

import getpass
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import support
from support import run_production_include


ROLE = "ludus_detection_workload"
_SUBPROCESS_RUN = subprocess.run


def _executable(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/sh\nset -eu\n{body}\n", encoding="utf-8")
    path.chmod(0o755)


def _tar_gz(path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o755
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))


def make_fixture(tmp_path: Path) -> dict[str, Any]:
    root = tmp_path / "target"
    fake_bin = tmp_path / "bin"
    state = root / "state"
    cache = root / "cache"
    namespace_root = root / "namespace-root"
    namespace_etc = namespace_root / "etc"
    namespace_opt = namespace_root / "opt"
    for directory in (root, fake_bin, state, cache, namespace_etc, namespace_opt):
        directory.mkdir(parents=True, exist_ok=True)
    for name in ("passwd", "group", "nsswitch.conf"):
        source_file = Path("/etc") / name
        if source_file.exists():
            shutil.copy2(source_file, namespace_etc / name)
    calls = root / "calls.jsonl"
    calls.touch()
    owner = getpass.getuser()
    workload_home = str(root / "home/debian")
    kubeconfig = str(root / "home/debian/.kube/config")
    cluster = "synthetic-range-minikube"

    def executable(name: str, body: str, *, log: bool = True) -> Path:
        prefix = f"printf '%s\\n' \"{name} $*\" >> {calls}\n" if log else ""
        path = fake_bin / name
        _executable(path, prefix + body)
        return path

    executable(
        "runuser",
        f"""
[ "$1" = -u ] || exit 64
identity=$2
shift 2
[ "$1" = -- ] || exit 64
shift
printf '%s\\n' "runuser identity=$identity $*" >> {calls}
export DE_IDENTITY=$identity
exec "$@"
""",
        log=False,
    )
    executable(
        "id",
        f"""
case "$1" in
  -u) [ -f {state}/user-$2 ] ;;
  -nG) user=${{2:-${{DE_IDENTITY:-}}}}; if [ "$user" = debian ]; then cat {state}/debian-groups; else cat {state}/deotel-groups; fi ;;
  *) exit 64 ;;
esac
""",
    )
    executable("useradd", f'for user in "$@"; do :; done; touch {state}/user-$user; printf deotel > {state}/deotel-groups')
    executable("usermod", f"grep -qw docker {state}/debian-groups || printf ' docker' >> {state}/debian-groups")
    executable("gpasswd", f"[ \"$*\" = '-d deotel docker' ] || exit 64; sed 's/ docker//g' {state}/deotel-groups > {state}/groups.tmp; mv {state}/groups.tmp {state}/deotel-groups")
    executable(
        "dpkg-query",
        f"""
for package in "$@"; do :; done
[ -f {state}/package-$package ] || exit 1
cat {state}/package-$package
""",
    )
    executable(
        "apt-get",
        f"""
case "$1" in
  update) : ;;
  install) shift 2; for pin in "$@"; do name=${{pin%%=*}}; version=${{pin#*=}}; printf %s "$version" > {state}/package-$name; done ;;
  *) exit 64 ;;
esac
""",
    )
    executable(
        "setfacl",
        f"""
case "$*" in
  *'u:deotel:--x '*'/docker') touch {state}/acl-docker ;;
  *'d:u:deotel:r-X '*'/docker/containers') touch {state}/acl-containers-default ;;
  *'u:deotel:r-X '*'/docker/containers') touch {state}/acl-containers ;;
  *) exit 64 ;;
esac
""",
    )
    executable(
        "getfacl",
        f"""
for path in "$@"; do :; done
case "$path" in
  */docker) [ ! -f {state}/acl-docker ] || printf '%s\n' 'user:deotel:--x' ;;
  */docker/containers)
    [ ! -f {state}/acl-containers ] || printf '%s\n' 'user:deotel:r-x'
    [ ! -f {state}/acl-containers-default ] || printf '%s\n' 'default:user:deotel:r-x' ;;
  *) exit 64 ;;
esac
""",
    )
    probe = root / "var/lib/docker/containers/synthetic/synthetic-json.log"
    probe.parent.mkdir(parents=True)
    probe.write_text('{"log":"{\\"message\\":\\"safe\\"}\\n"}\n', encoding="utf-8")
    executable("find", f"[ -f {state}/no-docker-log ] || printf '%s\\n' {probe}")
    executable("rmdir", "/usr/bin/rmdir \"$@\"")
    rmdir_python = executable(
        "rmdir-python",
        f"""
if [ -f {state}/rmdir-eacces ]; then exit 20; fi
exec {os.sys.executable} "$@"
""",
    )
    executable(
        "systemctl",
        f"""
for service in "$@"; do :; done
case "$1" in
  show)
    [ ! -f {state}/fail-systemd-probe ] || exit 90
    case "$*" in
      *LoadState*) if [ -f {root}/systemd/$service ]; then printf '%s\\n' loaded; else printf '%s\\n' not-found; fi ;;
      *MainPID*) if [ -f {state}/active-$service ]; then printf '%s\\n' 4242; else printf '%s\\n' 0; fi ;;
      *) exit 64 ;;
    esac ;;
  is-enabled)
    [ ! -f {state}/fail-systemd-probe ] || exit 90
    if [ -f {state}/enabled-$service ]; then printf '%s\\n' enabled
    elif [ -f {root}/systemd/$service ]; then printf '%s\\n' disabled; exit 1
    else printf '%s\\n' not-found; exit 1; fi ;;
  is-active)
    [ ! -f {state}/fail-systemd-probe ] || exit 90
    if [ -f {state}/active-$service ]; then printf '%s\\n' active
    else printf '%s\\n' inactive; exit 3; fi ;;
  enable) [ -f {root}/systemd/$service ] || exit 76; touch {state}/enabled-$service ;;
  disable) [ -f {state}/enabled-$service ] || exit 77; rm -f {state}/enabled-$service ;;
  start)
    [ -f {root}/systemd/$service ] || exit 76
    [ ! -f {state}/active-$service ] || exit 78
    [ ! -f {state}/fail-otel-start ] || [ "$service" != otel-host.service ] || exit 91
    if [ "$service" = otel-host.service ]; then
      [ -f {state}/loaded-otel-host-unit ] || exit 96
      [ "$(sha256sum {root}/systemd/otel-host.service | cut -d' ' -f1)" = "$(cat {state}/loaded-otel-host-unit)" ] || exit 97
    fi
    touch {state}/active-$service
    if [ "$service" = otel-host.service ]; then
      cp {state}/deotel-groups {state}/process-groups-$service
      [ ! -f {state}/fail-remediation-marker ] || mkdir -p {root}/etc/detection-engineering/workload/.otel-host-remediation-v1
    fi ;;
  restart)
    if [ "$service" = Splunkd.service ]; then
      [ ! -f {state}/fail-splunk-restart ] || exit 75
      touch {state}/active-$service
      if [ -f {namespace_opt}/splunk/etc/apps/detection_hec/local/inputs.conf ]; then
        touch {state}/splunk-effective-input
      else
        rm -f {state}/splunk-effective-input
      fi
    else
      [ -f {state}/active-$service ] || exit 79
      [ ! -f {state}/fail-otel-restart ] || exit 92
      cp {state}/deotel-groups {state}/process-groups-$service
    fi ;;
  stop) [ -f {state}/active-$service ] || exit 80; [ ! -f {state}/fail-otel-stop ] || exit 93; rm -f {state}/active-$service {state}/process-groups-$service ;;
  daemon-reload)
    [ ! -f {state}/fail-daemon-reload ] || exit 94
    if [ -f {root}/systemd/otel-host.service ]; then sha256sum {root}/systemd/otel-host.service | cut -d' ' -f1 > {state}/loaded-otel-host-unit; fi ;;
  *) exit 64 ;;
esac
""",
    )
    executable(
        "ps",
        f"""
[ "$*" = '-o supgrp= -p 4242' ] || exit 64
[ -f {state}/active-otel-host.service ] || exit 95
cat {state}/process-groups-otel-host.service
""",
    )
    executable(
        "gpg",
        f"""
printf '%s\\n' 'pub:-:4096:1:AAAA:0:0:::::::' 'fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:'
if [ -f {state}/gpg-extra-primary ]; then
  printf '%s\\n' 'pub:-:4096:1:BBBB:0:0:::::::' 'fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:'
fi
""",
    )
    (state / "user-debian").touch()
    (state / "debian-groups").write_text("debian\n", encoding="utf-8")
    (state / "deotel-groups").write_text("deotel\n", encoding="utf-8")

    common = f"""
identity=${{DE_IDENTITY:-root}}
context=none
for arg in "$@"; do
  case "$arg" in --context=*|--kube-context=*|--profile=*) context=${{arg#*=}} ;; esac
done
printf '%s\\n' "TOOL identity=$identity HOME=${{HOME:-}} KUBECONFIG=${{KUBECONFIG:-}} context=$context $*" >> {calls}
[ "$identity" = debian ] || exit 70
[ "${{HOME:-}}" = "{workload_home}" ] || exit 71
[ "${{KUBECONFIG:-}}" = "{kubeconfig}" ] || exit 72
"""
    minikube_body = common.replace("TOOL", "minikube") + f"""
case "$*" in
  *'version --short'*) printf '%s\\n' 'v1.2.3-synthetic' ;;
  *'status --profile {cluster}'*) [ -f {state}/minikube ] ;;
  *'start --profile={cluster}'*) touch {state}/minikube ;;
  *'stop --profile={cluster}'*) rm -f {state}/minikube ;;
  *) exit 64 ;;
esac
"""
    kubectl_body = common.replace("TOOL", "kubectl") + f"""
case "$*" in
  *'version --client=true --output=yaml'*)
    if [ -f {state}/malformed-kubectl-version ]; then
      printf '%s\\n' 'clientVersion: malformed'
    elif [ -f {state}/wrong-kubectl-version ]; then
      printf '%s\\n' 'clientVersion:' '  gitVersion: v9.9.9-wrong'
    else
      printf '%s\\n' 'clientVersion:' '  buildDate: "2026-10-17T00:00:00Z"' '  compiler: gc' '  gitCommit: abcdef0123456789' '  gitTreeState: clean' '  gitVersion: v1.2.3-synthetic' '  goVersion: go1.25.1' '  major: "1"' '  minor: "2"' '  platform: linux/amd64' 'kustomizeVersion: v5.7.1'
    fi ;;
  *' diff -f -')
    body=$(cat); printf %s "$body" | grep -q 'kind: Secret' && exit 81
    key=rbac
    digest=$(printf %s "$body" | sha256sum | cut -d' ' -f1)
    [ -f {state}/kubectl-$key ] && [ "$(cat {state}/kubectl-$key)" = "$digest" ] && exit 0 || exit 1 ;;
  *' apply -f -')
    body=$(cat); if printf %s "$body" | grep -q 'kind: Secret'; then key=secret; [ -f {state}/kubectl-rbac ] || exit 73; else key=rbac; fi
    printf '%s\\n' "kubectl identity=$identity HOME=${{HOME:-}} KUBECONFIG=${{KUBECONFIG:-}} context=$context apply-$key" >> {calls}
    if [ "$key" = secret ] && [ -f {state}/kubectl-apply-nonzero-empty ]; then exit 82; fi
    if [ "$key" = secret ] && [ -f {state}/kubectl-apply-nonzero-success ]; then printf '%s\\n' 'secret/splunk-hec configured'; exit 82; fi
    digest=$(printf %s "$body" | sha256sum | cut -d' ' -f1)
    if [ "$key" = secret ]; then resource=secret/splunk-hec; else resource=clusterrole/otel-collector; fi
    if [ -f {state}/kubectl-$key ] && [ "$(cat {state}/kubectl-$key)" = "$digest" ]; then
      printf '%s unchanged\\n' "$resource"
    elif [ -f {state}/kubectl-$key ]; then
      printf %s "$digest" > {state}/kubectl-$key
      printf '%s configured\\n' "$resource"
    else
      printf %s "$digest" > {state}/kubectl-$key
      printf '%s created\\n' "$resource"
    fi ;;
  *'delete secret splunk-hec'*)
    if [ -f {state}/kubectl-delete-probe-error ]; then exit 83; fi
    if [ -f {state}/kubectl-delete-nonzero-success ]; then printf '%s\\n' 'secret "splunk-hec" deleted'; exit 83; fi
    if [ -f {state}/kubectl-secret ]; then rm -f {state}/kubectl-secret; printf '%s\\n' 'secret "splunk-hec" deleted'; fi ;;
  *'get secret splunk-hec --output=name'*)
    [ ! -f {state}/kubectl-secret-probe-error ] || {{ printf '%s\\n' 'Unable to connect to the server' >&2; exit 84; }}
    if [ -f {state}/kubectl-secret ]; then printf '%s\\n' secret/splunk-hec
    else printf '%s\\n' 'Error from server (NotFound): secrets "splunk-hec" not found' >&2; exit 1; fi ;;
  *) exit 64 ;;
esac
"""
    helm_body = common.replace("TOOL", "helm") + f"""
case "$*" in
  *'version --short'*)
    if [ -f {state}/helm-version-output ]; then cat {state}/helm-version-output
    elif [ -f {state}/malformed-helm-version ]; then printf '%s\\n' 'version.BuildInfo{{Version:"broken"}}'
    elif [ -f {state}/wrong-helm-version ]; then printf '%s\\n' 'v9.9.9+gwrong999'
    else printf '%s\\n' 'v1.2.3-synthetic+gabcdef'; fi ;;
  *' pull '*) cp {root}/chart-source.tgz {cache}/opentelemetry-collector-0.1.2-synthetic.tgz ;;
  *'status otel-runtime --namespace otel-system --output json'*) [ ! -f {state}/helm-probe-error ] || {{ printf '%s\\n' 'Error: Kubernetes cluster unreachable' >&2; exit 86; }}; [ -f {state}/helm-release.json ] || {{ printf '%s\\n' 'Error: release: not found' >&2; exit 1; }}; cat {state}/helm-release.json ;;
  *'get values otel-runtime --namespace otel-system --output yaml'*) cat {state}/helm-values.yaml ;;
  *'upgrade --install otel-runtime'*)
    previous=; values=; for arg in "$@"; do [ "$previous" = --values ] && values=$arg; previous=$arg; done
    cp "$values" {state}/helm-values.yaml
    printf '%s' '{{"chart":"opentelemetry-collector-0.1.2-synthetic"}}' > {state}/helm-release.json ;;
  *'uninstall otel-runtime --namespace otel-system'*) [ ! -f {state}/fail-helm-uninstall ] || exit 74; rm -f {state}/helm-release.json {state}/helm-values.yaml ;;
  *) exit 64 ;;
esac
"""
    otel_body = f"printf '%s\\n' \"otelcol $*\" >> {calls}\ncase \"$*\" in '--version') printf '%s\\n' 'otelcol-contrib version 1.2.3-synthetic' ;; *) : ;; esac\n"

    def script_bytes(body: str) -> bytes:
        return f"#!/bin/sh\nset -eu\n{body}\n".encode()

    raw_sources = {
        "minikube": script_bytes(minikube_body),
        "kubectl": script_bytes(kubectl_body),
    }
    artifact_paths = {
        "minikube": cache / "minikube.artifact",
        "kubectl": cache / "kubectl.artifact",
        "helm": cache / "helm.artifact",
        "otel_host": cache / "otel-host.artifact",
    }
    artifact_paths["minikube"].write_bytes(raw_sources["minikube"])
    artifact_paths["kubectl"].write_bytes(raw_sources["kubectl"])
    _tar_gz(artifact_paths["helm"], {"linux-amd64/helm": script_bytes(helm_body)})
    _tar_gz(artifact_paths["otel_host"], {"otelcol-contrib": script_bytes(otel_body)})

    source = namespace_etc / "detection-engineering/secrets/hec-workload.token"
    source.parent.mkdir(parents=True)
    source.write_text("SYNTHETIC-HEC-TOKEN-NEVER-LOG\n", encoding="utf-8")
    source.chmod(0o600)
    splunk_input = namespace_opt / "splunk/etc/apps/detection_hec/local/inputs.conf"
    splunk_input.parent.mkdir(parents=True)
    splunk_input.write_text("[http://detection-workload]\n", encoding="utf-8")
    (state / "splunk-effective-input").touch()

    chart_bytes = b"synthetic chart fixture\n"
    (root / "chart-source.tgz").write_bytes(chart_bytes)
    chart_archive = cache / "opentelemetry-collector-0.1.2-synthetic.tgz"
    chart_archive.write_bytes(chart_bytes)
    docker_key = root / "etc/apt/docker.gpg"
    docker_key.parent.mkdir(parents=True)
    docker_key.write_text("synthetic Docker signing key fixture\n", encoding="utf-8")
    os_release = root / "etc/os-release"
    os_release.write_text("ID=synthetic\nVERSION_CODENAME=synthetic-suite\n", encoding="utf-8")

    def runtime_artifact(name: str) -> dict[str, Any]:
        return {
            "version": "1.2.3-synthetic",
            "url": f"https://fixtures.invalid/{name}",
            "sha256": hashlib.sha256(artifact_paths[name].read_bytes()).hexdigest(),
            "download_auth_required": False,
        }

    artifacts = {name: runtime_artifact(name) for name in artifact_paths}
    artifacts["otel_host"] = {**artifacts["otel_host"], "build": "synthetic-build"}
    layouts = {}
    for name, member in {"minikube": None, "kubectl": None, "helm": "linux-amd64/helm", "otel_host": "otelcol-contrib"}.items():
        layouts[name] = {
            "status": "VERIFIED",
            "source": {"url": f"https://fixtures.invalid/layouts/{name}", "observed_at": "2026-10-16T00:00:00Z"},
            "observed": {
                "artifact_sha256": artifacts[name]["sha256"],
                "format": "raw" if member is None else "tar.gz",
                "member": member,
            },
            "limitation": "explicitly synthetic fixture; not factual evidence",
            "stops": [7, 8, 9, 10],
        }

    variables = {
        "range_id": "synthetic-range",
        "detection_docker_packages": [
            {"name": "docker-ce", "version": "1.2.3-1"},
            {"name": "containerd.io", "version": "1.2.3-1"},
            {"name": "docker-buildx-plugin", "version": "1.2.3-1"},
        ],
        "detection_docker_repository_url": "https://fixtures.invalid/docker",
        "detection_docker_signing_key_url": "https://fixtures.invalid/docker.gpg",
        "detection_docker_signing_key_fingerprint": "A" * 40,
        "detection_minikube_artifact": artifacts["minikube"],
        "detection_kubectl_artifact": artifacts["kubectl"],
        "detection_helm_artifact": artifacts["helm"],
        "detection_otel_host_artifact": artifacts["otel_host"],
        "detection_runtime_artifact_layouts": layouts,
        "detection_otel_chart": {
            "repository": "https://fixtures.invalid/charts", "chart": "opentelemetry-collector",
            "version": "0.1.2-synthetic", "digest": "sha256:" + hashlib.sha256(chart_bytes).hexdigest(),
        },
        "detection_otel_contract": {
            "secret_file_provider": True, "audit_path": "/var/log/kubernetes/audit/audit.log",
            "node_log_inputs": ["/var/log/containers/*.log", "/var/log/pods/kube-system_*/*/*.log"],
            "required_rbac": {"nodes": ["get", "list", "watch"], "pods": ["get", "list", "watch"]},
        },
        "detection_workload_user": "debian", "detection_workload_home": workload_home,
        "detection_cluster_name": cluster, "detection_kubeconfig_path": kubeconfig,
        "detection_splunk_hec_url": "http://synthetic-range-splunk:8088/services/collector/event",
        "detection_runtime_token_state": "present",
        "detection_splunk_hec_handoff": {
            "delegate_host": "testhost", "source_path": "/etc/detection-engineering/secrets/hec-workload.token",
            "input_path": "/opt/splunk/etc/apps/detection_hec/local/inputs.conf", "service_name": "Splunkd.service",
        },
        "detection_root_owner": "root", "detection_root_group": "root",
        "detection_workload_owner": "root", "detection_workload_group": "root",
        "detection_otel_owner": "root", "detection_otel_group": "root",
        "detection_etc_dir": str(root / "etc/detection-engineering"),
        "detection_secret_dir": str(root / "etc/detection-engineering/secrets"),
        "detection_host_token_path": str(root / "etc/detection-engineering/secrets/hec-workload.token"),
        "detection_minikube_home": str(root / "home/debian/.minikube"),
        "detection_audit_policy_stage_path": str(root / "home/debian/.minikube/files/etc/kubernetes/audit-policy.yaml"),
        "detection_workload_config_dir": str(root / "etc/detection-engineering/workload"),
        "detection_systemd_dir": str(root / "systemd"), "detection_cache_dir": str(cache),
        "detection_minikube_path": str(fake_bin / "minikube"), "detection_kubectl_path": str(fake_bin / "kubectl"),
        "detection_helm_path": str(fake_bin / "helm"), "detection_otel_host_path": str(fake_bin / "otelcol"),
        "detection_minikube_artifact_path": str(artifact_paths["minikube"]),
        "detection_kubectl_artifact_path": str(artifact_paths["kubectl"]),
        "detection_helm_artifact_path": str(artifact_paths["helm"]),
        "detection_otel_host_artifact_path": str(artifact_paths["otel_host"]),
        "detection_artifact_installer_path": str(cache / "install-runtime-artifact.py"),
        "detection_otel_chart_archive_path": str(chart_archive),
        "detection_docker_keyring_path": str(docker_key),
        "detection_docker_source_path": str(root / "etc/apt/docker.sources"),
        "detection_docker_root": str(root / "var/lib/docker"), "detection_docker_log_probe_path": str(probe),
        "detection_python": os.sys.executable, "detection_os_release_path": str(os_release),
        "detection_apt_get": str(fake_bin / "apt-get"), "detection_dpkg_query": str(fake_bin / "dpkg-query"),
        "detection_useradd": str(fake_bin / "useradd"), "detection_usermod": str(fake_bin / "usermod"),
        "detection_id": str(fake_bin / "id"), "detection_gpasswd": str(fake_bin / "gpasswd"),
        "detection_runuser": str(fake_bin / "runuser"), "detection_docker_cli": str(fake_bin / "docker"),
        "detection_setfacl": str(fake_bin / "setfacl"), "detection_find": str(fake_bin / "find"),
        "detection_getfacl": str(fake_bin / "getfacl"),
        "detection_gpg": str(fake_bin / "gpg"), "detection_systemctl": str(fake_bin / "systemctl"),
        "detection_ps": str(fake_bin / "ps"),
        "detection_rmdir": str(fake_bin / "rmdir"),
    }
    # Docker readiness is separate from runtime artifacts and is package-owned.
    docker = f"""
identity=${{DE_IDENTITY:-root}}
printf '%s\\n' "docker identity=$identity HOME=${{HOME:-}} $*" >> {calls}
[ "$identity" = debian ] || exit 70
[ "${{HOME:-}}" = "{workload_home}" ] || exit 71
case "$*" in info) printf '%s\\n' 'Server Version: synthetic' ;; *) exit 64 ;; esac
"""
    _executable(fake_bin / "docker", docker)
    namespace_wrapper = root / "run-in-fixture-namespace"
    _executable(
        namespace_wrapper,
        'fixture_root=$1\nshift\nmount --bind "$fixture_root/etc" /etc\nmount --bind "$fixture_root/opt" /opt\nexec "$@"',
    )
    return {
        "root": root,
        "fake_bin": fake_bin,
        "calls": calls,
        "state": state,
        "variables": variables,
        "source": source,
        "splunk_input": splunk_input,
        "namespace_root": namespace_root,
        "namespace_wrapper": namespace_wrapper,
        "rmdir_python": rmdir_python,
    }


def run_role(fixture: dict[str, Any], **updates: Any):
    variables = dict(fixture["variables"])
    variables.update(updates)

    def run_in_namespace(command, **kwargs):
        namespaced = [
            "/usr/bin/unshare",
            "--user",
            "--map-root-user",
            "--mount",
            "--fork",
            str(fixture["namespace_wrapper"]),
            str(fixture["namespace_root"]),
            *command,
        ]
        return _SUBPROCESS_RUN(namespaced, **kwargs)

    with patch.object(support.subprocess, "run", side_effect=run_in_namespace):
        return run_production_include(ROLE, "main", variables, fixture["fake_bin"])


def calls(fixture: dict[str, Any]) -> list[str]:
    return fixture["calls"].read_text(encoding="utf-8").splitlines()
