from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from passlib.apache import HtpasswdFile

from helpers import ROLE_DIR, env_value, make_source, run_tasks


AUTHENTICATION = ROLE_DIR / "tasks" / "authentication.yml"
CONFIGURE = ROLE_DIR / "tasks" / "configure.yml"
SECRET_KEY = ROLE_DIR / "tasks" / "secret-key.yml"
TLS = ROLE_DIR / "tasks" / "tls.yml"
PACKAGES = ROLE_DIR / "tasks" / "packages.yml"


def fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def openssl(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["openssl", *args], text=True, capture_output=True, check=check)


def test_target_installs_cryptography_for_native_tls_modules() -> None:
    import yaml

    tasks = yaml.safe_load(PACKAGES.read_text(encoding="utf-8"))
    packages = next(task["ansible.builtin.apt"]["name"] for task in tasks if "ansible.builtin.apt" in task)
    assert "python3-cryptography" in packages


def test_fresh_upstream_scaffold_initializes_credentials_and_reruns_without_rotation(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    placeholder = source / "opensearch" / ".gitignore"
    placeholder_before = placeholder.read_bytes()

    first = run_tasks(tmp_path, [CONFIGURE, AUTHENTICATION])

    assert first.returncode == 0, first.stdout + first.stderr
    credentials = [
        source / "config" / name
        for name in ("netbox-secret.env", "postgres.env", "valkey.env", "arkime-secret.env", "auth.env")
    ] + [source / ".opensearch.primary.curlrc"]
    before = {path: path.read_bytes() for path in credentials}
    assert all(before.values())

    second = run_tasks(tmp_path, [CONFIGURE, AUTHENTICATION])

    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout
    assert before == {path: path.read_bytes() for path in credentials}
    assert placeholder.read_bytes() == placeholder_before


def test_documented_machine_credential_is_applied_and_converges(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    variables = {
        "ludus_install_malcolm_admin_username": "debian",
        "ludus_install_malcolm_admin_password": "debian",
    }

    first = run_tasks(tmp_path, [CONFIGURE, AUTHENTICATION], variables=variables)
    assert first.returncode == 0, first.stdout + first.stderr
    htpasswd = HtpasswdFile(str(source / "nginx" / "htpasswd"))
    assert htpasswd.check_password("debian", "debian")

    second = run_tasks(tmp_path, [CONFIGURE, AUTHENTICATION], variables=variables)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout
    assert HtpasswdFile(str(source / "nginx" / "htpasswd")).check_password("debian", "debian")


def test_backend_secrets_recover_individually_and_converge(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    netbox = source / "config" / "netbox-secret.env"
    retained = "R" * 50
    netbox.write_text(f"SECRET_KEY={retained}\nSUPERUSER_API_TOKEN={'x' * 40}\nSUPERUSER_PASSWORD=\n", encoding="utf-8")
    primary_curlrc = source / ".opensearch.primary.curlrc"
    primary_curlrc.touch()

    first = run_tasks(tmp_path, [CONFIGURE, AUTHENTICATION])

    assert first.returncode == 0, first.stdout + first.stderr
    assert env_value(netbox, "SECRET_KEY") == retained
    assert len(env_value(netbox, "SUPERUSER_API_TOKEN")) == 40
    assert env_value(netbox, "SUPERUSER_API_TOKEN") != "x" * 40
    assert len(env_value(netbox, "SUPERUSER_PASSWORD")) == 24
    assert primary_curlrc.read_text(encoding="utf-8").startswith('user: "malcolm_internal:')
    evidence = source / ".ludus-initialization"
    for marker in (
        "config__netbox-secret.env",
        "config__postgres.env",
        "config__valkey.env",
        "config__arkime-secret.env",
        "opensearch-primary-curlrc",
        "forwarding-ca",
    ):
        assert (evidence / marker).is_file()
    values = {
        path.name: path.read_bytes()
        for path in (source / "config").glob("*.env")
        if path.name in {"netbox-secret.env", "postgres.env", "valkey.env", "arkime-secret.env", "auth.env"}
    }
    second = run_tasks(tmp_path, [CONFIGURE, AUTHENTICATION])
    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout
    assert values == {path.name: path.read_bytes() for path in (source / "config").glob("*.env") if path.name in values}


def test_established_backend_file_loss_fails_before_example_recreation(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    initialized = run_tasks(tmp_path, [CONFIGURE, AUTHENTICATION])
    assert initialized.returncode == 0, initialized.stdout + initialized.stderr
    postgres = source / "config" / "postgres.env"
    postgres.unlink()

    failed = run_tasks(tmp_path, [CONFIGURE])

    assert failed.returncode != 0
    assert "postgres.env" in failed.stdout + failed.stderr
    assert "restore" in (failed.stdout + failed.stderr).lower()
    assert not postgres.exists()


def test_legacy_backend_loss_with_retained_data_fails_before_example_recreation(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    configured = run_tasks(tmp_path, [CONFIGURE])
    assert configured.returncode == 0, configured.stdout + configured.stderr
    postgres = source / "config" / "postgres.env"
    postgres.unlink()
    data = source / "postgres"
    data.mkdir()
    (data / "PG_VERSION").write_text("16\n", encoding="utf-8")

    failed = run_tasks(tmp_path, [CONFIGURE])

    assert failed.returncode != 0
    assert "legacy" in (failed.stdout + failed.stderr).lower()
    assert "postgres.env" in failed.stdout + failed.stderr
    assert not postgres.exists()
    assert not (source / ".ludus-initialization").exists()


def test_established_primary_curlrc_complete_loss_fails_without_rotation(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    initialized = run_tasks(tmp_path, [CONFIGURE, AUTHENTICATION])
    assert initialized.returncode == 0, initialized.stdout + initialized.stderr
    primary = source / ".opensearch.primary.curlrc"
    primary.unlink()

    failed = run_tasks(tmp_path, [AUTHENTICATION])

    assert failed.returncode != 0
    assert "primary OpenSearch" in failed.stdout + failed.stderr
    assert "restore" in (failed.stdout + failed.stderr).lower()
    assert not primary.exists()


def test_legacy_primary_curlrc_loss_with_retained_data_fails_before_generation(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    configured = run_tasks(tmp_path, [CONFIGURE])
    assert configured.returncode == 0, configured.stdout + configured.stderr
    retained = source / "opensearch" / "nodes"
    retained.mkdir()
    (retained / "established-state").write_text("retained\n", encoding="utf-8")
    primary = source / ".opensearch.primary.curlrc"
    before = {
        name: (source / "config" / name).read_bytes()
        for name in ("netbox-secret.env", "postgres.env", "valkey.env", "arkime-secret.env")
    }

    failed = run_tasks(tmp_path, [AUTHENTICATION])

    assert failed.returncode != 0
    assert "legacy" in (failed.stdout + failed.stderr).lower()
    assert "primary OpenSearch" in failed.stdout + failed.stderr
    assert not primary.exists()
    assert before == {name: (source / "config" / name).read_bytes() for name in before}
    assert not any((source / ".ludus-initialization").iterdir())


def test_failed_final_secret_persistence_leaves_no_marker_and_rerun_resumes(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    configured = run_tasks(tmp_path, [CONFIGURE])
    assert configured.returncode == 0, configured.stdout + configured.stderr
    evidence = source / ".ludus-initialization"
    evidence.mkdir(mode=0o750)
    netbox = source / "config" / "netbox-secret.env"
    netbox.write_text(
        f"SECRET_KEY={'R' * 50}\nSUPERUSER_PASSWORD={'S' * 24}\nSUPERUSER_API_TOKEN={'x' * 40}\n",
        encoding="utf-8",
    )
    marker = evidence / "config__netbox-secret.env"
    variables = {
        "item": {"file": "netbox-secret.env"},
        "_ludus_install_malcolm_secret_file": str(netbox),
        "_ludus_install_malcolm_secret_key": "SUPERUSER_API_TOKEN",
        "_ludus_install_malcolm_secret_length": 40,
        "_ludus_install_malcolm_secret_alphabet": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
        "_ludus_install_malcolm_secret_pattern": "^[A-Za-z0-9_]{40,}$",
        "_ludus_install_malcolm_secret_finalize_file": True,
        "_ludus_install_malcolm_secret_evidence": str(marker),
    }
    (source / "config").chmod(0o500)

    interrupted = run_tasks(tmp_path, [SECRET_KEY], variables=variables)

    assert interrupted.returncode != 0
    assert not marker.exists()
    assert env_value(netbox, "SUPERUSER_API_TOKEN") == "x" * 40

    (source / "config").chmod(0o700)
    resumed = run_tasks(tmp_path, [SECRET_KEY], variables=variables)

    assert resumed.returncode == 0, resumed.stdout + resumed.stderr
    assert marker.is_file()
    assert env_value(netbox, "SUPERUSER_API_TOKEN") != "x" * 40


def test_independent_evidence_does_not_block_interrupted_fresh_initialization(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    configured = run_tasks(tmp_path, [CONFIGURE])
    assert configured.returncode == 0, configured.stdout + configured.stderr
    evidence = source / ".ludus-initialization"
    evidence.mkdir(mode=0o700)
    (evidence / "config__netbox-secret.env").write_text(
        "role_malcolm_install initialized config/netbox-secret.env\n", encoding="utf-8"
    )
    netbox = source / "config" / "netbox-secret.env"
    netbox.write_text(
        f"SECRET_KEY={'R' * 50}\nSUPERUSER_PASSWORD={'S' * 24}\nSUPERUSER_API_TOKEN={'T' * 40}\n",
        encoding="utf-8",
    )

    recovered = run_tasks(tmp_path, [CONFIGURE, AUTHENTICATION])

    assert recovered.returncode == 0, recovered.stdout + recovered.stderr
    assert len(env_value(source / "config" / "postgres.env", "POSTGRES_PASSWORD")) == 24
    assert (evidence / "config__postgres.env").is_file()


def test_admin_change_preserves_secondary_htpasswd_principal(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    first = run_tasks(tmp_path, [CONFIGURE, AUTHENTICATION])
    assert first.returncode == 0, first.stdout + first.stderr
    htpasswd = source / "nginx" / "htpasswd"
    records = HtpasswdFile(str(htpasswd))
    records.set_password("secondary", "secondary-password")
    records.save()

    changed = run_tasks(
        tmp_path,
        [CONFIGURE, AUTHENTICATION],
        variables={
            "ludus_install_malcolm_admin_username": "newadmin",
            "ludus_install_malcolm_admin_password": "test-password-two",
        },
    )

    assert changed.returncode == 0, changed.stdout + changed.stderr
    records = htpasswd.read_text(encoding="utf-8").splitlines()
    assert any(line.startswith("secondary:") for line in records)
    assert any(line.startswith("newadmin:$2") for line in records)
    assert not any(line.startswith("admin:") for line in records)
    assert all(line.count(":") == 1 for line in records)
    assert htpasswd.read_bytes().endswith(b"\n")


def test_invalid_established_secret_fails_without_rotation(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    postgres = source / "config" / "postgres.env"
    example = source / "config" / "postgres.env.example"
    before = example.read_bytes().replace(b"POSTGRES_PASSWORD=xxxxxxxxxxxxxxxx", b"POSTGRES_PASSWORD=malformed-established")
    postgres.write_bytes(before)

    result = run_tasks(tmp_path, [CONFIGURE, AUTHENTICATION])

    assert result.returncode != 0
    assert "POSTGRES_PASSWORD" in result.stdout + result.stderr
    assert postgres.read_bytes() == before


def test_valid_forwarding_ca_is_retained_while_missing_leaf_is_repaired(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    variables = {"ludus_install_malcolm_tls_dhparam_size": 512}
    first = run_tasks(tmp_path, [TLS], variables=variables)
    assert first.returncode == 0, first.stdout + first.stderr
    ca = source / "logstash" / "certs" / "ca.crt"
    ca_before = fingerprint(ca)
    server_cert = source / "logstash" / "certs" / "server.crt"
    server_cert.unlink()

    repaired = run_tasks(tmp_path, [TLS], variables=variables)

    assert repaired.returncode == 0, repaired.stdout + repaired.stderr
    assert fingerprint(ca) == ca_before
    assert server_cert.stat().st_size > 0


def test_established_ca_without_private_key_fails_untouched(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    variables = {"ludus_install_malcolm_tls_dhparam_size": 512}
    first = run_tasks(tmp_path, [TLS], variables=variables)
    assert first.returncode == 0, first.stdout + first.stderr
    ca = source / "logstash" / "certs" / "ca.crt"
    before = ca.read_bytes()
    (source / "logstash" / "certs" / "ca.key").unlink()

    result = run_tasks(tmp_path, [TLS], variables=variables)

    assert result.returncode != 0
    assert "CA" in result.stdout + result.stderr
    assert ca.read_bytes() == before


def test_established_forwarding_ca_complete_loss_fails_without_rotation(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    variables = {"ludus_install_malcolm_tls_dhparam_size": 512}
    initialized = run_tasks(tmp_path, [TLS], variables=variables)
    assert initialized.returncode == 0, initialized.stdout + initialized.stderr
    ca_paths = (
        source / "logstash" / "certs" / "ca.key",
        source / "logstash" / "certs" / "ca.crt",
        source / "filebeat" / "certs" / "ca.crt",
    )
    for path in ca_paths:
        path.unlink()

    failed = run_tasks(tmp_path, [TLS], variables=variables)

    assert failed.returncode != 0
    assert "forwarding CA" in failed.stdout + failed.stderr
    assert "restore" in (failed.stdout + failed.stderr).lower()
    assert all(not path.exists() for path in ca_paths)


def test_filebeat_trust_and_matching_key_recover_missing_primary_ca(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    variables = {"ludus_install_malcolm_tls_dhparam_size": 512}
    first = run_tasks(tmp_path, [TLS], variables=variables)
    assert first.returncode == 0, first.stdout + first.stderr
    logstash = source / "logstash" / "certs"
    trust = source / "filebeat" / "certs" / "ca.crt"
    retained = trust.read_bytes()
    (logstash / "ca.crt").unlink()

    recovered = run_tasks(tmp_path, [TLS], variables=variables)

    assert recovered.returncode == 0, recovered.stdout + recovered.stderr
    assert (logstash / "ca.crt").read_bytes() == retained
    assert trust.read_bytes() == retained


def test_filebeat_trust_without_signing_key_fails_before_ca_mutation(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    variables = {"ludus_install_malcolm_tls_dhparam_size": 512}
    first = run_tasks(tmp_path, [TLS], variables=variables)
    assert first.returncode == 0, first.stdout + first.stderr
    logstash = source / "logstash" / "certs"
    trust = source / "filebeat" / "certs" / "ca.crt"
    retained = trust.read_bytes()
    (logstash / "ca.crt").unlink()
    (logstash / "ca.key").unlink()

    failed = run_tasks(tmp_path, [TLS], variables=variables)

    assert failed.returncode != 0
    assert trust.read_bytes() == retained
    assert not (logstash / "ca.crt").exists()
    assert not (logstash / "ca.key").exists()


def test_filebeat_trust_with_mismatched_signing_key_fails_untouched(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    variables = {"ludus_install_malcolm_tls_dhparam_size": 512}
    first = run_tasks(tmp_path, [TLS], variables=variables)
    assert first.returncode == 0, first.stdout + first.stderr
    logstash = source / "logstash" / "certs"
    trust = source / "filebeat" / "certs" / "ca.crt"
    (logstash / "ca.crt").unlink()
    openssl("genrsa", "-out", str(logstash / "ca.key"), "2048")
    before_key = (logstash / "ca.key").read_bytes()
    before_trust = trust.read_bytes()

    failed = run_tasks(tmp_path, [TLS], variables=variables)

    assert failed.returncode != 0
    assert (logstash / "ca.key").read_bytes() == before_key
    assert trust.read_bytes() == before_trust
    assert not (logstash / "ca.crt").exists()


def test_forwarding_leaves_are_reissued_under_retained_ca(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    variables = {"ludus_install_malcolm_tls_dhparam_size": 512}
    first = run_tasks(tmp_path, [TLS], variables=variables)
    assert first.returncode == 0, first.stdout + first.stderr
    retained_ca = source / "logstash" / "certs" / "ca.crt"
    retained_ca_before = retained_ca.read_bytes()
    other_key = tmp_path / "other-ca.key"
    other_cert = tmp_path / "other-ca.crt"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(other_key), "-out", str(other_cert), "-subj", "/CN=Other CA", "-days", "365")

    leaves = [
        (source / "logstash" / "certs" / "server.key", source / "logstash" / "certs" / "server.crt", "server"),
        (source / "filebeat" / "certs" / "client.key", source / "filebeat" / "certs" / "client.crt", "client"),
    ]
    key_bytes = {}
    for key, cert, name in leaves:
        csr = tmp_path / f"{name}.csr"
        openssl("req", "-new", "-key", str(key), "-out", str(csr), "-subj", f"/CN={name}")
        openssl("x509", "-req", "-in", str(csr), "-CA", str(other_cert), "-CAkey", str(other_key), "-CAcreateserial", "-out", str(cert), "-days", "365")
        assert openssl("verify", "-CAfile", str(retained_ca), str(cert), check=False).returncode != 0
        key_bytes[key] = key.read_bytes()

    repaired = run_tasks(tmp_path, [TLS], variables=variables)

    assert repaired.returncode == 0, repaired.stdout + repaired.stderr
    assert retained_ca.read_bytes() == retained_ca_before
    for key, cert, _ in leaves:
        assert key.read_bytes() == key_bytes[key]
        assert openssl("verify", "-CAfile", str(retained_ca), str(cert), check=False).returncode == 0


def test_expired_web_leaf_is_renewed_with_retained_key_and_then_stable(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    variables = {"ludus_install_malcolm_tls_dhparam_size": 512}
    first = run_tasks(tmp_path, [TLS], variables=variables)
    assert first.returncode == 0, first.stdout + first.stderr
    certs = source / "nginx" / "certs"
    key = certs / "key.pem"
    cert = certs / "cert.pem"
    key_before = key.read_bytes()
    private_key = serialization.load_pem_private_key(key_before, password=None)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "malcolm")])
    now = datetime.now(timezone.utc)
    expired = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now - timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    cert.write_bytes(expired.public_bytes(serialization.Encoding.PEM))
    assert openssl("x509", "-checkend", "0", "-noout", "-in", str(cert), check=False).returncode != 0

    renewed = run_tasks(tmp_path, [TLS], variables=variables)

    assert renewed.returncode == 0, renewed.stdout + renewed.stderr
    assert key.read_bytes() == key_before
    assert openssl("x509", "-checkend", "0", "-noout", "-in", str(cert), check=False).returncode == 0
    stable = run_tasks(tmp_path, [TLS], variables=variables)
    assert stable.returncode == 0, stable.stdout + stable.stderr
    assert "changed=0" in stable.stdout


def test_expired_forwarding_leaf_is_renewed_with_retained_key_and_ca(tmp_path: Path) -> None:
    source = make_source(tmp_path)
    variables = {"ludus_install_malcolm_tls_dhparam_size": 512}
    first = run_tasks(tmp_path, [TLS], variables=variables)
    assert first.returncode == 0, first.stdout + first.stderr
    certs = source / "logstash" / "certs"
    key = certs / "server.key"
    cert = certs / "server.crt"
    ca_key_path = certs / "ca.key"
    ca_cert_path = certs / "ca.crt"
    key_before = key.read_bytes()
    ca_key_before = ca_key_path.read_bytes()
    ca_cert_before = ca_cert_path.read_bytes()
    private_key = serialization.load_pem_private_key(key_before, password=None)
    ca_key = serialization.load_pem_private_key(ca_key_before, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_before)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "malcolm")])
    now = datetime.now(timezone.utc)
    expired = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now - timedelta(days=1))
        .sign(ca_key, hashes.SHA256())
    )
    cert.write_bytes(expired.public_bytes(serialization.Encoding.PEM))

    renewed = run_tasks(tmp_path, [TLS], variables=variables)

    assert renewed.returncode == 0, renewed.stdout + renewed.stderr
    assert key.read_bytes() == key_before
    assert ca_key_path.read_bytes() == ca_key_before
    assert ca_cert_path.read_bytes() == ca_cert_before
    assert openssl("verify", "-CAfile", str(ca_cert_path), str(cert), check=False).returncode == 0
