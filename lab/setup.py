"""Generate disposable local-lab certificates and credentials."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "generated"


def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write(name: str, key: rsa.RSAPrivateKey, certificate: x509.Certificate) -> None:
    (OUTPUT / f"{name}.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    (OUTPUT / f"{name}.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    # The disposable lab broker runs as an unprivileged user in a read-only mount.
    (OUTPUT / f"{name}.key").chmod(0o644)


def main() -> None:
    OUTPUT.mkdir(exist_ok=True)
    now = datetime.now(UTC)
    ca_key = _key()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "MQTT Scanner local test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    (OUTPUT / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for label, hostname, start, end in [
        ("localhost", "localhost", now - timedelta(days=1), now + timedelta(days=365)),
        ("wrong-host", "wrong-host.invalid", now - timedelta(days=1), now + timedelta(days=365)),
        ("expired", "localhost", now - timedelta(days=730), now - timedelta(days=365)),
    ]:
        key = _key()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        _write(label, key, certificate)
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{OUTPUT}:/out",
            "eclipse-mosquitto:2.0.22",
            "mosquitto_passwd",
            "-b",
            "-c",
            "/out/passwords",
            "testuser",
            "testpass",
        ],
        check=True,
    )
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{OUTPUT}:/out",
            "eclipse-mosquitto:2.0.22",
            "mosquitto_passwd",
            "-b",
            "/out/passwords",
            "publisher",
            "testpass",
        ],
        check=True,
    )
    (OUTPUT / "passwords").chmod(0o644)
    print(f"Generated local-only lab files in {OUTPUT}")


if __name__ == "__main__":
    main()
