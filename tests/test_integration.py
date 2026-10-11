from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from mqtt_scanner.models import Finding, Policy, Status, Target
from mqtt_scanner.runner import scan

LAB = Path(__file__).resolve().parents[1] / "lab"
CA_FILE = str(LAB / "generated" / "ca.pem")

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module", autouse=True)
def require_lab() -> None:
    required = os.getenv("MQTT_LAB") == "1"
    for port in range(18830, 18837):
        for attempt in range(30 if required else 1):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                    break
            except OSError:
                if attempt == 29 or not required:
                    if required:
                        pytest.fail(f"Mosquitto lab is unavailable on port {port}")
                    pytest.skip("local Mosquitto lab is not running")
                time.sleep(0.2)


def by_id(port: int, transport: str = "tcp", ca_file: str | None = None) -> dict[str, Finding]:
    report = scan(Target("localhost", port, transport), ca_file=ca_file)
    return {finding.check_id: finding for finding in report.findings}


def test_anonymous_listener_and_policy() -> None:
    findings = by_id(18830)
    assert findings["network.reachability"].status == Status.PASS
    assert findings["protocol.mqtt"].status == Status.PASS
    assert findings["transport.tls"].status == Status.FAIL
    assert findings["auth.anonymous"].status == Status.FAIL
    allowed = scan(Target("localhost", 18830, "tcp"), Policy(anonymous_allowed=True))
    assert allowed.findings[-1].status == Status.PASS


def test_password_listener_rejects_anonymous() -> None:
    findings = by_id(18831)
    assert findings["network.reachability"].status == Status.PASS
    assert findings["protocol.mqtt"].status == Status.PASS
    assert findings["transport.tls"].status == Status.FAIL
    assert findings["auth.anonymous"].status == Status.PASS


def test_trusted_tls_and_password() -> None:
    findings = by_id(18832, "tls", CA_FILE)
    assert [finding.status for finding in findings.values()] == [Status.PASS] * 4
    assert "TLSv1." in findings["transport.tls"].evidence
    assert "CONNACK" in findings["protocol.mqtt"].evidence


@pytest.mark.parametrize("port,detail", [(18833, "Hostname mismatch"), (18834, "expired")])
def test_invalid_certificates_are_not_downgraded(port: int, detail: str) -> None:
    findings = by_id(port, "tls", CA_FILE)
    assert findings["transport.tls"].status == Status.FAIL
    assert detail.lower() in findings["transport.tls"].evidence.lower()
    assert findings["protocol.mqtt"].status == Status.SKIPPED
    assert findings["auth.anonymous"].status == Status.SKIPPED


def test_untrusted_ca_and_wrong_transport() -> None:
    untrusted = by_id(18832, "tls")
    assert untrusted["transport.tls"].status == Status.FAIL
    assert untrusted["auth.anonymous"].status == Status.SKIPPED
    wrong = by_id(18831, "tls", CA_FILE)
    assert wrong["transport.tls"].status == Status.UNKNOWN
    assert wrong["auth.anonymous"].status == Status.SKIPPED


@pytest.mark.parametrize("port", [18835, 18836])
def test_acl_lab_profiles_do_not_produce_acl_claim(port: int) -> None:
    findings = by_id(port)
    assert findings["auth.anonymous"].status == Status.PASS
    assert not any(check_id.startswith("acl.") for check_id in findings)


def test_unavailable_endpoint_is_error() -> None:
    with socket.socket() as free_socket:
        free_socket.bind(("127.0.0.1", 0))
        port = free_socket.getsockname()[1]
    findings = by_id(port)
    assert findings["network.reachability"].status == Status.ERROR
    assert findings["protocol.mqtt"].status == Status.SKIPPED


def test_stalled_broker_obeys_whole_scan_deadline() -> None:
    ready = threading.Event()
    port_holder: list[int] = []

    def stall() -> None:
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(4)
            port_holder.append(server.getsockname()[1])
            ready.set()
            server.settimeout(4)
            connection, _ = server.accept()
            connection.close()
            server.settimeout(4)
            second, _ = server.accept()
            with second:
                threading.Event().wait(2)

    thread = threading.Thread(target=stall, daemon=True)
    thread.start()
    assert ready.wait(2)
    report = scan(Target("127.0.0.1", port_holder[0], "tcp"), timeout=3, deadline=1)
    assert report.findings[0].check_id == "scan.execution"
    assert report.findings[0].status == Status.ERROR
    thread.join(timeout=5)


def test_cli_writes_reports_and_exit_codes(tmp_path: Path) -> None:
    command = [
        sys.executable,
        "-m",
        "mqtt_scanner.cli",
        "check",
        "localhost",
        "--port",
        "18830",
        "--output",
        str(tmp_path),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    assert result.returncode == 1, result.stderr
    data = json.loads((tmp_path / "report.json").read_text())
    assert data["schema_version"] == "1.0"
    assert {item["check_id"] for item in data["findings"]} == {
        "network.reachability",
        "transport.tls",
        "protocol.mqtt",
        "auth.anonymous",
    }
    assert (tmp_path / "report.html").is_file()
    allowed = subprocess.run(
        command + ["--anonymous-allowed"], capture_output=True, text=True, timeout=20
    )
    assert allowed.returncode == 1  # Plaintext MQTT remains a finding.
    tls = subprocess.run(
        [
            sys.executable,
            "-m",
            "mqtt_scanner.cli",
            "check",
            "localhost",
            "--port",
            "18832",
            "--transport",
            "tls",
            "--ca-file",
            CA_FILE,
            "--output",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert tls.returncode == 0, tls.stderr
    assert all(
        item["status"] == "PASS"
        for item in json.loads((tmp_path / "report.json").read_text())["findings"]
    )
