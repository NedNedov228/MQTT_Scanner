from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from mqtt_scanner.models import Finding, Policy, Report, Severity, Status, Target
from mqtt_scanner.reporting import render_html, render_json, write_reports
from mqtt_scanner.runner import scan


@pytest.mark.parametrize(
    "host,port,transport",
    [
        ("", 1883, "tcp"),
        ("a b", 1883, "tcp"),
        ("x", 0, "tcp"),
        ("x", 65536, "tls"),
        ("x", 1883, "ws"),
    ],
)
def test_target_rejects_invalid_values(host: str, port: int, transport: str) -> None:
    with pytest.raises(ValueError):
        Target(host, port, transport)


def test_reports_use_same_structured_data_and_escape_html(tmp_path: Path) -> None:
    report = Report(
        "1.0",
        "0.1.0",
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:01+00:00",
        Target("localhost", 1883, "tcp"),
        Policy(),
        [
            Finding(
                "test",
                "<script>alert(1)</script>",
                Status.FAIL,
                Severity.HIGH,
                "untrusted <img src=x>",
                "limit",
                "fix",
            )
        ],
    )
    json_path, html_path = write_reports(report, tmp_path)
    assert json.loads(json_path.read_text()) == report.to_dict()
    assert render_json(report) == json_path.read_text()
    html = html_path.read_text()
    assert html == render_html(report)
    assert "&lt;script&gt;" in html and "&lt;img src=x&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x>" not in html


def test_scan_rejects_invalid_options() -> None:
    target = Target("localhost", 1883, "tcp")
    with pytest.raises(ValueError, match="positive"):
        scan(target, timeout=0)
    with pytest.raises(ValueError, match="only valid for TLS"):
        scan(target, ca_file="ca.pem")


def test_status_is_independent_of_severity() -> None:
    finding = Finding("id", "name", Status.UNKNOWN, Severity.INFO, "no reply", "limit", "retry")
    assert replace(finding, severity=Severity.HIGH).status == Status.UNKNOWN
