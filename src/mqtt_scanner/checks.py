"""Bounded network and MQTT observations for one selected endpoint."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Queue
from threading import Event
from uuid import uuid4

import paho.mqtt.client as mqtt
from paho.mqtt.enums import CallbackAPIVersion
from paho.mqtt.reasoncodes import ReasonCode

from mqtt_scanner.models import Finding, Policy, Severity, Status, Target


@dataclass(frozen=True)
class Probe:
    state: str
    detail: str


def _finding(
    check_id: str,
    title: str,
    status: Status,
    severity: Severity,
    evidence: str,
    limitation: str,
    recommendation: str,
) -> Finding:
    return Finding(check_id, title, status, severity, evidence, limitation, recommendation)


def _error_detail(error: BaseException) -> str:
    return f"{type(error).__name__}: {error}"


def _connect(target: Target, timeout: float) -> socket.socket:
    return socket.create_connection((target.host, target.port), timeout=timeout)


def _tls_context(ca_file: str | None) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=ca_file)


def _mqtt_probe(target: Target, timeout: float, ca_file: str | None) -> Probe:
    done = Event()
    answers: Queue[tuple[int, str]] = Queue(maxsize=1)

    def on_connect(
        _client: mqtt.Client,
        _userdata: object,
        _flags: object,
        reason_code: ReasonCode,
        _properties: object,
    ) -> None:
        answers.put((int(reason_code.value), str(reason_code)))
        done.set()

    client = mqtt.Client(
        callback_api_version=CallbackAPIVersion.VERSION2,
        client_id=f"mqtt-scanner-{uuid4().hex}",
        clean_session=True,
        protocol=mqtt.MQTTv311,
        reconnect_on_failure=False,
    )
    client.on_connect = on_connect
    if target.transport == "tls":
        client.tls_set_context(_tls_context(ca_file))
    try:
        client.connect(target.host, target.port, keepalive=max(2, int(timeout) + 1))
        client.loop_start()
        if not done.wait(timeout):
            return Probe("unknown", "No MQTT CONNACK before timeout")
        try:
            code, description = answers.get_nowait()
        except Empty:
            return Probe("unknown", "MQTT callback yielded no result")
        if code == 0:
            return Probe("accepted", "MQTT 3.1.1 CONNACK success (code 0)")
        # Callback API v2 normalizes MQTT 3 CONNACK codes to MQTT 5 reason codes.
        detail = f"MQTT 3.1.1 CONNACK: {description} (Paho reason code {code})"
        if code in {134, 135}:
            return Probe("rejected_auth", detail)
        return Probe("rejected_other", detail)
    except (OSError, ValueError) as error:
        return Probe("error", _error_detail(error))
    finally:
        client.loop_stop()
        client.disconnect()


def run_checks(
    target: Target, policy: Policy, timeout: float, ca_file: str | None
) -> list[Finding]:
    """Run non-destructive checks; transport is always explicitly selected."""
    if ca_file is not None and not Path(ca_file).is_file():
        raise ValueError(f"CA file does not exist: {ca_file}")
    findings: list[Finding] = []
    endpoint = f"{target.host}:{target.port}"
    try:
        with _connect(target, timeout):
            pass
    except OSError as error:
        findings.append(
            _finding(
                "network.reachability",
                "TCP reachability",
                Status.ERROR,
                Severity.INFO,
                f"Cannot connect to {endpoint}: {_error_detail(error)}",
                "No protocol or security assertion is possible.",
                "Check address, routing, firewall and broker availability.",
            )
        )
        return (
            findings
            + [
                _finding(
                    "transport.tls",
                    "Transport encryption",
                    Status.SKIPPED,
                    Severity.INFO,
                    "Transport was not checked because TCP connection failed.",
                    "No transport-security conclusion is possible.",
                    "Resolve the connection error and retry.",
                )
            ]
            + _skipped_protocol()
        )
    findings.append(
        _finding(
            "network.reachability",
            "TCP reachability",
            Status.PASS,
            Severity.INFO,
            f"TCP connection to {endpoint} succeeded.",
            "An open TCP port alone does not identify MQTT or a vulnerability.",
            "Restrict network exposure to intended clients.",
        )
    )

    if target.transport == "tls":
        try:
            with _connect(target, timeout) as raw:
                with _tls_context(ca_file).wrap_socket(raw, server_hostname=target.host) as stream:
                    version = stream.version() or "unknown"
                    cipher = stream.cipher()
                    cipher_name = cipher[0] if cipher else "unknown"
            findings.append(
                _finding(
                    "transport.tls",
                    "TLS verification",
                    Status.PASS,
                    Severity.INFO,
                    f"TLS handshake verified trust, hostname and validity; "
                    f"{version}, {cipher_name}.",
                    "Applies only to the selected endpoint and supplied trust store.",
                    "Keep certificate and TLS configuration current.",
                )
            )
        except ssl.SSLCertVerificationError as error:
            findings.append(
                _finding(
                    "transport.tls",
                    "TLS verification",
                    Status.FAIL,
                    Severity.HIGH,
                    f"Certificate verification failed: {_error_detail(error)}",
                    "TLS may be present, but identity or trust could not be verified.",
                    "Use a trusted, valid certificate for the requested hostname or supply its CA.",
                )
            )
            return findings + _skipped_protocol()
        except (OSError, ssl.SSLError) as error:
            findings.append(
                _finding(
                    "transport.tls",
                    "TLS verification",
                    Status.UNKNOWN,
                    Severity.INFO,
                    f"TLS handshake did not complete: {_error_detail(error)}",
                    "This does not prove that TLS is absent; no insecure fallback is attempted.",
                    "Confirm the intended transport, endpoint and broker TLS configuration.",
                )
            )
            return findings + _skipped_protocol()
    else:
        findings.append(
            _finding(
                "transport.tls",
                "Transport encryption",
                Status.UNKNOWN,
                Severity.INFO,
                "TCP selected; awaiting MQTT CONNACK to establish that plaintext MQTT is served.",
                "Other broker endpoints may support TLS.",
                "Use TLS for sensitive deployments.",
            )
        )

    probe = _mqtt_probe(target, timeout, ca_file)
    if probe.state in {"accepted", "rejected_auth", "rejected_other"}:
        findings.append(
            _finding(
                "protocol.mqtt",
                "MQTT protocol",
                Status.PASS,
                Severity.INFO,
                probe.detail,
                "Only MQTT 3.1.1 was tested on this endpoint.",
                "Confirm other protocol versions separately if required.",
            )
        )
        if target.transport == "tcp":
            findings[1] = _finding(
                "transport.tls",
                "Transport encryption",
                Status.FAIL,
                Severity.HIGH,
                f"MQTT CONNACK received over plaintext TCP at {endpoint}.",
                "This observation does not describe other broker ports or listeners.",
                "Serve MQTT over verified TLS for traffic requiring confidentiality.",
            )
        if probe.state == "accepted":
            findings.append(
                _finding(
                    "auth.anonymous",
                    "Anonymous connection",
                    Status.PASS if policy.anonymous_allowed else Status.FAIL,
                    Severity.INFO if policy.anonymous_allowed else Severity.HIGH,
                    "Broker accepted MQTT CONNECT without username or password.",
                    "This does not establish subscription or publication rights.",
                    "Require authentication unless anonymous access is explicitly intended.",
                )
            )
        elif probe.state == "rejected_auth":
            findings.append(
                _finding(
                    "auth.anonymous",
                    "Anonymous connection",
                    Status.FAIL if policy.anonymous_allowed else Status.PASS,
                    Severity.LOW if policy.anonymous_allowed else Severity.INFO,
                    f"Broker rejected anonymous CONNECT: {probe.detail}.",
                    "Authenticated access and ACL configuration were not tested.",
                    "Confirm the intended access policy and test credentials separately.",
                )
            )
        else:
            findings.append(_unknown_anonymous(probe.detail))
    else:
        findings.append(
            _finding(
                "protocol.mqtt",
                "MQTT protocol",
                Status.ERROR if probe.state == "error" else Status.UNKNOWN,
                Severity.INFO,
                probe.detail,
                "No valid CONNACK; TCP reachability alone does not identify MQTT.",
                "Confirm the transport, listener and protocol configuration.",
            )
        )
        findings.append(_unknown_anonymous("No valid MQTT CONNACK."))
    return findings


def _unknown_anonymous(evidence: str) -> Finding:
    return _finding(
        "auth.anonymous",
        "Anonymous connection",
        Status.UNKNOWN,
        Severity.INFO,
        evidence,
        "No authentication-policy conclusion is possible without CONNACK.",
        "Confirm the listener and retry with an appropriate transport.",
    )


def _skipped_protocol() -> list[Finding]:
    return [
        _finding(
            "protocol.mqtt",
            "MQTT protocol",
            Status.SKIPPED,
            Severity.INFO,
            "MQTT connection was not attempted.",
            "A prior network or TLS check prevented it.",
            "Resolve the preceding error and retry.",
        ),
        _finding(
            "auth.anonymous",
            "Anonymous connection",
            Status.SKIPPED,
            Severity.INFO,
            "Anonymous connection was not attempted.",
            "A prior network or TLS check prevented it.",
            "Resolve the preceding error and retry.",
        ),
    ]
