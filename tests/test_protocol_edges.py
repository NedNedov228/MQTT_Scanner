from __future__ import annotations

import socket
import threading
from time import monotonic

from mqtt_scanner.models import Status, Target
from mqtt_scanner.runner import scan


def test_http_on_open_port_is_not_labeled_plaintext_mqtt() -> None:
    ready = threading.Event()
    ports: list[int] = []

    def serve() -> None:
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(4)
            server.settimeout(5)
            ports.append(server.getsockname()[1])
            ready.set()
            for _ in range(2):
                connection, _ = server.accept()
                with connection:
                    connection.sendall(b"HTTP/1.1 200 OK\r\n\r\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(2)
    report = scan(Target("127.0.0.1", ports[0], "tcp"), timeout=0.5, deadline=4)
    findings = {finding.check_id: finding for finding in report.findings}
    assert findings["network.reachability"].status == Status.PASS
    assert findings["transport.tls"].status == Status.UNKNOWN
    assert findings["protocol.mqtt"].status in {Status.UNKNOWN, Status.ERROR}
    assert findings["auth.anonymous"].status == Status.UNKNOWN
    thread.join(timeout=2)


def test_oversized_broker_frame_is_rejected_before_payload() -> None:
    ready = threading.Event()
    ports: list[int] = []

    def serve() -> None:
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(4)
            server.settimeout(5)
            ports.append(server.getsockname()[1])
            ready.set()
            first, _ = server.accept()
            first.close()
            second, _ = server.accept()
            with second:
                second.settimeout(2)
                second.recv(512)
                second.sendall(b"\x20\xff\xff\xff\x7f")
                threading.Event().wait(0.5)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(2)
    started = monotonic()
    report = scan(Target("127.0.0.1", ports[0], "tcp"), timeout=2, deadline=4)
    elapsed = monotonic() - started
    findings = {finding.check_id: finding for finding in report.findings}
    assert findings["protocol.mqtt"].status == Status.UNKNOWN
    assert "four-byte" in findings["protocol.mqtt"].evidence
    assert findings["transport.tls"].status == Status.UNKNOWN
    assert findings["auth.anonymous"].status == Status.UNKNOWN
    assert elapsed < 2
    thread.join(timeout=2)
