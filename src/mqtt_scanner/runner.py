"""Parent-enforced deadline around DNS, TLS and MQTT library calls."""

from __future__ import annotations

import multiprocessing as mp
from math import isfinite
from queue import Empty

from mqtt_scanner import __version__
from mqtt_scanner.checks import run_checks
from mqtt_scanner.models import Finding, Policy, Report, Severity, Status, Target, utc_now


def _worker(
    queue: mp.Queue[list[Finding] | str],
    target: Target,
    policy: Policy,
    timeout: float,
    ca_file: str | None,
) -> None:
    try:
        queue.put(run_checks(target, policy, timeout, ca_file))
    except Exception as error:
        queue.put(f"{type(error).__name__}: {error}")


def scan(
    target: Target,
    policy: Policy | None = None,
    *,
    timeout: float = 3.0,
    deadline: float = 12.0,
    ca_file: str | None = None,
) -> Report:
    if not isfinite(timeout) or not isfinite(deadline) or timeout <= 0 or deadline <= 0:
        raise ValueError("timeout and deadline must be positive and finite")
    if ca_file is not None and target.transport != "tls":
        raise ValueError("CA file is only valid for TLS transport")
    if ca_file is not None:
        from pathlib import Path

        if not Path(ca_file).is_file():
            raise ValueError(f"CA file does not exist: {ca_file}")
    started_at = utc_now()
    chosen_policy = policy or Policy()
    context = mp.get_context("spawn")
    queue: mp.Queue[list[Finding] | str] = context.Queue(maxsize=1)
    process = context.Process(target=_worker, args=(queue, target, chosen_policy, timeout, ca_file))
    process.start()
    try:
        process.join(deadline)
        if process.is_alive():
            process.terminate()
            process.join(1)
            if process.is_alive():
                process.kill()
                process.join()
            result: list[Finding] | str = f"Overall scan deadline exceeded ({deadline:g}s)"
        else:
            try:
                result = queue.get(timeout=0.5)
            except Empty:
                result = f"Worker exited without a result (exit code {process.exitcode})"
    finally:
        if process.is_alive():
            process.terminate()
            process.join(1)
            if process.is_alive():
                process.kill()
                process.join()
        queue.close()
        queue.join_thread()
    if isinstance(result, str):
        findings = [
            Finding(
                "scan.execution",
                "Scan execution",
                Status.ERROR,
                Severity.INFO,
                result,
                "Checks did not complete; no security conclusion is possible.",
                "Confirm the endpoint and retry with a suitable deadline.",
            )
        ]
    else:
        findings = result
    return Report("1.0", __version__, started_at, utc_now(), target, chosen_policy, findings)
