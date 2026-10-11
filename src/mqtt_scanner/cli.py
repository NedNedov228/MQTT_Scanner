"""Command-line entry point."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from mqtt_scanner.models import Policy, Status, Target
from mqtt_scanner.reporting import write_reports
from mqtt_scanner.runner import scan


class Transport(StrEnum):
    tcp = "tcp"
    tls = "tls"


app = typer.Typer(help="Check one explicitly selected MQTT endpoint.", no_args_is_help=True)


@app.callback()
def main() -> None:
    """MQTT security scanner."""


@app.command()
def check(
    host: Annotated[str, typer.Argument(help="Broker hostname or IP address.")],
    port: Annotated[int, typer.Option(min=1, max=65535, help="Broker TCP port.")] = 1883,
    transport: Annotated[Transport, typer.Option(help="Selected transport.")] = Transport.tcp,
    ca_file: Annotated[
        Path | None, typer.Option(exists=True, dir_okay=False, help="Private CA PEM.")
    ] = None,
    anonymous_allowed: Annotated[
        bool, typer.Option(help="Anonymous access is expected by policy.")
    ] = False,
    timeout: Annotated[
        float, typer.Option(min=0.1, help="Per-operation timeout in seconds.")
    ] = 3.0,
    deadline: Annotated[
        float, typer.Option(min=0.1, help="Whole scan deadline in seconds.")
    ] = 12.0,
    output: Annotated[Path, typer.Option(help="Report directory.")] = Path("reports"),
) -> None:
    """Check reachability, MQTT, anonymous access and TLS."""
    try:
        report = scan(
            Target(host, port, transport.value),
            Policy(anonymous_allowed=anonymous_allowed),
            timeout=timeout,
            deadline=deadline,
            ca_file=str(ca_file) if ca_file else None,
        )
        json_path, html_path = write_reports(report, output)
    except (ValueError, OSError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(2) from error
    for finding in report.findings:
        typer.echo(f"{finding.status.value:<7} {finding.check_id}: {finding.evidence}")
    typer.echo(f"Reports: {json_path}, {html_path}")
    if any(item.status == Status.ERROR for item in report.findings):
        raise typer.Exit(2)
    if any(item.status == Status.UNKNOWN for item in report.findings):
        raise typer.Exit(3)
    if any(item.status == Status.FAIL for item in report.findings):
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
