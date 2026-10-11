"""JSON and self-contained HTML reports from a single structured model."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

from jinja2 import Environment, select_autoescape

from mqtt_scanner.models import Report


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2) + "\n"


def render_html(report: Report) -> str:
    template_text = (
        files("mqtt_scanner").joinpath("templates/report.html").read_text(encoding="utf-8")
    )
    environment = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    return environment.from_string(template_text).render(report=report)


def write_reports(report: Report, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "report.json"
    html_path = output_dir / "report.html"
    json_path.write_text(render_json(report), encoding="utf-8")
    html_path.write_text(render_html(report), encoding="utf-8")
    return json_path, html_path
