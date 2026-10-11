# MVP verification

Verified locally on 2026-10-11 on macOS ARM64 with Python 3.14.4 and 3.12.15,
and Mosquitto 2.0.22 in Docker. The original scanner implementation was
`ff278a9`; subsequent report-output changes retain the same network checks.

## Automated checks

| Check | Result |
| --- | --- |
| `MQTT_LAB=1 .venv/bin/pytest -q` | 43 passed, no skips, on both Python versions |
| `ruff check src tests lab/setup.py` | Passed |
| `ruff format --check src tests lab/setup.py` | Passed |
| `mypy src tests lab/setup.py` | Passed, 10 source files |
| `uv lock --check` | Passed |
| `pip-audit` | No known vulnerabilities in audited dependencies |
| `python -m build` | Wheel and source distribution built |

The unpublished local scanner package itself is skipped by the vulnerability
database lookup. Its source was assessed separately with Codex Security.
Dependency audit results are point-in-time observations.

Tests exercise all seven real lab listeners, anonymous policy, trusted TLS,
untrusted CA, expired and wrong-host certificates, and an incorrect transport.
Independent fixture tests use actual MQTT delivery to check allowed and blocked
subscriptions and publications. Separate Paho clients also confirm anonymous
and password authentication and the two invalid-certificate scenarios. These
controls exercise the lab independently of the scanner's result interpretation.
The scanner does not perform those authenticated or active ACL probes.

Additional tests cover DNS failure, unavailable ports, a silent peer, an overall
deadline with no surviving scan worker, an HTTP peer, fragmented/truncated or
invalid CONNACK responses, and an oversized MQTT length header. CLI tests verify
exit codes 0, 1, 2 and 3. Reporting tests verify JSON content, the HTML template,
and escaping of untrusted HTML.

## Installed-package demonstration

The final wheel was installed into a separate virtual environment. Its CLI was
run from outside the repository, so the source checkout was not required.
The internal template is packaged as `report.html.j2`; generated output remains
`report.html`. Regression assertions verify substituted endpoint values,
summary counts, absence of unresolved template syntax in fixture reports and
absolute output paths printed by the CLI.

| Endpoint | Observation | Exit |
| --- | --- | --- |
| localhost:18830 TCP | Reachable MQTT; anonymous CONNECT accepted; plaintext MQTT confirmed | 1 |
| localhost:18832 TLS with lab CA | Trust, hostname and validity verified; MQTT confirmed; anonymous CONNECT rejected | 0 |

Both runs generated JSON and HTML reports, including the template packaged in
the wheel. Generated reports are local outputs under `reports/anonymous/` and
`reports/tls/`, excluded from Git. The HTML was tested for content and escaping;
interactive visual inspection was unavailable because the browser blocked
opening the local file URL.

## Security review

Codex Security completed a repository scan of snapshot `511c1ec`:
`8eedb99c-116a-4a93-a95a-3adb0c74c5c5`.

It identified one medium-severity CWE-400 issue: a broker could make the original
Paho receive loop buffer an oversized MQTT response before CONNACK validation.
Commit `46fb8e0` replaced that receive path with a bounded four-byte CONNACK read.
The final tests verify early rejection of an oversized length header and malformed
responses; real Mosquitto tests verify that valid connections still work.

The sealed report describes the original snapshot and retains that finding.
It is not a clean-scan certificate for the later revision. No second full security
scan is claimed. Recorded scan usage: 4,987,504 total tokens, including
4,763,855 cached input tokens.

## Reproduce

Use the installation and lab commands in the root README, then run the checks
above. `MQTT_LAB=1` makes missing fixtures a failure rather than a skip.
GitHub Actions is configured to run locked dependencies on Python 3.12, start
the lab, run checks, build distributions, test the installed wheel and stop the
lab even after a failure.

Lab credential generation runs with the invoking user's UID/GID so generated
files remain manageable on Linux as well as Docker Desktop.
After installing the development extras, `make lab-up` recreates the complete
lab with one command; `make lab-down` stops it. CI uses these same commands.

## Original stages 1–6: acceptance evidence

| Stage | Implemented deliverable | Verification |
| --- | --- | --- |
| 1. Requirements and scope | `docs/requirements.md`, endpoint/transport/policy options | Explicit inputs and outcomes per check; MQTT 3.1.1 scope and exclusions documented |
| 2. Repository and architecture | `src/mqtt_scanner/`, `pyproject.toml`, `uv.lock`, architecture document | Ruff/mypy pass; wheel and sdist build; installed CLI works outside the checkout |
| 3. Reproducible lab | `make lab-up`, seven loopback Mosquitto profiles, generated certificates/accounts | Independent Paho connections and message-delivery controls verify every fixture scenario |
| 4. Network and anonymous connection | Reachability, bounded CONNACK parser, unique clean-session clients, process deadline | Real brokers plus DNS failure, closed/stalled/non-MQTT peers, fragmented replies and worker cleanup tests |
| 5. TLS verification | Explicit TCP/TLS, system or private CA, trust/hostname/validity checks | Trusted, untrusted, expired and wrong-host certificates; wrong transport; no downgrade after TLS failure |
| 6. Result model and reports | Five statuses, independent severity, policy, evidence, recommendations, schema-versioned JSON/HTML | Matching renderers, HTML escaping, CLI codes 0–3, generated demo reports and installable MVP 0.1.0 distributions |

Codex Security review and the CWE-400 regression are documented above. Git
history records incremental implementation, security correction, tests,
documentation and CI commits pushed to `origin/codex/mvp`.

Passing these tests establishes the documented MVP behavior in the tested
environments. It does not prove that a target broker has no other vulnerabilities.
Authenticated credential checks, active ACL scanning, MQTT 5 and network-range
discovery remain outside the agreed MVP scope.
