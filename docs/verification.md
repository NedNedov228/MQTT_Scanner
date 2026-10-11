# MVP verification

Verified locally on 2026-10-11 on macOS ARM64 with Python 3.14.4 and
Mosquitto 2.0.22 in Docker. Implementation under test: `ff278a9`.

## Automated checks

| Check | Result |
| --- | --- |
| `MQTT_LAB=1 .venv/bin/pytest -q` | 34 passed, no skips |
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
subscriptions. The scanner does not perform those active ACL probes.

Additional tests cover DNS failure, unavailable ports, a silent peer, an overall
deadline with no surviving scan worker, an HTTP peer, fragmented/truncated or
invalid CONNACK responses, and an oversized MQTT length header. CLI tests verify
exit codes 0, 1, 2 and 3. Reporting tests verify JSON content, the HTML template,
and escaping of untrusted HTML.

## Installed-package demonstration

The final wheel was installed into a separate virtual environment. Its CLI was
run from outside the repository, so the source checkout was not required.

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

Passing these tests establishes the documented MVP behavior in the tested
environments. It does not prove that a target broker has no other vulnerabilities.
Authenticated credential checks, active ACL scanning, MQTT 5 and network-range
discovery remain outside the agreed MVP scope.
