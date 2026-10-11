# MQTT Security Scanner

An evidence-based CLI for checking **one explicitly selected MQTT endpoint**.
The MVP uses MQTT 3.1.1 over TCP or TLS and reports TCP reachability, MQTT
identity, anonymous connection policy, and TLS trust/hostname/validity.
It never subscribes, publishes, guesses credentials, or scans a network range.

## Install

Requires Python 3.12 or newer. Docker is needed only for the local lab.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/mqtt-scanner --help
```

For a regular installation, use `pip install .` and omit development extras.
For the exact development dependencies used in CI, install `uv` and run
`uv sync --extra dev --locked`. The lockfile records those resolved versions.

## Run the local lab

```sh
make lab-up
.venv/bin/mqtt-scanner check localhost --port 18830 --output reports/anonymous
.venv/bin/mqtt-scanner check localhost --port 18832 --transport tls \
  --ca-file lab/generated/ca.pem --output reports/tls
```

The first scan exits with code `1`: anonymous access and plaintext MQTT violate
the default policy. The TLS scan exits with code `0`: it verifies the generated
test CA and confirms that this listener rejects anonymous clients. See
[lab scenarios](lab/README.md) for all seven profiles.

`make lab-up` recreates the lab and its test certificates/credentials; it requires
Make and Docker Compose after installing the development extras.
Use `make lab-down` to stop the lab. Its ports bind to
`127.0.0.1`; the generated certificates and credentials are disposable.

## Reports and exit codes

Each run writes `report.json` (schema `1.0`) and standalone `report.html` to the
chosen directory. Reports list a stable check ID, status, severity, evidence,
limitations, recommendation, policy, timestamps and the exact endpoint.
Reports contain operational details about the selected broker; store and share
them accordingly.

| Code | Meaning |
| --- | --- |
| 0 | All completed checks passed the selected policy |
| 1 | At least one policy failure, with no error or unknown result |
| 2 | Execution or network error |
| 3 | At least one inconclusive check, with no execution error |

If results contain both `FAIL` and `UNKNOWN`, exit code `3` takes precedence;
read the report for every finding. `SKIPPED` records checks blocked by an earlier
failure or error, and does not independently determine the exit code.

An open TCP port is informational. Plaintext MQTT is reported only after a valid
CONNACK over TCP. A TLS handshake failure does not prove TLS is absent, and the
scanner never retries without certificate verification. Anonymous connection
does not establish read or publish permissions. These conclusions apply only
to the selected listener; they are not a full broker security assessment.
The CONNECT-only probe reads at most four response bytes, rejecting any other
MQTT frame before its payload is buffered.

## Verify

```sh
MQTT_LAB=1 .venv/bin/pytest -q
.venv/bin/ruff check src tests lab/setup.py
.venv/bin/ruff format --check src tests lab/setup.py
.venv/bin/mypy src tests lab/setup.py
.venv/bin/pip-audit
.venv/bin/python -m build
```

The lab tests fail if any fixture listener is unavailable when `MQTT_LAB=1`.
Without it, integration tests skip; unit tests still run. CI starts the lab and
runs the full suite.

See [verification evidence](docs/verification.md) for the tested scenarios,
packaging checks and the security review outcome.

Only scan systems you own or are authorized to assess. See [requirements](docs/requirements.md)
and [architecture](docs/architecture.md) for scope and design details.
