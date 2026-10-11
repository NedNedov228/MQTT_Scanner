# Architecture

CLI -> validated endpoint/policy -> bounded worker -> structured report -> JSON/HTML.

`models.py` defines the shared data contract. `checks.py` owns networking and
interprets protocol responses. `runner.py` isolates blocking DNS/TLS/library calls
in a disposable process with a parent-enforced deadline. `reporting.py` renders
the same report to both formats; the packaged Jinja template enables autoescaping
and contains no scripts or remote assets.

Paho constructs the MQTT 3.1.1 CONNECT and handles TLS socket setup. The scanner
reads at most four response bytes from Paho's connected socket, validating the
fixed CONNACK header before reading more. This prevents a peer from forcing Paho
to buffer an arbitrary MQTT packet while this CONNECT-only probe is running.
Python's SSLContext implements TLS trust and hostname verification. A separate
initial socket establishes network/TLS evidence; Paho uses the same verification
policy. Each phase has a bounded timeout, and the parent bounds network work.

Result status and severity have different purposes: ERROR is execution failure,
UNKNOWN is insufficient evidence, FAIL is a violated expected policy. PASS applies
only to the named observation on the selected endpoint. It is never a claim that
the complete broker is secure.

The local operator controls targets, CA files and output paths. Broker responses,
certificate diagnostics and DNS are untrusted. The MVP sends no credentials or
application payloads. Reports contain endpoint metadata and should be treated as
operational data. The intentionally insecure lab is isolated to host loopback.
