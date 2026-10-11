# MVP requirements and acceptance criteria

## Scope

- One explicit host, port, and transport per invocation; MQTT 3.1.1 over TCP/TLS.
- TCP reachability is informational, not a vulnerability by itself.
- A valid MQTT CONNACK establishes MQTT identity even if authentication is refused.
- Anonymous access requires a successful unauthenticated CONNACK. By default the
  expected policy prohibits it; an explicit option can allow it.
- Anonymous access is not evidence of read/write permissions. No subscriptions,
  publications, credential guessing, persistent sessions, or last wills in the MVP.
- Confirm plaintext MQTT only after an actual MQTT CONNACK over TCP.
- Validate TLS trust, hostname and certificate validity, with optional private CA.
  A TLS error never establishes absence of TLS. Do not silently retry insecurely.
- Report statuses PASS, FAIL, UNKNOWN, ERROR, SKIPPED separately from severity.
- Include stable check IDs, timestamps, endpoint, evidence, limitations,
  recommendations, schema version and scan policy in JSON and HTML.
- Enforce an overall network deadline including DNS and TLS; close sockets and
  terminate timed-out workers. Use randomized client IDs and clean sessions.
- Test on local Mosquitto fixtures, including rejected authentication, invalid
  certificates, unavailable ports and stalled/non-MQTT peers.

## Completion gates

1. CLI installs from the built wheel in a fresh environment and shows help.
2. Local Compose lab reproduces anonymous, password, TLS, invalid certificate and
   ACL configurations, with ports bound only to 127.0.0.1.
3. Unit, integration and CLI tests pass; formatting and type checks pass.
4. CLI creates matching JSON/HTML reports; HTML escapes untrusted strings.
5. Document limitations, exit codes, exact commands and verification evidence.

## Deferred

Credential validation, active ACL probes, MQTT 5, WebSocket, subnet discovery,
broker configuration inspection and web UI are outside this MVP. The lab includes
ACL profiles to support subsequent development; the scanner makes no ACL claim.
