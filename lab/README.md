# Local Mosquitto lab

Run from the repository root:

```sh
.venv/bin/python lab/setup.py
docker compose -f lab/compose.yaml up -d
```

All published ports bind to host loopback. `testuser` / `testpass` exist only in
the generated disposable lab. Generated private keys are deliberately readable
inside the local lab container; they are not production credentials. Never
publish `lab/generated/` or expose the intentionally insecure listeners.

| Host port | Scenario | Expected anonymous result | TLS |
| --- | --- | --- | --- |
| 18830 | anonymous | accepted | no |
| 18831 | password | rejected | no |
| 18832 | TLS password and restricted ACL | rejected | trusted with generated CA |
| 18833 | wrong hostname | not reached | invalid identity |
| 18834 | expired certificate | not reached | expired |
| 18835 | ACL restricted | rejected | no |
| 18836 | ACL absent | rejected | no |

The TLS and ACL-secure profiles allow `testuser` to read `lab/sensor/#` and
write `lab/commands/testuser/#`. A second fixture account, `publisher` / `testpass`,
can write `lab/sensor/#`. The ACL-open profile omits restrictions.
These profiles support future authenticated ACL checks. The MVP scanner itself
does not assess ACL; an anonymous connection result must not be interpreted as
ACL evidence.

Stop with `docker compose -f lab/compose.yaml down`.
