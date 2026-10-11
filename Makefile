PYTHON ?= .venv/bin/python

.PHONY: lab-up lab-down

lab-up:
	docker compose -f lab/compose.yaml down
	$(PYTHON) lab/setup.py
	docker compose -f lab/compose.yaml up -d

lab-down:
	docker compose -f lab/compose.yaml down
