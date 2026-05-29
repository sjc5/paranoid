PACKAGE := paranoid-local-env-vault-playground
PLAYGROUND_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
FAUX_PROCESS := $(PLAYGROUND_DIR)faux_process.sh

configure:
	cargo run -p $(PACKAGE) -- configure

validate-api:
	cargo run -p $(PACKAGE) -- validate api

validate-worker:
	cargo run -p $(PACKAGE) -- validate worker

run-api:
	cargo run -p $(PACKAGE) -- run api -- $(FAUX_PROCESS)

run-worker:
	cargo run -p $(PACKAGE) -- run worker -- $(FAUX_PROCESS)
