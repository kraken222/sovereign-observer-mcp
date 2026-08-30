PYTHON ?= python

.PHONY: vendor test wheel clean

## Copy the IaC engine in from the backend. Required before building.
vendor:
	$(PYTHON) scripts/vendor_engine.py

test: vendor
	$(PYTHON) -m pytest tests/ -q

## Vendor THEN build — a wheel built without vendoring ships no engine.
wheel: vendor
	$(PYTHON) -m build --wheel

clean:
	rm -rf dist build *.egg-info sovereign_mcp/_vendor
