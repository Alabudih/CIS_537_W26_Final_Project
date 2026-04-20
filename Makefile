PYTHON ?= python

all: demo

demo:
	$(PYTHON) src/simulate_attacks.py
	$(PYTHON) src/analyze_results.py

clean:
	bash scripts/clean.sh
