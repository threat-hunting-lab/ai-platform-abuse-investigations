# AI Platform Abuse Investigations - Makefile
# Usage:
#   make install
#   make gen
#   make queries
#   make score
#   make report
#   make all

PY ?= python

# Defaults (override if you want)
CONFIG ?= configs/case0001.yaml
OUT ?= datasets/output
ROWS ?= 1000000
DUCKDB ?= ai_abuse.duckdb
SQL_DIR ?= sql
CASE_DIR ?= case_studies/CASE-0001-coordinated-influence

.PHONY: help install gen queries score report all clean clean_case clean_db

help:
	@echo "Targets:"
	@echo "  install     Install Python deps from requirements.txt"
	@echo "  gen         Generate synthetic parquet dataset"
	@echo "  queries     Run SQL detections and export artifact CSVs + findings.json"
	@echo "  score       Score the case artifacts into scoring.json"
	@echo "P|  report      Render REPORT.md from findings + scoring"
	@echo "  all         Run gen -> queries -> score -> report"
	@echo "  clean       Remove outputs (dataset parquet, duckdb, case artifacts)"
	@echo ""
	@echo "Vars you can override:"
	@echo "  CONFIG=... OUT=... ROWS=... DUCKDB=... SQL_DIR=... CASE_DIR=..."

install:
	$(PY) -m pip install -r requirements.txt

gen:
	$(PY) python/generate_dataset.py --config $(CONFIG) --out $(OUT) --rows $(ROWS)

queries:
	$(PY) python/run_queries.py --duckdb $(DUCKDB) --data $(OUT) --sql $(SQL_DIR) --case-dir $(CASE_DIR) --strict

score:
	$(PY) python/scoring.py --case-dir $(CASE_DIR)

report:
	$(PY) python/render_report.py --case-dir $(CASE_DIR)

all: gen queries score report

clean_case:
	@echo "Removing case artifacts for: $(CASE_DIR)"
	@rm -rf "$(CASE_DIR)/artifacts" "$(CASE_DIR)/findings.json" "$(CASE_DIR)/scoring.json" "$(CASE_DIR)/REPORT.md" "$(CASE_DIR)/report.md" || true

clean_db:
	@echo "Removing DuckDB: $(DUCKDB)"
	@rm -f "$(DUCKDB)" || true

clean:
	@echo "Removing dataset output: $(OUT)"
	@rm -rf "$(OUT)" || true
	@$(MAKE) clean_db
	@$(MAKE) clean_case
