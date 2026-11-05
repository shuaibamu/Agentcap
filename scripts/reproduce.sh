#!/bin/sh
# Full reproduction: dependencies -> builds -> tests -> experiments -> figures -> paper.
# Full experiments take ~1.5-2.5 h on 2 cores (emulating ECC verification is slow).
set -e
cd "$(dirname "$0")/.."
sh scripts/fetch_deps.sh
sh device/build_host.sh
sh device/build_mcu.sh
python3 py/test_agentcap.py
python3 scripts/smoke_mcu.py
if [ "$1" = "--quick" ]; then echo "quick mode: skipping full experiments"; exit 0; fi
python3 py/exp_device2.py
python3 py/exp_security.py
python3 py/exp_blast_seeds.py
python3 py/exp_host.py
python3 py/exp_hub.py --write
python3 py/exp_hub.py --scaling --write
python3 py/exp_cache_size.py
python3 py/analysis_model.py
python3 py/make_plots2.py
python3 py/make_plots3.py
sh scripts/build_figs.sh
cd paper && pdflatex -interaction=nonstopmode main >/dev/null && bibtex main >/dev/null && pdflatex -interaction=nonstopmode main >/dev/null && pdflatex -interaction=nonstopmode main >/dev/null
echo "done: paper/main.pdf"
