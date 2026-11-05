#!/bin/sh
# Compile the TikZ/PGFPlots sources figs/fN.tex to vector PDFs and copy them to paper/figs/
# under the figure numbers used in the manuscript (Fig1.pdf ... Fig15.pdf).
set -e
cd "$(dirname "$0")/.."
MAP="1:f1 2:f2 3:f3 4:f4 5:f15 6:f7 7:f14 8:f12 9:f9 10:f5 11:f6 12:f8 13:f13 14:f10 15:f11"
mkdir -p paper/figs
for m in $MAP; do n=${m%%:*}; f=${m#*:}; sh figs/wrap.sh $f >/dev/null; cp figs/prev_$f.pdf paper/figs/Fig$n.pdf; done
echo "built paper/figs/Fig1-15.pdf"
