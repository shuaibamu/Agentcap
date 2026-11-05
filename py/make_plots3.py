"""Figures for the cache-sizing experiment (f14) and the cost-model validation (f15)."""
import os, json
R = os.path.join(os.path.dirname(__file__), '..', 'results'); F = os.path.join(os.path.dirname(__file__), '..', 'figs')
cs = json.load(open(os.path.join(R, 'cache_size.json'))); mo = json.load(open(os.path.join(R, 'model.json')))
dev = json.load(open(os.path.join(R, 'device2.json')))
COL = {1: 'cJ', 2: 'cU', 4: 'cA', 8: 'cM', 16: 'cT'}; MK = {1: 'triangle*', 2: 'diamond*', 4: '*', 8: 'square*', 16: 'pentagon*'}
AX = (r"log basis x=2, xmin=0.8, xmax=40, xtick={1,2,4,8,16,32}, xticklabels={1,2,4,8,16,32}, ymin=0, ymax=105,"
      r" tick label style={font=\scriptsize}, label style={font=\footnotesize}, grid=major, grid style={gray!20},"
      r" every axis plot/.append style={line width=0.8pt, mark size=1.6pt}")
out = [r"\begin{tikzpicture}", r"\begin{groupplot}[group style={group size=2 by 1, horizontal sep=1.1cm, y descriptions at=edge left},"
       r" width=6.4cm, height=5.0cm, xmode=log, " + AX + r", ylabel={Cache hit rate (\%)}]"]
for i, law in enumerate(['zipf', 'uniform']):
    t = 'Zipf popularity' if law == 'zipf' else 'Uniform popularity'
    out.append(r"\nextgroupplot[title={\footnotesize (%s) %s}, xlabel={Concurrent chains $K$}%s]" % ('ab'[i], t,
               r", legend columns=5, legend style={font=\scriptsize, draw=none, fill=none, at={(1.12,1.18)}, anchor=south, /tikz/every even column/.append style={column sep=3pt}}" if i == 0 else ""))
    for N in cs['sizes']:
        pts = ''.join('(%s,%.1f)' % (K, 100 * cs['data'][law][str(K)][str(N)]['hit']) for K in cs['ks'])
        out.append(r"\addplot+[%s,solid,mark=%s,mark options={solid,fill=%s!60}] coordinates {%s};" % (COL[N], MK[N], COL[N], pts))
        if i == 0: out.append(r"\addlegendentry{$N{=}%d$}" % N)
out += [r"\end{groupplot}", r"\end{tikzpicture}"]
open(os.path.join(F, 'f14.tex'), 'w').write('\n'.join(out) + '\n')

# f15: measured cold cycles vs model 5*kappa*(n+1), three ISAs
out = [r"\begin{tikzpicture}", r"\begin{axis}[width=8.2cm, height=5.6cm, xlabel={Delegation depth $n$}, ylabel={Cold verification cycles ($\times10^3$)},"
       r" xmin=0.6, xmax=8.4, xtick={1,...,8}, ymin=0, ymax=640, tick label style={font=\scriptsize}, label style={font=\footnotesize},"
       r" grid=major, grid style={gray!20}, legend cell align=left, legend columns=2, legend style={font=\scriptsize, draw=none, fill=none, at={(0.02,0.98)}, anchor=north west},"
       r" every axis plot/.append style={line width=0.8pt, mark size=1.8pt}]"]
names = {'m0p': 'Cortex-M0+', 'm4': 'Cortex-M4', 'rv32': 'RV32IMC'}; cl = {'m0p': 'cJ', 'm4': 'cA', 'rv32': 'cM'}
for a in ['m0p', 'm4', 'rv32']:
    k = mo['compression'][a]['kappa']
    pts = ''.join('(%d,%.2f)' % (x['n'], x['cycles']['mean'] / 1e3) for x in dev['depth'][a]['agentcap'])
    out.append(r"\addplot+[%s,only marks,mark=*,mark options={fill=%s!60}] coordinates {%s};\addlegendentry{%s measured}" % (cl[a], cl[a], pts, names[a]))
    out.append(r"\addplot+[%s,densely dashed,no marks,domain=0.8:8.2,samples=2] {%.4f*(x+1)};\addlegendentry{$5\kappa(n{+}1)$, $\kappa{=}%s$}" % (cl[a], 5 * k / 1e3, format(round(k), ',').replace(',', '{,}')))
out += [r"\end{axis}", r"\end{tikzpicture}"]
open(os.path.join(F, 'f15.tex'), 'w').write('\n'.join(out) + '\n')
print('wrote f14.tex f15.tex')
