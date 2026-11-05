"""Revised figures f5..f13 (PGFPlots) from measured JSON."""
import json, os
R = os.path.join(os.path.dirname(__file__), '..', 'results')
F = os.path.join(os.path.dirname(__file__), '..', 'figs')
d2 = json.load(open(f'{R}/device2.json')); sec = json.load(open(f'{R}/security.json'))
host = json.load(open(f'{R}/host.json')); bl = json.load(open(f'{R}/blast_seeds.json'))
F_CPU = 64e6
NAMES = {'agentcap': 'AgentCap (cold)', 'agentcap_warm': 'AgentCap (cached)', 'macaroon': 'Macaroon',
         'ucan': 'UCAN-Ed25519', 'jwt': 'OAuth-JWT', 'tedpop': 'OAuth-TE+DPoP', 'acesym': 'ACE-OAuth (sym.\\ PoP)'}
SHORT = {'agentcap': 'AgentCap', 'agentcap_warm': 'AgentCap$^\\dagger$', 'macaroon': 'Macaroon', 'ucan': 'UCAN',
         'jwt': 'OAuth-JWT', 'tedpop': 'OAuth-TE', 'acesym': 'ACE-sym'}
def sty(c, mk, extra=''): return f'{c},solid,mark={mk},mark options={{solid,fill={c}!60{extra}}}'
STY = {'agentcap': sty('cA', '*'), 'agentcap_warm': 'cA,densely dashed,mark=o,mark options={solid,fill=white}',
       'macaroon': sty('cM', 'square*'), 'ucan': sty('cU', 'triangle*'), 'jwt': sty('cJ', 'diamond*'),
       'tedpop': sty('cT', 'pentagon*'), 'acesym': sty('teal', 'star', '')}
COMMON = r"""tick label style={font=\scriptsize}, label style={font=\footnotesize},
  legend cell align=left, legend style={font=\scriptsize, draw=none, fill=none, /tikz/every even column/.append style={column sep=4pt}},
  grid=major, grid style={gray!20}, every axis plot/.append style={line width=0.8pt, mark size=1.8pt}"""
def w(name, s): open(f'{F}/{name}.tex', 'w').write(s.strip() + '\n')
M4 = d2['depth']['m4']
def series(s):
    if s == 'agentcap_warm': return [(r['n'], r['warm_cycles']['mean'], r['warm_cycles']['sd']) for r in M4['agentcap_opt']]
    return [(r['n'], r['cycles']['mean'], r['cycles']['sd']) for r in M4[s]]

# ---- f5: M4 verification time vs depth ----
ORD5 = ['agentcap', 'agentcap_warm', 'macaroon', 'acesym', 'ucan', 'jwt', 'tedpop']
p = []
for s in ORD5:
    pts = ''.join(f'({n},{c / F_CPU * 1e3:.4f}) +- (0,{sd / F_CPU * 1e3:.4f})' for n, c, sd in series(s))
    p.append(f'\\addplot+[{STY[s]},thick,error bars/.cd,y dir=both,y explicit] coordinates {{{pts}}};\\addlegendentry{{{NAMES[s]}}}')
w('f5', rf"""
\begin{{tikzpicture}}
\begin{{semilogyaxis}}[width=7.9cm, height=5.8cm, xlabel={{Delegation depth $n$}}, ylabel={{Verification time (ms) @ 64\,MHz}},
  xmin=0.7, xmax=8.3, xtick={{1,...,8}}, ymin=0.1, ymax=3000, {COMMON},
  legend columns=2, legend style={{at={{(0.5,1.02)}}, anchor=south}}]
{chr(10).join(p)}
\end{{semilogyaxis}}
\end{{tikzpicture}}""")

# ---- f6: cross-architecture at n=3 (grouped bars, log cycles) ----
ORD6 = ['agentcap', 'agentcap_warm', 'macaroon', 'acesym', 'ucan', 'jwt', 'tedpop']
ARCHN = [('m0p', 'Cortex-M0+', 'cU!70'), ('m4', 'Cortex-M4', 'cA!75'), ('rv32', 'RV32IMC', 'cM!65')]
def at3(arch, s):
    rows = d2['depth'][arch]['agentcap_opt' if s == 'agentcap_warm' else s]; r = [x for x in rows if x['n'] == 3][0]
    return r['warm_cycles']['mean'] if s == 'agentcap_warm' else r['cycles']['mean']
xs = ','.join(SHORT[s] for s in ORD6)
p = []
for arch, lab, col in ARCHN:
    pts = ' '.join(f'({SHORT[s]},{at3(arch, s) / 1e3:.2f})' for s in ORD6)
    p.append(f'\\addplot+[ybar, fill={col}, draw=black!55, line width=0.3pt] coordinates {{{pts}}};\\addlegendentry{{{lab}}}')
w('f6', rf"""
\begin{{tikzpicture}}
\begin{{axis}}[ybar, ymode=log, log origin=infty, width=8.6cm, height=5.6cm, bar width=4pt, ylabel={{Cycles ($\times10^3$), $n=3$}},
  symbolic x coords={{{xs}}}, xtick=data, x tick label style={{rotate=30, anchor=east, font=\scriptsize}},
  ymin=5, ymax=300000, enlarge x limits=0.08, tick label style={{font=\scriptsize}}, label style={{font=\footnotesize}},
  ymajorgrids, grid style={{gray!20}}, legend columns=3, legend style={{font=\scriptsize, draw=none, at={{(0.5,1.02)}}, anchor=south,
  /tikz/every even column/.append style={{column sep=4pt}}}}, area legend]
{chr(10).join(p)}
\end{{axis}}
\end{{tikzpicture}}""")

# ---- f7: cache under concurrent chains ----
C = d2['cache']; Ks = sorted(C, key=int)
po = ''.join(f'({k},{C[k]["opt"]["mean"] / 1e3:.2f})' for k in Ks)
pm = ''.join(f'({k},{C[k]["p50"] / 1e3:.2f})' for k in Ks)
pb = ''.join(f'({k},{C[k]["base"]["mean"] / 1e3:.2f})' for k in Ks)
hits = '\n'.join(rf'\node[font=\tiny, text=cA, anchor=south] at (axis cs:{k},{C[k]["opt"]["mean"] / 1e3 + 4:.2f}) {{{100 * C[k]["hit_rate"]:.0f}\%}};' for k in Ks)
w('f7', rf"""
\begin{{tikzpicture}}
\begin{{semilogxaxis}}[log basis x=2, width=8.2cm, height=5.0cm, xlabel={{Concurrent delegation chains at one device (Zipf)}},
  ylabel={{Cycles per verification ($\times10^3$)}}, xmin=0.8, xmax=20, xtick={{1,2,4,8,16}}, xticklabels={{1,2,4,8,16}},
  ymin=0, ymax=110, {COMMON}, legend columns=2, legend style={{at={{(0.5,1.02)}}, anchor=south}}]
\addplot+[{STY['agentcap']},thick] coordinates {{{pb}}};\addlegendentry{{no cache (all requests)}}
\addplot+[{STY['agentcap_warm']},thick] coordinates {{{po}}};\addlegendentry{{4-entry cache, mean}}
\addplot+[cM,solid,mark=square*,mark options={{solid,fill=cM!60}},thick] coordinates {{{pm}}};\addlegendentry{{4-entry cache, median}}
{hits}
\end{{semilogxaxis}}
\end{{tikzpicture}}""")

# ---- f8: wire size vs depth ----
per = 127 - 40
ORD8 = ['agentcap', 'macaroon', 'acesym', 'ucan', 'jwt', 'tedpop']
p = []
for s in ORD8:
    pts = ''.join(f'({r["n"]},{r["bytes"]})' for r in M4[s])
    p.append(f'\\addplot+[{STY[s]},thick] coordinates {{{pts}}};\\addlegendentry{{{NAMES[s].replace(" (cold)", "")}}}')
lines = '\n'.join(rf'\draw[densely dashed, gray] (axis cs:0.7,{k * per}) -- (axis cs:8.3,{k * per}) node[pos=1, right, inner sep=1.5pt, font=\tiny, text=gray!80!black] {{{k}\,fr.}};' for k in (1, 2, 4, 8))
w('f8', rf"""
\begin{{tikzpicture}}
\begin{{axis}}[width=7.2cm, height=5.6cm, clip=false, xlabel={{Delegation depth $n$}}, ylabel={{Presentation size (bytes)}},
  xmin=0.7, xmax=8.3, xtick={{1,...,8}}, ymin=0, ymax=1100, {COMMON},
  legend columns=2, legend style={{at={{(0.55,1.02)}}, anchor=south}}]
{chr(10).join(p)}
{lines}
\end{{axis}}
\end{{tikzpicture}}""")

# ---- f9: end-to-end latency ----
E = host['e2e']; ORD9 = ['agentcap', 'agentcap_warm', 'macaroon', 'acesym', 'ucan', 'jwt', 'tedpop']
LAB9 = {'agentcap': 'AgentCap', 'agentcap_warm': 'AgentCap (cached)', 'macaroon': 'Macaroon', 'acesym': 'ACE-sym',
        'ucan': 'UCAN-Ed25519', 'jwt': 'OAuth-JWT', 'tedpop': 'OAuth-TE+DPoP'}
comps = [('delegation_ms', 'Delegation (2 hops)', 'cT!55'), ('present_ms', 'Proof generation', 'cJ!35'),
         ('challenge_ms', 'Nonce challenge', 'cU!45'), ('radio_ms', 'Radio (802.15.4)', 'cM!50'),
         ('verify_ms', 'Device verification', 'cA!75')]
yl = ','.join('{' + LAB9[s] + '}' for s in reversed(ORD9))
plots = []
for key, lab, col in comps:
    pts = ' '.join(f'({E[s][key]:.3f},{{{LAB9[s]}}})' for s in reversed(ORD9))
    plots.append(rf'\addplot+[xbar stacked, fill={col}, draw=black!60, line width=0.3pt] coordinates {{{pts}}};\addlegendentry{{{lab}}}')
tot = '\n'.join(rf'\node[anchor=west, font=\scriptsize] at (axis cs:{E[s]["total_ms"]:.2f},{{{LAB9[s]}}}) {{{E[s]["total_ms"]:.1f}}};' for s in ORD9)
w('f9', rf"""
\begin{{tikzpicture}}
\begin{{axis}}[xbar stacked, width=6.4cm, height=6.0cm, bar width=7pt, xlabel={{End-to-end latency (ms), $n=3$}},
  symbolic y coords={{{yl}}}, ytick=data, xmin=0, xmax=690, enlarge y limits=0.1,
  tick label style={{font=\scriptsize}}, label style={{font=\footnotesize}}, xmajorgrids, grid style={{gray!20}},
  legend columns=2, legend style={{font=\scriptsize, draw=none, at={{(0.4,1.02)}}, anchor=south, /tikz/every even column/.append style={{column sep=4pt}}}},
  legend cell align=left, area legend]
{chr(10).join(plots)}
{tot}
\end{{axis}}
\end{{tikzpicture}}""")

# ---- f10: attack matrix (rows = schemes, columns = attacks) ----
A = sec['attacks']; ORDA = ['agentcap', 'macaroon', 'ucan', 'jwt', 'tedpop', 'acesym']
RLAB = {'agentcap': 'AgentCap (ours)', 'macaroon': 'Macaroon (bearer)', 'ucan': 'UCAN-Ed25519',
        'jwt': 'OAuth-JWT', 'tedpop': 'OAuth-TE+DPoP', 'acesym': 'ACE-OAuth sym.\\ PoP'}
ATT = ['forward', 'replay', 'tamper', 'truncate', 'rogue', 'crossdev', 'forge', 'insider']
cw, ch = 0.74, 0.46; cells = []
for j, a_ in enumerate(ATT):
    cells.append(rf'\node[font=\scriptsize, anchor=south] at ({j * cw + cw / 2:.2f},0.03) {{A{j + 1}}};')
for i, s_ in enumerate(ORDA):
    y = -(i + 1) * ch
    cells.append(rf'\node[font=\scriptsize, anchor=east] at (-0.08,{y + ch / 2:.2f}) {{{RLAB[s_]}}};')
    for j, a_ in enumerate(ATT):
        v = A[a_][s_]
        if v is None: fill, txt, tc = 'gray!12', 'n/a', ''
        else:
            r = v['rate']; fill = f'cJ!{int(15 + 70 * r)}' if r > 0 else 'cM!22'
            txt = '0' if r == 0 else ('1.0' if r == 1 else f'{r:.2f}'); tc = ', text=white' if r == 1 else ''
        cells.append(rf'\filldraw[fill={fill}, draw=white, line width=1pt] ({j * cw:.2f},{y:.2f}) rectangle ({(j + 1) * cw:.2f},{y + ch:.2f});')
        cells.append(rf'\node[font=\scriptsize{tc}] at ({j * cw + cw / 2:.2f},{y + ch / 2:.2f}) {{{txt}}};')
w('f10', '\\begin{tikzpicture}\n' + '\n'.join(cells) + '\n\\end{tikzpicture}')

# ---- f11: prompt injection with seed error bars ----
ms_ = bl['ms']
ser = [('owner', 'Owner token', STY['jwt']), ('oauth', 'OAuth scopes', STY['tedpop']), ('agentcap', 'AgentCap (all tiers)', STY['agentcap'])]
p = []
for k, lab, st in ser:
    pts = ''.join(f'({m},{bl[k]["rate_mean"][str(m)]:.4f}) +- (0,{bl[k]["rate_sd"][str(m)]:.4f})' for m in ms_)
    p.append(f'\\addplot+[{st},thick,error bars/.cd,y dir=both,y explicit] coordinates {{{pts}}};\\addlegendentry{{{lab}}}')
w('f11', rf"""
\begin{{tikzpicture}}
\begin{{semilogxaxis}}[width=8.1cm, height=5.3cm, log basis x=2, xlabel={{Injected harmful commands per session $m$}},
  ylabel={{P(out-of-intent action executed)}}, xmin=0.8, xmax=80, ymin=-0.04, ymax=1.08, xtick={{1,2,4,8,16,32,64}},
  xticklabels={{1,2,4,8,16,32,64}}, {COMMON}, legend columns=1, legend style={{at={{(0.03,0.6)}}, anchor=west, fill=white, fill opacity=0.85, text opacity=1}}]
{chr(10).join(p)}
\end{{semilogxaxis}}
\end{{tikzpicture}}""")

# ---- f12: (a) revocation bandwidth, (b) availability ----
RV = sec['revocation']; AV = host['availability']
pa = ''.join(f'({r["k"]},{r["agentcap_bytes"]})' for r in RV); pt = ''.join(f'({r["k"]},{r["per_token_bytes"]})' for r in RV)
p1 = ''.join(f'({r["down"]},{r["te"]:.4f})' for r in AV['1.0']); p10 = ''.join(f'({r["down"]},{r["te"]:.4f})' for r in AV['10.0'])
pf = ''.join(f'({r["down"]},1.0)' for r in AV['1.0'])
LG = r"legend style={font=\tiny, draw=none, fill=white, fill opacity=0.85, text opacity=1, inner sep=1pt}, legend cell align=left"
w('f12', rf"""
\begin{{tikzpicture}}
\begin{{groupplot}}[group style={{group size=2 by 1, horizontal sep=1.15cm}}, width=4.6cm, height=4.7cm, {COMMON}]
\nextgroupplot[xmode=log, ymode=log, xlabel={{Descendants $k$}}, ylabel={{Revocation push (B)}}, xmin=0.7, xmax=1500, ymin=4, ymax=60000,
  title={{\footnotesize (a)}}, title style={{yshift=-4pt}}, xtick={{1,10,100,1000}}, legend pos=north west, {LG}]
\addplot+[{STY['agentcap']},thick] coordinates {{{pa}}};\addlegendentry{{prefix id (ours)}}
\addplot+[{STY['tedpop']},thick] coordinates {{{pt}}};\addlegendentry{{per-token ids}}
\nextgroupplot[xlabel={{AS unreachable fraction}}, ylabel={{Delegations on time}}, xmin=-0.03, xmax=0.53, ymin=0.3, ymax=1.05,
  xtick={{0,0.25,0.5}}, title={{\footnotesize (b)}}, title style={{yshift=-4pt}}, legend pos=south west, {LG}]
\addplot+[{STY['agentcap']},thick] coordinates {{{pf}}};\addlegendentry{{offline (ours)}}
\addplot+[{STY['tedpop']},thick] coordinates {{{p10}}};\addlegendentry{{online AS, 10\,s}}
\addplot+[cT!60,mark=pentagon,mark options={{solid}},thick,densely dashed] coordinates {{{p1}}};\addlegendentry{{online AS, 1\,s}}
\end{{groupplot}}
\end{{tikzpicture}}""")

# ---- f13: agent-side cost ----
DD = host['deleg_depth']; Hc = host['host']
p = []
for s in ['agentcap', 'macaroon', 'ucan', 'tedpop', 'acesym']:
    pts = ''.join(f'({r["n"]},{max(r["us"], 0.0) / 1000:.4f})' for r in DD[s] if r['n'] > 1)
    lab = NAMES[s].replace(' (cold)', '').replace(' (sym.\\ PoP)', '-sym')
    p.append(f'\\addplot+[{STY[s]},thick] coordinates {{{pts}}};\\addlegendentry{{{lab}}}')
comp = [('ac_quote_gen', 'Quote gen.'), ('ac_quote_verify', 'Quote verify'), ('ac_hmac', 'HMAC'), ('ac_seal', 'Seal $t_i$'), ('ac_open', 'Open $t_i$')]
bars = ' '.join(f'({Hc[k]["median"]:.1f},{{{lab}}})' for k, lab in comp); labs = ','.join('{' + lab + '}' for _, lab in comp)
w('f13', rf"""
\begin{{tikzpicture}}
\begin{{groupplot}}[group style={{group size=2 by 1, horizontal sep=1.95cm}}, height=4.6cm, {COMMON}]
\nextgroupplot[width=3.55cm, ymode=log, xlabel={{Depth $n$}}, ylabel={{Agent-side compute (ms)}}, xmin=1.6, xmax=8.4,
  xtick={{2,4,6,8}}, ymin=0.001, ymax=10, title={{\footnotesize (a)}}, title style={{yshift=-4pt}},
  legend columns=3, legend style={{at={{(1.25,1.14)}}, anchor=south}}]
{chr(10).join(p)}
\nextgroupplot[width=3.45cm, xbar, bar width=6pt, xlabel={{Median time ($\mu$s)}}, symbolic y coords={{{labs}}}, ytick=data,
  xmin=0, xmax=170, enlarge y limits=0.15, title={{\footnotesize (b)}}, title style={{yshift=-4pt}},
  nodes near coords, nodes near coords style={{font=\tiny, text=black, /pgf/number format/fixed, /pgf/number format/precision=0}}]
\addplot+[fill=cA!70, draw=cA] coordinates {{{bars}}};
\end{{groupplot}}
\end{{tikzpicture}}""")
print('ok')
