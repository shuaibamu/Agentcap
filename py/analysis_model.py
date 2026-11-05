"""Analytical models derived from the measured data (no new measurements):
(1) linear cost-model fits C(n)=a+b*n per scheme and ISA, and the SHA-256-compression model of AgentCap;
(2) validation of the cache mixture model E[C]=h*C_hit+(1-h)*C_miss against the cache workload;
(3) energy per verification and per received presentation using nRF52840 datasheet constants;
(4) device cost of naive compositions of existing mechanisms, composed from measured primitives.
Writes results/model.json."""
import os, json, statistics as st
R = os.path.join(os.path.dirname(__file__), '..', 'results')
dev = json.load(open(os.path.join(R, 'device2.json')))
out = {}

def fit(ns, ys):
    mx, my = st.mean(ns), st.mean(ys)
    b = sum((x - mx) * (y - my) for x, y in zip(ns, ys)) / sum((x - mx) ** 2 for x in ns); a = my - b * mx
    tot = sum((y - my) ** 2 for y in ys); ss = sum((y - a - b * x) ** 2 for x, y in zip(ns, ys))
    return dict(a=a, b=b, r2=1 - ss / tot if tot else 1.0, max_rel_err=max(abs(y - a - b * x) / y for x, y in zip(ns, ys)))

# (1) fits
out['fits'] = {}
for arch, d in dev['depth'].items():
    out['fits'][arch] = {}
    for s, v in d.items():
        ns = [x['n'] for x in v]; out['fits'][arch][s] = fit(ns, [x['cycles']['mean'] for x in v])
        if s == 'agentcap_opt':
            out['fits'][arch]['agentcap_cached'] = fit(ns, [x['warm_cycles']['mean'] for x in v])
# compression model: cold AgentCap = kappa * 5(n+1) compressions (n = blocks incl. root)
out['compression'] = {}
for arch, v in dev['depth'].items():
    ys = [x['cycles']['mean'] for x in v['agentcap']]; ns = [x['n'] for x in v['agentcap']]
    kappa = sum(y / (5 * (n + 1)) for y, n in zip(ys, ns)) / len(ns)
    out['compression'][arch] = dict(kappa=kappa, max_rel_err=max(abs(y - kappa * 5 * (n + 1)) / y for y, n in zip(ys, ns)))

# (2) mixture-model validation (Cortex-M4, n=3)
m4 = {x['n']: x for x in dev['depth']['m4']['agentcap_opt']}
c_hit, c_miss = m4[3]['warm_cycles']['mean'], m4[3]['cycles']['mean']
out['mixture'] = {}
for K, c in dev['cache'].items():
    pred = c['hit_rate'] * c_hit + (1 - c['hit_rate']) * c_miss
    out['mixture'][K] = dict(hit=c['hit_rate'], measured=c['opt']['mean'], predicted=pred,
                             rel_err=abs(pred - c['opt']['mean']) / c['opt']['mean'])

# (3) energy. nRF52840 PS v1.1 (2019): 52 uA/MHz running CoreMark from flash (DC/DC, 3 V); 4.6 mA peak RX current (
# used as a proxy for 802.15.4 reception); 802.15.4 at 250 kbit/s with 40 B overhead per 127 B frame.
V = 3.0; F = 64e6; I_CPU = 52e-6 * 64; E_CYC = I_CPU * V / F; P_RX = 4.6e-3 * V
def frames(b): return -(-b // (127 - 40))
out['energy'] = {'E_per_cycle_nJ': E_CYC * 1e9, 'P_rx_mW': P_RX * 1e3, 'n3': {}}
for s, v in dev['depth']['m4'].items():
    x = [y for y in v if y['n'] == 3][0]
    cyc = x['warm_cycles']['mean'] if s == 'agentcap_opt' else x['cycles']['mean']
    key = 'agentcap_cached' if s == 'agentcap_opt' else s
    airtime = (x['bytes'] + 40 * frames(x['bytes'])) * 8 / 250e3
    out['energy']['n3'][key] = dict(cycles=cyc, verify_uJ=cyc * E_CYC * 1e6, bytes=x['bytes'],
                                    rx_uJ=airtime * P_RX * 1e6)

# (4) naive compositions on Cortex-M4 at n=3 (cycles), from measured primitives
f = out['fits']['m4']; d3 = {s: [y for y in v if y['n'] == 3][0]['cycles']['mean'] for s, v in dev['depth']['m4'].items()}
ed = f['ucan']['b']                     # one Ed25519 verification (UCAN slope per block)
ecdsa = d3['jwt'] - d3['macaroon'] * 0  # one ES256 verification dominates the JWT verifier
out['composition_m4_n3'] = {
    'macaroon': d3['macaroon'],
    'macaroon+dpop': d3['macaroon'] + d3['jwt'],
    'macaroon+device_quote_appraisal': d3['macaroon'] + 3 * ed,
    'ucan+device_quote_appraisal': d3['ucan'] + 3 * ed,
    'acesym': d3['acesym'],
    'agentcap_cold': d3['agentcap'],
    'agentcap_cached': m4[3]['warm_cycles']['mean'],
    'ed25519_verify': ed, 'es256_verify': d3['jwt']}
json.dump(out, open(os.path.join(R, 'model.json'), 'w'), indent=1)
for k in ('compression', 'mixture', 'composition_m4_n3'): print(k, json.dumps(out[k], indent=0)[:900])
print(json.dumps(out['energy'], indent=0))
print({a: {s: (round(v['a']), round(v['b']), round(v['r2'], 5)) for s, v in out['fits'][a].items()} for a in out['fits']})
