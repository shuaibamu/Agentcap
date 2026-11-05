"""E3: agent-side delegation/presentation cost (host-measured) and end-to-end latency model;
E8: availability of delegation under intermittent connectivity to a cloud AS;
over-privilege volume of the E5 intent templates."""
import sys, os, json, time, random, statistics, math
sys.path.insert(0, os.path.dirname(__file__))
from agentcap import *
import exp_security as ES

OUT = os.path.join(os.path.dirname(__file__), '..', 'results')
GOOD = hashlib.sha256(b'agent-v1').digest()
random.seed(11)

import gc
def timeit(fn, reps=300, rounds=7):
    """Median over `rounds` of per-round medians (robust to scheduler noise)."""
    meds = []; allx = []
    gc.disable()
    for _ in range(rounds):
        xs = []
        for _ in range(reps):
            t = time.perf_counter(); fn(); xs.append((time.perf_counter() - t) * 1e6)
        meds.append(statistics.median(xs)); allx += xs
    gc.enable(); allx.sort()
    return dict(median=statistics.median(meds), p10=allx[len(allx) // 10], p90=allx[9 * len(allx) // 10],
                round_sd=statistics.pstdev(meds))

def host_costs():
    V = AttestationVendor(); H = Hub(V); D = 7
    a = AgentRuntime('a', V); H.issue(D, a, [dev(D), caps(1), rng(1, 16, 26)], {GOOD})
    res = {}
    # AgentCap delegation, split into components
    child = AgentRuntime('c', V); nonce = os.urandom(16)
    res['ac_quote_gen'] = timeit(lambda: child.evidence(nonce))
    msg, sig = child.evidence(nonce)
    res['ac_quote_verify'] = timeit(lambda: V.check(msg, sig))
    r, b, t = a.cap
    res['ac_hmac'] = timeit(lambda: hm(t, caps(1)))
    res['ac_seal'] = timeit(lambda: seal_tag(child.pk, t, r + b''.join(b)))
    sealed = seal_tag(child.pk, t, r + b''.join(b))
    res['ac_open'] = timeit(lambda: open_tag(child.kem, sealed, r + b''.join(b)))
    res['ac_delegate_total'] = timeit(lambda: a.delegate(child, [caps(1)], {GOOD}), reps=100)
    res['ac_present'] = timeit(lambda: a.present(cmd(D, 1, 1, 20), nonce[:8]))
    # baselines
    ks = [ed25519.Ed25519PrivateKey.generate() for _ in range(2)]
    res['ucan_delegate'] = timeit(lambda: ks[0].sign(os.urandom(64) + caps(1) + ed_raw(ks[1])))
    res['ucan_present'] = res['ucan_delegate']
    mk = os.urandom(32)
    res['mac_delegate'] = timeit(lambda: hm(mk, caps(1)))
    as_sk = ec.generate_private_key(ec.SECP256R1()); hk = ec.generate_private_key(ec.SECP256R1())
    cl = dev(D) + caps(1) + act_chain([b'a', b'b']) + cnf(p256_raw_pub(hk))
    sigv = es256(as_sk, cl)
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    der = encode_dss_signature(int.from_bytes(sigv[:32], 'big'), int.from_bytes(sigv[32:], 'big'))
    pub = as_sk.public_key()
    res['te_as_verify_subject'] = timeit(lambda: pub.verify(der, cl, ec.ECDSA(hashes.SHA256())))
    res['te_as_mint'] = timeit(lambda: es256(as_sk, cl))
    res['te_dpop_sign'] = timeit(lambda: es256(hk, b'INV' + os.urandom(16)))
    k16 = os.urandom(16); pop = os.urandom(32); ccm = AESCCM(k16, tag_length=8)
    res['ace_as_mint'] = timeit(lambda: ccm.encrypt(os.urandom(13), cl + pop, b'ACE'))
    res['ace_present'] = timeit(lambda: hm(pop, b'INV', os.urandom(16))[:16])
    res['te_delegate_compute'] = dict(median=res['te_as_verify_subject']['median'] * 2 + res['te_as_mint']['median'] + res['te_dpop_sign']['median'])
    return res

# ---- latency model parameters (stated in the paper) ----
F_CPU = 64e6            # device clock
RATE = 250e3            # IEEE 802.15.4 2.4 GHz PHY
HDR = 40                # MAC+6LoWPAN+UDP+CoAP overhead per frame (bytes)
MAXF = 127              # max PHY payload (bytes)
T_MAC = 1.9e-3          # mean backoff + ACK turnaround per frame (s)
RTT_WAN = 0.080         # agent <-> cloud AS round trip (s)

def radio(nbytes):
    per = MAXF - HDR; frames = max(1, math.ceil(nbytes / per))
    return frames * T_MAC + (nbytes + frames * HDR) * 8 / RATE, frames

def e2e(dev_res, hc, n=3, arch='m4'):
    rows = {}
    cyc = {s: [r for r in dev_res['depth'][arch][s] if r['n'] == n][0] for s in dev_res['depth'][arch]}
    for s in list(cyc):
        if s == 'agentcap_opt':
            cyc['agentcap_warm'] = dict(cyc[s], cycles=cyc[s]['warm_cycles'])
    for s in cyc:
        size = cyc[s]['bytes']
        verify = cyc[s]['cycles']['mean'] / F_CPU
        tx, frames = radio(size)
        chal = radio(12)[0] if s in ('agentcap', 'agentcap_opt', 'agentcap_warm', 'ucan', 'tedpop', 'acesym') else 0.0
        if s in ('agentcap', 'agentcap_opt', 'agentcap_warm'):
            deleg = (n - 1) * hc['ac_delegate_total']['median'] * 1e-6; pres = hc['ac_present']['median'] * 1e-6
        elif s == 'macaroon':
            deleg = (n - 1) * hc['mac_delegate']['median'] * 1e-6; pres = 0
        elif s == 'ucan':
            deleg = (n - 1) * hc['ucan_delegate']['median'] * 1e-6; pres = hc['ucan_present']['median'] * 1e-6
        elif s == 'jwt':
            deleg = 0; pres = 0
        elif s == 'acesym':
            deleg = (n - 1) * (hc['ace_as_mint']['median'] * 1e-6 + RTT_WAN); pres = hc['ace_present']['median'] * 1e-6
        else:
            deleg = (n - 1) * (hc['te_delegate_compute']['median'] * 1e-6 + RTT_WAN); pres = hc['te_dpop_sign']['median'] * 1e-6
        rows[s] = dict(delegation_ms=deleg * 1e3, present_ms=pres * 1e3, challenge_ms=chal * 1e3,
                       radio_ms=tx * 1e3, frames=frames, verify_ms=verify * 1e3,
                       total_ms=(deleg + pres + chal + tx + verify) * 1e3)
    return rows

def availability():
    """Two-state Markov link to the cloud AS; task needs k=2 delegations before deadline."""
    out = {}
    mean_down = 30.0
    for dl in [1.0, 10.0]:
        pts = []
        for frac in [0.0, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5]:
            ok = 0; trials = 20000
            mean_up = mean_down * (1 - frac) / frac if frac > 0 else float('inf')
            for _ in range(trials):
                up = random.random() >= frac
                rem = (random.expovariate(1 / mean_up) if up else random.expovariate(1 / mean_down)) if frac > 0 else float('inf')
                t = 0.0; need = 2; done = False
                while t <= dl:
                    if up:
                        step = 2 * RTT_WAN / 2  # one exchange
                        if rem >= step:
                            need -= 1; rem -= step; t += step
                            if need == 0: done = True; break
                        else:
                            t += rem; up = False; rem = random.expovariate(1 / mean_down)
                    else:
                        t += rem; up = True; rem = random.expovariate(1 / mean_up)
                ok += done and t <= dl
            pts.append(dict(down=frac, te=ok / trials))
        out[str(dl)] = pts
    return out

def privilege_volume():
    T = ES.intents(); HOUR = 3600
    pr = {1: 31, 2: 101, 0: 1}   # param domain sizes: temp 5..35, level 0..100, none
    acts_per_dev = 4; devs = 8
    vols = {'owner': [], 'oauth': [], 'agentcap': [], 'agentcap_sub': []}
    for _ in range(2000):
        task = random.sample(T, random.randint(1, 3))
        vols['owner'].append(devs * acts_per_dev * 101 * 24 * HOUR)
        scopes = {(D, a): p for (_t, D, a, p, *_r) in task}
        vols['oauth'].append(sum(pr[p] * HOUR for (_D, _a), p in scopes.items()))
        vols['agentcap'].append(sum(((hi - lo + 1) if p else 1) * dur for (_t, D, a, p, lo, hi, dur, *_r) in task))
        vols['agentcap_sub'].append(sum(((hi - lo + 1) if p else 1) * min(dur, 900) for (_t, D, a, p, lo, hi, dur, *_r) in task))
    base = statistics.median(vols['agentcap_sub'])
    return {k: dict(median=statistics.median(v), ratio=statistics.median(v) / base) for k, v in vols.items()}

if __name__ == '__main__':
    dev_res = json.load(open(os.path.join(OUT, 'device2.json')))
    hc = host_costs(); print(json.dumps({k: round(v['median'], 1) for k, v in hc.items()}, indent=0))
    lat = e2e(dev_res, hc); print(json.dumps(lat, indent=0))
    av = availability(); print(av)
    pv = privilege_volume(); print(pv)
    # delegation compute vs depth (cumulative, host)
    dd = {}
    for s, per in [('agentcap', hc['ac_delegate_total']['median']), ('macaroon', hc['mac_delegate']['median']),
                   ('ucan', hc['ucan_delegate']['median']), ('tedpop', hc['te_delegate_compute']['median']),
                   ('acesym', hc['ace_as_mint']['median'])]:
        dd[s] = [dict(n=n, us=(n - 1) * per) for n in range(1, 9)]
    json.dump(dict(host=hc, e2e=lat, availability=av, privilege=pv, deleg_depth=dd,
                   params=dict(F_CPU=F_CPU, RATE=RATE, HDR=HDR, MAXF=MAXF, T_MAC=T_MAC, RTT_WAN=RTT_WAN)),
              open(os.path.join(OUT, 'host.json'), 'w'), indent=1)
