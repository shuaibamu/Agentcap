"""Revised device experiments: 3 MCU ISAs x 7 verifiers x depth 1..8 with repetitions,
footprint, cache behaviour under multi-chain workloads, caveat/revocation sensitivity."""
import sys, os, json, statistics, random
sys.path.insert(0, os.path.dirname(__file__))
from agentcap import *
from mcuemu import MCU, ctx_arm

OUT = os.path.join(os.path.dirname(__file__), '..', 'results')
ELF = os.path.join(os.path.dirname(__file__), '..', 'device', 'mcu')
D = 7; GOOD = hashlib.sha256(b'agent-v1').digest()
ROOT_CAV = [dev(D), caps(0, 1, 2), rng(1, 16, 26), tw(0, 5000), depth(8)]
LVL_CAV = [caps(1), rng(1, 18, 24), tw(0, 4000)]
COMMAND = cmd(D, 1, 1, 21)
ARCHS = ['m0p', 'm4', 'rv32']
SCHEMES = ['agentcap', 'agentcap_opt', 'macaroon', 'ucan', 'jwt', 'tedpop', 'acesym']
random.seed(3)

def agentcap_chain(n, extra_root=()):
    V = AttestationVendor(); H = Hub(V); ag = [AgentRuntime(f'a{i}', V) for i in range(n)]
    H.issue(D, ag[0], ROOT_CAV + list(extra_root), {GOOD})
    for i in range(1, n): ag[i - 1].delegate(ag[i], LVL_CAV, {GOOD})
    return H, ag

def build(scheme, n, nonce):
    if scheme in ('agentcap', 'agentcap_opt'):
        H, ag = agentcap_chain(n)
        return ag[-1].present(COMMAND, nonce), dict(key=H.kd(D), nonce=nonce, nonce_valid=1), ag[-1]
    if scheme == 'macaroon':
        key = os.urandom(32); rid0 = os.urandom(8)
        blocks = [b''.join(ROOT_CAV)] + [b''.join(LVL_CAV)] * (n - 1)
        return macaroon_wire(rid0, blocks, macaroon_present(key, rid0, blocks), COMMAND), dict(key=key), None
    if scheme == 'ucan':
        owner = ed25519.Ed25519PrivateKey.generate(); ks = [ed25519.Ed25519PrivateKey.generate() for _ in range(n)]
        parts = ucan_build(owner, ks, [b''.join(ROOT_CAV)] + [b''.join(LVL_CAV)] * (n - 1))
        return ucan_wire(parts, ks[-1], COMMAND, nonce), dict(owner_pk=ed_raw(owner), nonce=nonce, nonce_valid=1), None
    if scheme == 'acesym':
        k16 = os.urandom(16)
        cl = b''.join(ROOT_CAV[:4]) + act_chain([b'a%d' % i for i in range(n)])
        return acesym_wire(k16, cl, os.urandom(32), COMMAND, nonce), dict(key=k16 + b'\0' * 16, nonce=nonce, nonce_valid=1), None
    as_sk = ec.generate_private_key(ec.SECP256R1())
    if scheme == 'jwt':
        return jwt_wire(as_sk, b''.join(ROOT_CAV[:4]), COMMAND), dict(as_pk=p256_raw_pub(as_sk)), None
    hk = ec.generate_private_key(ec.SECP256R1())
    cl = b''.join(ROOT_CAV[:4]) + act_chain([b'a%d' % i for i in range(n)]) + cnf(p256_raw_pub(hk))
    return tedpop_wire(as_sk, cl, hk, COMMAND, nonce), dict(as_pk=p256_raw_pub(as_sk), nonce=nonce, nonce_valid=1), None

def ms(v): return dict(mean=statistics.mean(v), sd=statistics.pstdev(v) if len(v) > 1 else 0.0)

def depth_sweep():
    res = {}
    for arch in ARCHS:
        res[arch] = {}
        for s in SCHEMES:
            emu = MCU(f'{ELF}/{s}.{arch}.O2.elf', arch); rows = []
            for n in range(1, 9):
                reps = 10 if s in ('agentcap', 'agentcap_opt', 'macaroon', 'acesym') else 3
                cyc, ins, warm, warm_ins = [], [], [], []
                for _ in range(reps):
                    nonce = os.urandom(8); wire, kw, holder = build(s, n, nonce)
                    emu.load_ctx(ctx_arm(D, **kw)); emu.boot()
                    r = emu.run(wire); assert r['ret'] == 0, (arch, s, n, r['ret'])
                    cyc.append(r['cycles']); ins.append(r['insns']); stack = r['stack']
                    if s == 'agentcap_opt':
                        n2 = os.urandom(8); emu.set_nonce(n2)
                        r2 = emu.run(holder.present(cmd(D, 1, 1, 20), n2)); assert r2['ret'] == 0
                        warm.append(r2['cycles']); warm_ins.append(r2['insns'])
                row = dict(n=n, cycles=ms(cyc), insns=ms(ins), bytes=len(wire), stack=stack, reps=reps)
                if warm: row.update(warm_cycles=ms(warm), warm_insns=ms(warm_ins))
                rows.append(row)
            res[arch][s] = rows
            print(arch, s, [(r['n'], round(r['cycles']['mean'])) for r in rows], flush=True)
    return res

def footprint():
    out = {}
    for arch in ARCHS:
        out[arch] = {}
        for s in SCHEMES:
            a = MCU(f'{ELF}/{s}.{arch}.O2.elf', arch); b = MCU(f'{ELF}/{s}.{arch}.Os.elf', arch)
            out[arch][s] = dict(flash_O2=a.text_size, flash_Os=b.text_size, ram_static=a.ram_static)
    return out

def cache_workload():
    """Device receives a Zipf-distributed stream from K concurrent depth-3 chains; cache has 4 entries."""
    out = {}
    emu = MCU(f'{ELF}/agentcap_opt.m4.O2.elf', 'm4')
    base = MCU(f'{ELF}/agentcap.m4.O2.elf', 'm4')
    for K in [1, 2, 4, 8, 16]:
        V = AttestationVendor(); H = Hub(V); holders = []
        for k in range(K):
            ag = [AgentRuntime('a', V) for _ in range(3)]
            H.issue(D, ag[0], ROOT_CAV, {GOOD})
            for i in range(1, 3): ag[i - 1].delegate(ag[i], LVL_CAV, {GOOD})
            holders.append(ag[2])
        w = [1 / (i + 1) for i in range(K)]
        emu.load_ctx(ctx_arm(D, key=H.kd(D))); emu.boot(); base.load_ctx(ctx_arm(D, key=H.kd(D)))
        cyc, bcyc = [], []
        for _ in range(150):
            h = random.choices(holders, weights=w)[0]; n = os.urandom(8)
            emu.set_nonce(n); base.set_nonce(n); wire = h.present(COMMAND, n)
            r = emu.run(wire); rb = base.run(wire); assert r['ret'] == 0 and rb['ret'] == 0
            cyc.append(r['cycles']); bcyc.append(rb['cycles'])
        out[K] = dict(opt=ms(cyc), base=ms(bcyc), hit_rate=sum(c < 40000 for c in cyc) / len(cyc),
                      p50=statistics.median(cyc))
        print('cache K', K, out[K], flush=True)
    return out

def sensitivity():
    out = {'caveats': {}, 'revlist': {}}
    em = MCU(f'{ELF}/agentcap.m4.O2.elf', 'm4')
    for k in [0, 2, 4, 8, 12, 16]:
        extra = [rng(2 + (j % 6), -100, 100) if j % 2 else state(j % 8, 1, 1000) for j in range(k)]
        H, ag = agentcap_chain(3, extra)
        nonce = os.urandom(8); r = em.run(ag[-1].present(COMMAND, nonce), ctx_arm(D, key=H.kd(D), nonce=nonce, nonce_valid=1))
        assert r['ret'] == 0; out['caveats'][k] = r['cycles']
    H, ag = agentcap_chain(3)
    for L in [0, 10, 100, 1000, 10000, 100000]:
        blob = b''.join(sorted(os.urandom(8) for _ in range(L))); nonce = os.urandom(8)
        r = em.run(ag[-1].present(COMMAND, nonce), ctx_arm(D, key=H.kd(D), nonce=nonce, nonce_valid=1, nrev=L), rev=blob)
        assert r['ret'] == 0; out['revlist'][L] = r['cycles']
    print(out)
    return out

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'patch':
        res = json.load(open(os.path.join(OUT, 'device2.json')))
        SCHEMES[:] = ['agentcap_opt']
        new = depth_sweep()
        for a in new: res['depth'][a]['agentcap_opt'] = new[a]['agentcap_opt']
        SCHEMES[:] = ['agentcap', 'agentcap_opt', 'macaroon', 'ucan', 'jwt', 'tedpop', 'acesym']
        res['footprint'] = footprint(); res['cache'] = cache_workload()
        json.dump(res, open(os.path.join(OUT, 'device2.json'), 'w'), indent=1)
    else:
        res = dict(depth=depth_sweep(), footprint=footprint(), cache=cache_workload(), sensitivity=sensitivity())
        json.dump(res, open(os.path.join(OUT, 'device2.json'), 'w'), indent=1)
