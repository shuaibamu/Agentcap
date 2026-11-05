"""E10: verified-prefix cache sizing. Cortex-M4 (-O2) builds of AgentCap-opt with CACHE_N in
{1,2,4,8,16} entries (device/mcu/agentcap_opt_c<N>.m4.O2.elf, built by build_mcu.sh) replay a stream of
presentations from K concurrent depth-3 chains under a Zipf(1) and a uniform chain-popularity law.
Every presentation is also checked by the cold verifier; verdicts must agree. Writes results/cache_size.json."""
import sys, os, json, random, statistics
sys.path.insert(0, os.path.dirname(__file__))
from agentcap import *
from mcuemu import MCU, ctx_arm

OUT = os.path.join(os.path.dirname(__file__), '..', 'results')
ELF = os.path.join(os.path.dirname(__file__), '..', 'device', 'mcu')
D = 7; GOOD = hashlib.sha256(b'agent-v1').digest()
ROOT_CAV = [dev(D), caps(0, 1, 2), rng(1, 16, 26), tw(0, 5000), depth(8)]
LVL_CAV = [caps(1), rng(1, 18, 24), tw(0, 4000)]
COMMAND = cmd(D, 1, 1, 21)
SIZES = [1, 2, 4, 8, 16]; KS = [1, 2, 4, 8, 16, 32]; LAWS = ['zipf', 'uniform']
STREAM = 300; SEEDS = [1, 2, 3]

def chains(K):
    V = AttestationVendor(); H = Hub(V); hs = []
    for _ in range(K):
        ag = [AgentRuntime('a', V) for _ in range(3)]
        H.issue(D, ag[0], ROOT_CAV, {GOOD})
        for i in range(1, 3): ag[i - 1].delegate(ag[i], LVL_CAV, {GOOD})
        hs.append(ag[2])
    return H, hs

def main():
    emus = {N: MCU(f'{ELF}/agentcap_opt_c{N}.m4.O2.elf', 'm4') for N in SIZES}
    base = MCU(f'{ELF}/agentcap.m4.O2.elf', 'm4')
    res = {'sizes': SIZES, 'ks': KS, 'stream': STREAM, 'seeds': SEEDS, 'ram_static': {}, 'data': {}}
    for N in SIZES: res['ram_static'][N] = emus[N].ram_static if hasattr(emus[N], 'ram_static') else None
    for law in LAWS:
        res['data'][law] = {}
        for K in KS:
            per = {N: {'hit': [], 'mean': []} for N in SIZES}; bmean = []
            for seed in SEEDS:
                random.seed(1000 * seed + K)
                H, hs = chains(K)
                w = [1 / (i + 1) for i in range(K)] if law == 'zipf' else [1] * K
                trace = [random.choices(range(K), weights=w)[0] for _ in range(STREAM)]
                ctx = ctx_arm(D, key=H.kd(D))
                for N in SIZES: emus[N].load_ctx(ctx); emus[N].boot()
                base.load_ctx(ctx)
                cyc = {N: [] for N in SIZES}; bc = []
                for j in trace:
                    n = os.urandom(8); wire = hs[j].present(COMMAND, n)
                    base.set_nonce(n); rb = base.run(wire); assert rb['ret'] == 0; bc.append(rb['cycles'])
                    for N in SIZES:
                        emus[N].set_nonce(n); r = emus[N].run(wire); assert r['ret'] == rb['ret']
                        cyc[N].append(r['cycles'])
                for N in SIZES:
                    per[N]['hit'].append(sum(c < 40000 for c in cyc[N]) / STREAM)
                    per[N]['mean'].append(statistics.mean(cyc[N]))
                bmean.append(statistics.mean(bc))
            res['data'][law][K] = {'cold_mean': statistics.mean(bmean),
                                   **{N: dict(hit=statistics.mean(per[N]['hit']), hit_sd=statistics.pstdev(per[N]['hit']),
                                              mean=statistics.mean(per[N]['mean']), mean_sd=statistics.pstdev(per[N]['mean']))
                                      for N in SIZES}}
            print(law, K, {N: (round(res['data'][law][K][N]['hit'], 3), round(res['data'][law][K][N]['mean'])) for N in SIZES},
                  round(res['data'][law][K]['cold_mean']), flush=True)
    json.dump(res, open(os.path.join(OUT, 'cache_size.json'), 'w'), indent=1)

if __name__ == '__main__':
    main()
