"""E9: hub-side throughput. Root issuance (quote appraisal + root-tag derivation + sealing,
including the agent's quote generation and tag opening in the same process) and computation of
the revocation identifiers of a depth-8 chain. Writes results/hub.json."""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(__file__))
from agentcap import *

OUT = os.path.join(os.path.dirname(__file__), '..', 'results')
GOOD = hashlib.sha256(b'agent-v1').digest()

def main(reps_issue=500, reps_rid=20000):
    V = AttestationVendor(); H = Hub(V); D = 7
    agents = [AgentRuntime('a%d' % i, V) for i in range(16)]
    cav = [dev(D), caps(1), rng(1, 16, 26)]
    for a in agents: H.issue(D, a, cav, {GOOD})      # warm-up
    t = time.perf_counter()
    for i in range(reps_issue): H.issue(D, agents[i % 16], cav, {GOOD})
    issue_us = (time.perf_counter() - t) * 1e6 / reps_issue
    rid0, blk = H.issue(D, agents[0], cav, {GOOD})
    blocks = [blk] + [caps(1) + rng(1, 18, 24)] * 8
    t = time.perf_counter()
    for _ in range(reps_rid): H.chain_ids(D, rid0, blocks)
    rid_us = (time.perf_counter() - t) * 1e6 / reps_rid
    res = dict(issue_us=round(issue_us, 1), issue_per_s=int(1e6 / issue_us), rid_chain8_us=round(rid_us, 1),
               reps_issue=reps_issue, reps_rid=reps_rid)
    print(res)
    if '--write' in sys.argv:
        json.dump(res, open(os.path.join(OUT, 'hub.json'), 'w'))


def _worker(args):
    reps, seed = args
    V = AttestationVendor(); H = Hub(V); D = 7
    agents = [AgentRuntime('a%d' % i, V) for i in range(16)]
    cav = [dev(D), caps(1), rng(1, 16, 26)]
    for a in agents: H.issue(D, a, cav, {GOOD})
    t = time.perf_counter()
    for i in range(reps): H.issue(D, agents[i % 16], cav, {GOOD})
    return reps, time.perf_counter() - t

def scaling(reps=2000):
    """Aggregate issuance throughput with 1..nproc independent worker processes."""
    import multiprocessing as mp
    out = {}
    for w in range(1, (os.cpu_count() or 1) + 1):
        with mp.Pool(w) as p:
            t = time.perf_counter(); r = p.map(_worker, [(reps, s) for s in range(w)]); wall = time.perf_counter() - t
        per_s = sum(x[0] for x in r) / max(x[1] for x in r)
        out[w] = dict(per_s=int(per_s), wall_s=round(wall, 2))
        print('workers', w, out[w], flush=True)
    return out

if __name__ == '__main__':
    if '--scaling' in sys.argv:
        res = [scaling() for _ in range(5)]   # five independent runs
        if '--write' in sys.argv: json.dump(res, open(os.path.join(OUT, 'hub_scaling.json'), 'w'))
    else:
        main()
