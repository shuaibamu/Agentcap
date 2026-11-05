import sys, os, json, random, statistics
sys.path.insert(0, os.path.dirname(__file__))
import exp_security as ES
runs = []
for seed in range(1, 6):
    random.seed(seed); r = ES.blast_radius(); runs.append(r); print('seed', seed, r['adaptive'], flush=True)
ms = runs[0]['ms']; out = {'ms': ms, 'seeds': 5, 'sessions_per_seed': runs[0]['sessions']}
for k in runs[0]['rate']:
    out[k] = {'rate_mean': {m: statistics.mean(r['rate'][k][m] for r in runs) for m in ms},
              'rate_sd': {m: statistics.pstdev(r['rate'][k][m] for r in runs) for m in ms},
              'adaptive_mean': statistics.mean(r['adaptive'][k] for r in runs),
              'adaptive_sd': statistics.pstdev(r['adaptive'][k] for r in runs),
              'in_intent_mean': statistics.mean(r['in_intent'][k] for r in runs)}
json.dump(out, open(os.path.join(os.path.dirname(__file__), '..', 'results', 'blast_seeds.json'), 'w'), indent=1)
print(json.dumps({k: (out[k]['adaptive_mean'], out[k]['rate_mean'][64]) for k in runs[0]['rate']}))
