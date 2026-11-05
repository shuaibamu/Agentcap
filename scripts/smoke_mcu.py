"""Quick check: run AgentCap (cold and cached) and ACE-sym on the three emulated MCU cores at depth 3."""
import sys, os
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(HERE, '..', 'py'))
from agentcap import *
from mcuemu import MCU, ctx_arm
ELF = os.path.join(HERE, '..', 'device', 'mcu')
D = 7; V = AttestationVendor(); H = Hub(V); good = hashlib.sha256(b'agent-v1').digest()
ag = [AgentRuntime(f'a{i}', V) for i in range(3)]
H.issue(D, ag[0], [dev(D), caps(0, 1, 2), rng(1, 16, 26), tw(0, 5000), depth(4)], {good})
for i in range(1, 3): ag[i - 1].delegate(ag[i], [caps(1), rng(1, 18, 24)], {good})
for arch in ['m0p', 'm4', 'rv32']:
    m = MCU(f'{ELF}/agentcap_opt.{arch}.O2.elf', arch); n = os.urandom(8)
    m.load_ctx(ctx_arm(D, key=H.kd(D), nonce=n, nonce_valid=1)); m.boot()
    r1 = m.run(ag[2].present(cmd(D, 1, 1, 21), n)); n2 = os.urandom(8); m.set_nonce(n2)
    r2 = m.run(ag[2].present(cmd(D, 1, 1, 20), n2))
    print(f'{arch:5s} AgentCap cold {r1["cycles"]:>8d} cycles  cached {r2["cycles"]:>7d} cycles  (ret {r1["ret"]},{r2["ret"]})')
