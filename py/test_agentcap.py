import sys, os, struct
sys.path.insert(0, os.path.dirname(__file__))
from agentcap import *

def setup(depth_n=3):
    V = AttestationVendor(); H = Hub(V); good = hashlib.sha256(b'agent-v1').digest()
    D = 7; dv = Device(D, key=H.kd(D))
    agents = [AgentRuntime(f'a{i}', V) for i in range(depth_n)]
    H.issue(D, agents[0], [dev(D), caps(0, 1, 2), rng(1, 16, 26), tw(0, 5000), depth(4), reqatt(0b10)], {good})
    for i in range(1, depth_n):
        agents[i - 1].delegate(agents[i], [caps(1), rng(1, 18, 24)], {good})
    return V, H, D, dv, agents, good

def t(name, cond):
    print(('PASS ' if cond else 'FAIL ') + name); assert cond

V, H, D, dv, ag, good = setup(3)
n = dv.challenge(); w = ag[2].present(cmd(D, 1, 1, 21), n)
t('completeness depth3', dv.verify('agentcap', w) == 0)
t('replay rejected', dv.verify('agentcap', w) == -5)
n = dv.challenge(); t('attenuated action rejected', dv.verify('agentcap', ag[2].present(cmd(D, 2, 0, 0), n)) == -3)
n = dv.challenge(); t('range narrowed', dv.verify('agentcap', ag[2].present(cmd(D, 1, 1, 25), n)) == -3)
n = dv.challenge(); t('parent wider ok', dv.verify('agentcap', ag[1].present(cmd(D, 1, 1, 18), n)) == 0)
# tamper: widen a caveat in transit
n = dv.challenge(); w = bytearray(ag[2].present(cmd(D, 1, 1, 21), n)); i = w.find(bytes([C_RANGE, 5, 1]) + struct.pack('<h', 18)); w[i + 3] = 10
t('caveat tamper -> AUTH', dv.verify('agentcap', bytes(w)) == -2)
# strip last block (privilege escalation by truncation) without tag
root_id, blocks, tag = ag[2].cap
n = dv.challenge(); w = enc_chain(b'A', root_id, blocks[:2]) + cmd(D, 0) + n + hm(tag, b'INV', cmd(D, 0), n)[:16]
t('truncation -> AUTH', dv.verify('agentcap', w) == -2)
# stolen public token without tag (forwarding)
n = dv.challenge(); w = enc_chain(b'A', root_id, blocks) + cmd(D, 1, 1, 21) + n + os.urandom(16)
t('forwarded token w/o tag -> AUTH', dv.verify('agentcap', w) == -2)
# unattested child: delegation refuses
bad = AgentRuntime('evil', V, meas=b'evil');
try: ag[2].delegate(bad, [caps(1)], {good}); ok = False
except ValueError: ok = True
t('unattested delegation refused', ok)
# compromised holder appends BIND with disallowed class
root_id, blocks, tag = ag[2].cap
blk = cav(C_BIND, bytes([3]) + os.urandom(15)) + caps(1); nt = hm(tag, blk)
n = dv.challenge(); w = enc_chain(b'A', root_id, blocks + [blk]) + cmd(D, 1, 1, 20) + n + hm(nt, b'INV', cmd(D, 1, 1, 20), n)[:16]
t('REQATT class enforced', dv.verify('agentcap', w) == -8)
# depth
V, H, D, dv, ag, good = setup(6)
n = dv.challenge(); t('depth limit', dv.verify('agentcap', ag[5].present(cmd(D, 1, 1, 20), n)) == -7)
n = dv.challenge(); t('within depth', dv.verify('agentcap', ag[4].present(cmd(D, 1, 1, 20), n)) == 0)
# revocation of subtree
ids = H.chain_ids(D, ag[2].cap[0], ag[2].cap[1]); H.revoke(ids[1]); dv.set_rev(H.revlist())
n = dv.challenge(); t('subtree revoked (child)', dv.verify('agentcap', ag[3].present(cmd(D, 1, 1, 20), n)) == -4)
n = dv.challenge(); t('ancestor unaffected', dv.verify('agentcap', ag[0].present(cmd(D, 1, 1, 20), n)) == 0)
# rate + state + time
V = AttestationVendor(); H = Hub(V); dv = Device(9, key=H.kd(9)); a = AgentRuntime('x', V)
H.issue(9, a, [dev(9), caps(3), rate(2), state(0, 0, 1), tw(100, 2000)], {hashlib.sha256(b'agent-v1').digest()})
dv.set_state(0, 1)
r = [dv.verify('agentcap', a.present(cmd(9, 3), dv.challenge())) for _ in range(3)]
t('rate limit 2', r == [0, 0, -6])
dv2 = Device(9, key=H.kd(9)); dv2.set_state(0, 0)
t('state predicate', dv2.verify('agentcap', a.present(cmd(9, 3), dv2.challenge())) == -3)
dv3 = Device(9, key=H.kd(9), now=5000); dv3.set_state(0, 1)
t('expired', dv3.verify('agentcap', a.present(cmd(9, 3), dv3.challenge())) == -3)
t('wrong device key', Device(9, key=H.kd(10)).verify('agentcap', a.present(cmd(9, 3), b'\0' * 8)) == -2)
# ---- baselines
key = os.urandom(32); rid0 = os.urandom(8); blocks = [dev(4) + caps(1), caps(1)]
dm = Device(4, key=key)
t('macaroon ok', dm.verify('macaroon', macaroon_wire(rid0, blocks, macaroon_present(key, rid0, blocks), cmd(4, 1))) == 0)
t('macaroon bad tag', dm.verify('macaroon', macaroon_wire(rid0, blocks, os.urandom(32), cmd(4, 1))) == -2)
owner = ed25519.Ed25519PrivateKey.generate(); ks = [ed25519.Ed25519PrivateKey.generate() for _ in range(3)]
du = Device(4, owner_pk=ed_raw(owner)); parts = ucan_build(owner, ks, [dev(4) + caps(1, 2), caps(1), caps(1)])
t('ucan ok', du.verify('ucan', ucan_wire(parts, ks[2], cmd(4, 1), du.challenge())) == 0)
t('ucan wrong holder', du.verify('ucan', ucan_wire(parts, ks[1], cmd(4, 1), du.challenge())) == -2)
t('ucan attenuated', du.verify('ucan', ucan_wire(parts, ks[2], cmd(4, 2), du.challenge())) == -3)
as_sk = ec.generate_private_key(ec.SECP256R1()); dj = Device(4, as_pk=p256_raw_pub(as_sk))
t('jwt ok', dj.verify('jwt', jwt_wire(as_sk, dev(4) + caps(1), cmd(4, 1))) == 0)
w = bytearray(jwt_wire(as_sk, dev(4) + caps(1), cmd(4, 1))); w[8] ^= 1
t('jwt tamper', dj.verify('jwt', bytes(w)) == -2)
hk = ec.generate_private_key(ec.SECP256R1())
cl = dev(4) + caps(1) + act_chain([b'a', b'b']) + cnf(p256_raw_pub(hk))
t('tedpop ok', dj.verify('tedpop', tedpop_wire(as_sk, cl, hk, cmd(4, 1), dj.challenge())) == 0)
t('tedpop wrong holder', dj.verify('tedpop', tedpop_wire(as_sk, cl, as_sk, cmd(4, 1), dj.challenge())) == -2)
# ACE symmetric PoP
k16 = os.urandom(16); da = Device(4, key=k16 + b'\0' * 16); pk = os.urandom(32)
t('acesym ok', da.verify('acesym', acesym_wire(k16, dev(4) + caps(1), pk, cmd(4, 1), da.challenge())) == 0)
t('acesym wrong pop', da.verify('acesym', acesym_wire(k16, dev(4) + caps(1), os.urandom(32), cmd(4, 1), da.challenge())[:-16] + os.urandom(16)) == -2)
w = bytearray(acesym_wire(k16, dev(4) + caps(1), pk, cmd(4, 1), da.challenge())); w[20] ^= 1
t('acesym ct tamper', da.verify('acesym', bytes(w)) == -2)
t('acesym attenuated', da.verify('acesym', acesym_wire(k16, dev(4) + caps(1), pk, cmd(4, 2), da.challenge())) == -3)
# AgentCap-opt equivalence and cache
V, H, D, dv, ag, good = setup(3)
LIB.ac_boot(ctypes.byref(dv.c))
r1 = dv.verify('agentcap_opt', ag[2].present(cmd(D, 1, 1, 21), dv.challenge()))
r2 = dv.verify('agentcap_opt', ag[2].present(cmd(D, 1, 1, 22), dv.challenge()))
hits = ctypes.c_ulong.in_dll(LIB, 'g_cache_hits').value
t('opt cold+warm accept, 1 hit', r1 == 0 and r2 == 0 and hits == 1)
t('opt parent prefix hit', dv.verify('agentcap_opt', ag[1].present(cmd(D, 1, 1, 19), dv.challenge())) == 0)
n = dv.challenge(); w = bytearray(ag[2].present(cmd(D, 1, 1, 21), n)); i = w.find(bytes([C_RANGE, 5, 1]) + struct.pack('<h', 18)); w[i + 3] = 10
t('opt tamper after cache -> AUTH', dv.verify('agentcap_opt', bytes(w)) == -2)
n = dv.challenge(); t('opt narrowed', dv.verify('agentcap_opt', ag[2].present(cmd(D, 1, 1, 25), n)) == -3)
ids = H.chain_ids(D, ag[2].cap[0], ag[2].cap[1]); H.revoke(ids[2]); dv.set_rev(H.revlist())
t('opt revocation honoured with warm cache', dv.verify('agentcap_opt', ag[2].present(cmd(D, 1, 1, 21), dv.challenge())) == -4)
r, b, tg = ag[2].cap
n = dv.challenge(); w = enc_chain(b'A', r, b) + cmd(D, 1, 1, 21) + n + os.urandom(16)
t('opt forged sigma with cached chain', dv.verify('agentcap_opt', w) == -2)
# randomized equivalence between base and opt verifiers
import random
for trial in range(200):
    V, H, D, dvb, ag, good = setup(random.randint(1, 5))
    dvo = Device(D, key=H.kd(D)); LIB.ac_boot(ctypes.byref(dvo.c))
    for _ in range(3):
        c = cmd(D, random.randint(0, 3), 1, random.randint(10, 30)); a = random.choice(ag)
        n = os.urandom(8)
        for d_ in (dvb, dvo): ctypes.memmove(d_.c.nonce, n, 8); d_.c.nonce_valid = 1
        w = bytearray(a.present(c, n))
        if random.random() < 0.3: w[random.randrange(len(w))] ^= 1 << random.randrange(8)
        rb = dvb.verify('agentcap', bytes(w)); ro = dvo.verify('agentcap_opt', bytes(w))
        assert rb == ro, (rb, ro)
t('base==opt on 600 random (incl. bit-flipped) presentations', True)
# authenticated revocation epochs (ac_set_epoch)
V, H, D, dv, ag, good = setup(3)
ids = H.chain_ids(D, ag[1].cap[0], ag[1].cap[1]); H.revoke(ids[1])
e, rl, tg = H.epoch_update(D, 1)
t('epoch: forged tag rejected', dv.set_epoch(e, rl, bytes(16)) == -2)
t('epoch: valid update accepted', dv.set_epoch(e, rl, tg) == 0)
t('epoch: sub-tree below revoked node rejected after update',
  dv.verify('agentcap', ag[2].present(cmd(D, 1, 1, 21), dv.challenge())) == -4)
t('epoch: replayed (non-increasing) epoch rejected', dv.set_epoch(e, rl, tg) == -5)
H.revoked.clear(); e2, rl2, tg2 = H.epoch_update(D, 1)
t('epoch: rollback to an older list with stale counter rejected', dv.set_epoch(e2, rl2, tg2) in (-2, -5))
print('ALL TESTS PASSED')
