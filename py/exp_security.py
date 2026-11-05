"""E4: attack matrix (real C verifier via ctypes); E5: prompt-injection blast radius;
E6: subtree revocation bandwidth and effectiveness."""
import sys, os, json, random
sys.path.insert(0, os.path.dirname(__file__))
from agentcap import *

OUT = os.path.join(os.path.dirname(__file__), '..', 'results')
GOOD = hashlib.sha256(b'agent-v1').digest()
N = 1000
SCHEMES = ['agentcap', 'macaroon', 'ucan', 'jwt', 'tedpop', 'acesym']
random.seed(7)

class World:
    """A depth-3 credential for device D under each scheme, plus everything an attacker can observe."""
    def __init__(self, D=7):
        self.D = D
        self.V = AttestationVendor(); self.H = Hub(self.V)
        self.ag = [AgentRuntime(f'a{i}', self.V) for i in range(3)]
        self.root = [dev(D), caps(0, 1, 2), rng(1, 16, 26), tw(0, 5000), depth(4), reqatt(0b10)]
        self.H.issue(D, self.ag[0], self.root, {GOOD})
        for i in range(1, 3): self.ag[i - 1].delegate(self.ag[i], [caps(1), rng(1, 18, 24)], {GOOD})
        self.mkey = os.urandom(32); self.mrid = os.urandom(8)
        self.mblocks = [dev(D) + caps(0, 1, 2) + rng(1, 16, 26), caps(1) + rng(1, 18, 24), caps(1) + rng(1, 18, 24)]
        self.owner = ed25519.Ed25519PrivateKey.generate(); self.uk = [ed25519.Ed25519PrivateKey.generate() for _ in range(3)]
        self.uparts = ucan_build(self.owner, self.uk, self.mblocks)
        self.as_sk = ec.generate_private_key(ec.SECP256R1()); self.hk = ec.generate_private_key(ec.SECP256R1())
        self.jclaims = dev(D) + caps(1) + rng(1, 18, 24)
        self.tclaims = self.jclaims + act_chain([b'a0', b'a1', b'a2']) + cnf(p256_raw_pub(self.hk))
        self.k16 = os.urandom(16); self.popkey = os.urandom(32)
        self.aclaims = self.jclaims + act_chain([b'a0', b'a1', b'a2'])
    def device(self, D=None):
        D = D or self.D
        return Device(D, key=self.H.kd(D) if D == self.D else self.H.kd(D), owner_pk=ed_raw(self.owner), as_pk=p256_raw_pub(self.as_sk))
    def legit(self, s, dv, c):
        n = dv.challenge()
        if s in ('agentcap', 'agentcap_noatt'): return self.ag[2].present(c, n)
        if s == 'macaroon': return macaroon_wire(self.mrid, self.mblocks, macaroon_present(self.mkey, self.mrid, self.mblocks), c)
        if s == 'ucan': return ucan_wire(self.uparts, self.uk[2], c, n)
        if s == 'jwt': return jwt_wire(self.as_sk, self.jclaims, c)
        if s == 'tedpop': return tedpop_wire(self.as_sk, self.tclaims, self.hk, c, n)
        if s == 'acesym': return acesym_wire(self.k16, self.aclaims, self.popkey, c, n)

def mdev(w, dv):
    dv.c.dev_id = w.D; ctypes.memmove(dv.c.key, w.mkey, 32); return dv

def adev(w, dv):
    ctypes.memmove(dv.c.key, w.k16 + b'\0' * 16, 32); return dv

def attack(w, s, kind):
    D = w.D; dv = w.device()
    if s == 'macaroon': mdev(w, dv)
    if s == 'acesym': adev(w, dv)
    c_ok = cmd(D, 1, 1, random.randint(18, 24))
    observed = w.legit(s, dv, c_ok); assert dv.verify(s, observed) == 0
    c_new = cmd(D, 1, 1, random.randint(18, 24))
    if kind == 'forward':   # stolen credential reused by another party for a new command
        n = dv.challenge()
        if s == 'agentcap':
            r, b, _ = w.ag[2].cap; wire = enc_chain(b'A', r, b) + c_new + n + os.urandom(16)
        elif s == 'macaroon':
            wire = observed[:-40] + c_new + observed[-32:]
        elif s == 'ucan':
            atk = ed25519.Ed25519PrivateKey.generate(); wire = ucan_wire(w.uparts, atk, c_new, n)
        elif s == 'jwt':
            wire = observed[:-8] + c_new
        elif s == 'acesym':   # ciphertext token observed; PoP key is inside it and unknown
            wire = observed[:-32] + c_new + n + os.urandom(16)
        else:
            atk = ec.generate_private_key(ec.SECP256R1()); wire = tedpop_wire(w.as_sk, w.tclaims, atk, c_new, n)
        return dv.verify(s, wire) == 0
    if kind == 'replay':
        dv.challenge(); return dv.verify(s, observed) == 0
    if kind == 'tamper':    # widen authority by editing a caveat, keep proof
        wire = bytearray(observed)
        if s == 'acesym':
            wire[17 + 6] ^= 0x40; ctypes.memmove(dv.c.nonce, observed[-24:-16], 8); dv.c.nonce_valid = 1
            return dv.verify(s, bytes(wire)) == 0
        i = wire.find(bytes([C_RANGE, 5, 1]) + struct.pack('<h', 18))
        if i < 0: i = wire.find(bytes([C_RANGE, 5, 1]))
        wire[i + 3:i + 5] = struct.pack('<h', -500)
        if s in ('agentcap', 'ucan', 'tedpop'):
            # re-arm the nonce the observed proof used so that only integrity is tested
            nn = observed[-24:-16] if s == 'agentcap' else observed[-72:-64]
            ctypes.memmove(dv.c.nonce, nn, 8); dv.c.nonce_valid = 1
        return dv.verify(s, bytes(wire)) == 0
    if kind == 'truncate':
        if s in ('jwt', 'tedpop', 'acesym'): return None
        n = dv.challenge()
        if s == 'agentcap':
            r, b, t = w.ag[2].cap; wire = enc_chain(b'A', r, b[:2]) + c_new + n + hm(t, b'INV', c_new, n)[:16]
        elif s == 'macaroon':
            wire = macaroon_wire(w.mrid, w.mblocks[:2], observed[-32:], c_new)
        else:
            wire = ucan_wire(w.uparts[:2], w.uk[2], c_new, n)
        return dv.verify(s, wire) == 0
    if kind == 'rogue':     # sub-agent spawned from an unvetted runtime
        V = w.V; rogue = AgentRuntime('rogue', V, meas=b'injected-tool')
        if s == 'agentcap':
            try: w.ag[2].delegate(rogue, [caps(1)], {GOOD})
            except ValueError: return False
            return dv.verify(s, rogue.present(c_new, dv.challenge())) == 0
        if s == 'agentcap_noatt':   # ablation: attestation policy disabled (W = any measurement)
            w.ag[2].delegate(rogue, [caps(1)], {GOOD, rogue.meas})
            return dv.verify('agentcap', rogue.present(c_new, dv.challenge())) == 0
        if s == 'acesym':           # AS performs exchange for the rogue client; no runtime evidence
            return dv.verify(s, acesym_wire(w.k16, w.aclaims + act_chain([b'r']), os.urandom(32), c_new, dv.challenge())) == 0
        if s == 'macaroon':
            return dv.verify(s, macaroon_wire(w.mrid, w.mblocks + [caps(1)], hm(observed[-32:], caps(1)), c_new)) == 0
        if s == 'ucan':
            rk = ed25519.Ed25519PrivateKey.generate()
            parts = list(w.uparts); prev = parts[-1][2]; blk = caps(1); aud = ed_raw(rk)
            parts.append((blk, aud, w.uk[2].sign(prev + blk + aud)))
            return dv.verify(s, ucan_wire(parts, rk, c_new, dv.challenge())) == 0
        if s == 'jwt':
            return dv.verify(s, observed[:-8] + c_new) == 0
        rk = ec.generate_private_key(ec.SECP256R1())   # AS performs exchange; no runtime evidence in RFC 8693
        cl = w.jclaims + act_chain([b'a0', b'a1', b'a2', b'r']) + cnf(p256_raw_pub(rk))
        return dv.verify(s, tedpop_wire(w.as_sk, cl, rk, c_new, dv.challenge())) == 0
    if kind == 'insider':   # compromised (attested) delegator lies in BIND / hands authority on
        if s == 'acesym':
            return dv.verify(s, acesym_wire(w.k16, w.aclaims, w.popkey, c_new, dv.challenge())) == 0
        if s == 'agentcap':
            r, b, t = w.ag[2].cap; blk = cav(C_BIND, bytes([1]) + os.urandom(15)) + caps(1); nt = hm(t, blk)
            n = dv.challenge(); wire = enc_chain(b'A', r, b + [blk]) + c_new + n + hm(nt, b'INV', c_new, n)[:16]
            return dv.verify(s, wire) == 0
        return attack(w, s, 'rogue')
    if kind == 'crossdev':
        other = w.device(D + 1)
        if s in ('macaroon', 'acesym'): ctypes.memmove(other.c.key, os.urandom(32), 32)
        wire = w.legit(s, other, cmd(D + 1, 1, 1, 20))
        return other.verify(s, wire) == 0
    if kind == 'forge':
        n = dv.challenge()
        if s == 'agentcap':
            r, b, _ = w.ag[2].cap; wire = enc_chain(b'A', r, [dev(D) + caps(0, 1, 2, 3)]) + cmd(D, 3) + n + os.urandom(16)
        elif s == 'macaroon': wire = macaroon_wire(os.urandom(8), [dev(D) + caps(3)], os.urandom(32), cmd(D, 3))
        elif s == 'ucan':
            fk = ed25519.Ed25519PrivateKey.generate(); parts = ucan_build(fk, [fk], [dev(D) + caps(3)])
            wire = ucan_wire(parts, fk, cmd(D, 3), n)
        elif s == 'jwt': wire = jwt_wire(ec.generate_private_key(ec.SECP256R1()), dev(D) + caps(3), cmd(D, 3))
        elif s == 'acesym': wire = acesym_wire(os.urandom(16), dev(D) + caps(3), os.urandom(32), cmd(D, 3), n)
        else:
            fk = ec.generate_private_key(ec.SECP256R1())
            wire = tedpop_wire(fk, dev(D) + caps(3) + cnf(p256_raw_pub(fk)), fk, cmd(D, 3), n)
        return dv.verify(s, wire) == 0

ATTACKS = ['forward', 'replay', 'tamper', 'truncate', 'rogue', 'insider', 'crossdev', 'forge']

def attack_matrix():
    res = {}
    worlds = [World() for _ in range(20)]
    for a in ATTACKS:
        res[a] = {}
        for s in SCHEMES:
            trials = N if s in ('agentcap', 'macaroon', 'jwt', 'acesym') else N // 4  # signature-heavy schemes: fewer trials
            outs = [attack(worlds[t % 20], s, a) for t in range(trials)]
            if outs[0] is None: res[a][s] = None
            else: res[a][s] = dict(trials=trials, success=sum(outs), rate=sum(outs) / trials)
            print(a, s, res[a][s], flush=True)
    outs = [attack(worlds[t % 20], 'agentcap_noatt', 'rogue') for t in range(N)]
    res['ablation_noatt_rogue'] = dict(trials=N, success=sum(outs), rate=sum(outs) / N)
    print('ablation', res['ablation_noatt_rogue'])
    return res

# ---------------- E5: prompt-injection blast radius ----------------
# device ids, action ids, param ids
LOCK, THERMO, LIGHT, CAM, OVEN, GARAGE, PLUG, BLIND = range(1, 9)
TEMP, LEVEL = 1, 2
HOUR = 3600
def intents():
    """Templates: (text, device, action, param, lo, hi, duration_s, uses, state)."""
    return [
        ('heat living room', THERMO, 1, TEMP, 19, 23, HOUR, 2, None),
        ('cool down', THERMO, 1, TEMP, 18, 22, HOUR, 2, None),
        ('dim lights', LIGHT, 1, LEVEL, 10, 60, 2 * HOUR, 4, None),
        ('lights off', LIGHT, 0, 0, 0, 0, 900, 1, None),
        ('preheat oven', OVEN, 1, TEMP, 160, 200, HOUR, 1, (0, 0, 1)),
        ('let cleaner in', LOCK, 1, 0, 0, 0, 900, 1, None),
        ('lock up', LOCK, 0, 0, 0, 0, 900, 1, None),
        ('open blinds', BLIND, 1, LEVEL, 0, 100, 900, 2, None),
        ('charge scooter', PLUG, 1, 0, 0, 0, 3 * HOUR, 1, None),
        ('check camera', CAM, 2, 0, 0, 0, 600, 3, None),
        ('close garage', GARAGE, 0, 0, 0, 0, 600, 1, None),
    ]
def harmful():
    """Commands an injected attacker wants: (device, action, param, value, when_offset_s)."""
    H = []
    for t in range(0, 4 * HOUR, 600):
        H += [(LOCK, 1, 0, 0, t), (CAM, 0, 0, 0, t), (OVEN, 1, TEMP, 260, t), (THERMO, 1, TEMP, 35, t),
              (THERMO, 1, TEMP, 5, t), (GARAGE, 1, 0, 0, t), (PLUG, 1, 0, 0, t), (LIGHT, 0, 0, 0, t)]
    return H

def blast_radius():
    V = AttestationVendor(); Hb = Hub(V)
    as_sk = ec.generate_private_key(ec.SECP256R1()); aspk = p256_raw_pub(as_sk)
    T0 = 100000
    ms = [1, 2, 4, 8, 16, 32, 64]; sessions = 300
    out = {k: {m: 0 for m in ms} for k in ('owner', 'oauth', 'agentcap', 'agentcap_sub')}
    adaptive = {k: 0 for k in out}; inint = {k: 0 for k in out}
    HARM = harmful(); TEMPL = intents()
    for sidx in range(sessions):
        task = random.sample(TEMPL, random.randint(1, 3))
        creds = {}  # device -> dict(scheme -> (presenter fn))
        for (txt, D, act, par, lo, hi, dur, uses, st) in task:
            a = AgentRuntime('planner', V); sub = AgentRuntime('tool', V)
            cv = [dev(D), caps(act), tw(T0, T0 + dur), rate(uses), intent(txt)]
            if par: cv.append(rng(par, lo, hi))
            if st: cv.append(state(*st))
            Hb.issue(D, a, cv, {GOOD})
            a.delegate(sub, [caps(act), tw(T0, T0 + min(dur, 900))], {GOOD})
            creds.setdefault(D, []).append((a, sub, act))
        oauth_scopes = {}
        for (txt, D, act, *_r) in task: oauth_scopes.setdefault(D, set()).add(act)
        def accepted(kind, h, devs):
            D, act, par, val, off = h
            dv = devs.setdefault((kind, D), Device(D, key=Hb.kd(D), as_pk=aspk, now=T0 + off))
            dv.c.now = T0 + off; dv.set_state(0, 0)  # oven unattended -> occupancy 0
            c = cmd(D, act, par, val)
            if kind == 'owner':
                return dv.verify('jwt', jwt_wire(as_sk, dev(D) + caps(*range(16)) + tw(T0, T0 + 24 * HOUR), c)) == 0
            if kind == 'oauth':
                if D not in oauth_scopes: return False
                return dv.verify('jwt', jwt_wire(as_sk, dev(D) + caps(*oauth_scopes[D]) + tw(T0, T0 + HOUR), c)) == 0
            for (a, sub, _a) in creds.get(D, []):
                holder = a if kind == 'agentcap' else sub
                if dv.verify('agentcap', holder.present(c, dv.challenge())) == 0: return True
            return False
        def intended(h):
            D, act, par, val, off = h
            return any(D == tD and act == tact and (par == 0 or (par == tpar and tlo <= val <= thi)) and off <= tdur
                       for (_t, tD, tact, tpar, tlo, thi, tdur, _u, _s) in task)
        for kind in out:
            adaptive[kind] += any((not intended(h)) and accepted(kind, h, {}) for h in HARM)
            inint[kind] += any(intended(h) and accepted(kind, h, {}) for h in HARM)
            for m in ms:
                devs = {}
                hit = False
                for _ in range(m):
                    h = random.choice(HARM)
                    if accepted(kind, h, devs) and not intended(h): hit = True
                out[kind][m] += hit
        if sidx % 50 == 0: print('session', sidx, {k: out[k][64] for k in out}, flush=True)
    return dict(ms=ms, sessions=sessions, rate={k: {m: out[k][m] / sessions for m in ms} for k in out},
                adaptive={k: adaptive[k] / sessions for k in adaptive},
                in_intent={k: inint[k] / sessions for k in inint})

# ---------------- E6: subtree revocation ----------------
def revocation():
    V = AttestationVendor(); H = Hub(V); D = 7
    res = []
    for k in [1, 4, 16, 64, 256, 1024]:
        root = AgentRuntime('r', V); H.issue(D, root, [dev(D), caps(1), rate(60000)], {GOOD})
        mid = AgentRuntime('m', V); root.delegate(mid, [caps(1)], {GOOD})
        leaves = []
        for i in range(k):
            l = AgentRuntime('l', V); mid.delegate(l, [caps(1)], {GOOD}); leaves.append(l)
        H.revoked = set(); H.revoke(H.chain_ids(D, mid.cap[0], mid.cap[1])[1])
        dv = Device(D, key=H.kd(D)); dv.set_rev(H.revlist())
        blocked = sum(dv.verify('agentcap', l.present(cmd(D, 1), dv.challenge())) == -4 for l in leaves)
        root_ok = dv.verify('agentcap', root.present(cmd(D, 1), dv.challenge())) == 0
        res.append(dict(k=k, agentcap_bytes=len(H.revlist()), per_token_bytes=8 * (k + 1),
                        blocked=blocked, root_ok=root_ok))
        print(res[-1], flush=True)
    return res

if __name__ == '__main__':
    out = {'attacks': attack_matrix(), 'blast': blast_radius(), 'revocation': revocation()}
    json.dump(out, open(os.path.join(OUT, 'security.json'), 'w'), indent=1, default=str)
