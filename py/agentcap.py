"""AgentCap reference implementation (agent/hub side) + baselines + ctypes device wrapper."""
import os, struct, hmac, hashlib, ctypes, time
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESCCM

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = ctypes.CDLL(os.path.join(HERE, '..', 'device', 'libverif.so'))

# ---------------- caveat language ----------------
C_DEV, C_CAPS, C_RANGE, C_TIME, C_RATE, C_DEPTH, C_BIND, C_INTENT, C_STATE, C_REQATT, C_ACT, C_CNF = \
    1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0B, 0x0C, 0x0D
ERR = {0: 'OK', -1: 'FMT', -2: 'AUTH', -3: 'CAV', -4: 'REV', -5: 'NONCE', -6: 'RATE', -7: 'DEPTH', -8: 'ATT'}

def cav(t, v): return bytes([t, len(v)]) + v
def dev(d): return cav(C_DEV, struct.pack('<I', d))
def caps(*actions):
    m = 0
    for a in actions: m |= 1 << a
    return cav(C_CAPS, struct.pack('<H', m))
def rng(param, lo, hi): return cav(C_RANGE, struct.pack('<Bhh', param, lo, hi))
def tw(nbf, exp): return cav(C_TIME, struct.pack('<II', nbf, exp))
def rate(n): return cav(C_RATE, struct.pack('<H', n))
def depth(d): return cav(C_DEPTH, bytes([d]))
def bind(cls, pk, meas): return cav(C_BIND, bytes([cls]) + hashlib.sha256(pk + meas).digest()[:15])
def intent(text): return cav(C_INTENT, hashlib.sha256(text.encode()).digest()[:16])
def state(sensor, op, val): return cav(C_STATE, struct.pack('<BBh', sensor, op, val))
def reqatt(mask): return cav(C_REQATT, bytes([mask]))

def cmd(devid, action, param=0, value=0): return struct.pack('<IBBh', devid, action, param, value)

def hm(k, *parts):
    h = hmac.new(k, digestmod=hashlib.sha256)
    for p in parts: h.update(p)
    return h.digest()
def rid(tag): return hashlib.sha256(b'RID' + tag).digest()[:8]

# ---------------- attestation (simulated TEE vendor) ----------------
class AttestationVendor:
    """Signs quotes binding an agent runtime key to its measured code identity."""
    def __init__(self):
        self.sk = ed25519.Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()
    def quote(self, agent_pk, meas, cls, nonce):
        msg = b'Q' + agent_pk + meas + bytes([cls]) + nonce
        return msg, self.sk.sign(msg)
    def check(self, msg, sig):
        try: self.pk.verify(sig, msg); return True
        except Exception: return False

def raw_x(pk): return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

class AgentRuntime:
    """An agent running inside an attested runtime: holds an X25519 KEM key and its capability."""
    def __init__(self, name, vendor, meas=b'agent-v1', cls=1):
        self.name = name; self.vendor = vendor
        self.kem = x25519.X25519PrivateKey.generate(); self.pk = raw_x(self.kem.public_key())
        self.meas = hashlib.sha256(meas).digest(); self.cls = cls
        self.cap = None  # (root_id, [blocks], tag)
    def evidence(self, nonce): return self.vendor.quote(self.pk, self.meas, self.cls, nonce)
    def receive(self, root_id, blocks, sealed):
        tag = open_tag(self.kem, sealed, root_id + b''.join(blocks))
        self.cap = (root_id, list(blocks), tag)
    def delegate(self, child, caveats, allow_meas, nonce=None):
        """Attenuate own capability to an attested child runtime (Alg. 2)."""
        nonce = nonce or os.urandom(16)
        msg, sig = child.evidence(nonce)
        if not self.vendor.check(msg, sig): raise ValueError('bad quote')
        if msg[1 + 32:1 + 64] not in allow_meas: raise ValueError('measurement not allowed')
        root_id, blocks, tag = self.cap
        blk = bind(child.cls, child.pk, child.meas) + b''.join(caveats)
        ntag = hm(tag, blk)
        sealed = seal_tag(child.pk, ntag, root_id + b''.join(blocks + [blk]))
        child.receive(root_id, blocks + [blk], sealed)
        return blk
    def present(self, command, nonce):
        root_id, blocks, tag = self.cap
        sigma = hm(tag, b'INV', command, nonce)[:16]
        return enc_chain(b'A', root_id, blocks) + command + nonce + sigma

def enc_chain(magic, root_id, blocks):
    out = magic + b'\x01' + root_id + bytes([len(blocks)])
    for b in blocks:
        assert len(b) < 256; out += bytes([len(b)]) + b
    return out

def seal_tag(recipient_pk, tag, aad):
    eph = x25519.X25519PrivateKey.generate()
    ss = eph.exchange(x25519.X25519PublicKey.from_public_bytes(recipient_pk))
    epk = raw_x(eph.public_key())
    k = HKDF(hashes.SHA256(), 32, None, b'agentcap-seal' + epk + recipient_pk).derive(ss)
    return epk + ChaCha20Poly1305(k).encrypt(b'\x00' * 12, tag, aad)
def open_tag(sk, sealed, aad):
    epk, ct = sealed[:32], sealed[32:]
    ss = sk.exchange(x25519.X25519PublicKey.from_public_bytes(epk))
    k = HKDF(hashes.SHA256(), 32, None, b'agentcap-seal' + epk + raw_x(sk.public_key())).derive(ss)
    return ChaCha20Poly1305(k).decrypt(b'\x00' * 12, ct, aad)

class Hub:
    """Home hub / owner: shares K_d with each device, issues root capabilities, keeps revocation."""
    def __init__(self, vendor):
        self.master = os.urandom(32); self.vendor = vendor; self.revoked = set()
    def kd(self, devid): return hm(self.master, b'KD', struct.pack('<I', devid))
    def issue(self, devid, agent, caveats, allow_meas):
        nonce = os.urandom(16)
        msg, sig = agent.evidence(nonce)
        if not self.vendor.check(msg, sig) or msg[33:65] not in allow_meas: raise ValueError('attestation')
        root_id = os.urandom(8)
        blk = bind(agent.cls, agent.pk, agent.meas) + b''.join(caveats)
        tag = hm(self.kd(devid), root_id, blk)
        agent.receive(root_id, [blk], seal_tag(agent.pk, tag, root_id + blk))
        return root_id, blk
    def chain_ids(self, devid, root_id, blocks):
        t = hm(self.kd(devid), root_id, blocks[0]); ids = [rid(t)]
        for b in blocks[1:]: t = hm(t, b); ids.append(rid(t))
        return ids
    def revoke(self, ident): self.revoked.add(ident)
    def revlist(self): return b''.join(sorted(self.revoked))
    def epoch_update(self, devid, epoch):
        """Authenticated revocation epoch for device devid: (epoch, RL_e, 16-byte tag)."""
        rl = self.revlist()
        tag = hm(self.kd(devid), b'EPOCH', struct.pack('<II', epoch, len(rl) // 8), rl)[:16]
        return epoch, rl, tag

# ---------------- baselines (token side) ----------------
def macaroon_present(root_key, root_id, blocks):
    t = hm(root_key, root_id, blocks[0])
    for b in blocks[1:]: t = hm(t, b)
    return t

def macaroon_wire(root_id, blocks, tag, command):
    return enc_chain(b'M', root_id, blocks) + command + tag

def ed_raw(sk): return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

def ucan_build(owner_sk, keys, blocks):
    """keys[i] is the audience (holder) Ed25519 key of block i; block 0 signed by owner."""
    parts = []; prev = None
    for i, b in enumerate(blocks):
        aud = ed_raw(keys[i]); signer = owner_sk if i == 0 else keys[i - 1]
        msg = (prev or b'') + b + aud; s = signer.sign(msg); prev = s
        parts.append((b, aud, s))
    return parts
def ucan_wire(parts, holder_sk, command, nonce):
    out = b'U\x01' + bytes([len(parts)])
    for b, aud, s in parts: out += bytes([len(b)]) + b + aud + s
    return out + command + nonce + holder_sk.sign(b'INV' + command + nonce)

def p256_raw_pub(sk):
    n = sk.public_key().public_numbers(); return n.x.to_bytes(32, 'big') + n.y.to_bytes(32, 'big')
def es256(sk, msg):
    r, s = decode_dss_signature(sk.sign(msg, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
def jwt_wire(as_sk, claims, command):
    return b'J\x01' + struct.pack('<H', len(claims)) + claims + es256(as_sk, claims) + command
def tedpop_wire(as_sk, claims, holder_sk, command, nonce):
    sig = es256(as_sk, claims)
    return b'T\x01' + struct.pack('<H', len(claims)) + claims + sig + command + nonce + es256(holder_sk, b'INV' + command + nonce)
def act_chain(agent_ids): return cav(C_ACT, b''.join(hashlib.sha256(a).digest()[:16] for a in agent_ids))
def cnf(pk_raw): return cav(C_CNF, pk_raw)

def acesym_wire(as_key16, claims, popkey, command, nonce):
    n13 = os.urandom(13); ctt = AESCCM(as_key16, tag_length=8).encrypt(n13, claims + popkey, b'ACE')
    ct, tag = ctt[:-8], ctt[-8:]
    sig = hm(popkey, b'INV', command, nonce)[:16]
    return b'S\x01' + n13 + struct.pack('<H', len(ct)) + ct + tag + command + nonce + sig

# ---------------- device wrapper (C verifier via ctypes) ----------------
class VCtx(ctypes.Structure):
    _fields_ = [('dev_id', ctypes.c_uint32), ('now', ctypes.c_uint32), ('state', ctypes.c_int16 * 8),
                ('rev', ctypes.c_char_p), ('nrev', ctypes.c_uint32), ('nonce', ctypes.c_uint8 * 8),
                ('nonce_valid', ctypes.c_uint8), ('rate_id', (ctypes.c_uint8 * 8) * 16),
                ('rate_cnt', ctypes.c_uint16 * 16), ('nrate', ctypes.c_uint32), ('key', ctypes.c_uint8 * 32),
                ('owner_pk', ctypes.c_uint8 * 32), ('as_pk', ctypes.c_uint8 * 64)]

class Device:
    FN = {'agentcap': LIB.v_agentcap, 'macaroon': LIB.v_macaroon, 'ucan': LIB.v_ucan,
          'jwt': LIB.v_jwt, 'tedpop': LIB.v_tedpop,
          'acesym': LIB.v_acesym, 'agentcap_opt': LIB.v_agentcap_opt, 'agentcap_noatt': LIB.v_agentcap}
    def __init__(self, devid, key=b'\0' * 32, owner_pk=b'\0' * 32, as_pk=b'\0' * 64, now=1000):
        self.c = VCtx(); self.c.dev_id = devid; self.c.now = now
        ctypes.memmove(self.c.key, key, 32); ctypes.memmove(self.c.owner_pk, owner_pk, 32)
        ctypes.memmove(self.c.as_pk, as_pk, 64); self._rev = b''; self.set_rev(b'')
    def set_rev(self, blob):
        self._rev = ctypes.create_string_buffer(blob, max(1, len(blob)))
        self.c.rev = ctypes.cast(self._rev, ctypes.c_char_p); self.c.nrev = len(blob) // 8
    def challenge(self):
        n = os.urandom(8); ctypes.memmove(self.c.nonce, n, 8); self.c.nonce_valid = 1; return n
    def set_state(self, i, v): self.c.state[i] = v
    def set_epoch(self, epoch, rl, tag):
        self._rev = ctypes.create_string_buffer(rl, max(1, len(rl)))
        return LIB.ac_set_epoch(ctypes.byref(self.c), ctypes.c_uint32(epoch),
                                ctypes.cast(self._rev, ctypes.c_char_p), ctypes.c_uint32(len(rl) // 8), tag)
    def verify(self, scheme, wire):
        buf = ctypes.create_string_buffer(wire, len(wire))
        return self.FN[scheme](ctypes.byref(self.c), buf, ctypes.c_uint32(len(wire)))
