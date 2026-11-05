"""Execute cross-compiled verifiers on emulated MCU cores (Unicorn) and count executed
instructions; convert to cycles with per-ISA in-order timing models; measure stack."""
import struct
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_HOOK_BLOCK, UC_ARCH_RISCV, UC_MODE_RISCV32
from unicorn import arm_const as A, riscv_const as R
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCVC
from elftools.elf.elffile import ELFFile

FLASH, RAM, EXT = 0x08000000, 0x20000000, 0x30000000
CTX, WIRE, STACK_LO, STACK_TOP = 0x20020000, 0x20021000, 0x20030000, 0x20040000
MAGIC = 0x080FF000

def _ldm_n(op): return op.count(',') + 1

def cyc_m4(ins, last):
    m = ins.mnemonic.split('.')[0]; op = ins.op_str
    if m in ('ldm', 'ldmia', 'ldmdb', 'pop'): return 1 + _ldm_n(op) + (2 if 'pc' in op else 0)
    if m in ('stm', 'stmia', 'stmdb', 'push'): return 1 + _ldm_n(op)
    if m.startswith('ldrd'): return 3
    if m.startswith('strd'): return 2
    if m.startswith('ldr'): return 2
    if m in ('udiv', 'sdiv'): return 7
    if m in ('bl', 'blx'): return 4
    if m in ('cbz', 'cbnz') or m == 'bx' or (m.startswith('b') and m not in ('bic', 'bics', 'bfi', 'bfc')):
        return 3 if last else 1
    return 1

def cyc_m0p(ins, last):
    """ARMv6-M, 2-stage pipeline: LDR/STR 2, LDM/STM/PUSH/POP 1+N (+2 if PC), taken branch 2, BL 3, MULS 1."""
    m = ins.mnemonic.split('.')[0]; op = ins.op_str
    if m in ('ldm', 'ldmia', 'pop'): return 1 + _ldm_n(op) + (2 if 'pc' in op else 0)
    if m in ('stm', 'stmia', 'push'): return 1 + _ldm_n(op)
    if m.startswith('ldr') or m.startswith('str'): return 2
    if m in ('bl', 'blx'): return 3
    if m == 'bx' or (m.startswith('b') and m not in ('bic', 'bics')): return 2 if last else 1
    return 1

def cyc_rv(ins, last):
    """Generic single-issue in-order RV32IMC: load 2, taken branch/jump 3, mul 1, div 33."""
    m = ins.mnemonic
    if m.startswith('c.'): m = m[2:]
    if m in ('lw', 'lh', 'lhu', 'lb', 'lbu', 'lwsp'): return 2
    if m in ('div', 'divu', 'rem', 'remu'): return 33
    if m in ('jal', 'jalr', 'j', 'jr', 'ret', 'call') or m.startswith('b'): return 3 if last else 1
    return 1

ARCH = {
    'm4':  dict(uc=(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS), cs=(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS), cyc=cyc_m4, thumb=True),
    'm0p': dict(uc=(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS), cs=(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS), cyc=cyc_m0p, thumb=True),
    'rv32': dict(uc=(UC_ARCH_RISCV, UC_MODE_RISCV32), cs=(CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC), cyc=cyc_rv, thumb=False),
}

class MCU:
    def __init__(self, elf_path, arch):
        a = ARCH[arch]; self.arch = arch; self.a = a
        self.uc = Uc(*a['uc']); self.cs = Cs(*a['cs'])
        uc = self.uc
        uc.mem_map(FLASH, 0x100000); uc.mem_map(RAM, 0x80000); uc.mem_map(EXT, 0x200000)
        with open(elf_path, 'rb') as f:
            e = ELFFile(f)
            for seg in e.iter_segments():
                if seg['p_type'] == 'PT_LOAD' and seg['p_filesz']:
                    uc.mem_write(seg['p_paddr'], seg.data())
            sym = e.get_section_by_name('.symtab')
            g = lambda n: sym.get_symbol_by_name(n)[0]['st_value']
            self.sym = {n: g(n) for n in ('bench', 'bench_boot', 'g_comp')}
            self.text_size = sum(s['sh_size'] for s in e.iter_sections() if s.name in ('.text', '.rodata', '.srodata'))
            self.ram_static = sum(s['sh_size'] for s in e.iter_sections() if s.name in ('.data', '.bss', '.sbss', '.sdata'))
        if a['thumb']:
            pass
        else:
            uc.mem_write(MAGIC, b'\x01\x00\x01\x00')  # c.nop padding (never executed)
        self.cache = {}; self.ins = 0; self.cyc = 0
        uc.hook_add(UC_HOOK_BLOCK, self._blk)

    def _blk(self, uc, addr, size, _):
        k = (addr, size); v = self.cache.get(k)
        if v is None:
            ins = list(self.cs.disasm(bytes(uc.mem_read(addr, size)), addr))
            v = (len(ins), sum(self.a['cyc'](x, i == len(ins) - 1) for i, x in enumerate(ins)))
            self.cache[k] = v
        self.ins += v[0]; self.cyc += v[1]

    def _call(self, name, args):
        uc = self.uc
        if self.a['thumb']:
            uc.reg_write(A.UC_ARM_REG_SP, STACK_TOP); uc.reg_write(A.UC_ARM_REG_LR, MAGIC | 1)
            for r, v in zip((A.UC_ARM_REG_R0, A.UC_ARM_REG_R1, A.UC_ARM_REG_R2), args): uc.reg_write(r, v)
            uc.emu_start((self.sym[name] & ~1) | 1, MAGIC, count=400_000_000)
            ret = uc.reg_read(A.UC_ARM_REG_R0)
        else:
            uc.reg_write(R.UC_RISCV_REG_SP, STACK_TOP); uc.reg_write(R.UC_RISCV_REG_RA, MAGIC)
            for r, v in zip((R.UC_RISCV_REG_A0, R.UC_RISCV_REG_A1, R.UC_RISCV_REG_A2), args): uc.reg_write(r, v)
            uc.emu_start(self.sym[name], MAGIC, count=400_000_000)
            ret = uc.reg_read(R.UC_RISCV_REG_A0)
        return ret - (1 << 32) if ret & 0x80000000 else ret

    def load_ctx(self, ctx_bytes, rev=b''):
        self.uc.mem_write(CTX, ctx_bytes)
        if rev: self.uc.mem_write(EXT, rev)

    def boot(self):
        self._call('bench_boot', (CTX,))

    def run(self, wire, ctx_bytes=None, rev=b''):
        uc = self.uc
        if ctx_bytes is not None: self.load_ctx(ctx_bytes, rev)
        uc.mem_write(STACK_LO, b'\xAA' * (STACK_TOP - STACK_LO)); uc.mem_write(WIRE, wire)
        self.ins = self.cyc = 0
        ret = self._call('bench', (CTX, WIRE, len(wire)))
        st = bytes(uc.mem_read(STACK_LO, STACK_TOP - STACK_LO)); i = 0
        while i < len(st) and st[i] == 0xAA: i += 1
        comp = struct.unpack('<I', uc.mem_read(self.sym['g_comp'], 4))[0]
        return dict(ret=ret, insns=self.ins, cycles=self.cyc, sha_comp=comp, stack=len(st) - i)

    def set_nonce(self, nonce):
        self.uc.mem_write(CTX + 32, nonce + b'\x01')

def ctx_arm(dev_id, now=1000, state=(0,) * 8, nrev=0, nonce=b'\0' * 8, nonce_valid=0,
            key=b'\0' * 32, owner_pk=b'\0' * 32, as_pk=b'\0' * 64):
    b = struct.pack('<II8hII', dev_id, now, *state, EXT, nrev) + nonce + bytes([nonce_valid])
    b += b'\0' * 128 + b'\0' + b'\0' * 32 + b'\0\0' + struct.pack('<I', 0) + key + owner_pk + as_pk
    assert len(b) == 336
    return b
