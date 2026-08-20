#!/usr/bin/env python3
"""
sbf_disasm.py -- Standalone Solana SBF/eBPF disassembler (no LLVM dependency).

Decodes both memory-encoding generations:
  * classic eBPF classes  (LDX 0x61/0x69/0x71/0x79, ST 0x62.., STX 0x72..)
  * SBF "moved" classes   (LD_*_REG 0x2c/0x3c/0x8c/0x9c,
                           ST_*_IMM 0x27/0x37/0x87/0x97,
                           ST_*_REG 0x2f/0x3f/0x8f/0x9f)
    -- emitted by the new Solana LLVM fork; stock llvm-objdump prints these as
    `<unknown>` (see solana-sbpf ebpf.rs, `move_memory_instruction_classes`).

Opcode map ported from solana-sbpf 0.23.0 (crates.io) src/ebpf.rs.

Output: text compatible with repo tooling (`  <pc>:\t<bytes>\t<text>`), plus
function boundaries collected from pc-relative `call` targets.

Usage:
  sbf_disasm.py <program.so> [--json out.json] [--text out.txt]
"""
import sys
import json
import argparse

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    sys.exit("pyelftools required: pip3 install --break-system-packages pyelftools")

# ---- opcode constants (solana-sbpf ebpf.rs) --------------------------------
BPF_LD, BPF_LDX, BPF_ST, BPF_STX = 0x00, 0x01, 0x02, 0x03
BPF_ALU32_LOAD, BPF_JMP64, BPF_JMP32, BPF_ALU64_STORE = 0x04, 0x05, 0x06, 0x07
BPF_W, BPF_H, BPF_B, BPF_DW = 0x00, 0x08, 0x10, 0x18
BPF_1B, BPF_2B, BPF_4B, BPF_8B = 0x20, 0x30, 0x80, 0x90
BPF_IMM, BPF_MEM, BPF_K, BPF_X = 0x00, 0x60, 0x00, 0x08
BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV = 0x00, 0x10, 0x20, 0x30
BPF_OR, BPF_AND, BPF_LSH, BPF_RSH = 0x40, 0x50, 0x60, 0x70
BPF_NEG, BPF_MOD, BPF_XOR, BPF_MOV = 0x80, 0x90, 0xa0, 0xb0
BPF_ARSH, BPF_END, BPF_HOR = 0xc0, 0xd0, 0xf0
BPF_JA, BPF_JEQ, BPF_JGT, BPF_JGE = 0x00, 0x10, 0x20, 0x30
BPF_JSET, BPF_JNE, BPF_JSGT, BPF_JSGE = 0x40, 0x50, 0x60, 0x70
BPF_CALL, BPF_EXIT, BPF_JLT, BPF_JLE = 0x80, 0x90, 0xa0, 0xb0
BPF_JSLT, BPF_JSLE = 0xc0, 0xd0

LD_DW_IMM = BPF_LD | BPF_IMM | BPF_DW  # 0x18

# moved memory encodings
LD_1B_REG = BPF_ALU32_LOAD | BPF_X | BPF_1B  # 0x2c
LD_2B_REG = BPF_ALU32_LOAD | BPF_X | BPF_2B  # 0x3c
LD_4B_REG = BPF_ALU32_LOAD | BPF_X | BPF_4B  # 0x8c
LD_8B_REG = BPF_ALU32_LOAD | BPF_X | BPF_8B  # 0x9c
ST_1B_IMM = BPF_ALU64_STORE | BPF_K | BPF_1B  # 0x27
ST_2B_IMM = BPF_ALU64_STORE | BPF_K | BPF_2B  # 0x37
ST_4B_IMM = BPF_ALU64_STORE | BPF_K | BPF_4B  # 0x87
ST_8B_IMM = BPF_ALU64_STORE | BPF_K | BPF_8B  # 0x97
ST_1B_REG = BPF_ALU64_STORE | BPF_X | BPF_1B  # 0x2f
ST_2B_REG = BPF_ALU64_STORE | BPF_X | BPF_2B  # 0x3f
ST_4B_REG = BPF_ALU64_STORE | BPF_X | BPF_4B  # 0x8f
ST_8B_REG = BPF_ALU64_STORE | BPF_X | BPF_8B  # 0x9f

SIZES_MOVED = {LD_1B_REG: ('ldxb', 1), LD_2B_REG: ('ldxh', 2),
               LD_4B_REG: ('ldxw', 4), LD_8B_REG: ('ldxdw', 8)}
ST_IMM_MOVED = {ST_1B_IMM: ('stb', 1), ST_2B_IMM: ('sth', 2),
                ST_4B_IMM: ('stw', 4), ST_8B_IMM: ('stdw', 8)}
ST_REG_MOVED = {ST_1B_REG: ('stxb', 1), ST_2B_REG: ('stxh', 2),
                ST_4B_REG: ('stxw', 4), ST_8B_REG: ('stxdw', 8)}

# classic classes
LDX_CLASSIC = {BPF_LDX | BPF_MEM | BPF_W: ('ldxw', 4),
               BPF_LDX | BPF_MEM | BPF_H: ('ldxh', 2),
               BPF_LDX | BPF_MEM | BPF_B: ('ldxb', 1),
               BPF_LDX | BPF_MEM | BPF_DW: ('ldxdw', 8)}
ST_CLASSIC = {BPF_ST | BPF_MEM | BPF_W: ('stw', 4),
              BPF_ST | BPF_MEM | BPF_H: ('sth', 2),
              BPF_ST | BPF_MEM | BPF_B: ('stb', 1),
              BPF_ST | BPF_MEM | BPF_DW: ('stdw', 8)}
STX_CLASSIC = {BPF_STX | BPF_MEM | BPF_W: ('stxw', 4),
               BPF_STX | BPF_MEM | BPF_H: ('stxh', 2),
               BPF_STX | BPF_MEM | BPF_B: ('stxb', 1),
               BPF_STX | BPF_MEM | BPF_DW: ('stxdw', 8)}

ALU_OPS = {BPF_ADD: 'add', BPF_SUB: 'sub', BPF_MUL: 'mul', BPF_DIV: 'div',
           BPF_OR: 'or', BPF_AND: 'and', BPF_LSH: 'lsh', BPF_RSH: 'rsh',
           BPF_MOD: 'mod', BPF_XOR: 'xor', BPF_MOV: 'mov', BPF_ARSH: 'arsh',
           BPF_END: 'end', BPF_NEG: 'neg', BPF_HOR: 'hor'}
JMP_OPS = {BPF_JA: None, BPF_JEQ: '==', BPF_JGT: '>', BPF_JGE: '>=',
           BPF_JSET: '&', BPF_JNE: '!=', BPF_JSGT: 's>', BPF_JSGE: 's>=',
           BPF_JLT: '<', BPF_JLE: '<=', BPF_JSLT: 's<', BPF_JSLE: 's<='}

SBF_TEXT_BASE = 0x100000000


def sx(val, bits):
    m = 1 << (bits - 1)
    return (val ^ m) - m


class Insn:
    __slots__ = ('pc', 'raw', 'op', 'dst', 'src', 'off', 'imm', 'text',
                 'call_target')

    def __init__(self, pc, raw):
        self.pc = pc
        self.raw = raw
        self.op = raw[0]
        self.dst = raw[1] & 0xF
        self.src = (raw[1] >> 4) & 0xF
        self.off = sx(int.from_bytes(raw[2:4], 'little'), 16)
        self.imm = sx(int.from_bytes(raw[4:8], 'little', signed=False), 32)
        self.text = None
        self.call_target = None


def decode(insn, next_imm=None, llvm_compat=False):
    """Decode one insn; next_imm = imm of the following slot (lddw pairs).

    llvm_compat renders memory operands like llvm-objdump (`*(u8 *)(r1 + 0x8)`,
    `goto +0x1d`, `call -0x5d229`) so scripts/extract_disc_disasm.py -- written
    against llvm output -- consumes our text directly.
    """
    op, dst, src, off, imm = insn.op, insn.dst, insn.src, insn.off, insn.imm
    clz = op & 0x07
    if op == LD_DW_IMM:
        insn.text = f'lddw r{dst}, {next_imm & 0xFFFFFFFFFFFFFFFF:#x}'
        return
    if op in SIZES_MOVED:
        name, sz = SIZES_MOVED[op]
        insn.text = render_ldx(name, sz, dst, src, off, llvm_compat)
        return
    if op in ST_IMM_MOVED:
        name, sz = ST_IMM_MOVED[op]
        insn.text = render_st_imm(name, sz, dst, off, imm, llvm_compat)
        return
    if op in ST_REG_MOVED:
        name, sz = ST_REG_MOVED[op]
        insn.text = render_stx(name, sz, dst, src, off, llvm_compat)
        return
    if clz == BPF_LDX and op in LDX_CLASSIC:
        name, sz = LDX_CLASSIC[op]
        insn.text = render_ldx(name, sz, dst, src, off, llvm_compat)
        return
    if clz == BPF_ST and op in ST_CLASSIC:
        name, sz = ST_CLASSIC[op]
        insn.text = render_st_imm(name, sz, dst, off, imm, llvm_compat)
        return
    if clz == BPF_STX and op in STX_CLASSIC:
        name, sz = STX_CLASSIC[op]
        insn.text = render_stx(name, sz, dst, src, off, llvm_compat)
        return
    if clz in (BPF_ALU32_LOAD, BPF_ALU64_STORE):  # classic ALU32/ALU64
        aop = op & 0xF0
        reg = bool(op & BPF_X)
        w = 'w' if clz == BPF_ALU32_LOAD else 'r'
        name = ALU_OPS.get(aop)
        if name is None:
            insn.text = f'<unknown {op:#04x}>'
            return
        sym = ALU_SYMBOLS.get(name, name)
        if name == 'neg':
            insn.text = f'{w}{dst} = -{w}{dst}'
        elif name == 'end':
            insn.text = f'{w}{dst} = {"" if reg else "be"}{imm} {w}{dst}'
        elif name == 'mov':
            insn.text = f'{w}{dst} = ' + (f'{w}{src}' if reg else fmt_imm(imm))
        else:
            rhs = f'{w}{src}' if reg else fmt_imm(imm)
            insn.text = f'{w}{dst} {sym} {rhs}' if llvm_compat else f'{w}{dst} {name}= {rhs}'
        return
    if clz in (BPF_JMP64, BPF_JMP32):
        aop = op & 0xF0
        reg = bool(op & BPF_X)
        rel = off  # already sign-extended in Insn.__init__; sx() again would corrupt
        if aop == BPF_JA:
            insn.text = (f'goto {fmt_rel(rel)}' if llvm_compat
                         else f'goto <{insn.pc + 1 + rel}>')
            return
        if aop == BPF_EXIT:
            insn.text = 'exit'
            return
        if op == 0x8d:  # callx: register-indirect call, NO pc-relative target
            insn.text = f'callx r{src}'
            return
        if aop == BPF_CALL and not reg:
            insn.call_target = insn.pc + 1 + imm  # pc-relative, in slots
            insn.text = (f'call {fmt_rel(imm)}' if llvm_compat
                         else f'call <{insn.call_target}>')
            return
        cond = JMP_OPS.get(aop)
        if cond is None:
            insn.text = f'<unknown {op:#04x}>'
            return
        w = 'w' if clz == BPF_JMP32 else 'r'
        lhs = f'{w}{dst}'
        rhs = f'{w}{src}' if reg else fmt_imm(imm)
        insn.text = (f'if {lhs} {cond} {rhs} goto {fmt_rel(rel)}' if llvm_compat
                     else f'if {lhs} {cond} {rhs} goto <{insn.pc + 1 + rel}>')
        return
    insn.text = f'<unknown {op:#04x}>'


ALU_SYMBOLS = {'add': '+=', 'sub': '-=', 'mul': '*=', 'div': '/=',
               'or': '|=', 'and': '&=', 'lsh': '<<=', 'rsh': '>>=',
               'mod': '%=', 'xor': '^=', 'arsh': 's>>=', 'neg': 'neg',
               'mov': 'mov', 'end': 'end', 'hor': 'hor'}


def fmt_off(off):
    return f'+{off:#x}' if off >= 0 else f'-{-off:#x}'


def fmt_imm(imm):
    return f'{imm & 0xFFFFFFFF:#x}' if imm >= 0 else f'-{abs(imm):#x}'


def fmt_rel(rel):
    return f'{rel:+#x}' if rel >= 0 else f'{rel:#x}'


def llvm_mem(sz, reg, off):
    t = {1: 'u8', 2: 'u16', 4: 'u32', 8: 'u64'}[sz]
    if off > 0:
        o = f' + {off:#x}'
    elif off < 0:
        o = f' - {-off:#x}'
    else:
        o = ''
    return f'*(u{8 * sz} *)(r{reg}{o})'


def render_ldx(name, sz, dst, src, off, llvm_compat):
    if llvm_compat:
        return f'r{dst} = {llvm_mem(sz, src, off)}'
    return f'{name} r{dst}, [r{src}{fmt_off(off)}]'


def render_st_imm(name, sz, dst, off, imm, llvm_compat):
    if llvm_compat:
        return f'{llvm_mem(sz, dst, off)} = {imm:#x}'
    return f'{name} [r{dst}{fmt_off(off)}], {imm & 0xFFFFFFFF:#x}'


def render_stx(name, sz, dst, src, off, llvm_compat):
    if llvm_compat:
        return f'{llvm_mem(sz, dst, off)} = r{src}'
    return f'{name} [r{dst}{fmt_off(off)}], r{src}'


def disasm(path, llvm_compat=False):
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name('.text')
        data = text.data()
        entry = elf.header.e_entry
    insns = []
    i = 0
    n = len(data)
    while i + 8 <= n:
        raw = data[i:i + 8]
        pc = i // 8
        insn = Insn(pc, raw)
        if raw[0] == LD_DW_IMM and i + 16 <= n:
            imm2 = int.from_bytes(data[i + 12:i + 16], 'little', signed=False)
            big = (insn.imm & 0xFFFFFFFF) | (imm2 << 32)
            decode(insn, big, llvm_compat)
            insns.append(insn)
            i += 16
            continue
        decode(insn, llvm_compat=llvm_compat)
        insns.append(insn)
        i += 8
    return insns, entry // 8


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('so')
    ap.add_argument('--json')
    ap.add_argument('--text')
    ap.add_argument('--llvm-compat', action='store_true',
                    help='emit llvm-objdump-style text (for extract_disc_disasm.py)')
    args = ap.parse_args()
    insns, entry_pc = disasm(args.so, args.llvm_compat)
    unknown = sum(1 for i in insns if i.text.startswith('<unknown'))
    funcs = {i.call_target for i in insns if i.call_target is not None}
    funcs.add(entry_pc)
    names = {entry_pc: 'entrypoint'}
    print(f'{args.so}: {len(insns)} insns, {unknown} unknown, '
          f'{len(funcs)} call targets', file=sys.stderr)

    lines = []
    for i in insns:
        rawhex = ' '.join(f'{b:02x}' for b in i.raw)
        # llvm-compat: only the <entrypoint> label (llvm emits none for
        # stripped SBF; extract_disc_disasm.py stops scanning at next <label>:)
        if i.pc == entry_pc or (i.pc in funcs and not args.llvm_compat):
            name = names.get(i.pc, f'sub_{i.pc}')
            lines.append(f'{i.pc * 8:016x} <{name}>:')
        lines.append(f'  {i.pc}:\t{rawhex}\t{i.text}')
    text = '\n'.join(lines) + '\n'
    if args.text:
        with open(args.text, 'w') as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    if args.json:
        with open(args.json, 'w') as f:
            json.dump({'n_insns': len(insns), 'unknown': unknown,
                       'entry_pc': entry_pc,
                       'functions': sorted(funcs),
                       'insns': [{'pc': i.pc, 'op': i.op, 'dst': i.dst,
                                  'src': i.src, 'off': i.off, 'imm': i.imm,
                                  'text': i.text,
                                  'call_target': i.call_target}
                                 for i in insns]}, f)


if __name__ == '__main__':
    main()
