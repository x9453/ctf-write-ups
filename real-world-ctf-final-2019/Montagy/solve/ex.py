from solcx import compile_files
from z3 import *

def tag(a):
    t1, t2 = 0x21711730, 0x7312f103
    for i in range(0, len(a), 32):
        s = 0x6644498b
        tmp = int(a[i:i+32], 16)
        m1 = tmp & 0xffffffff
        tmp >>= 0x20
        m2 = tmp & 0xffffffff
        tmp >>= 0x20
        m3 = tmp & 0xffffffff
        tmp >>= 0x20
        m4 = tmp & 0xffffffff

        for j in range(4):
            s = (s + 0x68696e74) & 0xffffffff
            p1 = (t1<<4) - m1
            p2 = t1 + s
            p3 = (t1>>5) + m2
            t2 = (t2 + (p1^(p2^p3))) & 0xffffffff
            p1 = (t2<<4) + m3
            p2 = t2 + s
            p3 = (t2>>5) - m4
            t1 = (t1 + (p1^(p2^p3))) & 0xffffffff

    res = (t1<<0x20) | t2
    return hex(res)[2:].zfill(16)

def find(last, target):
    t1, t2 = int(last[:8], 16), int(last[8:], 16)
    tar1, tar2 = int(target[:8], 16), int(target[8:], 16)

    s = 0x6644498b
    s = BitVecVal(s, 256)
    m1 = BitVec('m1', 256)
    m2 = BitVec('m2', 256)
    m3 = BitVec('m3', 256)
    m4 = BitVec('m4', 256)

    for j in range(4):
        s = (s + 0x68696e74) & 0xffffffff
        p1 = (t1<<4) - m1
        p2 = t1 + s
        p3 = (t1>>5) + m2
        t2 = (t2 + (p1^(p2^p3))) & 0xffffffff
        p1 = (t2<<4) + m3
        p2 = t2 + s
        p3 = (t2>>5) - m4
        t1 = (t1 + (p1^(p2^p3))) & 0xffffffff

    sol = Solver()
    sol.add(And(t1 == tar1, t2 == tar2))
    if sol.check():
        m = sol.model()
        m_l = map(lambda x: m[x].as_long(), [m4, m3, m2, m1])
        pad = 0
        for x in m_l:
            pad <<= 0x20
            pad |= x
        return hex(pad)[2:].zfill(32)
    else:
        raise Exception('No solution')

def main():
    compiled_sol = compile_files(['P3.sol'])
    src = compiled_sol['P3.sol:P3']['bin']

    with open('P3.bytecode', 'w') as f:
        f.write(src)

    if len(src) % 32:
        src += '0'*(32 - (len(src) % 32))

    last = tag(src)
    target = 'f09b200b11fa1705'
    #target = '5100c112a2cf3f9c'

    pad = find(last, target)
    src += pad
    assert(tag(src) == target)

    with open('P3-padded.bytecode', 'w') as f:
        f.write(src)

main()
