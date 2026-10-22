import struct, capstone
data = open("NR2003.exe", "rb").read()
IB = 0x400000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

TEXT_VA0 = IB + 0x1000
TEXT_OFF0 = 0x1000
TEXT_OFF1 = 0x2E9000

def find_callers(target):
    res = []
    # E8 rel32 : target = addr+5+rel
    for i in range(TEXT_OFF0, TEXT_OFF1 - 5):
        if data[i] == 0xE8:
            rel = struct.unpack_from("<i", data, i+1)[0]
            if (IB + i) + 5 + rel == target:
                res.append(IB + i)
    return res

def dis(va, n):
    for ins in md.disasm(data[va-IB:va-IB+n], va):
        print(f"0x{ins.address:08X}: {ins.mnemonic:8s} {ins.op_str}")

for t in [0x411850, 0x411860, 0x5D9730, 0x441C10, 0x441C20]:
    c = find_callers(t)
    print(f"\n### callers of 0x{t:X}: {[hex(x) for x in c]}")
    for a in c[:6]:
        print("  context:")
        dis(a-0x20, 0x40)
