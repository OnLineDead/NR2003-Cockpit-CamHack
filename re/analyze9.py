import struct, capstone
data = open("NR2003.exe", "rb").read()
IB = 0x400000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def dis(va, n, label=""):
    print(f"\n=== 0x{va:X} {label} ===")
    for ins in md.disasm(data[va-IB:va-IB+n], va):
        print(f"0x{ins.address:08X}: {ins.mnemonic:8s} {ins.op_str}")

# find absolute refs to globals in text by scanning bytes pattern mov [abs]
def arefs(addr):
    pat = struct.pack("<I", addr)
    res = []
    s = 0x1000
    while True:
        i = data.find(pat, s, 0x2E9000)
        if i < 0: break
        res.append(IB+i)
        s = i+1
    return res

for g in [0xc5736c, 0xc5c27c, 0xc5c29c, 0xc5c280, 0xc57368]:
    print(f"\n##### refs to 0x{g:X}: {[hex(a) for a in arefs(g)]}")
    for a in arefs(g)[:4]:
        dis(a-0x10, 0x30)

dis(0x567D10, 0x70, "FOV apply/clamp")
dis(0x569700, 0xB0, "FOV slider buttons")
dis(0x56ABE0, 0x90, "camera math with FOV")
