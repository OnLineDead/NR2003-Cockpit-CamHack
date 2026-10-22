import struct, capstone

data = open("NR2003.exe", "rb").read()
IB = 0x400000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def disasm(va, size=0x60, label=""):
    off = va - IB
    print(f"\n=== disasm VA 0x{va:X} {label} ===")
    for ins in md.disasm(data[off:off+size], va):
        print(f"  0x{ins.address:08X}: {ins.mnemonic:8s} {ins.op_str}")

def find_call(target):
    pat = struct.pack("<I", target)
    res = []
    start = 0x1000
    while True:
        i = data.find(pat, start, 0x2E9000)
        if i < 0: break
        # check if byte before is E8 (call rel32) 
        if i >= 1 and data[i-1] == 0xE8:
            res.append(i-1)
        elif i >= 2 and data[i-2] == 0xFF and data[i-1] == 0x15:
            res.append(i-2)
        else:
            res.append(i)  # raw pointer
        start = i + 1
    return res

print("### getter 0x441C10 refs")
for i in find_call(0x441C10):
    kind = "call" if data[i] == 0xE8 else ("iatcall" if data[i]==0xFF else "ptr")
    print(f"  VA 0x{IB+i:X} [{kind}]")
print("\n### setter 0x441C20 refs")
for i in find_call(0x441C20):
    kind = "call" if data[i] == 0xE8 else ("iatcall" if data[i]==0xFF else "ptr")
    print(f"  VA 0x{IB+i:X} [{kind}]")

disasm(0x568300, 0xC0, "camera .cam filename code")
