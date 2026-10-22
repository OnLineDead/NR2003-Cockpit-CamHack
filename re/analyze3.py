import struct, capstone

data = open("NR2003.exe", "rb").read()
IB = 0x400000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = False

def disasm(va, size=0x100):
    off = va - IB
    code = data[off:off+size]
    print(f"\n=== disasm VA 0x{va:X} ===")
    for ins in md.disasm(code, va):
        print(f"  0x{ins.address:08X}: {ins.mnemonic:8s} {ins.op_str}")

# ProfileValue init for field_of_view
disasm(0x440A20, 0xC0)

# context: what profile value object; check what's before (function start?)
disasm(0x440900, 0x120)
