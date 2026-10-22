import struct, capstone

data = open("NR2003.exe", "rb").read()
IB = 0x400000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = False

text_start = 0x1000
text_end = 0x2E8000 + 0x1000

# collect disasm once
insns = []
for ins in md.disasm(data[text_start:text_end], IB + text_start):
    insns.append((ins.address, ins.mnemonic, ins.op_str, ins.bytes))

print("total insns", len(insns))

def callers_of(target):
    res = []
    for addr, mn, ops, bs in insns:
        if mn in ("call", "jmp"):
            try:
                if ops.startswith("0x"):
                    t = int(ops, 16)
                    if t == target:
                        res.append((addr, mn))
            except ValueError:
                pass
    return res

for name, t in [("getterFOV 0x441C10", 0x441C10), ("setterFOV 0x441C20", 0x441C20)]:
    print(f"\n{name}:")
    for a, mn in callers_of(t):
        print(f"  {mn} from VA 0x{a:X}")

# Also find who reads/writes 0x894ee8 via any addressing (full text disasm operand search)
print("\n=== all instructions referencing 0x894ee8 ===")
for addr, mn, ops, bs in insns:
    if "0x894ee8" in ops:
        print(f"  0x{addr:X}: {mn} {ops}")

# who references 0x8953e0 (the ProfileValue object)
print("\n=== instructions referencing 0x8953e0 ===")
for addr, mn, ops, bs in insns:
    if "0x8953e0" in ops:
        print(f"  0x{addr:X}: {mn} {ops}")
