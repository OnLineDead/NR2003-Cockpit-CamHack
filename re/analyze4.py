import struct, capstone, re

data = open("NR2003.exe", "rb").read()
IB = 0x400000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def f32(rva): return struct.unpack_from("<f", data, rva)[0]
def disasm(va, size=0x80, label=""):
    off = va - IB
    print(f"\n=== disasm VA 0x{va:X} {label} ===")
    for ins in md.disasm(data[off:off+size], va):
        print(f"  0x{ins.address:08X}: {ins.mnemonic:8s} {ins.op_str}")

# default FOV value
print("default FOV float @ 0x6EF48C =", f32(0x2EF48C))

# string cluster around .cam
print("\n=== strings 0x34EB80-0x34ED80 ===")
chunk = data[0x34EB80:0x34ED80]
i = 0
while i < len(chunk):
    if 32 <= chunk[i] < 127:
        j = i
        while j < len(chunk) and 32 <= chunk[j] < 127: j += 1
        if j - i >= 3:
            print(f"  0x{0x34EB80+i:X}: {chunk[i:j].decode()}")
        i = j
    else:
        i += 1

# xrefs to '.cam' (0x74EC74)
target = IB + 0x34EC74
pat = struct.pack("<I", target)
print("\n=== xrefs to '.cam' ===")
start = 0
while True:
    i = data.find(pat, start)
    if i < 0: break
    print(f"  file+0x{i:X} VA=0x{IB+i:X}")
    start = i + 1

# xrefs to %spitch,yaw,roll string (0x754998)
target = IB + 0x354998
pat = struct.pack("<I", target)
print("\n=== xrefs to '%spitch, yaw, roll' ===")
start = 0
while True:
    i = data.find(pat, start)
    if i < 0: break
    print(f"  file+0x{i:X} VA=0x{IB+i:X}")
    start = i + 1

# all code xrefs to FOV global 0x894EE8 (search 4-byte imm in .text)
print("\n=== code refs to FOV global 0x894EE8 ===")
pat = struct.pack("<I", 0x894EE8)
start = 0x1000
hits = []
while True:
    i = data.find(pat, start, 0x2E9000)
    if i < 0: break
    hits.append(i)
    start = i + 1
for i in hits:
    va = IB + i
    print(f"\n--- ref at VA 0x{va:X} ---")
    disasm(va - 0x18, 0x40)

# xrefs to cockpitView (0x723280) & drivingView (0x72DF28) code context
disasm(0x42A4B0, 0x40, "cockpitView xref ctx")
disasm(0x4446C0, 0x40, "drivingView xref ctx")
