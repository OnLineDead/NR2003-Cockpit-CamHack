import struct, capstone
data = open("NR2003.exe", "rb").read()
IB = 0x400000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def d(va, n, label=""):
    print(f"\n=== VA 0x{va:X} {label} ===")
    for ins in md.disasm(data[va-IB:va-IB+n], va):
        print(f"0x{ins.address:08X}: {ins.mnemonic:8s} {ins.op_str}")

def ptr_refs(va):
    pat=struct.pack('<I',IB+va); r=[]; s=0
    while True:
        i=data.find(pat,s)
        if i<0: break
        r.append(i); s=i+1
    return r

print("refs to 'cockpitView' ptr:", [hex(IB+i) for i in ptr_refs(0x323280)])
print("refs to 'rearView' ptr:", [hex(IB+i) for i in ptr_refs(0x322F84)])
d(0x5D9700, 0x90, "pitch yaw roll debug")
# camera loader function start: find 'push ebp / mov ebp,esp' before 0x568300
off=0x568300-IB
for i in range(off, off-0x400, -1):
    if data[i]==0x55 and data[i+1]==0x8B and data[i+2]==0xEC:
        d(IB+i, 0x80, "camera loader start")
        break
