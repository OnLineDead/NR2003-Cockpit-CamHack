import struct, sys, re

data = open("NR2003.exe", "rb").read()

pe = struct.unpack_from("<I", data, 0x3C)[0]
numsec = struct.unpack_from("<H", data, pe+6)[0]
optsz = struct.unpack_from("<H", data, pe+20)[0]
opt = pe + 24
imagebase = struct.unpack_from("<I", data, opt+28)[0]
dd = opt + 96
import_rva = struct.unpack_from("<I", data, dd+8)[0]
import_sz = struct.unpack_from("<I", data, dd+12)[0]

sections = []
s = opt + optsz
for i in range(numsec):
    o = s + i*40
    name = data[o:o+8].rstrip(b"\0").decode("ascii", "replace")
    vsz, va, rsz, raw = struct.unpack_from("<IIII", data, o+8)
    sections.append((name, va, vsz, raw, rsz))

def rva2off(rva):
    for name, va, vsz, raw, rsz in sections:
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va)
    return None

def off2rva(off):
    for name, va, vsz, raw, rsz in sections:
        if raw <= off < raw + rsz:
            return va + (off - raw)
    return None

def va2off(va):
    return rva2off(va - imagebase)

# imports
print("=== IMPORTS ===")
off = rva2off(import_rva)
end = off + import_sz
while off < end:
    ilt, ts, chain, name_rva, iat = struct.unpack_from("<IIIII", data, off)
    if name_rva == 0: break
    no = rva2off(name_rva)
    dll = data[no:data.index(b"\0", no)].decode()
    print(f"\n{dll} (desc VA 0x{imagebase+off-imagebase+ (0):X}, IAT RVA 0x{iat:X})")
    # walk IAT
    j = iat
    idx = 0
    while True:
        jo = rva2off(j)
        entry = struct.unpack_from("<I", data, jo)[0]
        if entry == 0: break
        if entry & 0x80000000:
            print(f"  [{idx}] ord {entry & 0xFFFF}")
        else:
            ho = rva2off(entry)
            fname = data[ho+2:data.index(b"\0", ho+2)].decode()
            print(f"  [{idx}] {fname}  (IAT entry VA 0x{imagebase+j:X})")
        j += 4
        idx += 1
    off += 20

# interesting strings
print("\n=== INTERESTING STRINGS (ascii) ===")
pat = re.compile(rb"[\x20-\x7E]{5,}")
keywords = [b"fov", b"FOV", b"camera", b"Camera", b"cockpit", b"Cockpit", b"offset", b"eye", b"Eye", b"proj", b"look", b"View", b"view"]
seen = set()
for m in pat.finditer(data):
    s_ = m.group()
    if any(k in s_ for k in keywords):
        o = m.start()
        txt = s_.decode("ascii", "replace")
        if txt in seen: continue
        seen.add(txt)
        rva = off2rva(o)
        va = (imagebase + rva) if rva is not None else None
        print(f"  file+0x{o:06X} VA={('0x%08X' % va) if va else '?'} : {txt[:120]}")
