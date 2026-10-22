import struct

data = open("NR2003.exe", "rb").read()
IB = 0x400000

def u32(o): return struct.unpack_from("<I", data, o)[0]
def f32(o): return struct.unpack_from("<f", data, o)[0]
def f64(o): return struct.unpack_from("<d", data, o)[0]

# .rdata identity map: file off == RVA for 0x2E9000..0x31B000
def find_cstr(s):
    b = s.encode() + b"\0"
    offs = []
    start = 0
    while True:
        i = data.find(b, start)
        if i < 0: break
        offs.append(i)
        start = i + 1
    return offs

def xrefs(str_off):
    """find pointer dwords in file pointing at IB+rva (rva==off in rdata)"""
    target = IB + str_off  # only valid for .rdata
    pat = struct.pack("<I", target)
    res = []
    start = 0
    while True:
        i = data.find(pat, start)
        if i < 0: break
        res.append(i)
        start = i + 1
    return res

# context around 'field of view' cluster
print("=== context around 0x32CF0C (rdata) ===")
base = 0x32CEC0
chunk = data[base:0x32D080]
i = 0
while i < len(chunk):
    if 32 <= chunk[i] < 127:
        j = i
        while j < len(chunk) and 32 <= chunk[j] < 127: j += 1
        if j - i >= 4:
            print(f"  0x{base+i:X}: {chunk[i:j].decode()}")
        i = j
    else:
        i += 1

print("\n=== context around 0x32DF18 'driving view' ===")
base = 0x32DE80
chunk = data[base:0x32E120]
i = 0
while i < len(chunk):
    if 32 <= chunk[i] < 127:
        j = i
        while j < len(chunk) and 32 <= chunk[j] < 127: j += 1
        if j - i >= 4:
            print(f"  0x{base+i:X}: {chunk[i:j].decode()}")
        i = j
    else:
        i += 1

print("\n=== context around 0x33E708 defCockpitLook / FOV sliders (ui) ===")
base = 0x33E460
chunk = data[base:0x33E560]
i = 0
while i < len(chunk):
    if 32 <= chunk[i] < 127:
        j = i
        while j < len(chunk) and 32 <= chunk[j] < 127: j += 1
        if j - i >= 4:
            print(f"  0x{base+i:X}: {chunk[i:j].decode()}")
        i = j
    else:
        i += 1

print("\n=== xrefs to 'field_of_view' (0x72CF30) ===")
for o in xrefs(0x32CF30):
    print(f"  file+0x{o:X}  VA=0x{IB+o:X}  (context dwords: {[hex(u32(o+k)) for k in range(-16,32,4)]})")

print("\n=== xrefs to 'cockpit field of view, in degrees' (0x72CF0C) ===")
for o in xrefs(0x32CF0C):
    print(f"  file+0x{o:X}  VA=0x{IB+o:X}")

print("\n=== xrefs to 'cockpitView' (0x723280) ===")
for o in xrefs(0x723280 - IB):
    print(f"  file+0x{o:X}  VA=0x{IB+o:X}")

print("\n=== xrefs to 'drivingView' (0x72DF28) ===")
for o in xrefs(0x72DF28 - IB):
    print(f"  file+0x{o:X}  VA=0x{IB+o:X}")

print("\n=== xrefs to 'defCockpitLook' (0x73E708) ===")
for o in xrefs(0x73E708 - IB):
    print(f"  file+0x{o:X}  VA=0x{IB+o:X}")
