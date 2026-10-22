import struct, shutil, sys

SRC = "NR2003.exe"
DST = "NR2003_patched_test.exe"

data = bytearray(open(SRC, "rb").read())
orig = bytes(data)

def wr(off, raw):
    data[off:off+len(raw)] = raw
def f32(x):
    return struct.pack("<f", x)

FOV = 80.0
OX, OY, OZ = 0.2, 0.1, -0.3

# sanity on original
assert struct.unpack_from("<f", orig, 0x2EF48C)[0] == 65.0, "def const not 65"
assert struct.unpack_from("<f", orig, 0x2F5F00)[0] == 65.0, "min const not 65"
assert struct.unpack_from("<f", orig, 0x2F5F04)[0] == 78.0, "max const not 78"
assert orig[0x41C10:0x41C17] == bytes.fromhex("d905e84e8900c3"), "getter sig mismatch"
assert struct.unpack_from("<I", orig, 0x41C12)[0] == 0x00894EE8, "getter operand mismatch"

wr(0x2EF48C, f32(FOV))
wr(0x2F5F00, f32(FOV))
wr(0x2F5F04, f32(FOV))
wr(0x41C12, struct.pack("<I", 0x006EF48C))
wr(0x34EBBC, f32(OX))
wr(0x34EBC0, f32(OY))
wr(0x34EBC4, f32(OZ))

# report changed offsets
diffs = [i for i in range(len(orig)) if data[i] != orig[i]]
print("changed byte offsets:", [hex(i) for i in diffs])
# group into 4-byte words
groups = sorted(set(d & ~3 for d in diffs))
print("changed 4-byte words:", [hex(g) for g in groups])

open(DST, "wb").write(data)
print("wrote", DST)

# verify getter now reads our const
print("getter bytes now:", bytes(data[0x41C10:0x41C17]).hex())
assert struct.unpack_from("<I", data, 0x41C12)[0] == 0x006EF48C
print("getter operand now -> 0x%08X" % struct.unpack_from("<I", data, 0x41C12)[0])
print("FOV const now =", struct.unpack_from("<f", data, 0x2EF48C)[0])
print("offset now =", struct.unpack_from("<f", data, 0x34EBBC)[0],
      struct.unpack_from("<f", data, 0x34EBC0)[0], struct.unpack_from("<f", data, 0x34EBC4)[0])

# PE validity
try:
    import pefile
    pe = pefile.PE(DST, fast_load=True)
    print("PE parse OK; entrypoint RVA = 0x%X" % pe.OPTIONAL_HEADER.AddressOfEntryPoint)
except Exception as e:
    print("PE parse FAILED:", e)
