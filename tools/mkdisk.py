#!/usr/bin/env python3
"""Create the 12 MiB raw test disk.

  sector 0            magic string
  sectors 100..107    scratch (raw block-driver test writes here)
  sectors 1024..13311 system partition: read-only EROFS image (6 MiB; SYSTEM_MIB=n makes it larger, see below)
  sectors 13312..24575 data partition: log-structured store (formatted by its server)
(Layout 5: the size of the system partition is in the header (bytes 48..56 of sector 0, little endian, in sectors) and the data partition starts right after it, so
a disk for a desktop can have a system partition of hundreds of MiB: SYSTEM_MIB=512 python3 tools/mkdisk.py disk.img. The default stays 6 MiB, so the test disks are
the same as with layout 4. Layout 4: the system partition grew from 4 to 6 MiB for the JavaScript engine (Kataan, about 1.3 MB compressed), and the disk from 10 to 12 MiB so the data
partition kept its size. Layout 3: the system partition grew from 2 to 4 MiB when TLS and the root certificates outgrew it, and the disk from 8 to 10 MiB so the
data partition kept its size. Layout 2 had grown it from 1.5 to 2 MiB. Byte 40 of sector 0 says "layout=5"; an older disk is not kept.)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import mkerofs

ROFS_BASE = 1024
SYSTEM_MIB = float(os.environ.get("SYSTEM_MIB", "6"))
ROFS_SECTORS = int(SYSTEM_MIB * 2048) // 8 * 8
assert ROFS_SECTORS >= 2048, "the system partition must be at least 1 MiB"
DATA_BASE = ROFS_BASE + ROFS_SECTORS  # the data partition starts right after the system partition (13312 for the default 6 MiB: tools/volume-test.py and checkdisk.py assume it)
LAYOUT = b"layout=5"
# The data partition is the rest of the disk, and the guest uses all of it (the storage server asks the block driver how big the disk is). The test
# disks keep the small default (5.5 MiB: the cleaner test of the QEMU suite writes far past the end of it); a disk for real use asks for more, and the
# file is sparse, so 32 GiB costs nothing until it is written: DATA_MIB=32768 python3 tools/mkdisk.py disk.img
DATA_MIB = float(os.environ.get("DATA_MIB", "5.5"))
DATA_SECTORS = int(DATA_MIB * 2048) // 8 * 8
assert DATA_SECTORS >= 4096, "the data partition must be at least 2 MiB"
SECTORS = DATA_BASE + DATA_SECTORS

d = bytearray(DATA_BASE * 512)  # (everything before the data partition; the data partition itself is left to the guest to format)
d[0:64] = b"METAL-OS-DISK v1 sector 0".ljust(64, b".")
d[40:40 + len(LAYOUT)] = LAYOUT
d[48:56] = ROFS_SECTORS.to_bytes(8, "little")
import shutil
import subprocess
import tempfile

tree = mkerofs.system_tree()
if shutil.which("mkfs.erofs"):
    # the reference tool, with fixed timestamps so the image is reproducible.
    # EROFS_OPTS selects the compression (default: ZSTD with 16 KiB big physical clusters).
    import shlex
    opts = shlex.split(os.environ.get("EROFS_OPTS", "-zzstd,level=19 -C16384"))
    with tempfile.TemporaryDirectory() as tmp:
        mkerofs.write_tree(tree, tmp + "/root")
        subprocess.run(["mkfs.erofs", *opts, "-T0", "-U", "00000000-0000-0000-0000-000000000000",
                        tmp + "/img.erofs", tmp + "/root"], check=True, capture_output=True)
        img = open(tmp + "/img.erofs", "rb").read()
    print(f"system image: mkfs.erofs {' '.join(opts)}, {len(img)} bytes", file=sys.stderr)
else:
    img = mkerofs.build(tree)
    print(f"system image: built-in uncompressed builder, {len(img)} bytes (mkfs.erofs not found)", file=sys.stderr)
assert len(img) <= ROFS_SECTORS * 512, "system image too large for its partition"
d[ROFS_BASE * 512:ROFS_BASE * 512 + len(img)] = img
if len(sys.argv) > 2:
    open(sys.argv[2], "wb").write(img)  # standalone copy for `make erofs-check`
# An interactive run keeps what is on the data partition (the saved colours and settings, installed programs) from the last run: KEEP_DATA=1.
out = sys.argv[1]
if os.environ.get("KEEP_DATA") == "1" and os.path.exists(out) and os.path.getsize(out) == SECTORS * 512:
    with open(out, "rb") as f:
        old_head = f.read(64)
    if old_head[40:40 + len(LAYOUT)] == LAYOUT:
        with open(out, "r+b") as f:  # (only what is before the data partition is rewritten)
            f.write(d)
        print("kept the data partition of the existing disk", file=sys.stderr)
        sys.exit(0)
    print("the existing disk has an older layout: its data partition is not kept", file=sys.stderr)
with open(out, "wb") as f:
    f.write(d)
    f.truncate(SECTORS * 512)  # a sparse file: the data partition reads as zeros
