#!/usr/bin/env python3
"""Minimal EROFS image builder (uncompressed, 4 KiB blocks, compact inodes,
flat-plain layout). Written from the public format description; the Rust
reader in libs/metallium-erofs is the independent check (see `make erofs-check`)."""
import struct

BLK = 4096
MAGIC = 0xE0F5E1E2
S_IFDIR, S_IFREG = 0o040000, 0o100000


def build(tree):
    """tree: {name: bytes | dict}. Returns the image as bytes. (Symbolic links are left out: this builder cannot write them; mkfs.erofs can.)"""
    def no_links(t):
        return {k: no_links(v) for k, v in t.items() if not isinstance(v, Symlink)} if isinstance(t, dict) else t
    tree = no_links(tree)
    nodes = []  # dicts: kind, data/children, parent

    def add(t, parent):
        nid = len(nodes)
        nodes.append({"dir": isinstance(t, dict), "t": t, "parent": parent if parent is not None else nid})
        if isinstance(t, dict):
            nodes[nid]["kids"] = []
            for name in sorted(t):
                nodes[nid]["kids"].append((name, add(t[name], nid)))
        return nid

    add(tree, None)
    meta_blocks = -(-len(nodes) * 32 // BLK)
    next_blk = 1 + meta_blocks
    for n in nodes:
        if n["dir"]:
            ents = [(".", None), ("..", None)] + n["kids"]
            blocks, cur, used = [], [], 0
            for name, kid in ents:
                need = 12 + len(name)
                if used + need > BLK:
                    blocks.append(cur); cur, used = [], 0
                cur.append((name, kid)); used += need
            blocks.append(cur)
            n["dirblocks"] = blocks
            last_used = sum(12 + len(nm) for nm, _ in blocks[-1])
            n["size"] = (len(blocks) - 1) * BLK + last_used
            n["nblocks"] = len(blocks)
        else:
            n["size"] = len(n["t"])
            n["nblocks"] = -(-n["size"] // BLK)
        n["blk"] = next_blk
        next_blk += n["nblocks"]

    img = bytearray(next_blk * BLK)
    sb = struct.pack("<IIIBBHQQIII", MAGIC, 0, 0, 12, 0, 0, len(nodes), 0, 0, next_blk, 1)
    # superblock fields: magic, csum, feature_compat, blkszbits@12, extslots@13, root_nid@14,
    # inos@16, build_time@24, build_time_nsec@32, blocks@36, meta_blkaddr@40
    img[1024:1024 + 44] = sb[:44]
    for nid, n in enumerate(nodes):
        mode = (S_IFDIR | 0o755) if n["dir"] else (S_IFREG | 0o644)
        ino = struct.pack("<HHHHIIIIHHI", 0, 0, mode, 1, n["size"], 0, n["blk"], nid, 0, 0, 0)
        img[BLK + nid * 32:BLK + nid * 32 + 32] = ino
        base = n["blk"] * BLK
        if n["dir"]:
            for bi, ents in enumerate(n["dirblocks"]):
                hdr, names = bytearray(), bytearray()
                off = 12 * len(ents)
                for name, kid in ents:
                    tgt = nid if name == "." else n["parent"] if name == ".." else kid
                    ftype = 2 if nodes[tgt]["dir"] else 1
                    hdr += struct.pack("<QHBB", tgt, off + len(names), ftype, 0)
                    names += name.encode()
                blob = bytes(hdr + names)
                img[base + bi * BLK:base + bi * BLK + len(blob)] = blob
        else:
            img[base:base + n["size"]] = n["t"]
    return bytes(img)


LOREM = "".join("Metallium-OS system image, line %05d: the quick brown fox\n" % i for i in range(4000)).encode()


class Symlink:
    """A symbolic link in a system_tree() dict: `target` as the link says it (relative to the link's directory, or absolute from the root of the image).
    Only an image made by mkfs.erofs has them (the built-in uncompressed builder leaves them out)."""
    def __init__(self, target):
        self.target = target


def write_tree(tree, root):
    """Materialise a system_tree() dict as real files (for mkfs.erofs)."""
    import os
    os.makedirs(root, exist_ok=True)
    for name, t in tree.items():
        p = os.path.join(root, name)
        if isinstance(t, dict):
            write_tree(t, p)
        elif isinstance(t, Symlink):
            os.symlink(t.target, p)
        else:
            open(p, "wb").write(t)


def programs():
    """The programs in programs/build (position-independent ELF files, static ELF files and flat images), by file name."""
    import glob, os
    here = os.path.dirname(os.path.abspath(__file__))
    files = sorted(glob.glob(os.path.join(here, "..", "programs", "build", "*.bin")) + glob.glob(os.path.join(here, "..", "programs", "build", "*.elf")) + glob.glob(os.path.join(here, "..", "programs", "build", "*.pie")))
    # programs that are only ever installed from their package (`prog install`) and large would be left out of /bin (their image is in the package): none now
    package_only = set()
    return {os.path.basename(f) if f.endswith(".elf") else os.path.basename(f).rsplit(".", 1)[0]: open(f, "rb").read() for f in files if os.path.basename(f).rsplit(".", 1)[0] not in package_only}


def system_tree():
    tree = {
        "hello.txt": b"Hello from the Metallium-OS system image!\n",
        "etc": {"os-release": b"NAME=Metallium-OS\nVERSION=0.1\n"},
        "bin": {"blob.bin": bytes((i * 7) % 251 for i in range(9000))},
        # compressible: exercises the LZ4 path when the image is built with mkfs.erofs -zlz4hc
        # dirtest: a directory of 420 entries, more names than one page of a listing holds (the test reads it in pieces)
        # links: the cases the symbolic link tests (user/src/vfs.rs) go through; hop0 .. hop19 is a chain of 20 links to links/target.txt (more than a path may follow)
        "usr": {"share": {"lorem.txt": LOREM, "dirtest": {f"entry-{i:04d}-with-a-longish-name": b"" for i in range(420)},
                          "links": {"target.txt": b"link target\n", "sub": {"inner.txt": b"inner\n"},
                                    "rel": Symlink("target.txt"), "abs": Symlink("/usr/share/links/target.txt"), "up": Symlink("../links/target.txt"),
                                    "dirlink": Symlink("sub"), "dirabs": Symlink("/usr/share/links/sub"),
                                    "loop1": Symlink("loop2"), "loop2": Symlink("loop1"), "dangling": Symlink("nowhere.txt"),
                                    **{f"hop{i}": Symlink(f"hop{i + 1}" if i < 19 else "target.txt") for i in range(20)}}}},
    }
    tree["bin"].update(programs())
    import mkmap
    tree["etc"]["program-keys"] = mkmap.program_keys().encode()
    tree["etc"]["program-policy"] = mkmap.program_policy().encode()
    if mkmap.extra_defaults():
        tree["etc"]["program-defaults"] = mkmap.extra_defaults().encode()  # what a desktop installs and starts by default
    tree["usr"]["programs"] = mkmap.packages()  # Metal Program Packages for the program manager (see docs/PROGRAMS.md)
    return tree
