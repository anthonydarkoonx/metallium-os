#!/usr/bin/env python3
"""The display driver's ttys, under QEMU (`make tty-test`): the conductor (`opt/metallium/only=15`) draws a red screen into tty 1's buffer and a blue one into tty 2's while tty 0 is in
front, then has the driver show 1, 2 and 0. This script takes a screenshot through QMP at each stage and checks what is on the screen: the hidden buffers must not show, each tty shows its own
colour when in front. Usage: tty-test.py '<qemu command line of the usual tests>'."""
import json, os, re, shlex, socket, subprocess, sys, time

cmd = sys.argv[1]
SOCK, LOG = "build-tty.sock", "build-tty.log"
c = cmd.replace("-nographic", f"-display none -serial file:{LOG} -monitor none -qmp unix:{SOCK},server,nowait")
c += " -fw_cfg name=opt/metallium/only,string=15 -fw_cfg name=opt/metallium/interactive,string=1"
for f in (SOCK,):
    if os.path.exists(f):
        os.remove(f)
open(LOG, "w").close()
p = subprocess.Popen(shlex.split(c), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(100):
    if os.path.exists(SOCK):
        break
    time.sleep(0.1)
s = socket.socket(socket.AF_UNIX)
s.connect(SOCK)
f = s.makefile("r")
f.readline()


def q(o):
    s.sendall((json.dumps(o) + "\n").encode())
    while True:
        m = json.loads(f.readline())
        if "return" in m or "error" in m:
            return m


q({"execute": "qmp_capabilities"})
log = lambda: open(LOG, errors="replace").read()


def wait(text, timeout=240):
    end = time.time() + timeout
    while time.time() < end:
        if text in log():
            return True
        time.sleep(0.3)
    return False


def key(qcode, ctrl=False, alt=False):
    ev = lambda k, d: {"type": "key", "data": {"down": d, "key": {"type": "qcode", "data": k}}}
    mods = (["ctrl"] if ctrl else []) + (["alt"] if alt else [])
    q({"execute": "input-send-event", "arguments": {"events": [ev(m, True) for m in mods] + [ev(qcode, True)]}})
    time.sleep(0.15)
    q({"execute": "input-send-event", "arguments": {"events": [ev(qcode, False)] + [ev(m, False) for m in reversed(mods)]}})
    time.sleep(0.15)


def dominant(name):
    """The most common pixel of a screendump (PPM, P6), as (r, g, b)."""
    path = os.path.abspath(f"build-tty-{name}.ppm")
    q({"execute": "screendump", "arguments": {"filename": path}})
    time.sleep(1)
    data = open(path, "rb").read()
    m = re.match(rb"P6\s+(\d+)\s+(\d+)\s+255\s", data)
    px = data[m.end():]
    counts = {}
    for i in range(0, len(px) - 2, 3 * 97):  # (a sample is enough for a plain colour)
        counts[px[i:i + 3]] = counts.get(px[i:i + 3], 0) + 1
    top = max(counts, key=counts.get)
    share = counts[top] / sum(counts.values())
    return tuple(top), share


results = []


def check(what, ok):
    results.append(ok)
    print(f"[tty-test] TEST {what}: {'PASS' if ok else 'FAIL'}")


ok = wait("[tty] hidden:")
hidden, hs = dominant("hidden")
check("the buffers of ttys that are not in front do not show (tty 0 does)", ok and hidden not in ((255, 0, 0), (0, 0, 255)))
for t, want in ((1, (255, 0, 0)), (2, (0, 0, 255))):
    ok = wait(f"[tty] showing {t}")
    col, share = dominant(f"tty{t}")
    check(f"tty {t} is on the screen when it is in front ({col}, {share:.0%})", ok and col == want and share > 0.9)
ok = wait("[tty] showing 0")
col, share = dominant("tty0")
check(f"tty 0 comes back ({col})", ok and col not in ((255, 0, 0), (0, 0, 255)))
# the keyboard: type on tty 0 (nobody there reads it), switch to tty 2 with Ctrl+Alt+F3, type, switch back with Ctrl+Alt+F1, type
wait("[tty] input: start")
time.sleep(1)
key("x")
key("f3", ctrl=True, alt=True)
time.sleep(1.5)
col, share = dominant("f3")
check(f"Ctrl+Alt+F3 puts tty 2 in front ({col})", col == (0, 0, 255))
key("y")
key("f1", ctrl=True, alt=True)
time.sleep(1.5)
col, share = dominant("f1")
check(f"Ctrl+Alt+F1 puts tty 0 back ({col})", col != (0, 0, 255))
key("z")
wait("[tty] done", 60)
p.kill()
p.wait()
text = log()
print("".join(l + "\n" for l in text.splitlines() if "[tty] TEST" in l and "FAIL" in l), end="")
check("the driver's own checks (counts, refusals, the screen task's refusal) pass", text.count("[tty] TEST") >= 8 and "[tty] TEST" in text and ": FAIL" not in text)
print("== TTY: ALL PASS ==" if all(results) else "== TTY: FAILED ==")
sys.exit(0 if all(results) else 1)
