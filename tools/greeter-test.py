#!/usr/bin/env python3
"""The greeter, end to end under QEMU (`make greeter-test GREETER=<the greeter repository>`): the screen task runs the greeter (built with its `log-key` feature, so the recovery key
can be read from the console: a real image never prints it) with the session service started by the conductor (`opt/metallium/only=14`), and this script types at it through QMP:
first boot (no accounts: make the administrator, read the key back), log in, then a second boot on the same disk: a wrong passphrase, the recovery key replaces the passphrase, the
old one stops working and the new one logs in. Screenshots of the screens go to build-greeter-*.png when PIL is available.
Usage: greeter-test.py '<qemu command line of the usual tests>'."""
import json, os, re, shlex, shutil, socket, subprocess, sys, time

cmd = sys.argv[1]
DISK = "build-greeter.img"
SOCK = "build-greeter.sock"
results = []
MANAGER = os.environ.get("GREETER_MANAGER") == "1"
TTY = os.environ.get("GREETER_TTY") == "1"  # (the interactive boot with a second account made by the conductor, `opt/metallium/only=16`: a second login on tty 1)


def check(what, ok):
    results.append(ok)
    print(f"[greeter-test] TEST {what}: {'PASS' if ok else 'FAIL'}")


def blank_disk():
    shutil.copy("disk.img", DISK)
    size = os.path.getsize(DISK)
    with open(DISK, "r+b") as f:
        f.truncate(13312 * 512)  # (the data partition blank)
        f.truncate(size)


class Boot:
    def __init__(self, tag):
        self.tag = tag
        self.logname = f"build-greeter-{tag}.log"
        c = re.sub(r"file=\S+?,format=raw", f"file={DISK},format=raw", cmd)
        c = c.replace("-nographic", f"-display none -serial file:{self.logname} -monitor none -qmp unix:{SOCK},server,nowait")
        # (GREETER_MANAGER=1: the interactive boot itself, with a program manager per session; else the test mode where the conductor only starts the session service)
        c += (" -fw_cfg name=opt/metallium/only,string=16" if TTY else "" if MANAGER else " -fw_cfg name=opt/metallium/only,string=14") + " -fw_cfg name=opt/metallium/interactive,string=1"
        if os.path.exists(SOCK):
            os.remove(SOCK)
        open(self.logname, "w").close()
        self.p = subprocess.Popen(shlex.split(c), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if os.path.exists(SOCK):
                break
            time.sleep(0.1)
        self.s = socket.socket(socket.AF_UNIX)
        self.s.connect(SOCK)
        self.f = self.s.makefile("r")
        self.f.readline()
        self.q({"execute": "qmp_capabilities"})

    def q(self, o):
        self.s.sendall((json.dumps(o) + "\n").encode())
        while True:
            m = json.loads(self.f.readline())
            if "return" in m or "error" in m:
                return m

    def log(self):
        return open(self.logname, errors="replace").read()

    def wait(self, text, timeout=240):
        end = time.time() + timeout
        while time.time() < end:
            if text in self.log():
                return True
            time.sleep(0.5)
        return False

    def key(self, qcode, shift=False, ctrl=False, alt=False):
        mods = (["ctrl"] if ctrl else []) + (["alt"] if alt else []) + (["shift"] if shift else [])
        ev = lambda k, d: {"type": "key", "data": {"down": d, "key": {"type": "qcode", "data": k}}}
        self.q({"execute": "input-send-event", "arguments": {"events": [ev(m, True) for m in mods] + [ev(qcode, True)]}})
        time.sleep(0.08)
        self.q({"execute": "input-send-event", "arguments": {"events": [ev(qcode, False)] + [ev(m, False) for m in reversed(mods)]}})
        time.sleep(0.08)

    def type(self, text):
        for c in text:
            self.key({" ": "spc", "-": "minus"}.get(c, c))

    def line(self, text):
        self.type(text)
        self.key("ret")

    def shot(self, name):
        path = f"build-greeter-{name}.ppm"
        self.q({"execute": "screendump", "arguments": {"filename": os.path.abspath(path)}})
        time.sleep(1)
        try:
            from PIL import Image
            Image.open(path).save(f"build-greeter-{name}.png")
            os.remove(path)
        except Exception:
            pass

    def stop(self):
        self.p.kill()
        self.p.wait()


PASS1, PASS2 = "correct-horse-1", "second-pass-99"
blank_disk()

# ---- first boot: no accounts
b = Boot("first")
check("the greeter starts with the setup screen on a machine with no accounts", b.wait("[greeter] up (Welcome screen)"))
time.sleep(2)
b.shot("1-setup")
b.line("root")
b.line(PASS1)
b.line(PASS1)
ok = b.wait("[greeter] test: recovery key")
check("making the administrator shows a recovery key", ok)
key = re.search(r"recovery key ([0-9A-Z-]{32})", b.log())
b.shot("2-key")
if key:
    b.key("ret")  # (the key is shown once; Enter goes on)
    time.sleep(2)
    b.shot("3-login")
    b.line("not-the-passphrase")
    time.sleep(8)
    check("a wrong passphrase does not log in", "[greeter] done" not in b.log())
    b.shot("4-wrong")
    b.line(PASS1)
    check("the right passphrase logs in and the greeter hands the screen on", b.wait("[greeter] done", 180))
    check("the session service started the administrator's session", "root logged in" in b.log())
    check("the screen task learns whose session has the screen (ACTIVE)", b.wait("has the screen", 30) and "nobody is logged in" not in b.log())
    if MANAGER or TTY:
        check("the session has its own program manager, and the console is given its control endpoint", b.wait("[progmgr] starting", 60) and b.wait("session 1's program manager is task", 60))
        b.line("prog list")
        time.sleep(3)
        b.shot("5-console")
        log = b.log()
        check("the machine has no program manager of its own (the session service and the session's manager only)", log.count("[progmgr] starting") == 1 and "[progmgr] cannot set up" not in log)
    if TTY:
        check("the conductor made the second account", b.wait("[client] test: the account tester is made", 120) and "tester is made (replies 0 0): PASS" in b.log())
        check("each of the other ttys has a console task with its input and buffer, and was asked for a login", b.wait("tty 3: console task", 60) and b.log().count("greeter asked (status 0)") == 3)
        time.sleep(3)
        b.key("f2", ctrl=True, alt=True)  # tty 1
        time.sleep(3)
        b.shot("7-tty1-login")
        b.line("tester")
        b.line("second-pass")
        ok = b.wait("tty 1: session 2's program manager", 180)
        check("a login on tty 1 starts that session's program manager and hands it to tty 1's console", ok)
        check("tty 1's console started on its own buffer", ok and b.wait("its console started (status 0)", 30) and b.log().count("[shell] ready") == 2)
        time.sleep(3)
        b.shot("8-tty1-console")
        b.line("prog list")
        time.sleep(3)
        b.shot("9-tty1-prog-list")
        b.key("f1", ctrl=True, alt=True)
        time.sleep(2)
        b.line("prog list")
        time.sleep(3)
        b.shot("10-tty0-after")
        log = b.log()
        check("two sessions, each with its own program manager", log.count("[progmgr] starting") == 2 and "[progmgr] cannot set up" not in log)
        # logout on tty 1: the session ends, the console is the greeter again, and a new login there is handed the new session
        b.key("f2", ctrl=True, alt=True)
        time.sleep(2)
        b.line("logout")
        ok = b.wait("[sessiond] session 2 ended", 60) and b.wait("tty 1: the session ended", 60)
        check("logout on tty 1 ends that session and the console goes back to the greeter", ok)
        time.sleep(4)
        b.shot("11-tty1-after-logout")
        b.line("tester")
        b.line("second-pass")
        check("a new login on tty 1 gets a new session and a console again", b.wait("tty 1: session 3's program manager", 180) and b.log().count("[shell] ready") == 3)
        # logout on tty 0, which has the screen task: the same, with the first user
        b.key("f1", ctrl=True, alt=True)
        time.sleep(2)
        b.line("logout")
        check("logout on tty 0 ends the session and the console goes back to the greeter", b.wait("[sessiond] session 1 ended", 60) and b.wait("tty 0: the session ended", 60))
        time.sleep(4)
        b.shot("12-tty0-after-logout")
        b.line("root")
        b.line(PASS1)
        check("a new login on tty 0 gets a new session and the console again", b.wait("tty 0: session 4's program manager", 180) and b.log().count("[shell] ready") == 4)
        time.sleep(3)
        b.shot("13-tty0-again")
        # keys go only to the tty in front: type on tty 0 while tty 1's console is hidden and the other way round; what is typed must show on the screen of the tty in front and change nothing
        # on the hidden one (the screens are compared pixel by pixel: typed text changes hundreds of pixels, a blinking cursor a few)
        def grab(name):
            path = os.path.abspath(f"build-greeter-iso-{name}.ppm")
            b.q({"execute": "screendump", "arguments": {"filename": path}})
            time.sleep(1.2)
            data = open(path, "rb").read()
            os.remove(path)
            return data[data.index(b"255\n") + 4:]

        def changed(x, y):
            return sum(1 for i in range(0, min(len(x), len(y)), 3) if x[i:i + 3] != y[i:i + 3])

        b.key("f1", ctrl=True, alt=True)
        time.sleep(1.5)
        a0 = grab("a0")
        b.key("f2", ctrl=True, alt=True)
        time.sleep(1.5)
        b0 = grab("b0")
        b.key("f1", ctrl=True, alt=True)
        time.sleep(1.5)
        b.line("echo onlyzero")
        time.sleep(1.5)
        a1 = grab("a1")
        b.key("f2", ctrl=True, alt=True)
        time.sleep(1.5)
        b1 = grab("b1")
        b.line("echo onlyone")
        time.sleep(1.5)
        b2 = grab("b2")
        b.key("f1", ctrl=True, alt=True)
        time.sleep(1.5)
        a2 = grab("a2")
        n = [changed(a0, a1), changed(b0, b1), changed(b1, b2), changed(a1, a2)]
        check(f"keys typed on tty 0 reach its console (changed pixels {n[0]})", n[0] > 150)
        check(f"keys typed on tty 0 do not reach tty 1's hidden console (changed pixels {n[1]})", n[1] < 40)
        check(f"keys typed on tty 1 reach its console (changed pixels {n[2]})", n[2] > 150)
        check(f"keys typed on tty 1 do not reach tty 0's hidden console (changed pixels {n[3]})", n[3] < 40)
    check("the recovery key was not written anywhere but the test's console line", len(re.findall(re.escape(key.group(1)), b.log())) == 1)
b.stop()
disk = open(DISK, "rb").read()
check("no passphrase is on the disk in the clear", PASS1.encode() not in disk)

# ---- second boot: the same disk, an account exists
b = Boot("second")
check("with an account the greeter starts at the login screen", b.wait("[greeter] up (Log in screen)"))
time.sleep(2)
b.line("root")
b.line(PASS2)  # (the old passphrase is the only valid one so far)
time.sleep(8)
check("the new passphrase does not work before the recovery", "[greeter] done" not in b.log())
b.key("r", ctrl=True)  # Ctrl+R: forgot my passphrase
time.sleep(1)
b.shot("5-recovery")
if key:
    b.line("root")
    b.line(key.group(1).lower().replace("-", ""))
    b.line(PASS2)
    b.line(PASS2)
    time.sleep(20)
    b.shot("6-after-recovery")
    b.line(PASS1)  # (the login screen has the name filled in and waits for the passphrase)
    time.sleep(8)
    check("the old passphrase stops working after the recovery", "[greeter] done" not in b.log())
    b.line(PASS2)
    check("the passphrase the recovery key set logs in", b.wait("[greeter] done", 180))
b.stop()
ok = bool(results) and all(results)
print("== GREETER: ALL PASS ==" if ok else "== GREETER: FAILED ==")
if not ok:
    for t in ("first", "second"):
        print(f"--- {t} ---")
        print(open(f"build-greeter-{t}.log", errors="replace").read()[-1500:])
sys.exit(0 if ok else 1)
