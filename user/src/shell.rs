//! The shell: a line editor and a set of commands on the console, working on the VFS.
//!
//! Keys come from the keyboard driver (polled, once per tick of sleep); files come from the VFS server
//! like any other client: `/system` (EROFS, read-only) and `/data` (log-structured, writable). The shell
//! holds exactly three capabilities beyond its screen: the keyboard driver, one VFS endpoint and its own
//! VFS page.
//!
//! A command line is `cmd args | cmd args ... [> file | >> file]`. Words may be quoted with "..." or '...'.
//! Programs are built in; each one reads text from a file argument or from the pipe and returns text.
use crate::console::{Console, ACCENT, COLS, ERR, FG};
use crate::info::{self, Facts};
use crate::proto::input::{K_BACKSPACE, K_DOWN, K_UP};
use crate::termedit::TermEdit;
use crate::vfs::{Vfs, O_READ};
use crate::*;
use alloc::vec;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const SHELL_SHM: usize = 0x8038_0000;
const MAX_LINE: usize = 160;
const HISTORY: usize = 16;
const CAT_LIMIT: usize = 8192;
const CAT_TOTAL: usize = 16384;
const APPEND_LIMIT: u64 = 1 << 20;
/// Largest file a text tool (grep, wc, head, ...) will read.
const TEXT_LIMIT: u64 = 1 << 20;

const COMMANDS: &[&str] = &[
    "cat", "cd", "clear", "echo", "edit", "fetch", "free", "grep", "head", "help", "ls", "download", "mkdir", "nano", "play", "prog", "ps", "pwd", "rm", "sort", "stat", "tail", "uptime", "wc",
];

const HELP: &str = "files:  ls cd pwd cat stat mkdir rm echo
text:   grep [-v -i -c] TEXT   (plain text, no regex)
        wc [-l]  head/tail [-n N]  sort [-r]
edit:   edit FILE  (or nano FILE): a small text editor, keys as in nano
        ^O write out  ^X exit  ^K cut line  ^U paste  ^W search  ^G help
system: ps free uptime fetch clear help
net:    download http://host/path [FILE]   (plain HTTP)
sound:  play [-v PERCENT] FILE.wav|http://URL   (PCM, any rate; Ctrl-C stops)
        play -t [HZ [SECONDS]]       (test tone)
programs:   prog list | available | install ID | start ID | stop ID
        program fg ID | bg ID | state ID | info ID | uninstall ID
pipes:  ls /system | grep etc      > file  >> file
write files under /data (the system image is read-only)
keys:   Tab completes, Up/Down history, Ctrl-L clears,
        Ctrl-C cancels the line
";

/// What the shell needs from whatever hosts it (the console): the characters typed since it last asked, and a chance to run
/// (draw frames, move the pointer) while the shell waits for a program it started.
pub struct Host {
    pub keys: fn() -> Vec<u8>,
    pub idle: fn(),
}

pub struct Shell {
    con: Console,
    vfs: Vfs,
    cwd: String,
    line: String,
    hist: Vec<String>,
    /// While browsing history with the arrow keys: the entry shown; `hist.len()` when not browsing.
    hist_at: usize,
    facts: Facts,
    /// Endpoint (my slot) programs write their standard output to; made on first use.
    stdout: Option<u64>,
    /// My slot holding a send capability to the program manager's control endpoint (the conductor hands it over), if it runs.
    pub progmgr: Option<u64>,
    host: Host,
    /// The full-screen editor, while `edit` runs (it takes every key until it exits), and the screen to put back when it does.
    edit: Option<TermEdit>,
    saved_screen: Option<crate::console::Snapshot>,
}

/// Turn `p` (absolute or relative to `cwd`) into a clean absolute path.
fn resolve(cwd: &str, p: &str) -> String {
    let full = if p.starts_with('/') { String::from(p) } else { format!("{cwd}/{p}") };
    let mut parts: Vec<&str> = Vec::new();
    for c in full.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            x => parts.push(x),
        }
    }
    if parts.is_empty() {
        String::from("/")
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Split `cmd > file` / `cmd >> file` (a `>` inside quotes is not a redirection): (command, Some((append, file))).
fn split_redirect(line: &str) -> (&str, Option<(bool, &str)>) {
    let mut quote = None;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '>') => {
                let append = line[i + 1..].starts_with('>');
                let target = line[i + 1 + append as usize..].trim();
                return (line[..i].trim_end(), Some((append, target)));
            }
            _ => {}
        }
    }
    (line, None)
}

/// Split on `|` outside quotes.
fn split_pipeline(cmd: &str) -> Vec<&str> {
    let (mut out, mut quote, mut start) = (Vec::new(), None, 0);
    for (i, c) in cmd.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None, '|') => {
                out.push(cmd[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(cmd[start..].trim());
    out
}

/// Words of a command, honouring "double" and 'single' quotes.
fn words(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut quote, mut any) = (Vec::new(), String::new(), None, false);
    for c in s.chars() {
        match (quote, c) {
            (None, '"' | '\'') => {
                quote = Some(c);
                any = true;
            }
            (Some(q), c) if c == q => quote = None,
            (None, c) if c.is_whitespace() => {
                if any || !cur.is_empty() {
                    out.push(core::mem::take(&mut cur));
                    any = false;
                }
            }
            (_, c) => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn common_prefix(items: &[String]) -> String {
    let mut p = items[0].clone();
    for s in &items[1..] {
        let n = p.bytes().zip(s.bytes()).take_while(|(a, b)| a == b).count();
        p.truncate(n);
    }
    p
}

type Reply = Result<String, String>;

impl Shell {
    /// # Safety
    /// As `Console::new` for `fb`.
    pub unsafe fn new(fb: *mut u32, facts: Facts, host: Host) -> Shell {
        // SAFETY: forwarded from `Shell::new`'s contract: `fb` is valid for `Console::new`.
        let con = unsafe { Console::new(fb) };
        Shell { con, vfs: Vfs::new(5, SHELL_SHM), cwd: String::from("/"), line: String::new(), hist: Vec::new(), hist_at: 0, facts, stdout: None, progmgr: None, host, edit: None, saved_screen: None }
    }

    /// Draw the first screen: banner, the machine summary, a prompt.
    pub fn start(&mut self) {
        if mem_map(6, SHELL_SHM, true) != 0 {
            println!("[shell] cannot map its VFS page");
            exit(1);
        }
        self.vfs = Vfs::new(5, va(SHELL_SHM)); // (now that the kernel has said where the page is)
        self.con.reset();
        // (no machine summary on the first screen: `fetch` prints it when asked)
        self.update_status();
        if let Some((id, name)) = crate::greeter::active_session() {
            self.con.print(&format!("Signed in as {name} (session {id})\n"));
        }
        self.prompt();
        self.con.flush();
        println!("[shell] ready: type on the keyboard");
    }

    fn kv(&mut self, k: &str, v: &str) {
        self.con.set_color(ACCENT);
        self.con.print(&format!("{k:<9}"));
        self.con.set_color(FG);
        self.con.print(v);
        self.con.put(b'\n');
    }

    fn fetch(&mut self) {
        const LOGO_COLS: usize = 21;
        let f = &self.facts;
        let tasks = sysinfo(1);
        let dev = device_names();
        let rows = [
            ("KERNEL", String::from("Metallium-OS 0.1 aarch64 microkernel")),
            ("UPTIME", info::uptime(f)),
            ("CPU", format!("{}x {}", f.ncpus, info::cpu_name(f.midr))),
            ("GPU", format!("{} {}x{}", dev.0, f.gpu_w, f.gpu_h)),
            ("RAM", info::ram(f)),
            ("STORAGE", format!("{} MiB {} (EROFS + LFS)", f.sectors * 512 >> 20, dev.1)),
            ("IOMMU", if tasks[1] != 0 { format!("Arm SMMUv3, {} devices confined", tasks[2]) } else { format!("none ({})", iommu_note()) }),
            ("TASKS", format!("{} running, {} driver restarts", tasks[3], tasks[4])),
        ];
        // the planet on the left, the rows beside it (8 rows of 19 px hold the 152 px logo)
        let top = self.con.reserve_rows(rows.len());
        self.con.draw_logo(0, top);
        for (i, (k, v)) in rows.into_iter().enumerate() {
            println!("[fetch] {k:<8}{v}");
            self.con.goto(LOGO_COLS, top + i);
            self.kv(k, &v);
        }
    }

    /// (The console's status bar shows uptime and memory now.)
    fn update_status(&mut self) {}

    fn prompt(&mut self) {
        self.con.set_color(ACCENT);
        let p = format!("metallium {}> ", self.cwd);
        self.con.print(&p);
        self.con.set_color(FG);
    }

    /// Type `s` into the line, as if the user had.
    fn insert(&mut self, s: &str) {
        for b in s.bytes() {
            if (0x20..=0x7e).contains(&b) && self.line.len() < MAX_LINE {
                self.line.push(b as char);
                self.con.put(b);
            }
        }
    }

    fn set_line(&mut self, new: &str) {
        for _ in 0..self.line.len() {
            self.con.backspace();
        }
        self.line.clear();
        self.insert(new);
    }

    fn key(&mut self, b: u8) {
        if self.edit.is_some() {
            return self.edit_key(b);
        }
        match b {
            b'\n' => {
                self.con.put(b'\n');
                let line = core::mem::take(&mut self.line);
                if !line.trim().is_empty() {
                    if self.hist.len() == HISTORY {
                        self.hist.remove(0);
                    }
                    self.hist.push(line.clone());
                }
                self.hist_at = self.hist.len();
                self.exec(&line);
                if self.edit.is_none() {
                    self.prompt(); // (the editor draws its own screen; the prompt comes back when it ends)
                }
            }
            b'\t' => self.complete(),
            K_BACKSPACE => {
                if self.line.pop().is_some() {
                    self.con.backspace();
                }
            }
            0x0c => {
                // Ctrl-L
                self.con.clear();
                self.prompt();
                let l = self.line.clone();
                self.con.print(&l);
            }
            0x03 => {
                // Ctrl-C
                self.con.print("^C\n");
                self.line.clear();
                self.prompt();
            }
            K_UP => {
                if self.hist_at > 0 {
                    self.hist_at -= 1;
                    let h = self.hist[self.hist_at].clone();
                    self.set_line(&h);
                }
            }
            K_DOWN => {
                if self.hist_at < self.hist.len() {
                    self.hist_at += 1;
                    let h = self.hist.get(self.hist_at).cloned().unwrap_or_default();
                    self.set_line(&h);
                }
            }
            0x20..=0x7e => self.insert(core::str::from_utf8(&[b]).unwrap_or("")),
            _ => {}
        }
    }

    /// `edit [FILE]`: the full-screen editor takes over the console until it exits.
    fn start_edit(&mut self, args: &[String]) {
        if args.len() > 1 {
            return self.error("usage: edit [FILE]");
        }
        let mut t = TermEdit::new(&self.vfs, &self.cwd, args.first().map(String::as_str));
        self.saved_screen = Some(self.con.snapshot());
        self.con.clear();
        t.draw(&mut self.con);
        self.edit = Some(t);
    }

    fn edit_key(&mut self, b: u8) {
        let Some(mut t) = self.edit.take() else { return };
        if t.key(&self.vfs, b) == metallium_edit::Outcome::Exit {
            // the screen as it was before the editor, as nano leaves it, then a new prompt
            match self.saved_screen.take() {
                Some(s) => self.con.restore(&s),
                None => self.con.clear(),
            }
            self.prompt();
        } else {
            t.draw(&mut self.con);
            self.edit = Some(t);
        }
    }

    /// Tab: complete the word before the cursor as a command (first word of a stage) or as a path.
    /// A unique match is completed; several matches are completed as far as they agree and, if that
    /// adds nothing, listed.
    fn complete(&mut self) {
        let line = self.line.clone();
        let start = line.rfind([' ', '|', '>']).map_or(0, |i| i + 1);
        let word = line[start..].to_string();
        let before = line[..start].trim_end();
        let (cands, typed): (Vec<String>, usize) = if before.is_empty() || before.ends_with('|') {
            (COMMANDS.iter().filter(|c| c.starts_with(word.as_str())).map(|c| c.to_string()).collect(), word.len())
        } else {
            let (dir, base) = match word.rfind('/') {
                Some(i) => (&word[..=i], &word[i + 1..]),
                None => ("", &word[..]),
            };
            let dirpath = resolve(&self.cwd, if dir.is_empty() { "." } else { dir });
            let names = self.vfs.list(&dirpath).unwrap_or_default();
            (names.lines().filter(|n| !n.is_empty() && n.starts_with(base)).map(String::from).collect(), base.len())
        };
        if cands.is_empty() {
            return;
        }
        let lcp = common_prefix(&cands);
        if lcp.len() > typed {
            self.insert(&lcp[typed..]);
        } else if cands.len() > 1 {
            // nothing more to add: show the choices, then the prompt and the line again
            self.con.put(b'\n');
            let mut col = 0;
            for c in &cands {
                if col + c.len() + 2 > COLS && col > 0 {
                    self.con.put(b'\n');
                    col = 0;
                }
                self.con.print(c);
                self.con.print("  ");
                col += c.len() + 2;
            }
            self.con.put(b'\n');
            self.prompt();
            let l = self.line.clone();
            self.con.print(&l);
            return;
        }
        if cands.len() == 1 && !cands[0].ends_with('/') && !self.line.ends_with(' ') {
            self.insert(" ");
        }
    }

    fn exec(&mut self, line: &str) {
        let (cmd, redirect) = split_redirect(line.trim());
        if cmd.trim().is_empty() {
            if redirect.is_some() {
                self.error("syntax error: nothing to redirect");
            }
            return;
        }
        let stages = split_pipeline(cmd);
        if stages.iter().any(|s| s.is_empty()) {
            return self.error("syntax error: empty command in a pipeline");
        }
        if stages.len() == 1 && redirect.is_none() {
            match stages[0] {
                "clear" => return self.con.clear(),
                "fetch" => return self.fetch(),
                _ => {}
            }
            let argv = words(stages[0]);
            if matches!(argv.first().map(String::as_str), Some("edit" | "nano")) {
                return self.start_edit(&argv[1..]);
            }
        }
        let mut data: Option<String> = None;
        let last = stages.len() - 1;
        for (i, stage) in stages.iter().enumerate() {
            let tty = i == last && redirect.is_none();
            match self.run(stage, data.take(), tty) {
                Ok(out) => data = Some(out),
                Err(e) => return self.error(&e),
            }
        }
        let out = data.unwrap_or_default();
        match redirect {
            None => self.con.print(&out),
            Some((append, target)) => {
                if target.is_empty() {
                    return self.error("missing file name after >");
                }
                let path = resolve(&self.cwd, target);
                let mut data = Vec::new();
                if append {
                    if matches!(self.vfs.stat(&path), Ok((_, size)) if size > APPEND_LIMIT) {
                        return self.error(&format!("{path}: too large to append to from the shell"));
                    }
                    data = self.vfs.read_file(&path).unwrap_or_default();
                }
                data.extend_from_slice(out.as_bytes());
                if let Err(e) = self.vfs.write_file(&path, &data) {
                    self.error(&format!("{path}: {}", errno(e)));
                }
            }
        }
    }

    /// Run one program. `stdin` is what the previous stage produced; `tty` says the output goes to the screen.
    fn run(&mut self, cmd: &str, stdin: Option<String>, tty: bool) -> Reply {
        let argv = words(cmd);
        let Some(name) = argv.first().map(String::as_str) else { return Ok(String::new()) };
        let args: Vec<&str> = argv[1..].iter().map(String::as_str).collect();
        match name {
            "help" => Ok(String::from(HELP)),
            "echo" => Ok(format!("{}\n", args.join(" "))),
            "pwd" => Ok(format!("{}\n", self.cwd)),
            "uptime" => Ok(format!("up {}\n", info::uptime(&self.facts))),
            "free" => Ok(format!("RAM {}\n", info::ram(&self.facts))),
            "ps" => Ok(self.ps()),
            "cd" => self.cd(args.first().copied().unwrap_or("/")),
            "ls" => self.ls(args.first().copied().unwrap_or("."), tty),
            "play" => self.play(&args),
            "download" => self.download(&args),
            "cat" => self.cat(&args, stdin),
            "stat" => self.stat(&args),
            "mkdir" => self.simple(&args, "mkdir", |v, p| v.mkdir(p)),
            "rm" => self.simple(&args, "rm", |v, p| v.unlink(p)),
            "grep" => self.grep(&args, stdin),
            "wc" => self.wc(&args, stdin),
            "head" => self.head_tail(&args, stdin, true),
            "tail" => self.head_tail(&args, stdin, false),
            "sort" => self.sort(&args, stdin),
            "clear" | "fetch" | "edit" | "nano" => Err(format!("{name}: cannot be piped or redirected")),
            _ => self.program(name, &args, stdin, tty),
        }
    }

    fn error(&mut self, msg: &str) {
        self.con.set_color(ERR);
        self.con.print(msg);
        self.con.put(b'\n');
        self.con.set_color(FG);
    }

    fn cd(&mut self, arg: &str) -> Reply {
        let p = resolve(&self.cwd, arg);
        if p == "/" || self.vfs.list(&p).is_ok() {
            self.cwd = p;
            Ok(String::new())
        } else {
            Err(format!("cd: {p}: not a directory"))
        }
    }

    fn ls(&mut self, arg: &str, tty: bool) -> Reply {
        let p = resolve(&self.cwd, arg);
        if let Ok((1, _)) = self.vfs.stat(&p) {
            return Ok(format!("{p}\n"));
        }
        let names = self.vfs.list(&p).map_err(|e| format!("ls: {p}: {}", errno(e)))?;
        let mut out = String::new();
        if !tty {
            // into a pipe or a file: one name per line, like every Unix ls
            for n in names.lines().filter(|n| !n.is_empty()) {
                out.push_str(n);
                out.push('\n');
            }
            return Ok(out);
        }
        let mut col = 0;
        for n in names.lines().filter(|n| !n.is_empty()) {
            if col + n.len() + 2 > COLS && col > 0 {
                out.push('\n');
                col = 0;
            }
            col += n.len() + 2;
            out.push_str(n); // the VFS already marks directories with a trailing '/'
            out.push_str("  ");
        }
        out.push('\n');
        Ok(out)
    }

    /// Make a file's bytes printable text: newlines kept, tabs as spaces, anything else a dot.
    fn printable(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|&b| match b {
                b'\n' => '\n',
                b'\t' => ' ',
                0x20..=0x7e => b as char,
                _ => '.',
            })
            .collect()
    }

    fn cat(&mut self, args: &[&str], stdin: Option<String>) -> Reply {
        if args.is_empty() {
            return stdin.ok_or_else(|| String::from("usage: cat <file> ..."));
        }
        let mut out = String::new();
        for a in args {
            if out.len() >= CAT_TOTAL {
                out.push_str("... (too much output, stopped)\n");
                break;
            }
            let p = resolve(&self.cwd, a);
            let fd = self.vfs.open(&p, O_READ).map_err(|e| format!("cat: {p}: {}", errno(e)))?;
            let mut buf = alloc::vec![0u8; CAT_LIMIT];
            let n = self.vfs.read(fd, &mut buf).map_err(|e| format!("cat: {p}: {}", errno(e)));
            let _ = self.vfs.close(fd);
            let n = n?;
            out.push_str(&Self::printable(&buf[..n]));
            if !out.ends_with('\n') {
                out.push('\n');
            }
            if n == CAT_LIMIT {
                out.push_str("... (output cut at 8 KiB)\n");
            }
        }
        Ok(out)
    }

    /// `play`: stream a WAV file (or a test tone) to the audio service. Runs until the sound has ended or Ctrl-C.
    fn play(&mut self, args: &[&str]) -> Reply {
        use crate::audio::{parse_wav, Converter, Format, Player, RATE};
        const USAGE: &str = "usage: play [-v PERCENT] FILE.wav | play -t [HZ [SECONDS]]";
        let mut volume = 70u32;
        let mut tone: Option<(u32, u32)> = None;
        let mut file: Option<&str> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i] {
                "-v" => {
                    i += 1;
                    volume = args.get(i).and_then(|v| v.parse().ok()).filter(|v| *v <= 200).ok_or_else(|| String::from(USAGE))?;
                }
                "-t" => {
                    let hz = args.get(i + 1).and_then(|v| v.parse().ok());
                    let secs = args.get(i + 2).and_then(|v| v.parse().ok());
                    tone = Some((hz.unwrap_or(440), secs.unwrap_or(3).clamp(1, 60)));
                    i += hz.is_some() as usize + secs.is_some() as usize;
                }
                a if !a.starts_with('-') && file.is_none() => file = Some(a),
                _ => return Err(String::from(USAGE)),
            }
            i += 1;
        }
        let mut player = Player::open().map_err(|e| format!("play: {e}"))?;
        let host_keys = self.host.keys;
        let host_idle = self.host.idle;
        let mut poll = move || {
            host_idle();
            host_keys().contains(&0x03)
        };
        if let Some((hz, secs)) = tone {
            self.con.print(&format!("playing a {hz} Hz tone for {secs} s (Ctrl-C stops)\n"));
            let mut frames = Vec::new();
            Converter::tone(hz, (secs * RATE) as usize, volume, &mut frames);
            for part in frames.chunks(8192) {
                player.push(part, &mut poll);
            }
            player.drain(&mut poll);
            return Ok(if player.cancelled { String::from("^C\n") } else { String::new() });
        }
        let name = file.ok_or_else(|| String::from(USAGE))?;
        enum Src {
            File(u64),
            Http(crate::httpc::Response),
        }
        let (mut src, label) = if name.starts_with("http://") {
            let url = crate::httpc::parse_url(name).map_err(|e| format!("play: {e}"))?;
            self.con.print("connecting ...\n");
            let r = crate::httpc::get_following(&url, &mut poll).map_err(|e| format!("play: {name}: {e}"))?;
            (Src::Http(r), String::from(name))
        } else {
            let p = resolve(&self.cwd, name);
            let fd = self.vfs.open(&p, O_READ).map_err(|e| format!("play: {p}: {}", errno(e)))?;
            (Src::File(fd), p)
        };
        let p = label;
        let vfs = &self.vfs;
        let mut read = |src: &mut Src, buf: &mut [u8], poll: &mut dyn FnMut() -> bool| -> Result<usize, String> {
            match src {
                Src::File(fd) => vfs.read(*fd, buf).map_err(|e| format!("read error: {}", errno(e))),
                Src::Http(r) => r.read(buf, poll),
            }
        };
        let finish = |src: Src| match src {
            Src::File(fd) => {
                let _ = vfs.close(fd);
            }
            Src::Http(r) => r.close(),
        };
        // the header: the first block (a WAV header is a few dozen bytes; a big LIST chunk may push the data further)
        let mut head = alloc::vec![0u8; 4096];
        let mut have = 0;
        while have < head.len() {
            match read(&mut src, &mut head[have..], &mut poll) {
                Ok(0) => break,
                Ok(n) => have += n,
                Err(e) => {
                    finish(src);
                    return Err(format!("play: {p}: {e}"));
                }
            }
        }
        head.truncate(have);
        let (fmt, data_at, data_len): (Format, usize, Option<usize>) = match parse_wav(&head) {
            Ok(v) => v,
            Err(e) => {
                finish(src);
                return Err(format!("play: {p}: {e}"));
            }
        };
        let secs = data_len.map(|l| l / (fmt.channels as usize * fmt.bits as usize / 8) / fmt.rate as usize);
        self.con.print(&format!(
            "playing {p}: {} Hz, {} bit, {} ch{} (Ctrl-C stops)\n",
            fmt.rate,
            fmt.bits,
            fmt.channels,
            secs.map(|s| format!(", {s} s")).unwrap_or_default()
        ));
        let mut conv = Converter::new(fmt, volume);
        let mut frames: Vec<u32> = Vec::new();
        let mut remaining = data_len;
        let mut chunk: Vec<u8> = head[data_at.min(head.len())..].to_vec();
        // a header that ran past the first block: skip what is not sample data
        let mut skip = data_at.saturating_sub(head.len());
        let mut buf = alloc::vec![0u8; 16384];
        let mut failure: Option<String> = None;
        loop {
            if skip > 0 {
                let n = skip.min(chunk.len());
                chunk.drain(..n);
                skip -= n;
            }
            if let Some(r) = remaining.as_mut() {
                if chunk.len() > *r {
                    chunk.truncate(*r);
                }
                *r -= chunk.len();
            }
            frames.clear();
            conv.convert(&chunk, &mut frames);
            player.push(&frames, &mut poll);
            if player.cancelled || remaining == Some(0) {
                break;
            }
            match read(&mut src, &mut buf, &mut poll) {
                Ok(0) => break,
                Ok(n) => {
                    chunk.clear();
                    chunk.extend_from_slice(&buf[..n]);
                }
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        finish(src);
        if let Some(e) = failure {
            player.cancel();
            return Err(format!("play: {p}: {e}"));
        }
        player.drain(&mut poll);
        let under = player.underruns();
        Ok(if player.cancelled {
            String::from("^C\n")
        } else if under > 0 {
            format!("done ({under} buffer underruns)\n")
        } else {
            String::new()
        })
    }

    /// `download URL [FILE]`: save an http:// resource under the current directory (or as FILE).
    fn download(&mut self, args: &[&str]) -> Reply {
        const USAGE: &str = "usage: download http://host[:port]/path [FILE]   (plain HTTP only; the data store holds about 5 MiB)";
        let Some(&u) = args.first() else { return Err(String::from(USAGE)) };
        let url = crate::httpc::parse_url(u).map_err(|e| format!("download: {e}"))?;
        let target = resolve(&self.cwd, args.get(1).copied().unwrap_or(&crate::httpc::file_name(&url)));
        let host_keys = self.host.keys;
        let host_idle = self.host.idle;
        let mut poll = move || {
            host_idle();
            host_keys().contains(&0x03)
        };
        self.con.print("connecting ...\n");
        let mut r = crate::httpc::get_following(&url, &mut poll).map_err(|e| format!("download: {e}"))?;
        let fd = match self.vfs.open(&target, crate::vfs::O_WRITE | crate::vfs::O_CREATE | crate::vfs::O_TRUNC) {
            Ok(fd) => fd,
            Err(e) => {
                r.close();
                return Err(format!("download: {target}: {}", errno(e)));
            }
        };
        let mut buf = alloc::vec![0u8; 16384];
        let mut total = 0u64;
        let mut last_report = 0u64;
        let mut err: Option<String> = None;
        loop {
            match r.read(&mut buf, &mut poll) {
                Ok(0) => break,
                Ok(n) => {
                    if let Err(e) = self.vfs.write(fd, &buf[..n]) {
                        err = Some(format!("{target}: {}", errno(e)));
                        break;
                    }
                    total += n as u64;
                    if total - last_report >= 256 * 1024 {
                        last_report = total;
                        let of = r.length.map(|l| format!(" of {} KiB", l / 1024)).unwrap_or_default();
                        self.con.print(&format!("  {} KiB{of}\n", total / 1024));
                    }
                }
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        let _ = self.vfs.close(fd);
        r.close();
        match err {
            Some(e) => Err(format!("download: {e} (kept {total} bytes in {target})")),
            None => Ok(format!("saved {total} bytes to {target}\n")),
        }
    }

    /// The text a tool works on: the named files, or what was piped in.
    fn text_input(&mut self, files: &[&str], stdin: Option<String>) -> Reply {
        if files.is_empty() {
            return stdin.ok_or_else(|| String::from("no input: name a file or pipe something in"));
        }
        let mut out = String::new();
        for f in files {
            let p = resolve(&self.cwd, f);
            match self.vfs.stat(&p) {
                Ok((_, size)) if size > TEXT_LIMIT => return Err(format!("{p}: too large (limit 1 MiB)")),
                Ok(_) => {}
                Err(e) => return Err(format!("{p}: {}", errno(e))),
            }
            let bytes = self.vfs.read_file(&p).map_err(|e| format!("{p}: {}", errno(e)))?;
            out.push_str(&Self::printable(&bytes));
            if !out.ends_with('\n') {
                out.push('\n');
            }
        }
        Ok(out)
    }

    fn grep(&mut self, args: &[&str], stdin: Option<String>) -> Reply {
        let (mut invert, mut count, mut icase, mut rest) = (false, false, false, Vec::new());
        for a in args {
            match *a {
                "-v" => invert = true,
                "-c" => count = true,
                "-i" => icase = true,
                _ => rest.push(*a),
            }
        }
        let Some((pat, files)) = rest.split_first() else { return Err(String::from("usage: grep [-v] [-i] [-c] pattern [file ...]")) };
        let text = self.text_input(files, stdin)?;
        let pat = if icase { pat.to_lowercase() } else { pat.to_string() };
        let hits: Vec<&str> = text.lines().filter(|l| (if icase { l.to_lowercase().contains(&pat) } else { l.contains(&pat) }) != invert).collect();
        if count {
            return Ok(format!("{}\n", hits.len()));
        }
        Ok(hits.iter().map(|l| format!("{l}\n")).collect())
    }

    fn wc(&mut self, args: &[&str], stdin: Option<String>) -> Reply {
        let lines_only = args.contains(&"-l");
        let files: Vec<&str> = args.iter().copied().filter(|a| *a != "-l").collect();
        let text = self.text_input(&files, stdin)?;
        let (l, w, b) = (text.lines().count(), text.split_whitespace().count(), text.len());
        Ok(if lines_only { format!("{l}\n") } else { format!("{l} {w} {b}\n") })
    }

    fn head_tail(&mut self, args: &[&str], stdin: Option<String>, head: bool) -> Reply {
        let (mut n, mut files, mut i) = (10usize, Vec::new(), 0);
        while i < args.len() {
            if args[i] == "-n" {
                n = args.get(i + 1).and_then(|v| v.parse().ok()).ok_or_else(|| String::from("usage: -n <count>"))?;
                i += 2;
            } else {
                files.push(args[i]);
                i += 1;
            }
        }
        let text = self.text_input(&files, stdin)?;
        let lines: Vec<&str> = text.lines().collect();
        let picked = if head { &lines[..n.min(lines.len())] } else { &lines[lines.len().saturating_sub(n)..] };
        Ok(picked.iter().map(|l| format!("{l}\n")).collect())
    }

    fn sort(&mut self, args: &[&str], stdin: Option<String>) -> Reply {
        let reverse = args.contains(&"-r");
        let files: Vec<&str> = args.iter().copied().filter(|a| *a != "-r").collect();
        let text = self.text_input(&files, stdin)?;
        let mut lines: Vec<&str> = text.lines().collect();
        lines.sort_unstable();
        if reverse {
            lines.reverse();
        }
        Ok(lines.iter().map(|l| format!("{l}\n")).collect())
    }

    fn ps(&mut self) -> String {
        const STATES: [&str; 9] = ["free", "ready", "recv", "call", "sleep", "irq", "ring", "dead", "wait"];
        let mut out = format!("{:>3} {:<11} {:<6} {}\n", "TID", "NAME", "STATE", "RESTARTS");
        for t in 0..4096u64 {
            let r = sysinfo_at(3, t);
            if r[0] as i64 != 0 {
                break; // past the last task slot
            }
            if r[3] == 0 {
                continue; // free slot
            }
            let bytes: Vec<u8> = r[1].to_le_bytes().into_iter().chain(r[2].to_le_bytes()).take_while(|&b| b != 0).collect();
            out.push_str(&format!("{t:>3} {:<11} {:<6} {}\n", String::from_utf8_lossy(&bytes), STATES[(r[3] as usize).min(8)], r[4]));
        }
        out
    }

    /// Run a program from /system/bin or /data/bin (or by path). It is started with file access and the shell as its
    /// console (a send capability in its slot 7): its output comes back as the command's output, so it can be piped and
    /// redirected; what the previous pipeline stage produced is its input, or, at the end of a pipeline, the keyboard
    /// (line by line, Ctrl-D ends the input). Ctrl-C ends the program. See docs/ABI.md for the protocol.
    fn program(&mut self, name: &str, args: &[&str], stdin: Option<String>, tty: bool) -> Reply {
        const WAIT: u64 = 25;
        const KILL: u64 = 26;
        const EP_CREATE: u64 = 27;
        const MAX_OUT: usize = 64 * 1024;
        // `program ...` is the `progctl` program with a send capability to the program manager
        let (prog, give) = if name == "prog" {
            match self.progmgr {
                Some(s) => ("progctl", Some(s)),
                None => return Err(String::from("prog: the program manager is not running")),
            }
        } else {
            (name, None)
        };
        let candidates = if prog.contains('/') {
            vec![resolve(&self.cwd, prog)]
        } else {
            vec![format!("/system/bin/{prog}"), format!("/data/bin/{prog}")]
        };
        let Some(image) = candidates.iter().find_map(|p| {
            self.vfs.read_file(p).ok().filter(|b| b.len() >= 32 && (b[..4] == [0x55, 0x53, 0x4F, 0x4D] || b[..4] == [0x7F, b'E', b'L', b'F']))
        }) else {
            return Err(format!("{name}: command not found (try help)"));
        };
        let out_slot = match self.stdout {
            Some(s) => s,
            None => {
                let r = svc(EP_CREATE, 9, 0, 0, 0, 0)[0] as i64;
                if r < 0 {
                    return Err(format!("{name}: cannot make an output channel ({r})"));
                }
                self.stdout = Some(r as u64);
                r as u64
            }
        };
        // argument block: the command line (name first), an empty string, then the environment
        let mut argblock = Vec::new();
        for a in core::iter::once(name).chain(args.iter().copied()) {
            argblock.extend_from_slice(a.as_bytes());
            argblock.push(0);
        }
        argblock.push(0);
        for e in [format!("PWD={}", self.cwd), String::from("PATH=/system/bin:/data/bin"), String::from("TERM=metallium"), String::from("HOME=/data")] {
            argblock.extend_from_slice(e.as_bytes());
            argblock.push(0);
        }
        if argblock.len() > 1024 {
            return Err(format!("{name}: arguments too long"));
        }
        let mut rq = [0u8; 96];
        rq[4..8].copy_from_slice(&3u32.to_le_bytes()); // file and network access
        rq[40..48].copy_from_slice(&(argblock.as_ptr() as u64).to_le_bytes());
        rq[48..56].copy_from_slice(&(argblock.len() as u64).to_le_bytes());
        for i in 0..8 {
            rq[64 + 4 * i] = 0xFF;
        }
        if let Some(s) = give {
            rq[64] = s as u8; // the program manager's control endpoint: send only
            rq[66..68].copy_from_slice(&1u16.to_le_bytes());
        }
        rq[64 + 4 * 7] = out_slot as u8; // the console: a send-only copy as the program's slot 7
        rq[66 + 4 * 7..68 + 4 * 7].copy_from_slice(&0b101u16.to_le_bytes()); // send, and hand it on to the programs it starts
        let mut tid = metallium_loader::spawn(|id, a1, a2, a3, a4| svc(id, a1, a2, a3, a4, 0)[0], 8, &mut rq, &image);
        if tid == -1 {
            // (no network on this machine: the program gets files only)
            rq[4..8].copy_from_slice(&1u32.to_le_bytes());
            tid = metallium_loader::spawn(|id, a1, a2, a3, a4| svc(id, a1, a2, a3, a4, 0)[0], 8, &mut rq, &image);
        }
        if tid < 0 {
            return Err(format!("{name}: cannot start ({tid})"));
        }
        let piped = stdin.is_some();
        let mut input: Vec<u8> = stdin.map(String::into_bytes).unwrap_or_default();
        let mut typed: Vec<u8> = Vec::new();
        let mut eof = piped; // a pipe ends when it is read up
        let mut want_read: Option<usize> = None;
        let mut out = Vec::new();
        let mut shown = 0usize;
        let code = loop {
            if want_read.is_none() {
                let m = svc(2, out_slot, 1, 0, 0, 0); // receive without waiting
                if m[0] as i64 == 0 {
                    let (w0, w1, w2) = (m[2], m[3], m[4]);
                    if w0 & 0xFF == 1 {
                        let n = ((w0 >> 8) & 0xFF) as usize;
                        let mut b = [0u8; 22];
                        b[..6].copy_from_slice(&(w0 >> 16).to_le_bytes()[..6]);
                        b[6..14].copy_from_slice(&w1.to_le_bytes());
                        b[14..22].copy_from_slice(&w2.to_le_bytes());
                        out.extend_from_slice(&b[..n.min(22)]);
                        reply([0, 0, 0]);
                        if out.len() > MAX_OUT {
                            svc(KILL, tid as u64, 0, 0, 0, 0);
                            out.extend_from_slice(b"\n[output cut off]\n");
                        }
                    } else if w0 & 0xFF == 3 {
                        // standard error goes to the screen at once, whatever the pipeline does with standard output
                        let n = ((w0 >> 8) & 0xFF) as usize;
                        let mut b = [0u8; 22];
                        b[..6].copy_from_slice(&(w0 >> 16).to_le_bytes()[..6]);
                        b[6..14].copy_from_slice(&w1.to_le_bytes());
                        b[14..22].copy_from_slice(&w2.to_le_bytes());
                        reply([0, 0, 0]);
                        self.con.print(&String::from_utf8_lossy(&b[..n.min(22)]));
                        self.con.flush();
                    } else if w0 & 0xFF == 2 {
                        want_read = Some((((w0 >> 8) & 0xFF) as usize).clamp(1, 23));
                    } else {
                        reply([0, 0, 0]);
                    }
                    if tty && out.len() > shown {
                        let text = String::from_utf8_lossy(&out[shown..]).into_owned();
                        shown = out.len();
                        self.con.print(&text);
                        self.con.flush();
                    }
                    continue;
                }
            }
            if let Some(max) = want_read {
                if !input.is_empty() || eof {
                    let n = input.len().min(max);
                    let chunk: Vec<u8> = input.drain(..n).collect();
                    let mut b = [0u8; 23];
                    b[..n].copy_from_slice(&chunk);
                    reply([n as u64 | u64::from_le_bytes(b[0..8].try_into().unwrap()) << 8 & !0xFF, u64::from_le_bytes(b[7..15].try_into().unwrap()), u64::from_le_bytes(b[15..23].try_into().unwrap())]);
                    want_read = None;
                    continue;
                }
            }
            let w = svc(WAIT, tid as u64, 1, 0, 0, 0)[0] as i64;
            if w != -10 {
                break w as u64;
            }
            // still running: the keyboard feeds its input, Ctrl-C ends it
            {
                for k in (self.host.keys)() {
                    match k {
                        0x03 => {
                            svc(KILL, tid as u64, 0, 0, 0, 0);
                            self.con.print("^C\n");
                        }
                        0x04 if !piped => {
                            // Ctrl-D: what was typed on the line is delivered, then the input ends
                            input.extend_from_slice(&typed);
                            typed.clear();
                            eof = true;
                        }
                        b'\n' if !piped => {
                            typed.push(b'\n');
                            input.extend_from_slice(&typed);
                            typed.clear();
                            self.con.put(b'\n');
                        }
                        K_BACKSPACE if !piped => {
                            if typed.pop().is_some() {
                                self.con.backspace();
                            }
                        }
                        0x20..=0x7E if !piped => {
                            typed.push(k);
                            self.con.put(k);
                        }
                        _ => {}
                    }
                }
            }
            if tty && out.len() > shown {
                let text = String::from_utf8_lossy(&out[shown..]).into_owned();
                shown = out.len();
                self.con.print(&text);
            }
            self.con.flush();
            (self.host.idle)(); // (the console draws a frame and sleeps a tick)
        };
        let mut text = String::from_utf8_lossy(&out[if tty { shown } else { 0 }..]).into_owned();
        let note = match code {
            0 => String::new(),
            u64::MAX => format!("[{name}: crashed]\n"),
            c if c == u64::MAX - 1 => format!("[{name}: killed]\n"),
            c => format!("[{name}: exit code {c}]\n"),
        };
        if !note.is_empty() {
            let at_line_start = if tty { out.last().map_or(true, |&b| b == b'\n') } else { text.is_empty() || text.ends_with('\n') };
            if !at_line_start {
                text.push('\n');
            }
            text.push_str(&note);
        }
        Ok(text)
    }

    fn stat(&mut self, args: &[&str]) -> Reply {
        let Some(a) = args.first() else { return Err(String::from("usage: stat <path>")) };
        let p = resolve(&self.cwd, a);
        match self.vfs.stat(&p) {
            Ok((1, size)) => Ok(format!("{p}: file, {size} bytes\n")),
            Ok(_) => Ok(format!("{p}: directory\n")),
            Err(e) => Err(format!("stat: {p}: {}", errno(e))),
        }
    }

    fn simple(&mut self, args: &[&str], name: &str, op: impl Fn(&Vfs, &str) -> Result<(), i64>) -> Reply {
        let Some(a) = args.first() else { return Err(format!("usage: {name} <path>")) };
        let p = resolve(&self.cwd, a);
        op(&self.vfs, &p).map(|_| String::new()).map_err(|e| format!("{name}: {p}: {}", errno(e)))
    }

    /// One typed character (the console delivers what the keyboard produced while this window had the focus).
    pub fn typed(&mut self, b: u8) {
        self.key(b);
        self.con.flush();
    }
}

/// Answer the program whose output call was just received.
fn call_reply() {
    reply([0, 0, 0]);
}

fn errno(e: i64) -> &'static str {
    use crate::vfs::*;
    match e as u64 {
        ENOENT => "no such file or directory",
        EISDIR => "wrong kind of object",
        EBADF => "bad file descriptor",
        EROFS => "read-only file system",
        ENOSPC => "no space left",
        EINVAL => "invalid argument",
        EEXIST => "already exists",
        ENOTEMPTY => "directory not empty",
        _ if e == E_DEAD => "the file system service is restarting, try again",
        _ => "I/O error",
    }
}

/// What the display and the storage are called, as the kernel's platform says (an older kernel that has no such page: the QEMU devices).
fn device_names() -> (String, String) {
    let r = sysinfo(19);
    if r[0] as i64 != 0 {
        return (String::from("virtio-gpu"), String::from("virtio-blk"));
    }
    let name = |a: u64, b: u64| {
        let bytes: alloc::vec::Vec<u8> = a.to_le_bytes().iter().chain(b.to_le_bytes().iter()).copied().take_while(|&c| c != 0).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    };
    (name(r[1], r[2]), name(r[3], r[4]))
}

/// Why there is no IOMMU on this machine (the kernel's platform says; an older kernel: nothing more than "none").
fn iommu_note() -> String {
    let r = sysinfo(20);
    if r[0] as i64 != 0 {
        return String::from("not used by this kernel");
    }
    let bytes: alloc::vec::Vec<u8> = r[1..5].iter().flat_map(|w| w.to_le_bytes()).take_while(|&c| c != 0).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
