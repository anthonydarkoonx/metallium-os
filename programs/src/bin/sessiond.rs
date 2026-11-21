#![no_std]
#![no_main]
extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use metallium_programs::ipc::{self, Endpoint};
use metallium_programs::process::{Child, Command};
use metallium_programs::*;

// The session service (docs/MULTIUSER-PLAN.md). It keeps the accounts and starts a user's session confined to the user's home.
//
// Slot 0: its control endpoint (receive; whoever holds the send right is the greeter), slot 5: the endpoint factory, slot 6: the spawn capability (with file access),
// slot 4: the data store's endpoint (the right to create, unlock and lock encryption domains). Accounts are lines `uid:name:role` in `/data/accounts`, which only this program
// (unconfined) can see; there is no credential in them. A user's credential is the key slot of the user's encryption *domain* in the data store (domain = uid): logging in means
// unlocking the domain with the passphrase, and everything the user's session writes under `/data/home/<name>` is sealed under that domain's key; logging out locks it
// again, so the files of a user who is not logged in cannot be read by anyone, this program and the administrator included. A recovery key (shown once, when the account is
// made) opens the domain too and is how a forgotten passphrase is replaced.
//
// Protocol (three words a message): `BEGIN` names the action and the user, then the secret follows in chunks of 16 bytes (as for the data volume's lock):
//   BEGIN  w0 = 1 | action << 8 | role << 16 | acting session << 32, w1 w2 = the user name (up to 16 bytes, NUL padded)
//   SECRET w0 = 2 | total length << 8 | offset << 24, w1 w2 = 16 bytes of the secret at `offset`; the last chunk runs the action
//   LOGOUT w0 = 3, w1 = session id
//   STATUS w0 = 4 -> [number of users, number of sessions, 0]
//   ACTIVE w0 = 5 -> [OK | session id << 8, w1 w2 = the user name (16 bytes, NUL padded)] of the newest live session, or [E_BAD, 0, 0] if there is none: the screen task asks it
//          after the greeter returns, to learn whose session has the screen (until each session has its own screen, the newest login has it)
// Actions: CREATE (secret: the passphrase; reply w0 = status | uid << 8, w1 w2 = the recovery key: show it once), LOGIN (the passphrase; reply w1 = the session id),
// RESET (the 16 recovery-key bytes: opens the account's domain for a following SETPASS), SETPASS (the new passphrase: after a RESET, or by the user's own session `acting`).
const OP_BEGIN: u64 = 1;
const OP_SECRET: u64 = 2;
const OP_LOGOUT: u64 = 3;
const OP_STATUS: u64 = 4;
const OP_ACTIVE: u64 = 5;
const ACT_CREATE: u64 = 1;
const ACT_LOGIN: u64 = 2;
const ACT_RESET: u64 = 3;
const ACT_SETPASS: u64 = 4;

const OK: u64 = 0;
const E_BAD: u64 = 1; // malformed request, or a name that is not allowed
const E_EXISTS: u64 = 2; // CREATE: the name is taken
const E_MORE: u64 = 4; // SECRET: send the next chunk
const E_DENIED: u64 = 5; // CREATE: the acting session is not an admin's (once there is an admin)
const E_FAILED: u64 = 6; // storage or start failure
const E_LOGIN: u64 = 7; // LOGIN: no such user or wrong passphrase (one answer for both: no way to find out which names exist)
const E_BUSY: u64 = 8; // LOGIN: that user already has a session

/// Files and directories a home may hold (the account holder's own quota; programs under it have theirs, never more).
const HOME_QUOTA: u64 = 64;

const R_SPAWN: u16 = 1 << 12;
const R_SPAWN_FS: u16 = 1 << 13;
const R_EP_CREATE: u16 = 1 << 14;
const FACTORY: u8 = 5;
const SPAWN: u8 = 6;
const STORE: Endpoint = Endpoint(4);

// the data store's domain calls (`proto::volume`)
const LFS_DOMAIN_CREATE: u64 = 123;
const LFS_DOMAIN_UNLOCK: u64 = 124;
const LFS_DOMAIN_LOCK: u64 = 125;
const LFS_DOMAIN_SET_PASSPHRASE: u64 = 127;
/// Accounts are numbered 1..=63: the number is the encryption domain.
const MAX_UID: u32 = 63;

struct Account {
    uid: u32,
    name: String,
    admin: bool,
}

struct Session {
    id: u64,
    uid: u32,
    name: String,
    child: Child,
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 16 && n.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_') && n.as_bytes()[0].is_ascii_lowercase()
}

/// What a login for a name that does not exist costs the same as one that does (the answer is not faster): the store's key derivation, done here for nothing.
fn dummy_work(pass: &[u8]) {
    let mut h = [0u8; 32];
    metallium_crypt::pbkdf2_hmac_sha512(pass, &[0u8; 16], 100_000, &mut h);
}

/// A call to the store's domain calls with a secret in chunks; the store's last reply.
fn store_call(op: u64, domain: u32, kind: u64, secret: &[u8]) -> [u64; 3] {
    let mut last = [E_FAILED, 0, 0];
    // (a call without a secret, LOCK, is one message)
    for off in (0..secret.len().max(1)).step_by(16) {
        let mut chunk = [0u8; 16];
        let n = (secret.len() - off).min(16);
        chunk[..n].copy_from_slice(&secret[off..off + n]);
        let w0 = op | (domain as u64) << 8 | (secret.len() as u64) << 16 | (off as u64) << 32 | kind << 48;
        match STORE.call([w0, u64::from_le_bytes(chunk[..8].try_into().unwrap()), u64::from_le_bytes(chunk[8..].try_into().unwrap())]) {
            Ok(r) => last = r,
            Err(_) => return [E_FAILED, 0, 0],
        }
        if last[0] != 4 {
            break;
        }
    }
    last
}

struct Svc {
    accounts: Vec<Account>,
    sessions: Vec<Session>,
    next_session: u64,
    /// The request being assembled: (action, role, acting session, name, secret so far).
    pending: Option<(u64, bool, u64, String, Vec<u8>)>,
    /// The account whose domain a recovery key has just opened (a SETPASS must follow).
    resetting: Option<u32>,
}

impl Svc {
    fn load() -> Vec<Account> {
        let mut v = Vec::new();
        let Ok(t) = fs::read_to_string("/data/accounts") else { return v };
        for line in t.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() != 3 {
                continue;
            }
            if let (Ok(uid), Ok(role)) = (f[0].parse::<u32>(), f[2].parse::<u8>()) {
                v.push(Account { uid, name: String::from(f[1]), admin: role == 1 });
            }
        }
        v
    }

    fn save(&self) -> bool {
        let mut t = String::new();
        for a in &self.accounts {
            t.push_str(&format!("{}:{}:{}\n", a.uid, a.name, a.admin as u8));
        }
        fs::write("/data/accounts", t.as_bytes()).is_ok() && fs::sync().is_ok()
    }

    fn create(&mut self, name: &str, want_admin: bool, acting: u64, pass: &[u8]) -> [u64; 3] {
        if !valid_name(name) || pass.is_empty() {
            return [E_BAD, 0, 0];
        }
        if self.accounts.iter().any(|a| a.name == name) {
            return [E_EXISTS, 0, 0];
        }
        // the first account is the administrator's; after that only an admin's live session may add accounts
        let first = self.accounts.is_empty();
        if !first {
            let by_admin = self.sessions.iter().any(|s| s.id == acting && self.accounts.iter().any(|a| a.uid == s.uid && a.admin));
            if !by_admin {
                return [E_DENIED, 0, 0];
            }
        }
        let uid = self.accounts.iter().map(|a| a.uid + 1).max().unwrap_or(1);
        if uid > MAX_UID {
            return [E_FAILED, 0, 0];
        }
        // the account's encryption domain, with its passphrase and a recovery key
        let r = store_call(LFS_DOMAIN_CREATE, uid, 1, pass);
        if r[0] != 0 {
            return [E_FAILED, 0, 0];
        }
        let recovery = [r[1], r[2]];
        let _ = fs::create_dir("/data/home");
        if fs::create_dir_in_domain(&format!("/data/home/{name}"), uid as u64).is_err() {
            let _ = store_call(LFS_DOMAIN_LOCK, uid, 0, &[]);
            return [E_FAILED, 0, 0];
        }
        self.accounts.push(Account { uid, name: String::from(name), admin: first || want_admin });
        if !self.save() {
            self.accounts.pop();
            return [E_FAILED, 0, 0];
        }
        let _ = store_call(LFS_DOMAIN_LOCK, uid, 0, &[]); // (made unlocked; it opens at the first login)
        println!("[sessiond] account {name} created (uid {uid}{})", if first { ", the administrator" } else { "" });
        [OK | (uid as u64) << 8, recovery[0], recovery[1]]
    }

    fn login(&mut self, name: &str, pass: &[u8]) -> [u64; 3] {
        let Some(a) = self.accounts.iter().find(|a| a.name == name) else {
            dummy_work(pass);
            return [E_LOGIN, 0, 0];
        };
        let (uid, name) = (a.uid, a.name.clone());
        if self.sessions.iter().any(|s| s.uid == uid) {
            return [E_BUSY, 0, 0];
        }
        // the credential is the domain's key slot: right means the domain is open
        if store_call(LFS_DOMAIN_UNLOCK, uid, 1, pass)[0] != 0 {
            return [E_LOGIN, 0, 0];
        }
        // the session: a program confined to the user's home (`/data` is `/data/home/<name>`), with a quota; the programs it starts are confined to the same directory
        let home = format!("/data/home/{name}");
        let mut cmd = Command::new("homeprobe");
        cmd.arg(&name).arg("probe").files(true).scope(&home).quota(HOME_QUOTA);
        cmd.give(FACTORY, 5, R_EP_CREATE).give(SPAWN, 6, R_SPAWN | R_SPAWN_FS).budget_pages(1000);
        let Ok(child) = cmd.spawn() else {
            let _ = store_call(LFS_DOMAIN_LOCK, uid, 0, &[]);
            return [E_FAILED, 0, 0];
        };
        self.next_session += 1;
        let id = self.next_session;
        println!("[sessiond] {name} logged in: session {id} (task {})", child.id());
        self.sessions.push(Session { id, uid, name: name.clone(), child });
        [OK, id, 0]
    }

    /// RESET: the recovery key opens the account's domain, for a SETPASS that follows.
    fn reset(&mut self, name: &str, key: &[u8]) -> [u64; 3] {
        let Some(a) = self.accounts.iter().find(|a| a.name == name) else {
            dummy_work(key);
            return [E_LOGIN, 0, 0];
        };
        let uid = a.uid;
        if key.len() != 16 || self.sessions.iter().any(|s| s.uid == uid) {
            return [E_BAD, 0, 0];
        }
        if store_call(LFS_DOMAIN_UNLOCK, uid, 3, key)[0] != 0 {
            return [E_LOGIN, 0, 0];
        }
        self.resetting = Some(uid);
        [OK, 0, 0]
    }

    /// SETPASS: a new passphrase for the account being reset, or for the account of the acting session.
    fn setpass(&mut self, acting: u64, pass: &[u8]) -> [u64; 3] {
        if pass.is_empty() {
            return [E_BAD, 0, 0];
        }
        let (uid, via_reset) = match (self.resetting, self.sessions.iter().find(|s| s.id == acting)) {
            (Some(u), _) => (u, true),
            (None, Some(s)) => (s.uid, false),
            _ => return [E_DENIED, 0, 0],
        };
        let r = store_call(LFS_DOMAIN_SET_PASSPHRASE, uid, 1, pass);
        if via_reset {
            self.resetting = None;
            let _ = store_call(LFS_DOMAIN_LOCK, uid, 0, &[]); // (the next thing is a login with the new passphrase)
        }
        [if r[0] == 0 { OK } else { E_FAILED }, 0, 0]
    }

    fn logout(&mut self, id: u64) -> [u64; 3] {
        let Some(i) = self.sessions.iter().position(|s| s.id == id) else { return [E_BAD, 0, 0] };
        let s = self.sessions.remove(i);
        let _ = s.child.kill();
        let _ = fs::sync();
        let _ = store_call(LFS_DOMAIN_LOCK, s.uid, 0, &[]); // the user's files are sealed again
        println!("[sessiond] session {id} ended");
        [OK, 0, 0]
    }

    fn request(&mut self, w: [u64; 3]) -> [u64; 3] {
        match w[0] & 0xFF {
            OP_BEGIN => {
                let mut raw = [0u8; 16];
                raw[..8].copy_from_slice(&w[1].to_le_bytes());
                raw[8..].copy_from_slice(&w[2].to_le_bytes());
                let n = raw.iter().position(|&c| c == 0).unwrap_or(16);
                let Ok(name) = core::str::from_utf8(&raw[..n]) else { return [E_BAD, 0, 0] };
                let action = (w[0] >> 8) & 0xFF;
                if !matches!(action, ACT_CREATE | ACT_LOGIN | ACT_RESET | ACT_SETPASS) {
                    return [E_BAD, 0, 0];
                }
                self.pending = Some((action, (w[0] >> 16) & 0xFF == 1, (w[0] >> 32) & 0xFFFF_FFFF, String::from(name), Vec::new()));
                [OK, 0, 0]
            }
            OP_SECRET => {
                let (total, offset) = (((w[0] >> 8) & 0xFFFF) as usize, ((w[0] >> 24) & 0xFFFF) as usize);
                let Some((action, admin, acting, name, mut secret)) = self.pending.take() else { return [E_BAD, 0, 0] };
                if total == 0 || total > 128 || offset != secret.len() || offset % 16 != 0 || offset >= total {
                    self.pending = None;
                    return [E_BAD, 0, 0];
                }
                let mut chunk = [0u8; 16];
                chunk[..8].copy_from_slice(&w[1].to_le_bytes());
                chunk[8..].copy_from_slice(&w[2].to_le_bytes());
                secret.extend_from_slice(&chunk[..(total - offset).min(16)]);
                if secret.len() < total {
                    self.pending = Some((action, admin, acting, name, secret));
                    return [E_MORE, 0, 0];
                }
                let r = match action {
                    ACT_CREATE => self.create(&name, admin, acting, &secret),
                    ACT_LOGIN => self.login(&name, &secret),
                    ACT_RESET => self.reset(&name, &secret),
                    _ => self.setpass(acting, &secret),
                };
                secret.iter_mut().for_each(|b| *b = 0);
                r
            }
            OP_LOGOUT => self.logout(w[1]),
            OP_STATUS => [self.accounts.len() as u64, self.sessions.len() as u64, 0],
            OP_ACTIVE => match self.sessions.last() {
                Some(s) => {
                    let mut raw = [0u8; 16];
                    raw[..s.name.len().min(16)].copy_from_slice(&s.name.as_bytes()[..s.name.len().min(16)]);
                    [OK | s.id << 8, u64::from_le_bytes(raw[..8].try_into().unwrap()), u64::from_le_bytes(raw[8..].try_into().unwrap())]
                }
                None => [E_BAD, 0, 0],
            },
            _ => [E_BAD, 0, 0],
        }
    }
}

program!("sessiond", |_c| {
    process::set_capabilities(SPAWN as u64, FACTORY as u64);
    let mut svc = Svc { accounts: Svc::load(), sessions: Vec::new(), next_session: 0, pending: None, resetting: None };
    println!("[sessiond] up: {} account(s)", svc.accounts.len());
    let ctl = Endpoint(0);
    loop {
        match ctl.recv() {
            Ok(r) => {
                let rep = svc.request(r.words);
                if r.is_call {
                    let _ = ipc::reply(rep);
                }
            }
            Err(_) => return 0,
        }
    }
});
