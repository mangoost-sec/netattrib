//! Background enrichment: process owner (token SID + account), and optionally the image's
//! hash and Authenticode signature.
//!
//! Runs off the capture path because `LookupAccountSidW` can block on a domain controller,
//! and hashing and signature checks read whole binaries. File work runs on a second thread,
//! so a large binary never delays the account lookups the GUI's User/System scope needs.
//! Results land in the process's `OnceLock` slots and are picked up by the output layer and
//! the GUI when they next read them.

use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::SystemTime;

use super::hash::Sha256Provider;
use super::query::{self, UserInfo};
use super::signature::{self, Signature};
use super::Process;

const SYSTEM_SID: &str = "S-1-5-18";

/// `hash`: SHA-256 of every image (`--hash`). `verify`: Authenticode status (the GUI).
pub fn spawn(rx: Receiver<Arc<Process>>, hash: bool, verify: bool) -> JoinHandle<()> {
    let files = (hash || verify).then(|| {
        let (tx, files_rx) = channel();
        std::thread::Builder::new()
            .name("enrich-files".into())
            .spawn(move || run_files(files_rx, hash, verify))
            .expect("spawn enrich-files thread");
        tx
    });
    std::thread::Builder::new()
        .name("enrich".into())
        .spawn(move || run(rx, files))
        .expect("spawn enrich thread")
}

fn run(rx: Receiver<Arc<Process>>, files: Option<Sender<Arc<Process>>>) {
    let mut accounts: HashMap<String, Option<String>> = HashMap::new();
    while let Ok(p) = rx.recv() {
        let user = resolve_user(&p, &mut accounts);
        let _ = p.user.set(user);
        if let Some(tx) = &files {
            let _ = tx.send(p);
        }
    }
}

/// Per image path (lower-cased): the file's `(len, mtime)` when the result was computed, so a
/// binary replaced in place (an update) is checked again.
type FileCache<T> = HashMap<String, (u64, SystemTime, T)>;

fn run_files(rx: Receiver<Arc<Process>>, hash: bool, verify: bool) {
    let provider = if hash { Sha256Provider::open() } else { None };
    let mut hashes: FileCache<Option<String>> = HashMap::new();
    let mut signatures: FileCache<Option<Signature>> = HashMap::new();
    while let Ok(p) = rx.recv() {
        // Signatures first: the GUI flags unsigned processes as soon as they are known.
        if verify {
            let sig = cached(&p, &mut signatures, signature::verify);
            let _ = p.signature.set(sig);
        }
        if let Some(prov) = &provider {
            let digest = cached(&p, &mut hashes, |path| prov.hash_file(path).ok());
            let _ = p.sha256.set(digest);
        }
    }
}

fn cached<T: Clone>(
    p: &Process,
    cache: &mut FileCache<Option<T>>,
    compute: impl FnOnce(&str) -> Option<T>,
) -> Option<T> {
    if p.path.is_empty() {
        return None;
    }
    let meta = std::fs::metadata(&p.path).ok()?;
    let (len, mtime) = (meta.len(), meta.modified().ok()?);
    if let Some((l, m, v)) = cache.get(&p.key) {
        if *l == len && *m == mtime {
            return v.clone();
        }
    }
    let v = compute(&p.path);
    cache.insert(p.key.clone(), (len, mtime, v.clone()));
    v
}

fn resolve_user(p: &Process, accounts: &mut HashMap<String, Option<String>>) -> Option<UserInfo> {
    if p.pid == 0 || p.pid == 4 {
        return Some(UserInfo {
            sid: SYSTEM_SID.into(),
            account: Some("NT AUTHORITY\\SYSTEM".into()),
        });
    }
    if !p.is_alive() {
        return None;
    }
    let h = query::open_limited(p.pid)?;
    // Never read the token of a different instance that recycled the PID.
    if p.create_time != 0 && query::create_time_of(&h) != Some(p.create_time) {
        return None;
    }
    query::token_user(&h, accounts)
}
