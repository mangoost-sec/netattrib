//! Process identity tracking with PID-reuse protection.
//!
//! A PID alone is not an identity: Windows recycles PIDs as soon as the last handle to an
//! exited process closes. Every process is therefore tracked as a *generation*
//! `(pid, create_time)`, and network events are bound to the generation that was alive at
//! the event's timestamp:
//!
//! ```text
//!   pid 4512:  [gen A: created t0 ........ exited t5]   [gen B: created t7 ......>
//!   event(pid 4512, t3) -> A        event(pid 4512, t8) -> B
//!   event(pid 4512, t6) -> neither (A dead, B not yet born) -> deferred, then "exited"
//! ```
//!
//! Generations come from the startup snapshot, ETW `Microsoft-Windows-Kernel-Process`
//! start/stop events, or (polling mode) a per-cycle snapshot. Exited generations are kept
//! for a grace period so late events still attribute correctly.

pub mod enrich;
pub mod hash;
pub mod query;
pub mod services;
pub mod signature;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, OnceLock};

use crate::filter::Filter;
use crate::model::Attribution;
use crate::util::{FileTime, TICKS_PER_MS, TICKS_PER_SEC};
use query::SnapEntry;
pub use query::UserInfo;
use signature::Signature;

/// Tolerance between the kernel's CreateTime and ETW event timestamps.
const CREATE_SKEW: u64 = 10 * TICKS_PER_MS;
/// Window after exit during which a *new* flow may still be attributed to a dead process.
const EXIT_GRACE: u64 = 500 * TICKS_PER_MS;
/// How long exited generations are retained once nothing references them.
const RETAIN_EXITED: u64 = 120 * TICKS_PER_SEC;

pub struct Process {
    pub pid: u32,
    pub ppid: u32,
    /// Kernel creation time (FILETIME); 0 for the Idle/System pseudo-processes or unknown.
    pub create_time: FileTime,
    exit_time: AtomicU64,
    pub name: String,
    /// Full normalized DOS path; empty when it could not be determined.
    pub path: String,
    /// Aggregation key: lower-cased path, or lower-cased name when the path is unknown.
    pub key: String,
    pub session_id: u32,
    pub included: bool,
    pub attribution: Attribution,
    /// Filled asynchronously by the enrichment worker: `Some(None)` = tried and denied.
    pub user: OnceLock<Option<UserInfo>>,
    pub sha256: OnceLock<Option<String>>,
    /// Authenticode status of the image (GUI only); `Some(None)` = the file could not be read.
    pub signature: OnceLock<Option<Signature>>,
}

impl Process {
    pub fn exit_time(&self) -> Option<FileTime> {
        match self.exit_time.load(Ordering::Relaxed) {
            0 => None,
            t => Some(t),
        }
    }

    pub fn mark_exited(&self, t: FileTime) {
        let _ = self
            .exit_time
            .compare_exchange(0, t.max(1), Ordering::Relaxed, Ordering::Relaxed);
    }

    pub fn is_alive(&self) -> bool {
        self.exit_time.load(Ordering::Relaxed) == 0
    }

    pub fn user_info(&self) -> Option<&UserInfo> {
        self.user.get().and_then(|u| u.as_ref())
    }

    pub fn sha256(&self) -> Option<&str> {
        self.sha256.get().and_then(|h| h.as_deref())
    }

    pub fn signature(&self) -> Option<&Signature> {
        self.signature.get().and_then(|s| s.as_ref())
    }
}

pub struct Seed {
    pub pid: u32,
    pub ppid: u32,
    pub create_time: FileTime,
    pub session_id: u32,
    pub name: String,
    pub path: String,
    pub attribution: Attribution,
    pub exit_time: Option<FileTime>,
}

pub struct ProcessTable {
    by_pid: HashMap<u32, Vec<Arc<Process>>>,
    filter: Filter,
    enrich: Sender<Arc<Process>>,
}

fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

impl ProcessTable {
    pub fn new(filter: Filter, enrich: Sender<Arc<Process>>) -> Self {
        ProcessTable {
            by_pid: HashMap::with_capacity(1024),
            filter,
            enrich,
        }
    }

    /// Bulk-load the startup snapshot. Sorting by creation time guarantees every parent is
    /// inserted before its children, so `--tree` inheritance resolves in a single pass.
    pub fn load_snapshot(&mut self, mut snap: Vec<SnapEntry>) {
        snap.sort_by_key(|e| e.create_time);
        for e in snap {
            let seed = seed_from_snapshot(&e);
            self.insert(seed);
        }
    }

    /// Polling-mode reconciliation: marks generations that vanished from the snapshot as
    /// exited and inserts new ones.
    pub fn reconcile(&mut self, snap: &[SnapEntry], now: FileTime) {
        let live: HashMap<u32, FileTime> = snap.iter().map(|e| (e.pid, e.create_time)).collect();
        for (pid, gens) in &self.by_pid {
            for g in gens.iter().filter(|g| g.is_alive()) {
                if g.create_time != 0 && live.get(pid) != Some(&g.create_time) {
                    g.mark_exited(now);
                }
            }
        }
        let mut fresh: Vec<&SnapEntry> = snap
            .iter()
            .filter(|e| {
                !self
                    .by_pid
                    .get(&e.pid)
                    .is_some_and(|gens| gens.iter().any(|g| g.create_time == e.create_time))
            })
            .collect();
        fresh.sort_by_key(|e| e.create_time);
        for e in fresh {
            let seed = seed_from_snapshot(e);
            self.insert(seed);
        }
    }

    pub fn insert(&mut self, seed: Seed) -> Arc<Process> {
        if let Some(existing) = self.find_exact(seed.pid, seed.create_time) {
            if let Some(t) = seed.exit_time {
                existing.mark_exited(t);
            }
            return existing;
        }
        // A new generation implies every older generation of this PID is dead.
        if let Some(gens) = self.by_pid.get(&seed.pid) {
            for g in gens {
                if g.create_time < seed.create_time {
                    g.mark_exited(seed.create_time);
                }
            }
        }
        let name_lc = seed.name.to_lowercase();
        let path_lc = seed.path.to_lowercase();
        // netattrib never reports itself (its own PTR lookups would only add noise).
        let included = seed.pid != std::process::id()
            && (self
                .filter
                .matches(seed.pid, seed.create_time, &name_lc, &path_lc)
                || (self.filter.tree && self.parent_included(seed.ppid, seed.create_time)));
        let key = if path_lc.is_empty() { name_lc } else { path_lc };
        let p = Arc::new(Process {
            pid: seed.pid,
            ppid: seed.ppid,
            create_time: seed.create_time,
            exit_time: AtomicU64::new(seed.exit_time.unwrap_or(0)),
            name: seed.name,
            path: seed.path,
            key,
            session_id: seed.session_id,
            included,
            attribution: seed.attribution,
            user: OnceLock::new(),
            sha256: OnceLock::new(),
            signature: OnceLock::new(),
        });
        let gens = self.by_pid.entry(p.pid).or_default();
        let pos = gens.partition_point(|g| g.create_time <= p.create_time);
        gens.insert(pos, p.clone());
        if included {
            let _ = self.enrich.send(p.clone());
        }
        p
    }

    fn find_exact(&self, pid: u32, create_time: FileTime) -> Option<Arc<Process>> {
        self.by_pid
            .get(&pid)?
            .iter()
            .find(|g| g.create_time == create_time)
            .cloned()
    }

    fn parent_included(&self, ppid: u32, child_created: FileTime) -> bool {
        // The parent must predate the child, otherwise the PPID was recycled.
        self.by_pid
            .get(&ppid)
            .and_then(|gens| gens.iter().rev().find(|g| g.create_time <= child_created))
            .is_some_and(|g| g.included)
    }

    pub fn on_exit(&mut self, pid: u32, create_time: FileTime, ts: FileTime, short_name: &str) {
        if let Some(p) = self.find_exact(pid, create_time) {
            p.mark_exited(ts);
            return;
        }
        // Started before monitoring and missed by the snapshot race: record what the stop
        // event tells us so in-flight events still get a name.
        self.insert(Seed {
            pid,
            ppid: 0,
            create_time,
            session_id: 0,
            name: short_name.to_string(),
            path: String::new(),
            attribution: Attribution::Exited,
            exit_time: Some(ts),
        });
    }

    /// The generation of `pid` alive at `ts`, if known.
    pub fn lookup(&self, pid: u32, ts: FileTime) -> Option<Arc<Process>> {
        let gens = self.by_pid.get(&pid)?;
        for g in gens.iter().rev() {
            if g.create_time <= ts + CREATE_SKEW {
                return match g.exit_time() {
                    None => Some(g.clone()),
                    Some(exit) if ts <= exit + EXIT_GRACE => Some(g.clone()),
                    // Event postdates this instance's death and no newer instance is known.
                    Some(_) => None,
                };
            }
        }
        None
    }

    /// Lookup, falling back to an on-demand query that still refuses to bind an event to a
    /// process created *after* it (the PID-reuse race).
    pub fn resolve(&mut self, pid: u32, ts: FileTime) -> Arc<Process> {
        if let Some(p) = self.lookup(pid, ts) {
            return p;
        }
        if let Some(h) = query::open_limited(pid) {
            if let Some(ct) = query::create_time_of(&h) {
                if ct <= ts + CREATE_SKEW {
                    let path = query::image_path(pid, Some(&h)).unwrap_or_default();
                    let name = if path.is_empty() {
                        format!("pid{}", pid)
                    } else {
                        file_name(&path).to_string()
                    };
                    let ppid = query::snapshot()
                        .ok()
                        .and_then(|s| s.into_iter().find(|e| e.pid == pid).map(|e| e.ppid))
                        .unwrap_or(0);
                    return self.insert(Seed {
                        pid,
                        ppid,
                        create_time: ct,
                        session_id: 0,
                        name,
                        path,
                        attribution: Attribution::Inferred,
                        exit_time: None,
                    });
                }
            }
        } else if let Ok(snap) = query::snapshot() {
            // Handle denied (protected / other session): the snapshot still has creation time.
            if let Some(e) = snap
                .iter()
                .find(|e| e.pid == pid && e.create_time <= ts + CREATE_SKEW)
            {
                let mut seed = seed_from_snapshot(e);
                seed.attribution = Attribution::Inferred;
                return self.insert(seed);
            }
        }
        // Owner is gone (or the PID now belongs to a younger process): placeholder.
        self.insert(Seed {
            pid,
            ppid: 0,
            create_time: ts.saturating_sub(1),
            session_id: 0,
            name: "<exited>".into(),
            path: String::new(),
            attribution: Attribution::Exited,
            exit_time: Some(ts),
        })
    }

    /// Drops exited generations that are old and no longer referenced by any flow.
    pub fn gc(&mut self, now: FileTime) {
        self.by_pid.retain(|_, gens| {
            gens.retain(|g| match g.exit_time() {
                Some(t) => now.saturating_sub(t) < RETAIN_EXITED || Arc::strong_count(g) > 1,
                None => true,
            });
            !gens.is_empty()
        });
    }

    /// The live generation of every PID (at most one per PID).
    pub fn alive(&self) -> Vec<Arc<Process>> {
        self.by_pid
            .values()
            .filter_map(|g| g.last().filter(|p| p.is_alive()).cloned())
            .collect()
    }

    pub fn alive_count(&self) -> usize {
        self.by_pid
            .values()
            .filter(|g| g.last().is_some_and(|p| p.is_alive()))
            .count()
    }
}

fn seed_from_snapshot(e: &SnapEntry) -> Seed {
    let (name, path) = match e.pid {
        0 => ("System Idle Process".to_string(), String::new()),
        4 => ("System".to_string(), String::new()),
        pid => {
            let h = query::open_limited(pid);
            // Verify the handle refers to the same instance as the snapshot entry.
            let h = h.filter(|h| query::create_time_of(h) == Some(e.create_time));
            let path = query::image_path(pid, h.as_ref()).unwrap_or_default();
            let path = if path.contains('\\') {
                path
            } else {
                String::new()
            };
            let name = if e.name.is_empty() {
                file_name(&path).to_string()
            } else {
                e.name.clone()
            };
            (name, path)
        }
    };
    Seed {
        pid: e.pid,
        ppid: e.ppid,
        create_time: e.create_time,
        session_id: e.session_id,
        name,
        path,
        attribution: Attribution::Exact,
        exit_time: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;

    fn seed(pid: u32, ct: FileTime, name: &str) -> Seed {
        Seed {
            pid,
            ppid: 0,
            create_time: ct,
            session_id: 1,
            name: name.into(),
            path: format!("C:\\bin\\{}", name),
            attribution: Attribution::Exact,
            exit_time: None,
        }
    }

    #[test]
    fn pid_reuse_is_resolved_by_generation() {
        let (tx, _rx) = channel();
        let mut t = ProcessTable::new(Filter::default(), tx);
        let s = TICKS_PER_SEC;
        t.insert(seed(4512, 10 * s, "winword.exe"));
        t.on_exit(4512, 10 * s, 20 * s, "WINWORD.EXE");
        t.insert(seed(4512, 30 * s, "evil.exe"));

        assert_eq!(t.lookup(4512, 15 * s).unwrap().name, "winword.exe");
        // Within the exit grace window the dead instance still owns late events.
        assert_eq!(
            t.lookup(4512, 20 * s + 100 * TICKS_PER_MS).unwrap().name,
            "winword.exe"
        );
        // Between death and rebirth nobody owns the PID.
        assert!(t.lookup(4512, 25 * s).is_none());
        assert_eq!(t.lookup(4512, 31 * s).unwrap().name, "evil.exe");
    }

    #[test]
    fn new_generation_retires_old_one() {
        let (tx, _rx) = channel();
        let mut t = ProcessTable::new(Filter::default(), tx);
        let a = t.insert(seed(100, 1, "a.exe"));
        let b = t.insert(seed(100, 50, "b.exe"));
        assert!(!a.is_alive());
        assert!(b.is_alive());
    }

    #[test]
    fn tree_inheritance_respects_parent_age() {
        let (tx, _rx) = channel();
        let f = Filter::new(&["winword.exe".into()], &[], &[], true);
        let mut t = ProcessTable::new(f, tx);
        let parent = t.insert(seed(10, 100, "winword.exe"));
        assert!(parent.included);
        let mut child = seed(11, 200, "splwow64.exe");
        child.ppid = 10;
        assert!(t.insert(child).included);
        // A process claiming PPID 10 but created *before* winword (recycled PPID) is not a child.
        let mut impostor = seed(12, 50, "other.exe");
        impostor.ppid = 10;
        assert!(!t.insert(impostor).included);
    }

    #[test]
    fn gc_keeps_referenced_generations() {
        // No enrichment consumer: queued Arcs would otherwise count as references.
        let (tx, rx) = channel();
        drop(rx);
        let mut t = ProcessTable::new(Filter::default(), tx);
        let held = t.insert(seed(1, 1, "a.exe"));
        held.mark_exited(2);
        t.insert(seed(2, 1, "b.exe")).mark_exited(2);
        t.gc(RETAIN_EXITED * 2);
        assert!(t.by_pid.contains_key(&1));
        assert!(!t.by_pid.contains_key(&2));
        drop(held);
    }
}
