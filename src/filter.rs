//! Mode A target selection: executable name, full path pattern, or PID (bound to the
//! process *instance*, so a recycled PID never matches).

use crate::process::query::SnapEntry;
use crate::util::{FileTime, Glob};

#[derive(Debug, Clone)]
struct PidSpec {
    pid: u32,
    /// Creation time of the instance that held this PID at startup; `None` if it was not
    /// running, in which case any future process with this PID matches.
    create_time: Option<FileTime>,
}

#[derive(Debug, Clone, Default)]
pub struct Filter {
    exes: Vec<Glob>,
    paths: Vec<Glob>,
    pids: Vec<PidSpec>,
    /// Also include descendants of matched processes.
    pub tree: bool,
}

impl Filter {
    pub fn new(exes: &[String], paths: &[String], pids: &[u32], tree: bool) -> Self {
        let mut ex = Vec::new();
        for e in exes {
            let g = Glob::new(e);
            // `--filter-exe winword` is accepted as shorthand for `winword.exe`.
            if g.is_literal() && !e.to_lowercase().ends_with(".exe") {
                ex.push(Glob::new(&format!("{}.exe", e)));
            }
            ex.push(g);
        }
        Filter {
            exes: ex,
            paths: paths.iter().map(|p| Glob::new(p)).collect(),
            pids: pids
                .iter()
                .map(|&pid| PidSpec {
                    pid,
                    create_time: None,
                })
                .collect(),
            tree,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.exes.is_empty() && self.paths.is_empty() && self.pids.is_empty()
    }

    /// Pins each `--filter-pid` to the instance currently holding it. Returns PIDs not running.
    pub fn bind_pids(&mut self, snap: &[SnapEntry]) -> Vec<u32> {
        let mut missing = Vec::new();
        for spec in &mut self.pids {
            match snap.iter().find(|e| e.pid == spec.pid) {
                Some(e) => spec.create_time = Some(e.create_time),
                None => missing.push(spec.pid),
            }
        }
        missing
    }

    /// `name_lc` / `path_lc` must be lower-case.
    pub fn matches(&self, pid: u32, create_time: FileTime, name_lc: &str, path_lc: &str) -> bool {
        if self.is_empty() {
            return true;
        }
        if self
            .pids
            .iter()
            .any(|s| s.pid == pid && s.create_time.is_none_or(|ct| ct == create_time))
        {
            return true;
        }
        if self.exes.iter().any(|g| g.matches_lc(name_lc)) {
            return true;
        }
        !path_lc.is_empty() && self.paths.iter().any(|g| g.matches_lc(path_lc))
    }

    /// Running processes whose names resemble an unmatched `--filter-exe` value, e.g. the user
    /// typed `word.exe` but Microsoft Word's binary is `WINWORD.EXE`.
    pub fn suggestions(&self, snap: &[SnapEntry]) -> Vec<(String, Vec<String>)> {
        let mut out = Vec::new();
        for g in &self.exes {
            let any = snap.iter().any(|e| g.matches_lc(&e.name.to_lowercase()));
            if any {
                continue;
            }
            let stem = g
                .as_str()
                .to_lowercase()
                .trim_end_matches(".exe")
                .replace(['*', '?'], "");
            if stem.len() < 3 {
                continue;
            }
            let mut similar: Vec<String> = snap
                .iter()
                .filter(|e| e.name.to_lowercase().contains(&stem))
                .map(|e| format!("{} (pid {})", e.name, e.pid))
                .collect();
            similar.sort();
            similar.dedup();
            similar.truncate(5);
            out.push((g.as_str().to_string(), similar));
        }
        out.sort();
        out.dedup_by(|a, b| a.0.trim_end_matches(".exe") == b.0.trim_end_matches(".exe"));
        out
    }

    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        for g in &self.exes {
            parts.push(format!("exe={}", g.as_str()));
        }
        for g in &self.paths {
            parts.push(format!("path={}", g.as_str()));
        }
        for p in &self.pids {
            parts.push(format!("pid={}", p.pid));
        }
        if self.tree {
            parts.push("+children".into());
        }
        if parts.is_empty() {
            "all".into()
        } else {
            parts.join(" ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_shorthand_and_globs() {
        let f = Filter::new(&["winword".into()], &[], &[], false);
        assert!(f.matches(1, 0, "winword.exe", ""));
        assert!(!f.matches(1, 0, "excel.exe", ""));
        let f = Filter::new(&["*word*".into()], &[], &[], false);
        assert!(f.matches(1, 0, "winword.exe", ""));
    }

    #[test]
    fn pid_bound_to_instance() {
        let mut f = Filter::new(&[], &[], &[4512], false);
        let snap = vec![SnapEntry {
            pid: 4512,
            ppid: 1,
            create_time: 100,
            session_id: 1,
            name: "a.exe".into(),
        }];
        assert!(f.bind_pids(&snap).is_empty());
        assert!(f.matches(4512, 100, "a.exe", ""));
        // Same PID, different instance (PID reuse) -> no match.
        assert!(!f.matches(4512, 200, "b.exe", ""));
    }

    #[test]
    fn path_glob() {
        let f = Filter::new(&[], &["*\\office16\\*".into()], &[], false);
        assert!(f.matches(
            1,
            0,
            "winword.exe",
            "c:\\program files\\microsoft office\\root\\office16\\winword.exe"
        ));
        assert!(!f.matches(1, 0, "winword.exe", ""));
    }

    #[test]
    fn suggests_winword_for_word() {
        let f = Filter::new(&["word.exe".into()], &[], &[], false);
        let snap = vec![SnapEntry {
            pid: 7,
            ppid: 1,
            create_time: 1,
            session_id: 1,
            name: "WINWORD.EXE".into(),
        }];
        let s = f.suggestions(&snap);
        assert_eq!(s.len(), 1);
        assert!(s[0].1[0].starts_with("WINWORD.EXE"));
    }
}
