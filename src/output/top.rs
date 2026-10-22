//! Mode B: process-grouped live view (full-screen, alternate buffer) and its non-interactive
//! counterparts (periodic aggregate records and the exit summary).
//!
//! ```text
//!  netattrib  ETW+poll  14:03:22Z  up 12m03s  procs 213  flows 1203  4.5k ev/s  lost 0  filter: all
//!  PROCESS            PIDS   ACT  TOTAL  RMT      TX      RX  DESTINATIONS                       PATH
//!  WINWORD.EXE           1     7     42   18    1.2M   14.3M  ecs.office.com(4) login.micr…(6)   C:\Program Files\…\WINWORD.EXE
//!  ─ connections: 87 active, newest first
//!  PROCESS        PID PROTO REMOTE                DOMAIN                 STATE       DIR      TX      RX   AGE
//! ```
//!
//! Every frame re-queries the window size, pads each line with erase-to-EOL and clears below
//! the last line, so resizing never leaves stale fragments.

use std::collections::HashMap;
use std::fmt::Write as _;

use super::{user_display, Enricher};
use crate::aggregate::{SnapshotOpts, SortKey, TopRow, TopSnapshot};
use crate::model::fmt_endpoint;
use crate::util::{
    ellipsize_end, ellipsize_middle, hms_millis, human_bytes, human_count, human_duration, pad,
    rpad, FileTime,
};

pub struct Status {
    pub mode: &'static str,
    pub now: FileTime,
    pub started: FileTime,
    pub events_per_sec: u64,
    pub lost: u64,
    pub dropped: u64,
    pub filter: String,
    pub sort: SortKey,
}

pub fn sort_label(s: SortKey) -> &'static str {
    match s {
        SortKey::Activity => "activity",
        SortKey::Conns => "conns",
        SortKey::Active => "active",
        SortKey::Tx => "tx",
        SortKey::Rx => "rx",
        SortKey::Remotes => "remotes",
        SortKey::Name => "name",
    }
}

pub fn frame_opts(sort: SortKey, height: usize) -> SnapshotOpts {
    SnapshotOpts {
        sort,
        max_rows: height.max(4),
        remotes_per_row: 12,
        dns_per_row: 0,
        live_limit: height.max(4),
        changed_since: 0,
    }
}

/// Distinct destinations of a row, as `name(count)`, most-used first. Remote IPs are mapped
/// through the DNS cache so CDN addresses collapse under the name the app actually queried.
pub fn destinations(row: &TopRow, e: &Enricher) -> String {
    let mut by_label: Vec<(String, u32)> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for r in &row.top_remotes {
        let label = e
            .domain_for_ip(r.ip, row.sample.pid)
            .map(|d| d.to_string())
            .unwrap_or_else(|| r.ip.to_string());
        match index.get(&label) {
            Some(&i) => by_label[i].1 += r.stat.conns,
            None => {
                index.insert(label.clone(), by_label.len());
                by_label.push((label, r.stat.conns));
            }
        }
    }
    by_label.sort_by_key(|b| std::cmp::Reverse(b.1));
    by_label
        .iter()
        .map(|(l, c)| format!("{}({})", l, c))
        .collect::<Vec<_>>()
        .join(" ")
}

struct Painter {
    color: bool,
}

impl Painter {
    fn p(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{}m{}\x1b[0m", code, s)
        } else {
            s.to_string()
        }
    }
}

struct ExeCols {
    process: usize,
    user: usize,
    dest: usize,
    path: usize,
}

/// Numeric columns, each including its leading gap: PIDS ACT TOTAL RMT TX RX.
const NUM_COLS: usize = (1 + 6) + (1 + 5) + (1 + 6) + (1 + 4) + (1 + 7) + (1 + 7);

fn exe_cols(w: usize) -> ExeCols {
    let process = if w >= 100 { 18 } else { 14 };
    // Leading space + PROCESS + numbers; every further column costs its width + 1 gap.
    let mut rest = w.saturating_sub(1 + process + NUM_COLS + 1);
    let user = if rest >= 80 { 18 } else { 0 };
    rest = rest.saturating_sub(if user > 0 { user + 1 } else { 0 });
    let (dest, path) = if rest >= 70 {
        let path = (rest * 2 / 5).min(70);
        (rest - path - 1, path)
    } else {
        (rest, 0)
    };
    ExeCols {
        process,
        user,
        dest,
        path,
    }
}

/// One PID is shown as-is; several as a count (`[3]`) - the full list is in exports.
fn pids_label(pids: &[u32]) -> String {
    match pids {
        [one] => one.to_string(),
        many => format!("[{}]", many.len()),
    }
}

pub fn render_exe_header(w: usize, out: &mut String, paint: bool) {
    let c = exe_cols(w);
    let mut line = format!(
        " {} {} {} {} {} {} {}",
        pad("PROCESS", c.process),
        rpad("PIDS", 6),
        rpad("ACT", 5),
        rpad("TOTAL", 6),
        rpad("RMT", 4),
        rpad("TX", 7),
        rpad("RX", 7),
    );
    if c.user > 0 {
        line.push(' ');
        line.push_str(&pad("USER", c.user));
    }
    line.push(' ');
    line.push_str(&pad("DESTINATIONS", c.dest));
    if c.path > 0 {
        line.push(' ');
        line.push_str(&pad("PATH", c.path));
    }
    let line = pad(&line, w);
    out.push_str(&Painter { color: paint }.p("1;4", &line));
}

pub fn render_exe_row(row: &TopRow, e: &Enricher, w: usize, out: &mut String, paint: bool) {
    let c = exe_cols(w);
    let pp = Painter { color: paint };
    let pids = pids_label(&row.pids);
    let act = row.active.to_string();
    let mut line = format!(
        " {} {} {} {} {} {} {}",
        pad(&row.name, c.process),
        rpad(&pids, 6),
        rpad(&act, 5),
        rpad(&human_count(row.total), 6),
        rpad(&human_count(row.unique_remotes as u64), 4),
        rpad(&human_bytes(row.tx), 7),
        rpad(&human_bytes(row.rx), 7),
    );
    if c.user > 0 {
        line.push(' ');
        let u = user_display(&row.sample).unwrap_or("?");
        // DOMAIN\user -> user keeps the column readable; the full value is in exports.
        let u = u.rsplit('\\').next().unwrap_or(u);
        line.push_str(&pad(u, c.user));
    }
    line.push(' ');
    line.push_str(&pad(&destinations(row, e), c.dest));
    if c.path > 0 {
        line.push(' ');
        let p = if row.path.is_empty() {
            "-"
        } else {
            row.path.as_str()
        };
        line.push_str(&pad(&ellipsize_middle(p, c.path), c.path));
    }
    let line = ellipsize_end(&line, w);
    if row.active == 0 {
        out.push_str(&pp.p("2", &line));
    } else {
        out.push_str(&line);
    }
}

fn render_live(
    snap: &TopSnapshot,
    e: &Enricher,
    w: usize,
    rows: usize,
    lines: &mut Vec<String>,
    pp: &Painter,
    now: FileTime,
) {
    if rows < 3 {
        return;
    }
    lines.push(pp.p(
        "2",
        &pad(
            &format!(
                " ─ connections: {} active, most recent activity first",
                snap.live_total
            ),
            w,
        ),
    ));
    let fixed = 1 + 14 + 1 + 6 + 1 + 5 + 1 + 11 + 1 + 3 + 1 + 7 + 1 + 7 + 1 + 6;
    let rest = w.saturating_sub(fixed + 2);
    let remote = (rest * 9 / 20).clamp(15, 47).min(rest);
    let domain = rest.saturating_sub(remote);
    let header = format!(
        " {} {} {} {} {} {} {} {} {} {}",
        pad("PROCESS", 14),
        rpad("PID", 6),
        pad("PROTO", 5),
        pad("REMOTE", remote),
        pad("DOMAIN", domain),
        pad("STATE", 11),
        pad("DIR", 3),
        rpad("TX", 7),
        rpad("RX", 7),
        rpad("AGE", 6),
    );
    lines.push(pp.p("1;4", &pad(&header, w)));
    for c in snap.live.iter().take(rows - 2) {
        let dom = e
            .domain_for_ip(c.key.remote.ip(), c.proc.pid)
            .map(|d| d.to_string())
            .unwrap_or_default();
        let dom = if dom.chars().count() > domain && domain > 1 {
            let n = dom.chars().count();
            format!(
                "…{}",
                dom.chars().skip(n - (domain - 1)).collect::<String>()
            )
        } else {
            dom
        };
        let line = format!(
            " {} {} {} {} {} {} {} {} {} {}",
            pad(&c.proc.name, 14),
            rpad(&c.proc.pid.to_string(), 6),
            pad(c.key.proto_label(), 5),
            pad(
                &ellipsize_middle(&fmt_endpoint(&c.key.remote), remote),
                remote
            ),
            pad(&dom, domain),
            pad(c.state.label(), 11),
            pad(c.dir.label(), 3),
            rpad(&human_bytes(c.tx), 7),
            rpad(&human_bytes(c.rx), 7),
            rpad(&human_duration(now.saturating_sub(c.first_seen)), 6),
        );
        let line = ellipsize_end(&line, w);
        // Highlight flows that moved data in the last 2 seconds.
        if now.saturating_sub(c.last_activity) < 2 * crate::util::TICKS_PER_SEC {
            lines.push(pp.p("32", &line));
        } else {
            lines.push(line);
        }
    }
}

/// Renders one full frame (cursor home, lines, erase-below).
pub fn render_frame(
    snap: &TopSnapshot,
    st: &Status,
    e: &Enricher,
    w: usize,
    h: usize,
    color: bool,
) -> String {
    let pp = Painter { color };
    let w = w.max(40);
    let mut lines: Vec<String> = Vec::with_capacity(h);
    let status = format!(
        " netattrib  {}  {}  up {}  procs {}  flows {}  {} ev/s  lost {}  drop {}  sort {}  filter: {}  (Ctrl+C quits)",
        st.mode,
        hms_millis(st.now),
        human_duration(st.now.saturating_sub(st.started)),
        st.procs_alive_label(snap),
        snap.flows_tracked,
        human_count(st.events_per_sec),
        st.lost,
        st.dropped,
        sort_label(st.sort),
        st.filter,
    );
    lines.push(pp.p("7", &pad(&ellipsize_end(&status, w), w)));

    let body = h.saturating_sub(1);
    // Split the screen: executables on top, live connections below (when there is room).
    let exe_rows = snap.rows.len().min(if body > 12 {
        body * 11 / 20
    } else {
        body.saturating_sub(1)
    });
    let mut s = String::new();
    render_exe_header(w, &mut s, color);
    lines.push(std::mem::take(&mut s));
    for row in snap.rows.iter().take(exe_rows) {
        render_exe_row(row, e, w, &mut s, color);
        lines.push(std::mem::take(&mut s));
    }
    if snap.total_rows > exe_rows {
        lines.push(pp.p(
            "2",
            &format!(
                " … {} more executables (sorted by {})",
                snap.total_rows - exe_rows,
                sort_label(st.sort)
            ),
        ));
    }
    if snap.rows.is_empty() {
        lines.push(pp.p("2", " waiting for matching network activity…"));
    }
    let remaining = h.saturating_sub(lines.len() + 1);
    if remaining >= 4 {
        lines.push(String::new());
        render_live(snap, e, w, remaining - 1, &mut lines, &pp, st.now);
    }
    lines.truncate(h);
    let mut out = String::with_capacity(w * h + 64);
    out.push_str("\x1b[H");
    for (i, l) in lines.iter().enumerate() {
        out.push_str(l);
        out.push_str("\x1b[K");
        if i + 1 < lines.len() {
            out.push_str("\r\n");
        }
    }
    out.push_str("\x1b[J");
    out
}

impl Status {
    fn procs_alive_label(&self, snap: &TopSnapshot) -> String {
        if snap.pending > 0 {
            format!("{} (+{} pending)", snap.procs_alive, snap.pending)
        } else {
            snap.procs_alive.to_string()
        }
    }
}

/// Plain-text summary printed after the TUI exits or for non-console table output.
pub fn render_summary(snap: &TopSnapshot, e: &Enricher, w: usize) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "netattrib summary: {} executables with network activity",
        snap.total_rows
    );
    let mut s = String::new();
    render_exe_header(w, &mut s, false);
    out.push_str(s.trim_end());
    out.push('\n');
    for row in &snap.rows {
        s.clear();
        render_exe_row(row, e, w, &mut s, false);
        out.push_str(s.trim_end());
        out.push('\n');
        if !row.dns_names.is_empty() {
            let names: Vec<String> = row
                .dns_names
                .iter()
                .take(8)
                .map(|(n, c)| format!("{}({})", n, c))
                .collect();
            let _ = writeln!(
                out,
                "{}",
                ellipsize_end(&format!("   dns: {}", names.join(" ")), w)
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregate::{LiveConn, RemoteRow, RemoteStat, TopRow, TopSnapshot};
    use crate::dns::Dns;
    use crate::filter::Filter;
    use crate::model::{Attribution, ConnState, Direction, FlowKey, Proto};
    use crate::process::services::ServiceMap;
    use crate::process::{ProcessTable, Seed};
    use crate::util::TICKS_PER_SEC;
    use std::sync::Arc;

    fn visible(s: &str) -> usize {
        // Strip CSI sequences, then count cells.
        let mut n = 0;
        let mut it = s.chars();
        while let Some(c) = it.next() {
            if c == '\x1b' {
                for d in it.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                n += 1;
            }
        }
        n
    }

    fn sample() -> (TopSnapshot, Enricher) {
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let mut t = ProcessTable::new(Filter::default(), tx);
        let p = t.insert(Seed {
            pid: 4512,
            ppid: 1200,
            create_time: 1,
            session_id: 1,
            name: "WINWORD.EXE".into(),
            path: "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE".into(),
            attribution: Attribution::Exact,
            exit_time: None,
        });
        let now = crate::util::now();
        let remote = |ip: &str, conns| RemoteRow {
            ip: ip.parse().unwrap(),
            stat: RemoteStat {
                conns,
                tx: 1000,
                rx: 90_000,
                last: now,
                last_port: 443,
            },
        };
        let row = TopRow {
            name: p.name.clone(),
            path: p.path.clone(),
            sample: p.clone(),
            pids: vec![4512],
            active: 7,
            total: 42,
            tcp: 40,
            udp: 2,
            tx: 1_300_000,
            rx: 15_000_000,
            unique_remotes: 3,
            remotes_overflow: 0,
            top_remotes: vec![
                remote("52.109.8.21", 6),
                remote("13.107.42.14", 4),
                remote("2620:1ec:bdf::14", 2),
            ],
            dns_names: vec![("ecs.office.com".into(), 4)],
            first_seen: now - 60 * TICKS_PER_SEC,
            last_seen: now,
        };
        let conn = |remote: &str, state| LiveConn {
            proc: p.clone(),
            key: FlowKey {
                proto: Proto::Tcp,
                local: "10.0.0.5:50123".parse().unwrap(),
                remote: remote.parse().unwrap(),
            },
            state,
            dir: Direction::Outbound,
            tx: 4096,
            rx: 1 << 20,
            first_seen: now - 75 * TICKS_PER_SEC,
            last_activity: now,
        };
        let snap = TopSnapshot {
            rows: vec![row],
            total_rows: 1,
            live: vec![
                conn("52.109.8.21:443", ConnState::Established),
                conn("[2620:1ec:bdf::14]:443", ConnState::CloseWait),
            ],
            live_total: 2,
            flows_tracked: 120,
            procs_alive: 213,
            pending: 0,
        };
        let dns = Dns::new(false, 0);
        dns.observe_answer(4512, "ecs.office.com", &["52.109.8.21".parse().unwrap()]);
        dns.observe_answer(
            4512,
            "login.microsoftonline.com",
            &["13.107.42.14".parse().unwrap()],
        );
        (
            snap,
            Enricher {
                dns,
                services: Arc::new(ServiceMap::default()),
            },
        )
    }

    fn status() -> Status {
        let now = crate::util::now();
        Status {
            mode: "ETW+poll",
            now,
            started: now - 723 * TICKS_PER_SEC,
            events_per_sec: 4500,
            lost: 0,
            dropped: 0,
            filter: "exe=winword.exe".into(),
            sort: SortKey::Activity,
        }
    }

    #[test]
    fn frame_lines_fit_any_terminal_size() {
        let (snap, e) = sample();
        for (w, h) in [(40, 8), (60, 12), (80, 24), (120, 30), (200, 50), (300, 80)] {
            let f = render_frame(&snap, &status(), &e, w, h, true);
            let body = f.trim_start_matches("\x1b[H").trim_end_matches("\x1b[J");
            let lines: Vec<&str> = body.split("\r\n").collect();
            assert!(lines.len() <= h, "{}x{}: {} lines", w, h, lines.len());
            for l in lines {
                assert!(
                    visible(l) <= w.max(40),
                    "{}x{}: line of {} cells: {:?}",
                    w,
                    h,
                    visible(l),
                    l
                );
            }
        }
    }

    #[test]
    fn destinations_collapse_by_domain() {
        let (snap, e) = sample();
        let d = destinations(&snap.rows[0], &e);
        assert!(
            d.starts_with("ecs.office.com(6) login.microsoftonline.com(4)"),
            "{}",
            d
        );
    }

    #[test]
    fn print_sample_frame() {
        let (snap, e) = sample();
        let f = render_frame(&snap, &status(), &e, 150, 14, false);
        println!(
            "{}",
            f.replace("\x1b[K", "")
                .replace("\x1b[H", "")
                .replace("\x1b[J", "")
                .replace("\r\n", "\n")
        );
    }
}
