//! Background half of the GUI.
//!
//! The sampler thread turns engine state into an immutable [`Snapshot`] once a second and
//! publishes it through an `Arc<RwLock<Arc<Snapshot>>>`. The UI thread only clones the inner
//! `Arc`, so rendering never contends for the engine mutex the ETW consumer needs.
//!
//! The feed thread drains the engine's record stream. `close` records keep short-lived
//! connections in the table (a 1 Hz sample alone would never show a 50 ms connection): for
//! [`CLOSED_RETENTION`], or up to [`HISTORY_CAP`] rows while "Keep closed history" is on.
//! Every record is also forwarded to the `--log` writer.
//!
//! Both ends of a loopback connection belong to local processes. They are paired here, so an
//! application behind a system proxy shows *which* process it talks to on `127.0.0.1`.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use eframe::egui;

use crate::aggregate::{Engine, SnapshotOpts, SortKey};
use crate::console;
use crate::dns::DomainSource;
use crate::model::{fmt_endpoint, Direction, EventKind, FlowKey, Proto, Record};
use crate::output::Enricher;
use crate::process::Process;
use crate::util::{self, FileTime, TICKS_PER_SEC};

/// How long a closed connection stays visible while history is off.
pub const CLOSED_RETENTION: u64 = 10 * TICKS_PER_SEC;
/// Most closed connections kept, oldest dropped first.
pub const HISTORY_CAP: usize = 2_000;
/// Closes waiting between the feed and the sampler.
const QUEUE_CAP: usize = 5_000;
const SAMPLE_PERIOD: Duration = Duration::from_secs(1);

/// Display states for loopback rows, replacing the TCP state (kept in [`Conn::tcp_state`]).
pub const STATE_PROXY: &str = "PROXY/LOCAL";
pub const STATE_LOCAL_IN: &str = "LOCAL/IN";

/// Settings the window changes and the sampler applies; any change wakes the sampler so the
/// table reflects it at once.
pub struct Control {
    keep_history: AtomicBool,
    clear: AtomicBool,
    wake: AtomicBool,
}

impl Control {
    pub fn new(keep_history: bool) -> Self {
        Control {
            keep_history: AtomicBool::new(keep_history),
            clear: AtomicBool::new(false),
            wake: AtomicBool::new(false),
        }
    }

    pub fn set_keep_history(&self, keep: bool) {
        self.keep_history.store(keep, Ordering::Relaxed);
        self.wake.store(true, Ordering::Relaxed);
    }

    pub fn clear_history(&self) {
        self.clear.store(true, Ordering::Relaxed);
        self.wake.store(true, Ordering::Relaxed);
    }
}

/// Process instance identity: `(pid, create_time)` survives PID reuse.
pub type Ident = (u32, FileTime);

pub fn ident(p: &Process) -> Ident {
    (p.pid, p.create_time)
}

pub struct Conn {
    pub proc: Arc<Process>,
    /// Index of the owning process in [`Snapshot::procs`].
    pub node: usize,
    pub key: FlowKey,
    pub local: String,
    pub remote: String,
    pub domain: Option<(Arc<str>, DomainSource)>,
    /// What the State column shows: the TCP state, [`STATE_PROXY`] / [`STATE_LOCAL_IN`] for
    /// loopback, `CLOSED` for history.
    pub state: &'static str,
    pub tcp_state: &'static str,
    pub dir: Direction,
    pub tx: u64,
    pub rx: u64,
    pub last_activity: FileTime,
    /// `Some(t)`: closed, and the close was received at `t`.
    pub closed: Option<FileTime>,
    /// Loopback rows only.
    pub link: Option<LocalLink>,
}

/// The local end a loopback row talks to.
pub struct LocalLink {
    /// This row is the accepting side (the proxy / service), not the client.
    pub inbound: bool,
    /// The process owning the other end, when both ends are tracked.
    pub peer: Option<Arc<Process>>,
}

impl LocalLink {
    pub fn label(&self) -> String {
        match (&self.peer, self.inbound) {
            (Some(p), false) => format!("via {} ({})", p.name, p.pid),
            (Some(p), true) => format!("from {} ({})", p.name, p.pid),
            (None, false) => "local service".into(),
            (None, true) => "local client".into(),
        }
    }
}

pub struct Node {
    pub proc: Arc<Process>,
    /// Lower-cased name and hosted services (process filter).
    pub search: String,
    pub services: Option<Arc<str>>,
    pub account: Account,
    pub parent: Option<usize>,
    /// Ordered by creation time, like Process Explorer's tree.
    pub children: Vec<usize>,
}

/// Who a process runs as, for the All / User / System scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Account {
    /// The account netattrib runs under (elevation does not change the user SID).
    User,
    /// SYSTEM, LOCAL/NETWORK SERVICE and the per-service, DWM and font-driver accounts.
    System,
    /// Another interactive user.
    Other,
}

impl Account {
    /// `me` is the current user's SID.
    pub fn of(p: &Process, me: Option<&str>) -> Account {
        match p.user.get() {
            Some(Some(u)) if Some(u.sid.as_str()) == me => Account::User,
            Some(Some(u)) if is_system_sid(&u.sid) => Account::System,
            Some(Some(_)) => Account::Other,
            // The token of a live process could not be read. Our own processes always can
            // be, so this is a system or service process.
            Some(None) if p.is_alive() => Account::System,
            // Not looked up (yet), or exited first: services and the kernel run in session 0.
            _ if p.session_id == 0 => Account::System,
            _ => Account::User,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Account::User => "current user",
            Account::System => "system / service",
            Account::Other => "other user",
        }
    }
}

/// SYSTEM, LOCAL SERVICE, NETWORK SERVICE, and the NT SERVICE, IIS APPPOOL, NT VIRTUAL MACHINE,
/// Window Manager (DWM-n) and Font Driver Host (UMFD-n) account families.
fn is_system_sid(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20")
        || [
            "S-1-5-80-",
            "S-1-5-82-",
            "S-1-5-83-",
            "S-1-5-90-",
            "S-1-5-96-",
        ]
        .iter()
        .any(|prefix| sid.starts_with(prefix))
}

/// The SID netattrib itself runs as.
fn current_user_sid() -> Option<String> {
    let h = crate::process::query::open_limited(std::process::id())?;
    crate::process::query::token_user(&h, &mut HashMap::new()).map(|u| u.sid)
}

#[derive(Default)]
pub struct Stats {
    pub events_per_sec: u64,
    pub etw_lost: u64,
    pub dropped: u64,
    pub procs_alive: usize,
    pub uptime: u64,
}

/// One immutable sample of everything the window shows.
#[derive(Default)]
pub struct Snapshot {
    pub seq: u64,
    pub taken: FileTime,
    pub conns: Vec<Conn>,
    /// Live processes, plus exited ones that still own a row in `conns`.
    pub procs: Vec<Node>,
    pub roots: Vec<usize>,
    /// Pre-order walk of the forest (parents before children).
    pub preorder: Vec<usize>,
    pub index: HashMap<Ident, usize>,
    pub stats: Stats,
}

pub type Shared = Arc<RwLock<Arc<Snapshot>>>;
type ClosedQueue = Arc<Mutex<VecDeque<Record>>>;

/// Consumer of the engine's record channel while the GUI owns the output.
pub struct Feed {
    closed: ClosedQueue,
    join: JoinHandle<()>,
}

impl Feed {
    /// The thread exits once the engine (the channel's sender) is dropped, after forwarding
    /// the final `shutdown` close records to `log`.
    pub fn spawn(rx: Receiver<Record>, log: Option<SyncSender<Record>>) -> Feed {
        let closed = ClosedQueue::default();
        let queue = closed.clone();
        let join = std::thread::Builder::new()
            .name("gui-feed".into())
            .spawn(move || {
                while let Ok(r) = rx.recv() {
                    // Listener closes carry no remote endpoint and have no row to keep.
                    if r.kind == EventKind::Close && !r.key.remote.ip().is_unspecified() {
                        let mut q = queue.lock().unwrap_or_else(|e| e.into_inner());
                        if q.len() >= QUEUE_CAP {
                            q.pop_front();
                        }
                        q.push_back(r.clone());
                    }
                    if let Some(tx) = &log {
                        // Blocking is fine here: back-pressure lands on the engine's
                        // `try_send`, which counts drops instead of stalling ETW.
                        let _ = tx.send(r);
                    }
                }
            })
            .expect("spawn gui-feed thread");
        Feed { closed, join }
    }

    pub fn join(self) {
        let _ = self.join.join();
    }
}

pub fn spawn_sampler(
    engine: Arc<Engine>,
    enr: Arc<Enricher>,
    feed: &Feed,
    shared: Shared,
    control: Arc<Control>,
    repaint: Arc<OnceLock<egui::Context>>,
) -> JoinHandle<()> {
    let queue = feed.closed.clone();
    std::thread::Builder::new()
        .name("gui-sampler".into())
        .spawn(move || {
            let me = current_user_sid();
            // (arrival time, record), oldest first.
            let mut closed: VecDeque<(FileTime, Record)> = VecDeque::new();
            let mut seq = 0u64;
            let mut last = (
                engine.counters.etw_events.load(Ordering::Relaxed),
                Instant::now(),
            );
            while !console::stop_requested() {
                let started = Instant::now();
                let now = util::now();
                retain_closed(
                    &mut closed,
                    &mut queue.lock().unwrap_or_else(|e| e.into_inner()),
                    &control,
                    now,
                );
                let events = engine.counters.etw_events.load(Ordering::Relaxed);
                let dt = last.1.elapsed().as_secs_f64();
                let rate = if dt > 0.0 {
                    (events.saturating_sub(last.0) as f64 / dt) as u64
                } else {
                    0
                };
                last = (events, Instant::now());
                seq += 1;
                let snap = build(&engine, &enr, me.as_deref(), &closed, now, seq, rate);
                *shared.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(snap);
                if let Some(ctx) = repaint.get() {
                    ctx.request_repaint();
                }
                while started.elapsed() < SAMPLE_PERIOD
                    && !console::stop_requested()
                    && !control.wake.swap(false, Ordering::Relaxed)
                {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            // Stopped from outside the window (Ctrl+C in its console, broken --log sink):
            // wake the UI so it notices and closes instead of waiting for input.
            if let Some(ctx) = repaint.get() {
                ctx.request_repaint();
            }
        })
        .expect("spawn gui-sampler thread")
}

/// Moves newly closed connections from the feed's queue into `closed` (oldest first) and
/// applies "Clear", the 10 s window (history off) and the history cap.
fn retain_closed(
    closed: &mut VecDeque<(FileTime, Record)>,
    queue: &mut VecDeque<Record>,
    control: &Control,
    now: FileTime,
) {
    if control.clear.swap(false, Ordering::Relaxed) {
        closed.clear();
        queue.clear();
    }
    // Retention runs from arrival: a `gone`/`idle` close is stamped with the time the flow
    // went quiet, which can be long before it reaches us.
    closed.extend(queue.drain(..).map(|r| (now, r)));
    let keep = control.keep_history.load(Ordering::Relaxed);
    while closed.len() > HISTORY_CAP
        || closed
            .front()
            .is_some_and(|(t, _)| !keep && now.saturating_sub(*t) >= CLOSED_RETENTION)
    {
        closed.pop_front();
    }
}

fn build(
    engine: &Engine,
    enr: &Enricher,
    me: Option<&str>,
    closed: &VecDeque<(FileTime, Record)>,
    now: FileTime,
    seq: u64,
    events_per_sec: u64,
) -> Snapshot {
    let live = engine.snapshot(&SnapshotOpts {
        sort: SortKey::Activity,
        max_rows: 0,
        remotes_per_row: 0,
        dns_per_row: 0,
        live_limit: usize::MAX,
        // No per-executable rows needed.
        changed_since: FileTime::MAX,
    });
    let mut tree = TreeBuilder::new(me);
    for p in engine.processes() {
        tree.add(p, enr);
    }
    let mut conns = Vec::with_capacity(live.live.len() + closed.len());
    for c in live.live {
        let mut row = tree.conn(enr, c.proc, c.key);
        row.tcp_state = c.state.label();
        row.dir = c.dir;
        (row.tx, row.rx, row.last_activity) = (c.tx, c.rx, c.last_activity);
        conns.push(row);
    }
    for (t, r) in closed {
        let mut row = tree.conn(enr, r.proc.clone(), r.key);
        row.tcp_state = r.state.label();
        row.dir = r.direction;
        (row.tx, row.rx, row.last_activity) = (r.bytes_sent, r.bytes_recv, r.ts);
        row.closed = Some(*t);
        conns.push(row);
    }
    finish_rows(&mut conns);
    let (procs, roots, preorder, index) = tree.finish();
    let c = &engine.counters;
    Snapshot {
        seq,
        taken: now,
        conns,
        procs,
        roots,
        preorder,
        index,
        stats: Stats {
            events_per_sec,
            etw_lost: c.etw_lost.load(Ordering::Relaxed),
            dropped: c.dropped.load(Ordering::Relaxed),
            procs_alive: live.procs_alive,
            uptime: now.saturating_sub(engine.started),
        },
    }
}

/// Pairs the two ends of each loopback connection (the client's `local -> remote` is the
/// server's `remote -> local`; live rows win over closed history for the same tuple), then
/// sets every row's display state.
pub(super) fn finish_rows(conns: &mut [Conn]) {
    let mut ends: HashMap<(Proto, SocketAddr, SocketAddr), usize> = HashMap::new();
    for (i, c) in conns.iter().enumerate().rev() {
        if c.key.remote.ip().is_loopback() {
            ends.insert((c.key.proto, c.key.local, c.key.remote), i);
        }
    }
    let links: Vec<(usize, LocalLink)> = conns
        .iter()
        .enumerate()
        .filter(|(_, c)| c.key.remote.ip().is_loopback())
        .map(|(i, c)| {
            let peer = ends
                .get(&(c.key.proto, c.key.remote, c.key.local))
                .copied()
                .filter(|&j| j != i);
            let inbound = match (c.dir, peer.map(|j| conns[j].dir)) {
                (Direction::Inbound, _) | (Direction::Unknown, Some(Direction::Outbound)) => true,
                (Direction::Outbound, _) | (Direction::Unknown, Some(Direction::Inbound)) => false,
                // Clients connect from an ephemeral (high) port to a fixed service port.
                _ => c.key.local.port() < c.key.remote.port(),
            };
            let peer = peer.map(|j| conns[j].proc.clone());
            (i, LocalLink { inbound, peer })
        })
        .collect();
    for (i, link) in links {
        conns[i].link = Some(link);
    }
    for c in conns.iter_mut() {
        c.state = match &c.link {
            _ if c.closed.is_some() => c.tcp_state,
            Some(l) if l.inbound => STATE_LOCAL_IN,
            Some(_) => STATE_PROXY,
            None => c.tcp_state,
        };
    }
}

#[derive(Default)]
pub(super) struct TreeBuilder {
    nodes: Vec<Node>,
    index: HashMap<Ident, usize>,
    me: Option<String>,
}

impl TreeBuilder {
    pub(super) fn new(me: Option<&str>) -> Self {
        TreeBuilder {
            me: me.map(str::to_string),
            ..Default::default()
        }
    }

    pub(super) fn add(&mut self, p: Arc<Process>, enr: &Enricher) -> usize {
        if let Some(&i) = self.index.get(&ident(&p)) {
            return i;
        }
        let i = self.nodes.len();
        self.index.insert(ident(&p), i);
        let services = enr.services(&p);
        let mut search = p.name.to_lowercase();
        if let Some(s) = &services {
            search.push(' ');
            search.push_str(&s.to_lowercase());
        }
        self.nodes.push(Node {
            account: Account::of(&p, self.me.as_deref()),
            proc: p,
            search,
            services,
            parent: None,
            children: Vec::new(),
        });
        i
    }

    /// A row owned by `proc` with the per-sample fields (state, bytes, ...) left zeroed.
    pub(super) fn conn(&mut self, enr: &Enricher, proc: Arc<Process>, key: FlowKey) -> Conn {
        let node = self.add(proc.clone(), enr);
        let remote_ip = key.remote.ip();
        let domain = (!remote_ip.is_unspecified())
            .then(|| enr.dns.lookup(remote_ip, proc.pid))
            .flatten();
        Conn {
            proc,
            node,
            key,
            local: fmt_endpoint(&key.local),
            remote: fmt_endpoint(&key.remote),
            domain,
            state: "",
            tcp_state: "",
            dir: Direction::Unknown,
            tx: 0,
            rx: 0,
            last_activity: 0,
            closed: None,
            link: None,
        }
    }

    pub(super) fn finish(mut self) -> (Vec<Node>, Vec<usize>, Vec<usize>, HashMap<Ident, usize>) {
        let n = self.nodes.len();
        let mut by_pid: HashMap<u32, Vec<usize>> = HashMap::new();
        for (i, node) in self.nodes.iter().enumerate() {
            by_pid.entry(node.proc.pid).or_default().push(i);
        }
        // The parent is the youngest instance of PPID created no later than the child; an
        // older-than-child requirement rejects a PPID that was recycled by a newer process.
        // PID 0 (Idle) is nobody's parent.
        for i in 0..n {
            let p = &self.nodes[i].proc;
            if p.ppid == 0 || p.ppid == p.pid {
                continue;
            }
            let created = p.create_time;
            self.nodes[i].parent = by_pid.get(&p.ppid).and_then(|cands| {
                cands
                    .iter()
                    .copied()
                    .filter(|&j| self.nodes[j].proc.create_time <= created)
                    .max_by_key(|&j| self.nodes[j].proc.create_time)
            });
        }
        let mut order: Vec<usize> = (0..n).collect();
        order.sort_by_key(|&i| (self.nodes[i].proc.create_time, self.nodes[i].proc.pid));
        for &i in &order {
            if let Some(p) = self.nodes[i].parent {
                self.nodes[p].children.push(i);
            }
        }
        let mut roots: Vec<usize> = order
            .iter()
            .copied()
            .filter(|&i| self.nodes[i].parent.is_none())
            .collect();
        let mut seen = vec![false; n];
        let mut preorder = Vec::with_capacity(n);
        walk(&self.nodes, &roots, &mut seen, &mut preorder);
        // Identical creation times could in theory form a parent cycle that no root reaches:
        // cut it at its oldest member and make that a root.
        for &i in &order {
            if !seen[i] {
                if let Some(p) = self.nodes[i].parent.take() {
                    self.nodes[p].children.retain(|&c| c != i);
                }
                roots.push(i);
                walk(&self.nodes, &[i], &mut seen, &mut preorder);
            }
        }
        (self.nodes, roots, preorder, self.index)
    }
}

fn walk(nodes: &[Node], from: &[usize], seen: &mut [bool], out: &mut Vec<usize>) {
    let mut stack: Vec<usize> = from.iter().rev().copied().collect();
    while let Some(i) = stack.pop() {
        if std::mem::replace(&mut seen[i], true) {
            continue;
        }
        out.push(i);
        stack.extend(nodes[i].children.iter().rev());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::Dns;
    use crate::filter::Filter;
    use crate::model::Attribution;
    use crate::process::services::ServiceMap;
    use crate::process::{ProcessTable, Seed};

    fn proc(t: &mut ProcessTable, pid: u32, ppid: u32, ct: FileTime, name: &str) -> Arc<Process> {
        t.insert(Seed {
            pid,
            ppid,
            create_time: ct,
            session_id: 1,
            name: name.into(),
            path: String::new(),
            attribution: Attribution::Exact,
            exit_time: None,
        })
    }

    #[test]
    fn tree_respects_pid_reuse_and_creation_order() {
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let mut t = ProcessTable::new(Filter::default(), tx);
        let enr = Enricher {
            dns: Dns::new(false, 0),
            services: Arc::new(ServiceMap::default()),
        };
        let mut b = TreeBuilder::default();
        // explorer(10) -> pwsh(20) -> curl(30); "orphan" claims PPID 20 but predates pwsh,
        // so PID 20 was recycled after its real parent died.
        let names = [
            (10, 4, 100, "explorer.exe"),
            (20, 10, 200, "pwsh.exe"),
            (30, 20, 300, "curl.exe"),
            (40, 20, 150, "orphan.exe"),
            (4, 0, 1, "System"),
        ];
        for (pid, ppid, ct, name) in names {
            let p = proc(&mut t, pid, ppid, ct, name);
            b.add(p, &enr);
        }
        let (nodes, roots, preorder, index) = b.finish();
        let name = |i: usize| nodes[i].proc.name.as_str();
        let roots: Vec<&str> = roots.iter().map(|&i| name(i)).collect();
        assert_eq!(roots, ["System", "orphan.exe"]);
        let order: Vec<&str> = preorder.iter().map(|&i| name(i)).collect();
        assert_eq!(
            order,
            [
                "System",
                "explorer.exe",
                "pwsh.exe",
                "curl.exe",
                "orphan.exe"
            ]
        );
        let curl = index[&(30, 300)];
        assert_eq!(nodes[curl].parent, Some(index[&(20, 200)]));
    }

    #[test]
    fn closed_history_window_cap_and_clear() {
        use crate::model::{ConnState, Source};
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let mut t = ProcessTable::new(Filter::default(), tx);
        let p = proc(&mut t, 7, 1, 1, "curl.exe");
        let close = |port: u16| Record {
            ts: 0,
            kind: EventKind::Close,
            proc: p.clone(),
            key: FlowKey {
                proto: Proto::Tcp,
                local: SocketAddr::from(([10, 0, 0, 2], port)),
                remote: "1.1.1.1:443".parse().unwrap(),
            },
            state: ConnState::Closed,
            direction: Direction::Outbound,
            bytes_sent: 0,
            bytes_recv: 0,
            retransmits: 0,
            duration: 0,
            source: Source::Etw,
            attribution: crate::model::Attribution::Exact,
            reason: None,
            dns: None,
        };
        let s = TICKS_PER_SEC;
        let mut closed = VecDeque::new();
        let mut queue: VecDeque<Record> = (1..=3).map(close).collect();

        // History off: rows expire 10 s after they arrived, however old their timestamps.
        let control = Control::new(false);
        retain_closed(&mut closed, &mut queue, &control, 100 * s);
        assert_eq!((closed.len(), queue.len()), (3, 0));
        retain_closed(&mut closed, &mut queue, &control, 109 * s);
        assert_eq!(closed.len(), 3);
        retain_closed(&mut closed, &mut queue, &control, 110 * s);
        assert!(closed.is_empty());

        // History on: kept indefinitely, capped to the newest HISTORY_CAP.
        control.set_keep_history(true);
        queue.extend((0..HISTORY_CAP as u16 + 5).map(|i| close(1000 + i)));
        retain_closed(&mut closed, &mut queue, &control, 200 * s);
        retain_closed(&mut closed, &mut queue, &control, 10_000 * s);
        assert_eq!(closed.len(), HISTORY_CAP);
        assert_eq!(closed.front().unwrap().1.key.local.port(), 1005);

        // Clear drops the history and anything still queued.
        queue.push_back(close(9));
        control.clear_history();
        retain_closed(&mut closed, &mut queue, &control, 10_001 * s);
        assert!(closed.is_empty() && queue.is_empty());
        queue.push_back(close(10));
        retain_closed(&mut closed, &mut queue, &control, 10_002 * s);
        assert_eq!(closed.len(), 1, "clearing is one-shot");
    }

    #[test]
    fn loopback_ends_are_paired_with_their_processes() {
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let mut t = ProcessTable::new(Filter::default(), tx);
        let enr = Enricher {
            dns: Dns::new(false, 0),
            services: Arc::new(ServiceMap::default()),
        };
        let word = proc(&mut t, 40, 1, 400, "WINWORD.EXE");
        let xray = proc(&mut t, 50, 1, 500, "xray.exe");
        let key = |l: &str, r: &str| FlowKey {
            proto: Proto::Tcp,
            local: l.parse().unwrap(),
            remote: r.parse().unwrap(),
        };
        let mut b = TreeBuilder::default();
        let mut conns = vec![
            // Word through the system proxy, and the proxy's accepted end of the same socket.
            b.conn(
                &enr,
                word.clone(),
                key("127.0.0.1:50123", "127.0.0.1:10808"),
            ),
            b.conn(
                &enr,
                xray.clone(),
                key("127.0.0.1:10808", "127.0.0.1:50123"),
            ),
            // A loopback client whose server end is not tracked; direction unknown.
            b.conn(&enr, word.clone(), key("127.0.0.1:50999", "127.0.0.1:8080")),
            b.conn(
                &enr,
                xray.clone(),
                key("10.0.0.2:2892", "203.0.113.10:2052"),
            ),
        ];
        conns[0].dir = Direction::Outbound;
        conns[1].dir = Direction::Inbound;
        finish_rows(&mut conns);
        let client = conns[0].link.as_ref().unwrap();
        assert!(!client.inbound);
        assert_eq!(client.peer.as_ref().unwrap().name, "xray.exe");
        assert_eq!(client.label(), "via xray.exe (50)");
        let server = conns[1].link.as_ref().unwrap();
        assert!(server.inbound);
        assert_eq!(server.label(), "from WINWORD.EXE (40)");
        let lone = conns[2].link.as_ref().unwrap();
        assert!(!lone.inbound && lone.peer.is_none());
        assert!(conns[3].link.is_none());
    }
}
