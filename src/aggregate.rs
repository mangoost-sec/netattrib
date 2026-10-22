//! Thread-safe state aggregator.
//!
//! Merges three asynchronous inputs into one consistent flow table:
//! ETW network/process/DNS events (consumer thread), IP Helper polls (poller thread) and
//! housekeeping ticks. All mutation happens under one short-held mutex; records are built
//! into a local outbox and handed to the output channel *after* the lock is released, with
//! `try_send` so a slow sink can never stall kernel event delivery (drops are counted).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};

use crate::capture::etw::{NetEvent, NetOp};
use crate::capture::iphlp::{TcpRow, UdpRow};
use crate::dns::Dns;
use crate::model::*;
use crate::process::query::SnapEntry;
use crate::process::{Process, ProcessTable, Seed};
use crate::util::{FileTime, TICKS_PER_MS, TICKS_PER_SEC};

/// How long an ETW event for an unknown PID waits for its ProcessStart to arrive
/// (real-time buffers from different CPUs are not delivered in strict order).
const PENDING_WAIT: u64 = 1500 * TICKS_PER_MS;
const MAX_PENDING: usize = 50_000;
/// Suppress resurrection of a closed flow by late table rows / late ETW data events.
const TOMBSTONE_TTL: u64 = 240 * TICKS_PER_SEC;
const TOMBSTONE_POLL_GUARD: u64 = 5 * TICKS_PER_SEC;
/// ETW mode: how long a socket first seen by a table poll waits for an ETW event before it is
/// announced as poll-sourced. Real-time buffers are delivered at least every FlushTimer
/// (1 s, the documented minimum) and are force-flushed before each poll; 3 s leaves margin
/// for a busy consumer.
pub const ETW_CONFIRM_WINDOW: u64 = 3 * TICKS_PER_SEC;
const MAX_REMOTES_PER_EXE: usize = 4096;
const MAX_DNS_NAMES_PER_EXE: usize = 1024;

#[derive(Clone, Copy)]
pub struct EngineConfig {
    pub include_loopback: bool,
    pub listening: bool,
    pub udp_idle: u64,
    pub poll_interval: u64,
    pub states: bool,
    pub dns_events: bool,
    /// An ETW session is feeding the engine: table polls are reconciliation, not discovery.
    pub etw: bool,
}

#[derive(Default)]
pub struct Counters {
    pub etw_events: AtomicU64,
    pub net_events: AtomicU64,
    pub emitted: AtomicU64,
    pub dropped: AtomicU64,
    pub unattributed: AtomicU64,
    pub deferred: AtomicU64,
    pub polls: AtomicU64,
    pub etw_lost: AtomicU64,
}

struct Flow {
    proc: Arc<Process>,
    exe: Option<usize>,
    state: ConnState,
    dir: Direction,
    first_seen: FileTime,
    last_activity: FileTime,
    tx: u64,
    rx: u64,
    retrans: u32,
    source: Source,
    attribution: Attribution,
    /// `Some(deadline)` while the `open` record is withheld awaiting ETW confirmation.
    announce_by: Option<FileTime>,
    /// ETW mode: first poll in which the socket was absent from the table. The close is
    /// held back so ETW can still deliver its Disconnect and final byte counts.
    missing_since: Option<FileTime>,
    poll_gen: u64,
}

#[derive(Default, Clone)]
pub struct RemoteStat {
    pub conns: u32,
    pub tx: u64,
    pub rx: u64,
    pub last: FileTime,
    pub last_port: u16,
}

pub struct ExeStats {
    pub name: String,
    pub path: String,
    pub sample: Arc<Process>,
    pub pids: BTreeSet<u32>,
    pub active: u32,
    pub total: u64,
    pub tcp: u64,
    pub udp: u64,
    pub tx: u64,
    pub rx: u64,
    pub remotes: HashMap<IpAddr, RemoteStat>,
    pub remotes_overflow: u64,
    pub dns_names: HashMap<String, u32>,
    pub first_seen: FileTime,
    pub last_seen: FileTime,
}

struct Pending {
    deadline: FileTime,
    first: NetEvent,
    tx: u64,
    rx: u64,
}

struct Listener {
    pid: u32,
    proc: Arc<Process>,
    poll_gen: u64,
}

pub struct State {
    pub procs: ProcessTable,
    flows: HashMap<FlowKey, Flow>,
    tombstones: HashMap<FlowKey, FileTime>,
    exes: Vec<ExeStats>,
    exe_index: HashMap<String, usize>,
    listen_ports: HashSet<u16>,
    listeners: HashMap<(Proto, SocketAddr), Listener>,
    pending: HashMap<FlowKey, Pending>,
    poll_gen: u64,
    first_poll_done: bool,
    last_gc: FileTime,
}

pub struct Engine {
    state: Mutex<State>,
    cfg: EngineConfig,
    out: Option<SyncSender<Record>>,
    dns: Arc<Dns>,
    pub counters: Counters,
    pub started: FileTime,
}

type Outbox = Vec<Record>;

impl Engine {
    pub fn new(
        cfg: EngineConfig,
        procs: ProcessTable,
        out: Option<SyncSender<Record>>,
        dns: Arc<Dns>,
    ) -> Self {
        let now = crate::util::now();
        Engine {
            state: Mutex::new(State {
                procs,
                flows: HashMap::with_capacity(4096),
                tombstones: HashMap::new(),
                exes: Vec::new(),
                exe_index: HashMap::new(),
                listen_ports: HashSet::new(),
                listeners: HashMap::new(),
                pending: HashMap::new(),
                poll_gen: 0,
                first_poll_done: false,
                last_gc: now,
            }),
            cfg,
            out,
            dns,
            counters: Counters::default(),
            started: now,
        }
    }

    fn flush(&self, outbox: Outbox) {
        let Some(tx) = &self.out else { return };
        for r in outbox {
            match tx.try_send(r) {
                Ok(()) => self.counters.emitted.fetch_add(1, Ordering::Relaxed),
                Err(_) => self.counters.dropped.fetch_add(1, Ordering::Relaxed),
            };
        }
    }

    fn with_state(&self, f: impl FnOnce(&mut State, &EngineConfig, &Dns, &mut Outbox)) {
        let mut outbox = Outbox::new();
        {
            let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
            f(&mut st, &self.cfg, &self.dns, &mut outbox);
        }
        self.flush(outbox);
    }

    pub fn on_net(&self, ev: NetEvent) {
        self.counters.net_events.fetch_add(1, Ordering::Relaxed);
        if !self.cfg.include_loopback
            && (ev.key.remote.ip().is_loopback() || ev.key.local.ip().is_loopback())
        {
            return;
        }
        let c = &self.counters;
        self.with_state(|st, cfg, dns, out| st.net(ev, cfg, dns, c, out));
    }

    pub fn on_process_start(&self, seed: Seed) {
        let pid = seed.pid;
        self.with_state(|st, cfg, dns, out| {
            st.procs.insert(seed);
            // Events that raced ahead of this ProcessStart can be attributed right away.
            if !st.pending.is_empty() {
                let keys: Vec<FlowKey> = st
                    .pending
                    .iter()
                    .filter(|(_, p)| p.first.pid == pid)
                    .map(|(k, _)| *k)
                    .collect();
                for k in keys {
                    st.resolve_pending(k, cfg, dns, out);
                }
            }
        });
    }

    pub fn on_process_stop(&self, pid: u32, create_time: FileTime, ts: FileTime, name: &str) {
        self.with_state(|st, _, _, _| st.procs.on_exit(pid, create_time, ts, name));
    }

    pub fn on_dns(&self, pid: u32, ts: FileTime, answer: DnsAnswer) {
        let dns_events = self.cfg.dns_events;
        self.with_state(|st, _, _, out| {
            let Some(p) = st.procs.lookup(pid, ts) else {
                return;
            };
            if !p.included {
                return;
            }
            let i = st.exe_for(&p, ts);
            let e = &mut st.exes[i];
            if e.dns_names.len() < MAX_DNS_NAMES_PER_EXE || e.dns_names.contains_key(&answer.query)
            {
                *e.dns_names.entry(answer.query.clone()).or_insert(0) += 1;
            }
            if dns_events {
                let first = answer.addrs.first().copied();
                let v4 = first.is_none_or(|a| a.is_ipv4());
                out.push(Record {
                    ts,
                    kind: EventKind::Dns,
                    proc: p,
                    key: FlowKey {
                        proto: Proto::Udp,
                        local: unspecified(v4),
                        remote: first
                            .map(|a| SocketAddr::new(a, 53))
                            .unwrap_or_else(|| unspecified(v4)),
                    },
                    state: ConnState::Unknown,
                    direction: Direction::Outbound,
                    bytes_sent: 0,
                    bytes_recv: 0,
                    retransmits: 0,
                    duration: 0,
                    source: Source::Etw,
                    attribution: Attribution::Exact,
                    reason: None,
                    dns: Some(Arc::new(answer)),
                });
            }
        });
    }

    /// Polling-mode process tracking (no ETW): reconcile generations from a fresh snapshot.
    pub fn on_process_snapshot(&self, snap: &[SnapEntry], now: FileTime) {
        self.with_state(|st, _, _, _| st.procs.reconcile(snap, now));
    }

    /// Polling mode: true if the tables contain a socket that `on_poll` would have to
    /// attribute. Only then is a (costly) process snapshot needed for PID-reuse safety.
    pub fn has_unknown_rows(&self, tcp: &[TcpRow], udp: &[UdpRow]) -> bool {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let cfg = &self.cfg;
        let now = crate::util::now();
        let listener_known =
            |k: (Proto, SocketAddr), pid: u32| st.listeners.get(&k).is_some_and(|l| l.pid == pid);
        tcp.iter().any(|r| {
            if r.pid == 0 {
                return false;
            }
            if r.state == ConnState::Listen {
                return cfg.listening && !listener_known((Proto::Tcp, r.local), r.pid);
            }
            if !cfg.include_loopback && (r.remote.ip().is_loopback() || r.local.ip().is_loopback())
            {
                return false;
            }
            let key = FlowKey {
                proto: Proto::Tcp,
                local: r.local,
                remote: r.remote,
            };
            !st.flows.contains_key(&key) && !st.tombstone_suppresses(&key, r.state, now)
        }) || (cfg.listening
            && udp
                .iter()
                .any(|r| !listener_known((Proto::Udp, r.local), r.pid)))
    }

    /// `t1` must be the time the tables were read (before any process snapshot) so PID
    /// ownership is evaluated at the instant the table reported it.
    pub fn on_poll(&self, tcp: &[TcpRow], udp: &[UdpRow], t1: FileTime) {
        self.counters.polls.fetch_add(1, Ordering::Relaxed);
        self.with_state(|st, cfg, dns, out| st.poll(tcp, udp, t1, cfg, dns, out));
    }

    pub fn tick(&self, now: FileTime) {
        self.with_state(|st, cfg, dns, out| st.tick(now, cfg, dns, out));
    }

    /// Emits a `close` (reason `shutdown`) for every open flow so exported byte counters are final.
    pub fn shutdown(&self, now: FileTime) {
        self.with_state(|st, cfg, dns, out| {
            let keys: Vec<FlowKey> = st.pending.keys().copied().collect();
            for k in keys {
                st.resolve_pending(k, cfg, dns, out);
            }
            let keys: Vec<FlowKey> = st.flows.keys().copied().collect();
            for k in keys {
                st.close(k, now, CloseReason::Shutdown, out);
            }
        });
    }

    pub fn snapshot(&self, opts: &SnapshotOpts) -> TopSnapshot {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.snapshot(opts)
    }

    /// Live processes (one generation per PID), for the GUI process tree.
    pub fn processes(&self) -> Vec<Arc<Process>> {
        let st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        st.procs.alive()
    }
}

// ---------------------------------------------------------------------------------------
// State transitions
// ---------------------------------------------------------------------------------------

impl State {
    /// A table row for a 4-tuple we already closed is a teardown echo (FIN_WAIT2, LAST_ACK,
    /// CLOSE_WAIT linger for minutes after the ETW disconnect) - unless it is a handshake or
    /// established row old enough to be a new connection that reused the tuple.
    fn tombstone_suppresses(&self, key: &FlowKey, state: ConnState, now: FileTime) -> bool {
        let Some(&t) = self.tombstones.get(key) else {
            return false;
        };
        let reopening = matches!(
            state,
            ConnState::SynSent | ConnState::SynRcvd | ConnState::Established
        );
        !reopening || now.saturating_sub(t) < TOMBSTONE_POLL_GUARD
    }

    fn exe_for(&mut self, p: &Arc<Process>, ts: FileTime) -> usize {
        if let Some(&i) = self.exe_index.get(&p.key) {
            return i;
        }
        let i = self.exes.len();
        self.exes.push(ExeStats {
            name: p.name.clone(),
            path: p.path.clone(),
            sample: p.clone(),
            pids: BTreeSet::new(),
            active: 0,
            total: 0,
            tcp: 0,
            udp: 0,
            tx: 0,
            rx: 0,
            remotes: HashMap::new(),
            remotes_overflow: 0,
            dns_names: HashMap::new(),
            first_seen: ts,
            last_seen: ts,
        });
        self.exe_index.insert(p.key.clone(), i);
        i
    }

    fn net(&mut self, ev: NetEvent, cfg: &EngineConfig, dns: &Dns, c: &Counters, out: &mut Outbox) {
        if let Some(f) = self.flows.get_mut(&ev.key) {
            promote(f, &ev);
            if ev.op == NetOp::Disconnect {
                self.close(ev.key, ev.ts, CloseReason::Disconnect, out);
                return;
            }
            let exe = f.exe;
            let old = f.state;
            apply_op(f, &ev);
            let (state, dir, included, announced, source) = (
                f.state,
                f.dir,
                f.exe.is_some(),
                f.announce_by.is_none(),
                f.source,
            );
            if let Some(i) = exe {
                account_bytes(&mut self.exes[i], &ev);
            }
            if !announced && source == Source::Etw {
                // Confirmed by ETW: announce now, with the ETW start time and direction.
                self.announce(ev.key, out);
            } else if announced && included && cfg.states && old != state {
                let f = &self.flows[&ev.key];
                out.push(record(EventKind::State, ev.ts, ev.key, f, state, dir, None));
            }
            return;
        }
        if let Some(p) = self.pending.get_mut(&ev.key) {
            match ev.op {
                NetOp::Send => p.tx += ev.size as u64,
                NetOp::Recv => p.rx += ev.size as u64,
                _ => {}
            }
            return;
        }
        match ev.op {
            // Teardown of something we never saw open: nothing useful to report.
            NetOp::Disconnect => return,
            NetOp::Send | NetOp::Recv | NetOp::Retransmit
                if self.tombstones.contains_key(&ev.key) =>
            {
                return
            }
            NetOp::Connect | NetOp::Accept | NetOp::Reconnect => {
                self.tombstones.remove(&ev.key);
            }
            _ => {}
        }
        if ev.pid == 0 {
            c.unattributed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match self.procs.lookup(ev.pid, ev.ts) {
            Some(p) => self.open_from_etw(ev, p, Attribution::Exact, 0, 0, cfg, dns, out),
            None => {
                if self.pending.len() >= MAX_PENDING {
                    c.unattributed.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                c.deferred.fetch_add(1, Ordering::Relaxed);
                let (tx, rx) = match ev.op {
                    NetOp::Send => (ev.size as u64, 0),
                    NetOp::Recv => (0, ev.size as u64),
                    _ => (0, 0),
                };
                self.pending.insert(
                    ev.key,
                    Pending {
                        deadline: ev.ts + PENDING_WAIT,
                        first: ev,
                        tx,
                        rx,
                    },
                );
            }
        }
    }

    fn resolve_pending(&mut self, key: FlowKey, cfg: &EngineConfig, dns: &Dns, out: &mut Outbox) {
        let Some(p) = self.pending.remove(&key) else {
            return;
        };
        let ev = p.first;
        let (proc, attr) = match self.procs.lookup(ev.pid, ev.ts) {
            Some(proc) => (proc, Attribution::Exact),
            None => {
                let proc = self.procs.resolve(ev.pid, ev.ts);
                let attr = proc.attribution;
                (proc, attr)
            }
        };
        // The first event's bytes are already folded into p.tx/p.rx.
        let mut first = ev;
        if matches!(first.op, NetOp::Send | NetOp::Recv) {
            first.size = 0;
        }
        self.open_from_etw(first, proc, attr, p.tx, p.rx, cfg, dns, out);
    }

    #[allow(clippy::too_many_arguments)]
    fn open_from_etw(
        &mut self,
        ev: NetEvent,
        proc: Arc<Process>,
        attribution: Attribution,
        tx: u64,
        rx: u64,
        _cfg: &EngineConfig,
        dns: &Dns,
        out: &mut Outbox,
    ) {
        let (state, dir) = match (ev.key.proto, ev.op) {
            (Proto::Tcp, NetOp::Connect) => (ConnState::Established, Direction::Outbound),
            (Proto::Tcp, NetOp::Accept) => (ConnState::Established, Direction::Inbound),
            (Proto::Tcp, NetOp::Reconnect) => (ConnState::SynSent, Direction::Outbound),
            (Proto::Tcp, _) => (ConnState::Established, self.infer_dir(&ev.key)),
            (Proto::Udp, NetOp::Send) => (ConnState::Active, Direction::Outbound),
            (Proto::Udp, _) => (ConnState::Active, Direction::Inbound),
        };
        self.open(
            ev.key,
            proc,
            state,
            dir,
            ev.ts,
            Source::Etw,
            attribution,
            None,
            dns,
            out,
        );
        if let Some(f) = self.flows.get_mut(&ev.key) {
            f.tx += tx;
            f.rx += rx;
            apply_op(f, &ev);
            f.state = state;
            if let Some(i) = f.exe {
                let e = &mut self.exes[i];
                e.tx += tx;
                e.rx += rx;
                if let Some(r) = e.remotes.get_mut(&ev.key.remote.ip()) {
                    r.tx += tx;
                    r.rx += rx;
                }
                account_bytes(e, &ev);
            }
        }
    }

    fn infer_dir(&self, key: &FlowKey) -> Direction {
        if key.proto == Proto::Tcp && self.listen_ports.contains(&key.local.port()) {
            Direction::Inbound
        } else if key.proto == Proto::Tcp && self.first_poll_done {
            Direction::Outbound
        } else {
            Direction::Unknown
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn open(
        &mut self,
        key: FlowKey,
        proc: Arc<Process>,
        state: ConnState,
        dir: Direction,
        ts: FileTime,
        source: Source,
        attribution: Attribution,
        announce_by: Option<FileTime>,
        dns: &Dns,
        out: &mut Outbox,
    ) {
        let exe = if proc.included {
            Some(self.exe_for(&proc, ts))
        } else {
            None
        };
        if let Some(i) = exe {
            let e = &mut self.exes[i];
            e.total += 1;
            e.active += 1;
            match key.proto {
                Proto::Tcp => e.tcp += 1,
                Proto::Udp => e.udp += 1,
            }
            if e.pids.len() < 256 {
                e.pids.insert(proc.pid);
            }
            e.last_seen = ts;
            let ip = key.remote.ip();
            if e.remotes.len() < MAX_REMOTES_PER_EXE || e.remotes.contains_key(&ip) {
                let r = e.remotes.entry(ip).or_default();
                r.conns += 1;
                r.last = ts;
                r.last_port = key.remote.port();
            } else {
                e.remotes_overflow += 1;
            }
            dns.prefetch(ip);
        }
        let flow = Flow {
            proc,
            exe,
            state,
            dir,
            first_seen: ts,
            last_activity: ts,
            tx: 0,
            rx: 0,
            retrans: 0,
            source,
            attribution,
            announce_by,
            missing_since: None,
            poll_gen: 0,
        };
        if exe.is_some() && announce_by.is_none() {
            out.push(record(EventKind::Open, ts, key, &flow, state, dir, None));
        }
        self.flows.insert(key, flow);
    }

    /// Emits the withheld `open` record of a flow (no-op if already announced).
    fn announce(&mut self, key: FlowKey, out: &mut Outbox) {
        let Some(f) = self.flows.get_mut(&key) else {
            return;
        };
        if f.announce_by.take().is_some() && f.exe.is_some() {
            out.push(record(
                EventKind::Open,
                f.first_seen,
                key,
                f,
                f.state,
                f.dir,
                None,
            ));
        }
    }

    fn close(&mut self, key: FlowKey, ts: FileTime, reason: CloseReason, out: &mut Outbox) {
        // A flow closed inside its confirmation window still gets its open, in order.
        self.announce(key, out);
        let Some(f) = self.flows.remove(&key) else {
            return;
        };
        if key.proto == Proto::Tcp {
            self.tombstones.insert(key, ts);
        }
        if let Some(i) = f.exe {
            let e = &mut self.exes[i];
            e.active = e.active.saturating_sub(1);
            e.last_seen = e.last_seen.max(ts);
            out.push(record(
                EventKind::Close,
                ts,
                key,
                &f,
                ConnState::Closed,
                f.dir,
                Some(reason),
            ));
        }
    }

    fn poll(
        &mut self,
        tcp: &[TcpRow],
        udp: &[UdpRow],
        t1: FileTime,
        cfg: &EngineConfig,
        dns: &Dns,
        out: &mut Outbox,
    ) {
        self.poll_gen += 1;
        let gen = self.poll_gen;
        let source = if self.first_poll_done {
            Source::Poll
        } else {
            Source::Snapshot
        };

        self.listen_ports.clear();
        self.listen_ports.extend(
            tcp.iter()
                .filter(|r| r.state == ConnState::Listen)
                .map(|r| r.local.port()),
        );

        for r in tcp {
            if r.state == ConnState::Listen {
                if cfg.listening {
                    self.listener_seen(Proto::Tcp, r.local, r.pid, gen, t1, out);
                }
                continue;
            }
            if !cfg.include_loopback && (r.remote.ip().is_loopback() || r.local.ip().is_loopback())
            {
                continue;
            }
            let key = FlowKey {
                proto: Proto::Tcp,
                local: r.local,
                remote: r.remote,
            };
            if let Some(f) = self.flows.get_mut(&key) {
                f.poll_gen = gen;
                f.missing_since = None;
                if f.state != r.state {
                    f.state = r.state;
                    if f.exe.is_some() && cfg.states && f.announce_by.is_none() {
                        let f = &self.flows[&key];
                        out.push(record(EventKind::State, t1, key, f, r.state, f.dir, None));
                    }
                }
                continue;
            }
            // TIME_WAIT rows have no owner; anything closed moments ago is a late echo.
            if r.pid == 0 || self.pending.contains_key(&key) {
                continue;
            }
            if self.tombstone_suppresses(&key, r.state, t1) {
                continue;
            }
            if r.state.is_terminal() && self.first_poll_done {
                continue;
            }
            let proc = self.procs.resolve(r.pid, t1);
            let attr = if proc.attribution == Attribution::Exited {
                Attribution::Exited
            } else {
                Attribution::Exact
            };
            let dir = if self.listen_ports.contains(&r.local.port()) {
                Direction::Inbound
            } else {
                Direction::Outbound
            };
            // With ETW running, the table poll can see a socket before its ETW events are
            // delivered. Track it now, but let ETW claim (and timestamp) it before announcing.
            let announce_by = cfg.etw.then_some(t1 + ETW_CONFIRM_WINDOW);
            self.open(
                key,
                proc,
                r.state,
                dir,
                t1,
                source,
                attr,
                announce_by,
                dns,
                out,
            );
            if let Some(f) = self.flows.get_mut(&key) {
                f.poll_gen = gen;
            }
        }

        // TCP flows missing from this poll are gone. ETW-born flows that have not shown up
        // in any poll yet get two intervals of grace (they may simply be younger than the poll).
        let grace = 2 * cfg.poll_interval;
        let gone: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(k, f)| {
                k.proto == Proto::Tcp
                    && f.poll_gen != gen
                    && (f.poll_gen != 0 || t1.saturating_sub(f.last_activity) > grace)
            })
            .map(|(k, _)| *k)
            .collect();
        for k in gone {
            if cfg.etw {
                // Its Disconnect and last bytes may still be in flight from ETW; `tick`
                // closes it as gone only if ETW stays silent for the confirmation window.
                if let Some(f) = self.flows.get_mut(&k) {
                    f.missing_since.get_or_insert(t1);
                }
            } else {
                self.close(k, t1, CloseReason::Gone, out);
            }
        }

        if cfg.listening {
            for r in udp {
                if !cfg.include_loopback && r.local.ip().is_loopback() {
                    continue;
                }
                self.listener_seen(Proto::Udp, r.local, r.pid, gen, t1, out);
            }
            let stale: Vec<(Proto, SocketAddr)> = self
                .listeners
                .iter()
                .filter(|(_, l)| l.poll_gen != gen)
                .map(|(k, _)| *k)
                .collect();
            for k in stale {
                if let Some(l) = self.listeners.remove(&k) {
                    if l.proc.included {
                        out.push(listener_record(k, &l, t1, EventKind::Close));
                    }
                }
            }
        }
        self.first_poll_done = true;
    }

    fn listener_seen(
        &mut self,
        proto: Proto,
        local: SocketAddr,
        pid: u32,
        gen: u64,
        ts: FileTime,
        out: &mut Outbox,
    ) {
        let k = (proto, local);
        if let Some(l) = self.listeners.get_mut(&k) {
            if l.pid == pid {
                l.poll_gen = gen;
                return;
            }
        }
        let proc = self.procs.resolve(pid, ts);
        let l = Listener {
            pid,
            proc,
            poll_gen: gen,
        };
        if l.proc.included {
            out.push(listener_record(k, &l, ts, EventKind::Listen));
        }
        self.listeners.insert(k, l);
    }

    fn tick(&mut self, now: FileTime, cfg: &EngineConfig, dns: &Dns, out: &mut Outbox) {
        let unconfirmed: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, f)| f.announce_by.is_some_and(|d| d <= now))
            .map(|(k, _)| *k)
            .collect();
        for k in unconfirmed {
            self.announce(k, out);
        }
        let vanished: Vec<(FlowKey, FileTime)> = self
            .flows
            .iter()
            .filter_map(|(k, f)| {
                f.missing_since
                    .filter(|&m| now.saturating_sub(m) >= ETW_CONFIRM_WINDOW)
                    .map(|m| (*k, m))
            })
            .collect();
        for (k, missing_since) in vanished {
            self.close(k, missing_since, CloseReason::Gone, out);
        }
        if !self.pending.is_empty() {
            let due: Vec<FlowKey> = self
                .pending
                .iter()
                .filter(|(_, p)| p.deadline <= now)
                .map(|(k, _)| *k)
                .collect();
            for k in due {
                self.resolve_pending(k, cfg, dns, out);
            }
        }
        let idle: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(k, f)| {
                k.proto == Proto::Udp && now.saturating_sub(f.last_activity) > cfg.udp_idle
            })
            .map(|(k, _)| *k)
            .collect();
        for k in idle {
            let ts = self.flows[&k].last_activity;
            self.close(k, ts, CloseReason::Idle, out);
        }
        if now.saturating_sub(self.last_gc) > 10 * TICKS_PER_SEC {
            self.last_gc = now;
            self.tombstones
                .retain(|_, t| now.saturating_sub(*t) < TOMBSTONE_TTL);
            self.procs.gc(now);
        }
    }
}

/// An ETW event for a flow first found by a table poll proves ETW observed the socket:
/// the flow becomes ETW-sourced. While its `open` is still withheld it also adopts the ETW
/// start time and the authoritative direction. A pre-existing (snapshot) connection is only
/// re-labelled by a lifecycle-start event, which proves it was born during monitoring.
fn promote(f: &mut Flow, ev: &NetEvent) {
    let born_now = matches!(ev.op, NetOp::Connect | NetOp::Accept | NetOp::Reconnect);
    let eligible = match f.source {
        Source::Poll => true,
        Source::Snapshot => born_now,
        Source::Etw => false,
    };
    if !eligible {
        return;
    }
    f.source = Source::Etw;
    if f.announce_by.is_some() {
        f.first_seen = f.first_seen.min(ev.ts);
        match ev.op {
            NetOp::Connect | NetOp::Reconnect => f.dir = Direction::Outbound,
            NetOp::Accept => f.dir = Direction::Inbound,
            _ => {}
        }
    }
}

fn apply_op(f: &mut Flow, ev: &NetEvent) {
    match ev.op {
        NetOp::Send => f.tx += ev.size as u64,
        NetOp::Recv => f.rx += ev.size as u64,
        NetOp::Retransmit => f.retrans += 1,
        NetOp::Connect | NetOp::Accept => {
            if f.state == ConnState::SynSent
                || f.state == ConnState::SynRcvd
                || f.state == ConnState::Unknown
            {
                f.state = ConnState::Established;
            }
        }
        NetOp::Reconnect => {
            if f.state == ConnState::Unknown {
                f.state = ConnState::SynSent;
            }
        }
        NetOp::Disconnect => {}
    }
    f.last_activity = f.last_activity.max(ev.ts);
}

fn account_bytes(e: &mut ExeStats, ev: &NetEvent) {
    let (tx, rx) = match ev.op {
        NetOp::Send => (ev.size as u64, 0),
        NetOp::Recv => (0, ev.size as u64),
        _ => return,
    };
    e.tx += tx;
    e.rx += rx;
    e.last_seen = e.last_seen.max(ev.ts);
    if let Some(r) = e.remotes.get_mut(&ev.key.remote.ip()) {
        r.tx += tx;
        r.rx += rx;
        r.last = r.last.max(ev.ts);
    }
}

fn record(
    kind: EventKind,
    ts: FileTime,
    key: FlowKey,
    f: &Flow,
    state: ConnState,
    dir: Direction,
    reason: Option<CloseReason>,
) -> Record {
    Record {
        ts,
        kind,
        proc: f.proc.clone(),
        key,
        state,
        direction: dir,
        bytes_sent: f.tx,
        bytes_recv: f.rx,
        retransmits: f.retrans,
        duration: ts.saturating_sub(f.first_seen),
        source: f.source,
        attribution: if f.proc.attribution == Attribution::Exited {
            Attribution::Exited
        } else {
            f.attribution
        },
        reason,
        dns: None,
    }
}

fn listener_record(k: (Proto, SocketAddr), l: &Listener, ts: FileTime, kind: EventKind) -> Record {
    let (proto, local) = k;
    Record {
        ts,
        kind,
        proc: l.proc.clone(),
        key: FlowKey {
            proto,
            local,
            remote: unspecified(local.is_ipv4()),
        },
        state: if kind == EventKind::Close {
            ConnState::Closed
        } else if proto == Proto::Tcp {
            ConnState::Listen
        } else {
            ConnState::Bound
        },
        direction: Direction::Inbound,
        bytes_sent: 0,
        bytes_recv: 0,
        retransmits: 0,
        duration: 0,
        source: Source::Poll,
        attribution: l.proc.attribution,
        reason: (kind == EventKind::Close).then_some(CloseReason::Gone),
        dns: None,
    }
}

// ---------------------------------------------------------------------------------------
// Snapshots for Mode B (aggregated view) and summary export
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortKey {
    Activity,
    Conns,
    Active,
    Tx,
    Rx,
    Remotes,
    Name,
}

pub struct SnapshotOpts {
    pub sort: SortKey,
    pub max_rows: usize,
    pub remotes_per_row: usize,
    pub dns_per_row: usize,
    pub live_limit: usize,
    /// Only rows whose `last_seen` is at or after this time (incremental export).
    pub changed_since: FileTime,
}

pub struct RemoteRow {
    pub ip: IpAddr,
    pub stat: RemoteStat,
}

pub struct TopRow {
    pub name: String,
    pub path: String,
    pub sample: Arc<Process>,
    pub pids: Vec<u32>,
    pub active: u32,
    pub total: u64,
    pub tcp: u64,
    pub udp: u64,
    pub tx: u64,
    pub rx: u64,
    pub unique_remotes: usize,
    pub remotes_overflow: u64,
    pub top_remotes: Vec<RemoteRow>,
    pub dns_names: Vec<(String, u32)>,
    pub first_seen: FileTime,
    pub last_seen: FileTime,
}

pub struct LiveConn {
    pub proc: Arc<Process>,
    pub key: FlowKey,
    pub state: ConnState,
    pub dir: Direction,
    pub tx: u64,
    pub rx: u64,
    pub first_seen: FileTime,
    pub last_activity: FileTime,
}

pub struct TopSnapshot {
    pub rows: Vec<TopRow>,
    pub total_rows: usize,
    pub live: Vec<LiveConn>,
    pub live_total: usize,
    pub flows_tracked: usize,
    pub procs_alive: usize,
    pub pending: usize,
}

impl State {
    fn snapshot(&self, o: &SnapshotOpts) -> TopSnapshot {
        let mut idx: Vec<usize> = (0..self.exes.len())
            .filter(|&i| self.exes[i].last_seen >= o.changed_since && self.exes[i].total > 0)
            .collect();
        let key = |i: &usize| {
            let e = &self.exes[*i];
            match o.sort {
                SortKey::Activity => (e.active as u64, e.tx + e.rx, e.total),
                SortKey::Conns => (e.total, e.active as u64, e.tx + e.rx),
                SortKey::Active => (e.active as u64, e.total, 0),
                SortKey::Tx => (e.tx, e.rx, e.total),
                SortKey::Rx => (e.rx, e.tx, e.total),
                SortKey::Remotes => (e.remotes.len() as u64, e.total, 0),
                SortKey::Name => (0, 0, 0),
            }
        };
        if o.sort == SortKey::Name {
            idx.sort_by(|a, b| {
                self.exes[*a]
                    .name
                    .to_lowercase()
                    .cmp(&self.exes[*b].name.to_lowercase())
            });
        } else {
            idx.sort_by_key(|i| std::cmp::Reverse(key(i)));
        }
        let total_rows = idx.len();
        let rows = idx
            .into_iter()
            .take(o.max_rows)
            .map(|i| {
                let e = &self.exes[i];
                let mut remotes: Vec<RemoteRow> = e
                    .remotes
                    .iter()
                    .map(|(ip, s)| RemoteRow {
                        ip: *ip,
                        stat: s.clone(),
                    })
                    .collect();
                remotes.sort_by_key(|r| std::cmp::Reverse((r.stat.conns, r.stat.tx + r.stat.rx)));
                remotes.truncate(o.remotes_per_row);
                let mut names: Vec<(String, u32)> =
                    e.dns_names.iter().map(|(n, c)| (n.clone(), *c)).collect();
                names.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                names.truncate(o.dns_per_row);
                TopRow {
                    name: e.name.clone(),
                    path: e.path.clone(),
                    sample: e.sample.clone(),
                    pids: e.pids.iter().copied().collect(),
                    active: e.active,
                    total: e.total,
                    tcp: e.tcp,
                    udp: e.udp,
                    tx: e.tx,
                    rx: e.rx,
                    unique_remotes: e.remotes.len(),
                    remotes_overflow: e.remotes_overflow,
                    top_remotes: remotes,
                    dns_names: names,
                    first_seen: e.first_seen,
                    last_seen: e.last_seen,
                }
            })
            .collect();
        let mut live: Vec<LiveConn> = self
            .flows
            .iter()
            .filter(|(_, f)| f.exe.is_some())
            .map(|(k, f)| LiveConn {
                proc: f.proc.clone(),
                key: *k,
                state: f.state,
                dir: f.dir,
                tx: f.tx,
                rx: f.rx,
                first_seen: f.first_seen,
                last_activity: f.last_activity,
            })
            .collect();
        let live_total = live.len();
        live.sort_by_key(|c| std::cmp::Reverse(c.last_activity));
        live.truncate(o.live_limit);
        TopSnapshot {
            rows,
            total_rows,
            live,
            live_total,
            flows_tracked: self.flows.len(),
            procs_alive: self.procs.alive_count(),
            pending: self.pending.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::Filter;
    use std::sync::mpsc::{channel, sync_channel, Receiver};

    const S: u64 = TICKS_PER_SEC;

    fn engine(filter: Filter) -> (Engine, Receiver<Record>) {
        engine_with(filter, false)
    }

    fn engine_with(filter: Filter, etw: bool) -> (Engine, Receiver<Record>) {
        let (etx, _erx) = channel();
        std::mem::forget(_erx);
        let mut procs = ProcessTable::new(filter, etx);
        for (pid, name) in [(100u32, "winword.exe"), (200, "chrome.exe")] {
            procs.insert(Seed {
                pid,
                ppid: 1,
                create_time: S,
                session_id: 1,
                name: name.into(),
                path: format!("C:\\Apps\\{}", name),
                attribution: Attribution::Exact,
                exit_time: None,
            });
        }
        let (tx, rx) = sync_channel(1024);
        let cfg = EngineConfig {
            include_loopback: false,
            listening: false,
            udp_idle: 60 * S,
            poll_interval: S,
            states: true,
            dns_events: true,
            etw,
        };
        (Engine::new(cfg, procs, Some(tx), Dns::new(false, 0)), rx)
    }

    fn key(remote: &str, lport: u16) -> FlowKey {
        FlowKey {
            proto: Proto::Tcp,
            local: SocketAddr::from(([10, 0, 0, 2], lport)),
            remote: remote.parse().unwrap(),
        }
    }

    fn ev(pid: u32, op: NetOp, key: FlowKey, size: u32, ts: u64) -> NetEvent {
        NetEvent {
            ts,
            pid,
            op,
            key,
            size,
        }
    }

    fn drain(rx: &Receiver<Record>) -> Vec<Record> {
        rx.try_iter().collect()
    }

    #[test]
    fn etw_lifecycle_counts_bytes_and_closes() {
        let (e, rx) = engine(Filter::new(&["winword.exe".into()], &[], &[], false));
        let k = key("52.109.8.21:443", 50000);
        e.on_net(ev(100, NetOp::Connect, k, 0, 2 * S));
        e.on_net(ev(100, NetOp::Send, k, 1000, 2 * S + 1));
        e.on_net(ev(100, NetOp::Recv, k, 5000, 2 * S + 2));
        e.on_net(ev(100, NetOp::Disconnect, k, 0, 3 * S));
        let recs = drain(&rx);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].kind, EventKind::Open);
        assert_eq!(recs[0].direction, Direction::Outbound);
        assert_eq!(recs[1].kind, EventKind::Close);
        assert_eq!((recs[1].bytes_sent, recs[1].bytes_recv), (1000, 5000));
        assert_eq!(recs[1].reason, Some(CloseReason::Disconnect));
        // Late data after close is suppressed by the tombstone.
        e.on_net(ev(100, NetOp::Recv, k, 10, 3 * S + 5));
        assert!(drain(&rx).is_empty());
    }

    #[test]
    fn filter_excludes_other_processes() {
        let (e, rx) = engine(Filter::new(&["winword.exe".into()], &[], &[], false));
        e.on_net(ev(200, NetOp::Connect, key("1.1.1.1:443", 50001), 0, 2 * S));
        assert!(drain(&rx).is_empty());
        let snap = e.snapshot(&opts());
        assert_eq!(snap.rows.len(), 0);
    }

    #[test]
    fn unknown_pid_is_deferred_until_process_start() {
        let (e, rx) = engine(Filter::default());
        let k = key("8.8.4.4:443", 50002);
        e.on_net(ev(300, NetOp::Connect, k, 0, 5 * S));
        e.on_net(ev(300, NetOp::Send, k, 700, 5 * S + 1));
        assert!(drain(&rx).is_empty(), "held back while owner unknown");
        e.on_process_start(Seed {
            pid: 300,
            ppid: 1,
            create_time: 4 * S,
            session_id: 1,
            name: "late.exe".into(),
            path: "C:\\late.exe".into(),
            attribution: Attribution::Exact,
            exit_time: None,
        });
        let recs = drain(&rx);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].proc.name, "late.exe");
        let snap = e.snapshot(&opts());
        assert_eq!(snap.rows[0].tx, 700);
    }

    #[test]
    fn poll_seeds_states_and_detects_gone() {
        let (e, rx) = engine(Filter::default());
        let row = TcpRow {
            local: "10.0.0.2:50010".parse().unwrap(),
            remote: "20.1.1.1:443".parse().unwrap(),
            state: ConnState::Established,
            pid: 100,
        };
        e.on_poll(&[row], &[], 2 * S);
        let recs = drain(&rx);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].source, Source::Snapshot);
        let mut row2 = row;
        row2.state = ConnState::CloseWait;
        e.on_poll(&[row2], &[], 3 * S);
        let recs = drain(&rx);
        assert_eq!(recs[0].kind, EventKind::State);
        assert_eq!(recs[0].state, ConnState::CloseWait);
        e.on_poll(&[], &[], 4 * S);
        let recs = drain(&rx);
        assert_eq!(recs[0].kind, EventKind::Close);
        assert_eq!(recs[0].reason, Some(CloseReason::Gone));
    }

    #[test]
    fn teardown_rows_after_disconnect_are_not_reopened() {
        let (e, rx) = engine(Filter::default());
        let k = key("52.109.8.21:443", 50020);
        e.on_net(ev(100, NetOp::Connect, k, 0, 2 * S));
        e.on_net(ev(100, NetOp::Disconnect, k, 0, 3 * S));
        assert_eq!(drain(&rx).len(), 2);
        let lingering = TcpRow {
            local: k.local,
            remote: k.remote,
            state: ConnState::FinWait2,
            pid: 100,
        };
        // Well past the 5 s echo guard, the half-closed socket is still in the table.
        e.on_poll(&[lingering], &[], 30 * S);
        assert!(
            drain(&rx).is_empty(),
            "FIN_WAIT2 echo must not resurrect the flow"
        );
        assert!(!e.has_unknown_rows(&[lingering], &[]));
        // A fresh ESTABLISHED row on the same tuple much later is a genuinely new connection.
        let reused = TcpRow {
            state: ConnState::Established,
            ..lingering
        };
        e.on_poll(&[reused], &[], 60 * S);
        let recs = drain(&rx);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].kind, EventKind::Open);
    }

    fn row(k: FlowKey, state: ConnState, pid: u32) -> TcpRow {
        TcpRow {
            local: k.local,
            remote: k.remote,
            state,
            pid,
        }
    }

    #[test]
    fn etw_claims_socket_the_poll_saw_first() {
        // The self-test race: poll at t=6.0 s sees the socket, its ETW Connect (t=5.2 s) is
        // delivered at t=6.4 s.
        let (e, rx) = engine_with(Filter::default(), true);
        e.on_poll(&[], &[], 2 * S); // initial snapshot (empty)
        let k = key("198.18.0.17:80", 24350);
        e.on_poll(&[row(k, ConnState::Established, 100)], &[], 6 * S);
        assert!(
            drain(&rx).is_empty(),
            "poll-discovered socket is held for ETW confirmation"
        );
        e.on_net(ev(100, NetOp::Connect, k, 0, 5 * S + 2 * S / 10));
        e.on_net(ev(100, NetOp::Send, k, 56, 5 * S + 3 * S / 10));
        e.on_net(ev(100, NetOp::Recv, k, 928, 5 * S + 4 * S / 10));
        e.on_net(ev(100, NetOp::Disconnect, k, 0, 7 * S));
        let recs = drain(&rx);
        assert_eq!(recs.len(), 2, "exactly one open and one close");
        assert_eq!(recs[0].kind, EventKind::Open);
        assert_eq!(recs[0].source, Source::Etw);
        assert_eq!(
            recs[0].ts,
            5 * S + 2 * S / 10,
            "open carries the ETW start time"
        );
        assert_eq!(recs[0].direction, Direction::Outbound);
        assert_eq!(recs[1].kind, EventKind::Close);
        assert_eq!(recs[1].source, Source::Etw);
        assert_eq!((recs[1].bytes_sent, recs[1].bytes_recv), (56, 928));
        assert_eq!(recs[1].reason, Some(CloseReason::Disconnect));
    }

    #[test]
    fn etw_disconnect_wins_over_poll_disappearance() {
        let (e, rx) = engine_with(Filter::default(), true);
        e.on_poll(&[], &[], 2 * S);
        let k = key("198.18.0.17:80", 30121);
        e.on_net(ev(100, NetOp::Connect, k, 0, 3 * S));
        e.on_poll(&[row(k, ConnState::Established, 100)], &[], 3 * S + S / 4);
        // The socket is gone from the table before ETW delivered its last events.
        e.on_poll(&[], &[], 3 * S + S / 2);
        e.on_net(ev(100, NetOp::Recv, k, 928, 3 * S + S / 10));
        e.on_net(ev(100, NetOp::Disconnect, k, 0, 3 * S + S / 5));
        let recs = drain(&rx);
        let close = recs
            .iter()
            .find(|r| r.kind == EventKind::Close)
            .expect("closed");
        assert_eq!(close.reason, Some(CloseReason::Disconnect));
        assert_eq!(close.bytes_recv, 928);
        assert_eq!(
            recs.iter().filter(|r| r.kind == EventKind::Close).count(),
            1
        );
    }

    #[test]
    fn vanished_flow_without_etw_close_is_gone_after_window() {
        let (e, rx) = engine_with(Filter::default(), true);
        e.on_poll(&[], &[], 2 * S);
        let k = key("20.1.1.9:443", 50200);
        e.on_net(ev(100, NetOp::Connect, k, 0, 3 * S));
        e.on_poll(&[row(k, ConnState::Established, 100)], &[], 4 * S);
        e.on_poll(&[], &[], 5 * S);
        e.tick(6 * S);
        assert!(
            drain(&rx).iter().all(|r| r.kind != EventKind::Close),
            "held for ETW"
        );
        e.tick(5 * S + ETW_CONFIRM_WINDOW);
        let recs = drain(&rx);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].reason, Some(CloseReason::Gone));
        assert_eq!(
            recs[0].ts,
            5 * S,
            "close is stamped when it was first seen missing"
        );
    }

    #[test]
    fn unconfirmed_poll_flow_is_announced_after_window() {
        let (e, rx) = engine_with(Filter::default(), true);
        e.on_poll(&[], &[], 2 * S);
        let k = key("20.1.1.1:443", 50100);
        let r = row(k, ConnState::Established, 100);
        e.on_poll(&[r], &[], 10 * S);
        e.on_poll(&[row(k, ConnState::CloseWait, 100)], &[], 11 * S);
        e.tick(12 * S);
        assert!(drain(&rx).is_empty(), "no state record before the open");
        e.tick(10 * S + ETW_CONFIRM_WINDOW);
        let recs = drain(&rx);
        assert_eq!(recs.len(), 1);
        assert_eq!(
            (recs[0].kind, recs[0].source),
            (EventKind::Open, Source::Poll)
        );
        assert_eq!(recs[0].state, ConnState::CloseWait);
    }

    #[test]
    fn provisional_flow_closing_early_emits_open_then_close() {
        let (e, rx) = engine_with(Filter::default(), true);
        e.on_poll(&[], &[], 2 * S);
        let k = key("20.1.1.2:443", 50101);
        e.on_poll(&[row(k, ConnState::Established, 100)], &[], 10 * S);
        // Gone from the table before its confirmation window ended, and ETW never spoke.
        e.on_poll(&[], &[], 11 * S);
        assert!(drain(&rx).is_empty());
        // One housekeeping pass past both windows: the open must precede the close.
        e.tick(11 * S + ETW_CONFIRM_WINDOW);
        let recs = drain(&rx);
        let kinds: Vec<EventKind> = recs.iter().map(|r| r.kind).collect();
        assert_eq!(kinds, vec![EventKind::Open, EventKind::Close]);
        assert_eq!(recs[1].reason, Some(CloseReason::Gone));
    }

    #[test]
    fn snapshot_flows_promote_only_on_lifecycle_start() {
        let (e, rx) = engine_with(Filter::default(), true);
        let old = key("20.1.1.3:443", 50102);
        let fresh = key("20.1.1.4:443", 50103);
        e.on_poll(
            &[
                row(old, ConnState::Established, 100),
                row(fresh, ConnState::Established, 100),
            ],
            &[],
            2 * S,
        );
        // Data on a pre-existing connection does not make it ETW-born ...
        e.on_net(ev(100, NetOp::Recv, old, 10, 2 * S + 1));
        // ... but a Connect proves the socket opened while monitoring was starting.
        e.on_net(ev(100, NetOp::Connect, fresh, 0, 2 * S - 1));
        e.tick(2 * S + ETW_CONFIRM_WINDOW);
        let recs = drain(&rx);
        let src = |k: FlowKey| recs.iter().find(|r| r.key == k).unwrap().source;
        assert_eq!(src(old), Source::Snapshot);
        assert_eq!(src(fresh), Source::Etw);
    }

    #[test]
    fn udp_flows_expire_when_idle() {
        let (e, rx) = engine(Filter::default());
        let k = FlowKey {
            proto: Proto::Udp,
            local: "10.0.0.2:60000".parse().unwrap(),
            remote: "1.1.1.1:443".parse().unwrap(),
        };
        e.on_net(ev(200, NetOp::Send, k, 1200, 2 * S));
        e.tick(30 * S);
        assert_eq!(drain(&rx).len(), 1);
        e.tick(70 * S);
        let recs = drain(&rx);
        assert_eq!(recs[0].reason, Some(CloseReason::Idle));
        assert_eq!(recs[0].bytes_sent, 1200);
    }

    #[test]
    fn grouped_view_aggregates_per_binary() {
        let (e, _rx) = engine(Filter::default());
        for (i, r) in ["1.1.1.1:443", "1.1.1.1:443", "9.9.9.9:443"]
            .iter()
            .enumerate()
        {
            let k = key(r, 51000 + i as u16);
            e.on_net(ev(100, NetOp::Connect, k, 0, 2 * S));
            e.on_net(ev(100, NetOp::Recv, k, 100, 2 * S + 1));
        }
        let s = e.snapshot(&opts());
        assert_eq!(s.rows.len(), 1);
        let r = &s.rows[0];
        assert_eq!((r.total, r.active, r.unique_remotes, r.rx), (3, 3, 2, 300));
        assert_eq!(r.top_remotes[0].ip, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(r.top_remotes[0].stat.conns, 2);
    }

    fn opts() -> SnapshotOpts {
        SnapshotOpts {
            sort: SortKey::Activity,
            max_rows: 50,
            remotes_per_row: 5,
            dns_per_row: 5,
            live_limit: 50,
            changed_since: 0,
        }
    }
}
