//! Core value types shared by the capture, aggregation and output layers.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::process::Process;
use crate::util::FileTime;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

/// A 5-tuple without the protocol number ambiguity: `(proto, local, remote)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

impl FlowKey {
    pub fn proto_label(&self) -> &'static str {
        match (self.proto, self.local.is_ipv4()) {
            (Proto::Tcp, true) => "TCP4",
            (Proto::Tcp, false) => "TCP6",
            (Proto::Udp, true) => "UDP4",
            (Proto::Udp, false) => "UDP6",
        }
    }
}

/// TCP states as reported by `MIB_TCP_STATE`, plus pseudo-states for UDP flows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnState {
    Closed,
    Listen,
    SynSent,
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    /// UDP flow with recent datagrams.
    Active,
    /// UDP socket bound locally (only reported with `--listening`).
    Bound,
    Unknown,
}

impl ConnState {
    pub fn from_mib(v: u32) -> Self {
        match v {
            1 => ConnState::Closed,
            2 => ConnState::Listen,
            3 => ConnState::SynSent,
            4 => ConnState::SynRcvd,
            5 => ConnState::Established,
            6 => ConnState::FinWait1,
            7 => ConnState::FinWait2,
            8 => ConnState::CloseWait,
            9 => ConnState::Closing,
            10 => ConnState::LastAck,
            11 => ConnState::TimeWait,
            12 => ConnState::DeleteTcb,
            _ => ConnState::Unknown,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ConnState::Closed => "CLOSED",
            ConnState::Listen => "LISTEN",
            ConnState::SynSent => "SYN_SENT",
            ConnState::SynRcvd => "SYN_RCVD",
            ConnState::Established => "ESTABLISHED",
            ConnState::FinWait1 => "FIN_WAIT1",
            ConnState::FinWait2 => "FIN_WAIT2",
            ConnState::CloseWait => "CLOSE_WAIT",
            ConnState::Closing => "CLOSING",
            ConnState::LastAck => "LAST_ACK",
            ConnState::TimeWait => "TIME_WAIT",
            ConnState::DeleteTcb => "DELETE_TCB",
            ConnState::Active => "ACTIVE",
            ConnState::Bound => "BOUND",
            ConnState::Unknown => "UNKNOWN",
        }
    }

    /// True once the connection is past the point of carrying application data.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ConnState::Closed | ConnState::TimeWait | ConnState::DeleteTcb
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Outbound,
    Inbound,
    Unknown,
}

impl Direction {
    pub fn label(&self) -> &'static str {
        match self {
            Direction::Outbound => "out",
            Direction::Inbound => "in",
            Direction::Unknown => "?",
        }
    }
}

/// Where a flow was first observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// ETW real-time event (event-driven, catches sub-millisecond sockets).
    Etw,
    /// IP Helper table poll.
    Poll,
    /// Present in the very first poll: existed before monitoring started.
    Snapshot,
}

impl Source {
    pub fn label(&self) -> &'static str {
        match self {
            Source::Etw => "etw",
            Source::Poll => "poll",
            Source::Snapshot => "snapshot",
        }
    }
}

/// How confident the PID -> process binding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attribution {
    /// Process instance known from ETW process events or a snapshot whose creation time
    /// precedes the network event: immune to PID reuse.
    Exact,
    /// Resolved on demand after the fact; creation time verified to precede the event.
    Inferred,
    /// The owning process exited before it could be inspected; only partial data known.
    Exited,
}

impl Attribution {
    pub fn label(&self) -> &'static str {
        match self {
            Attribution::Exact => "exact",
            Attribution::Inferred => "inferred",
            Attribution::Exited => "exited",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// New connection / UDP flow.
    Open,
    /// TCP state transition observed by polling.
    State,
    /// Connection torn down, disappeared, went idle, or monitoring stopped.
    Close,
    /// New listening TCP socket or bound UDP socket (`--listening`).
    Listen,
    /// DNS query completed by a monitored process (`--dns-events`).
    Dns,
}

impl EventKind {
    pub fn label(&self) -> &'static str {
        match self {
            EventKind::Open => "open",
            EventKind::State => "state",
            EventKind::Close => "close",
            EventKind::Listen => "listen",
            EventKind::Dns => "dns",
        }
    }

    pub fn glyph(&self) -> char {
        match self {
            EventKind::Open => '+',
            EventKind::State => '~',
            EventKind::Close => '-',
            EventKind::Listen => 'L',
            EventKind::Dns => '?',
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// ETW disconnect event.
    Disconnect,
    /// No longer present in the TCP table.
    Gone,
    /// UDP flow without datagrams for `--udp-idle` seconds.
    Idle,
    /// Still open when monitoring stopped (final byte counters flushed).
    Shutdown,
}

impl CloseReason {
    pub fn label(&self) -> &'static str {
        match self {
            CloseReason::Disconnect => "disconnect",
            CloseReason::Gone => "gone",
            CloseReason::Idle => "idle",
            CloseReason::Shutdown => "shutdown",
        }
    }
}

/// One output record. Holds an `Arc<Process>` rather than copied strings so emission is
/// allocation-free; late-arriving enrichment (user, hash) is read at format time.
#[derive(Clone)]
pub struct Record {
    pub ts: FileTime,
    pub kind: EventKind,
    pub proc: Arc<Process>,
    pub key: FlowKey,
    pub state: ConnState,
    pub direction: Direction,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub retransmits: u32,
    pub duration: u64,
    pub source: Source,
    pub attribution: Attribution,
    pub reason: Option<CloseReason>,
    /// DNS records only: query name, status code and answer list.
    pub dns: Option<Arc<DnsAnswer>>,
}

#[derive(Debug)]
pub struct DnsAnswer {
    pub query: String,
    pub status: u32,
    pub addrs: Vec<IpAddr>,
}

pub fn unspecified(v4: bool) -> SocketAddr {
    if v4 {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    }
}

/// Collapses IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to plain IPv4 so ETW and IP Helper keys agree.
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

pub fn canonical(sa: SocketAddr) -> SocketAddr {
    SocketAddr::new(canonical_ip(sa.ip()), sa.port())
}

/// Addresses for which a PTR lookup is pointless.
pub fn skip_rdns(ip: &IpAddr) -> bool {
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || match ip {
            IpAddr::V4(v4) => v4.is_broadcast() || v4.is_link_local(),
            IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
        }
}

/// `1.2.3.4:443` / `[2001:db8::1]:443`
pub fn fmt_endpoint(sa: &SocketAddr) -> String {
    if sa.ip().is_unspecified() && sa.port() == 0 {
        return "*:*".to_string();
    }
    sa.to_string()
}
