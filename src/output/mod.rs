//! Output pipeline: a dedicated writer thread drains the record channel in batches and
//! renders each record through every configured sink (console table, JSON Lines, CSV).
//! Domain names, owners, hashes and service names are resolved here, at format time, so
//! enrichment that completed after the event was captured still makes it into the output.

pub mod table;
pub mod top;

use std::collections::VecDeque;
use std::io::Write;
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::aggregate::TopRow;
use crate::dns::{Dns, DomainSource};
use crate::model::{EventKind, Record};
use crate::process::services::ServiceMap;
use crate::process::Process;
use crate::util::{iso8601, FileTime, TICKS_PER_MS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Table,
    JsonLines,
    Csv,
}

pub struct Enricher {
    pub dns: Arc<Dns>,
    pub services: Arc<ServiceMap>,
}

impl Enricher {
    pub fn domain(&self, r: &Record) -> Option<(Arc<str>, Option<DomainSource>)> {
        if let Some(d) = &r.dns {
            return Some((Arc::from(d.query.as_str()), None));
        }
        let ip = r.key.remote.ip();
        if ip.is_unspecified() {
            return None;
        }
        self.dns.lookup(ip, r.proc.pid).map(|(n, s)| (n, Some(s)))
    }

    pub fn domain_for_ip(&self, ip: IpAddr, pid: u32) -> Option<Arc<str>> {
        self.dns.lookup(ip, pid).map(|(n, _)| n)
    }

    pub fn services(&self, p: &Process) -> Option<Arc<str>> {
        if p.name.eq_ignore_ascii_case("svchost.exe") {
            self.services.get(p.pid)
        } else {
            None
        }
    }
}

pub fn user_display(p: &Process) -> Option<&str> {
    p.user_info()
        .map(|u| u.account.as_deref().unwrap_or(u.sid.as_str()))
}

pub fn dns_status(code: u32) -> String {
    match code {
        0 => "NOERROR".into(),
        9003 => "NXDOMAIN".into(),
        9501 => "NODATA".into(),
        9002 => "SERVFAIL".into(),
        1460 => "TIMEOUT".into(),
        1214 => "BADNAME".into(),
        n => format!("ERR{}", n),
    }
}

/// Display label for the PROTO column.
pub fn proto_label(r: &Record) -> &'static str {
    if r.kind == EventKind::Dns {
        "DNS"
    } else {
        r.key.proto_label()
    }
}

/// Display label for the STATE column.
pub fn state_label(r: &Record) -> String {
    match &r.dns {
        Some(d) => dns_status(d.status),
        None => r.state.label().to_string(),
    }
}

// ---------------------------------------------------------------------------------------
// JSON / CSV encoding
// ---------------------------------------------------------------------------------------

pub fn json_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

pub struct Obj<'a> {
    out: &'a mut String,
    first: bool,
}

impl<'a> Obj<'a> {
    pub fn new(out: &'a mut String) -> Self {
        out.push('{');
        Obj { out, first: true }
    }
    fn key(&mut self, k: &str) {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        json_str(self.out, k);
        self.out.push(':');
    }
    pub fn str(&mut self, k: &str, v: &str) -> &mut Self {
        self.key(k);
        json_str(self.out, v);
        self
    }
    pub fn opt(&mut self, k: &str, v: Option<&str>) -> &mut Self {
        self.key(k);
        match v {
            Some(s) => json_str(self.out, s),
            None => self.out.push_str("null"),
        }
        self
    }
    pub fn num(&mut self, k: &str, v: u64) -> &mut Self {
        self.key(k);
        self.out.push_str(&v.to_string());
        self
    }
    fn raw(&mut self, k: &str, v: &str) -> &mut Self {
        self.key(k);
        self.out.push_str(v);
        self
    }
    pub fn end(&mut self) {
        self.out.push('}');
    }
}

pub fn json_record(out: &mut String, r: &Record, e: &Enricher) {
    let p = &r.proc;
    let domain = e.domain(r);
    let services = e.services(p);
    let ip_version = if r.key.local.is_ipv4() { 4 } else { 6 };
    let remote_ip = (!r.key.remote.ip().is_unspecified()).then(|| r.key.remote.ip().to_string());
    let mut o = Obj::new(out);
    o.str("ts", &iso8601(r.ts))
        .str("event", r.kind.label())
        .num("pid", p.pid as u64)
        .num("ppid", p.ppid as u64)
        .num("session_id", p.session_id as u64)
        .str("process", &p.name)
        .opt("path", (!p.path.is_empty()).then_some(p.path.as_str()))
        .opt("user", user_display(p))
        .opt("sid", p.user_info().map(|u| u.sid.as_str()))
        .opt("sha256", p.sha256())
        .opt("services", services.as_deref())
        .str(
            "proto",
            if r.kind == EventKind::Dns {
                "DNS"
            } else if r.key.proto == crate::model::Proto::Tcp {
                "TCP"
            } else {
                "UDP"
            },
        )
        .num("ip_version", ip_version)
        .str("local_ip", &r.key.local.ip().to_string())
        .num("local_port", r.key.local.port() as u64)
        .opt("remote_ip", remote_ip.as_deref())
        .num("remote_port", r.key.remote.port() as u64)
        .opt("domain", domain.as_ref().map(|d| &*d.0))
        .opt(
            "domain_source",
            domain.as_ref().and_then(|d| d.1).map(|s| s.label()),
        )
        .str("state", &state_label(r))
        .str("direction", r.direction.label())
        .num("bytes_sent", r.bytes_sent)
        .num("bytes_recv", r.bytes_recv)
        .num("retransmits", r.retransmits as u64)
        .num("duration_ms", r.duration / TICKS_PER_MS)
        .str("source", r.source.label())
        .str("attribution", r.attribution.label())
        .opt("reason", r.reason.map(|x| x.label()));
    if let Some(d) = &r.dns {
        let answers: Vec<String> = d
            .addrs
            .iter()
            .map(|a| {
                let mut s = String::new();
                json_str(&mut s, &a.to_string());
                s
            })
            .collect();
        o.num("dns_status", d.status as u64)
            .raw("answers", &format!("[{}]", answers.join(",")));
    }
    o.end();
}

pub const CSV_HEADER: &str = "ts,event,pid,ppid,process,path,user,sid,sha256,services,proto,local_ip,local_port,\
remote_ip,remote_port,domain,domain_source,state,direction,bytes_sent,bytes_recv,retransmits,duration_ms,source,\
attribution,reason";

pub fn csv_field(out: &mut String, s: &str) {
    if s.contains([',', '"', '\n', '\r']) {
        out.push('"');
        out.push_str(&s.replace('"', "\"\""));
        out.push('"');
    } else {
        out.push_str(s);
    }
}

pub fn csv_record(out: &mut String, r: &Record, e: &Enricher) {
    let p = &r.proc;
    let domain = e.domain(r);
    let remote_ip = if r.key.remote.ip().is_unspecified() {
        String::new()
    } else {
        r.key.remote.ip().to_string()
    };
    let fields: [String; 26] = [
        iso8601(r.ts),
        r.kind.label().into(),
        p.pid.to_string(),
        p.ppid.to_string(),
        p.name.clone(),
        p.path.clone(),
        user_display(p).unwrap_or("").into(),
        p.user_info().map(|u| u.sid.clone()).unwrap_or_default(),
        p.sha256().unwrap_or("").into(),
        e.services(p).map(|s| s.to_string()).unwrap_or_default(),
        proto_label(r).into(),
        r.key.local.ip().to_string(),
        r.key.local.port().to_string(),
        remote_ip,
        r.key.remote.port().to_string(),
        domain.as_ref().map(|d| d.0.to_string()).unwrap_or_default(),
        domain
            .as_ref()
            .and_then(|d| d.1)
            .map(|s| s.label().to_string())
            .unwrap_or_default(),
        state_label(r),
        r.direction.label().into(),
        r.bytes_sent.to_string(),
        r.bytes_recv.to_string(),
        r.retransmits.to_string(),
        (r.duration / TICKS_PER_MS).to_string(),
        r.source.label().into(),
        r.attribution.label().into(),
        r.reason.map(|x| x.label()).unwrap_or("").into(),
    ];
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        csv_field(out, f);
    }
}

// ---------------------------------------------------------------------------------------
// Aggregates (Mode B export / --summary)
// ---------------------------------------------------------------------------------------

pub fn json_aggregate(out: &mut String, kind: &str, ts: FileTime, row: &TopRow, e: &Enricher) {
    let p = &row.sample;
    let remotes: Vec<String> = row
        .top_remotes
        .iter()
        .map(|r| {
            let mut s = String::new();
            let domain = e.domain_for_ip(r.ip, p.pid);
            Obj::new(&mut s)
                .str("ip", &r.ip.to_string())
                .opt("domain", domain.as_deref())
                .num("last_port", r.stat.last_port as u64)
                .num("connections", r.stat.conns as u64)
                .num("bytes_sent", r.stat.tx)
                .num("bytes_recv", r.stat.rx)
                .str("last_seen", &iso8601(r.stat.last))
                .end();
            s
        })
        .collect();
    let dns: Vec<String> = row
        .dns_names
        .iter()
        .map(|(n, c)| {
            let mut s = String::new();
            Obj::new(&mut s)
                .str("name", n)
                .num("count", *c as u64)
                .end();
            s
        })
        .collect();
    let pids: Vec<String> = row.pids.iter().map(|p| p.to_string()).collect();
    Obj::new(out)
        .str("ts", &iso8601(ts))
        .str("event", kind)
        .str("process", &row.name)
        .opt("path", (!row.path.is_empty()).then_some(row.path.as_str()))
        .opt("user", user_display(p))
        .opt("sha256", p.sha256())
        .raw("pids", &format!("[{}]", pids.join(",")))
        .num("active", row.active as u64)
        .num("connections", row.total)
        .num("tcp", row.tcp)
        .num("udp", row.udp)
        .num("bytes_sent", row.tx)
        .num("bytes_recv", row.rx)
        .num("unique_remotes", row.unique_remotes as u64)
        .num("remotes_untracked", row.remotes_overflow)
        .str("first_seen", &iso8601(row.first_seen))
        .str("last_seen", &iso8601(row.last_seen))
        .raw("remotes", &format!("[{}]", remotes.join(",")))
        .raw("dns_queries", &format!("[{}]", dns.join(",")))
        .end();
}

pub const CSV_AGG_HEADER: &str =
    "ts,event,process,path,user,pids,active,connections,tcp,udp,bytes_sent,bytes_recv,\
unique_remotes,top_remotes,dns_queries,first_seen,last_seen";

pub fn csv_aggregate(out: &mut String, kind: &str, ts: FileTime, row: &TopRow, e: &Enricher) {
    let p = &row.sample;
    let remotes: Vec<String> = row
        .top_remotes
        .iter()
        .map(|r| {
            let d = e
                .domain_for_ip(r.ip, p.pid)
                .map(|d| format!("{}|", d))
                .unwrap_or_default();
            format!("{}{}({})", d, r.ip, r.stat.conns)
        })
        .collect();
    let dns: Vec<String> = row
        .dns_names
        .iter()
        .map(|(n, c)| format!("{}({})", n, c))
        .collect();
    let fields: [String; 17] = [
        iso8601(ts),
        kind.into(),
        row.name.clone(),
        row.path.clone(),
        user_display(p).unwrap_or("").into(),
        row.pids
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(";"),
        row.active.to_string(),
        row.total.to_string(),
        row.tcp.to_string(),
        row.udp.to_string(),
        row.tx.to_string(),
        row.rx.to_string(),
        row.unique_remotes.to_string(),
        remotes.join(";"),
        dns.join(";"),
        iso8601(row.first_seen),
        iso8601(row.last_seen),
    ];
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        csv_field(out, f);
    }
}

// ---------------------------------------------------------------------------------------
// Writer thread
// ---------------------------------------------------------------------------------------

pub enum Sink {
    Table(table::StreamTable, Box<dyn Write + Send>),
    JsonLines(Box<dyn Write + Send>),
    Csv {
        w: Box<dyn Write + Send>,
        header: bool,
    },
}

impl Sink {
    fn write(&mut self, r: &Record, e: &Enricher, buf: &mut String) -> std::io::Result<()> {
        buf.clear();
        match self {
            Sink::Table(t, w) => {
                t.render(r, e, buf);
                w.write_all(buf.as_bytes())
            }
            Sink::JsonLines(w) => {
                json_record(buf, r, e);
                buf.push('\n');
                w.write_all(buf.as_bytes())
            }
            Sink::Csv { w, header } => {
                if !*header {
                    *header = true;
                    buf.push_str(CSV_HEADER);
                    buf.push('\n');
                }
                csv_record(buf, r, e);
                buf.push('\n');
                w.write_all(buf.as_bytes())
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Sink::Table(_, w) | Sink::JsonLines(w) | Sink::Csv { w, .. } => w.flush(),
        }
    }
}

/// Records wait (in arrival order) at most this long for an in-flight PTR lookup, so the
/// DOMAIN column is filled on the line that opens a connection rather than only on its close.
pub struct WriterOpts {
    pub dns_wait: Duration,
}

pub fn spawn_writer(
    rx: Receiver<Record>,
    mut sinks: Vec<Sink>,
    enr: Arc<Enricher>,
    opts: WriterOpts,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("writer".into())
        .spawn(move || {
            let mut buf = String::with_capacity(1024);
            let mut broken = vec![false; sinks.len()];
            // FIFO hold queue: head-of-line blocking keeps output ordered; latency is bounded
            // by `dns_wait` because every record's deadline is fixed on arrival.
            let mut held: VecDeque<(Instant, Record)> = VecDeque::new();
            let mut disconnected = false;
            while !disconnected || !held.is_empty() {
                if !disconnected {
                    let timeout = held
                        .front()
                        .map(|(d, _)| d.saturating_duration_since(Instant::now()))
                        .unwrap_or(Duration::from_millis(250))
                        .clamp(Duration::from_millis(5), Duration::from_millis(250));
                    match rx.recv_timeout(timeout) {
                        Ok(r) => held.push_back((Instant::now() + opts.dns_wait, r)),
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => disconnected = true,
                    }
                    for r in rx.try_iter().take(4096) {
                        held.push_back((Instant::now() + opts.dns_wait, r));
                    }
                }
                let mut wrote = false;
                while let Some((deadline, r)) = held.front() {
                    let waiting = !disconnected
                        && Instant::now() < *deadline
                        && r.dns.is_none()
                        && enr.dns.in_flight(&r.key.remote.ip())
                        && enr.domain(r).is_none();
                    if waiting {
                        break;
                    }
                    let (_, r) = held.pop_front().unwrap();
                    for (i, s) in sinks.iter_mut().enumerate() {
                        if !broken[i] && s.write(&r, &enr, &mut buf).is_err() {
                            broken[i] = true; // e.g. `| head` closed the pipe
                        }
                    }
                    wrote = true;
                }
                // Batch: one flush per burst instead of per line.
                if wrote {
                    for (i, s) in sinks.iter_mut().enumerate() {
                        if !broken[i] && s.flush().is_err() {
                            broken[i] = true;
                        }
                    }
                }
                if !broken.is_empty() && broken.iter().all(|&b| b) {
                    crate::console::request_stop();
                    break;
                }
            }
            for s in sinks.iter_mut() {
                let _ = s.flush();
            }
        })
        .expect("spawn writer thread")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escaping() {
        let mut s = String::new();
        json_str(&mut s, "C:\\Program Files\\\"x\"\n");
        assert_eq!(s, "\"C:\\\\Program Files\\\\\\\"x\\\"\\n\"");
    }

    #[test]
    fn csv_quoting() {
        let mut s = String::new();
        csv_field(&mut s, "a,b \"c\"");
        assert_eq!(s, "\"a,b \"\"c\"\"\"");
        let mut s = String::new();
        csv_field(&mut s, "plain");
        assert_eq!(s, "plain");
    }

    #[test]
    fn csv_header_matches_field_count() {
        assert_eq!(CSV_HEADER.split(',').count(), 26);
        assert_eq!(CSV_AGG_HEADER.split(',').count(), 17);
    }
}
