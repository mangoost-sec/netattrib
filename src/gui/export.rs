//! "Export…": the rows currently shown in the connection table, as CSV or a JSON array.
//! Field names follow the `--json-lines` / `--csv` record schema; byte counters are raw.
//! `state` is what the table shows (`PROXY/LOCAL` for loopback), `tcp_state` the TCP state, and
//! `peer_process` / `peer_pid` the local process at the other end of a loopback connection.
//! `signature` is `signed`, `unsigned` or `invalid` (empty while unchecked or unreadable) and
//! `signer` the certificate's subject name.

use std::io::Write;
use std::path::Path;

use super::snapshot::Conn;
use crate::output::{csv_field, Obj};
use crate::process::Process;
use crate::util::{iso8601, FileTime};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Csv,
    Json,
}

impl Format {
    /// By extension; anything other than `.json` is written as CSV.
    pub fn for_path(p: &Path) -> Self {
        match p.extension().and_then(|e| e.to_str()) {
            Some(e) if e.eq_ignore_ascii_case("json") => Format::Json,
            _ => Format::Csv,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Format::Csv => "CSV",
            Format::Json => "JSON",
        }
    }
}

const CSV_HEADER: &str = "process,pid,path,signature,signer,proto,local_ip,local_port,remote_ip,\
remote_port,domain,domain_source,state,tcp_state,direction,peer_process,peer_pid,bytes_sent,\
bytes_recv,last_activity";

/// `netattrib-20261021-140322` (UTC), the suggested file name.
pub fn default_stem(now: FileTime) -> String {
    let digits: String = iso8601(now).chars().filter(char::is_ascii_digit).collect();
    format!("netattrib-{}-{}", &digits[..8], &digits[8..14])
}

pub fn write(path: &Path, format: Format, rows: &[&Conn]) -> std::io::Result<()> {
    let mut s = String::with_capacity(256 * (rows.len() + 1));
    match format {
        Format::Csv => {
            s.push_str(CSV_HEADER);
            s.push('\n');
            for c in rows {
                csv_row(&mut s, c);
                s.push('\n');
            }
        }
        Format::Json => {
            s.push_str("[\n");
            for (i, c) in rows.iter().enumerate() {
                s.push_str("  ");
                json_row(&mut s, c);
                s.push_str(if i + 1 < rows.len() { ",\n" } else { "\n" });
            }
            s.push_str("]\n");
        }
    }
    let mut f = std::fs::File::create(path)?;
    f.write_all(s.as_bytes())?;
    f.flush()
}

fn remote_ip(c: &Conn) -> Option<String> {
    let ip = c.key.remote.ip();
    (!ip.is_unspecified()).then(|| ip.to_string())
}

fn peer(c: &Conn) -> Option<&Process> {
    c.link.as_ref().and_then(|l| l.peer.as_deref())
}

fn csv_row(out: &mut String, c: &Conn) {
    let sig = c.proc.signature();
    let fields: [String; 20] = [
        c.proc.name.clone(),
        c.proc.pid.to_string(),
        c.proc.path.clone(),
        sig.map(|s| s.status().to_string()).unwrap_or_default(),
        sig.and_then(|s| s.signer())
            .map(str::to_string)
            .unwrap_or_default(),
        c.key.proto_label().into(),
        c.key.local.ip().to_string(),
        c.key.local.port().to_string(),
        remote_ip(c).unwrap_or_default(),
        c.key.remote.port().to_string(),
        c.domain
            .as_ref()
            .map(|d| d.0.to_string())
            .unwrap_or_default(),
        c.domain
            .as_ref()
            .map(|d| d.1.label().to_string())
            .unwrap_or_default(),
        c.state.into(),
        c.tcp_state.into(),
        c.dir.label().into(),
        peer(c).map(|p| p.name.clone()).unwrap_or_default(),
        peer(c).map(|p| p.pid.to_string()).unwrap_or_default(),
        c.tx.to_string(),
        c.rx.to_string(),
        iso8601(c.last_activity),
    ];
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        csv_field(out, f);
    }
}

fn json_row(out: &mut String, c: &Conn) {
    let sig = c.proc.signature();
    let mut o = Obj::new(out);
    o.str("process", &c.proc.name)
        .num("pid", c.proc.pid as u64)
        .opt(
            "path",
            (!c.proc.path.is_empty()).then_some(c.proc.path.as_str()),
        )
        .opt("signature", sig.map(|s| s.status()))
        .opt("signer", sig.and_then(|s| s.signer()))
        .str("proto", c.key.proto_label())
        .str("local_ip", &c.key.local.ip().to_string())
        .num("local_port", c.key.local.port() as u64)
        .opt("remote_ip", remote_ip(c).as_deref())
        .num("remote_port", c.key.remote.port() as u64)
        .opt("domain", c.domain.as_ref().map(|d| &*d.0))
        .opt("domain_source", c.domain.as_ref().map(|d| d.1.label()))
        .str("state", c.state)
        .str("tcp_state", c.tcp_state)
        .str("direction", c.dir.label())
        .opt("peer_process", peer(c).map(|p| p.name.as_str()));
    match peer(c) {
        Some(p) => o.num("peer_pid", p.pid as u64),
        None => o.opt("peer_pid", None),
    };
    o.num("bytes_sent", c.tx)
        .num("bytes_recv", c.rx)
        .str("last_activity", &iso8601(c.last_activity))
        .end();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_matches_field_count_and_stem() {
        assert_eq!(CSV_HEADER.split(',').count(), 20);
        // 2026-10-21T14:03:22Z
        let ft = 116_444_736_000_000_000 + 1_792_591_402 * crate::util::TICKS_PER_SEC;
        assert_eq!(default_stem(ft), "netattrib-20261021-140322");
        assert_eq!(Format::for_path(Path::new("a.JSON")), Format::Json);
        assert_eq!(Format::for_path(Path::new("a.csv")), Format::Csv);
    }
}
