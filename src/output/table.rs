//! Mode A console stream: one dense, aligned line per event.
//!
//! ```text
//!   TIMESTAMP     PROCESS         PID PATH                       PROTO LOCAL            REMOTE           DOMAIN                 STATE
//! + 14:03:22.123Z WINWORD.EXE    4512 C:\Program…\WINWORD.EXE    TCP4  10.0.0.5:50123   52.109.8.21:443  ecs.office.com         ESTABLISHED
//! ```
//!
//! The layout is recomputed whenever the console is resized (checked at most every 500 ms):
//! lines never exceed the window width (no wrap garbage), low-priority columns (BYTES, DIR,
//! PATH, LOCAL, DOMAIN) are dropped first on narrow terminals, and the header is re-printed
//! so columns stay aligned with what follows.

use std::time::{Duration, Instant};

use super::{proto_label, state_label, Enricher};
use crate::model::{fmt_endpoint, EventKind, Record};
use crate::util::{date, ellipsize_end, ellipsize_middle, hms_millis, human_bytes, pad, rpad};

const GAP: usize = 1;
const TS: usize = 13;
const PID: usize = 6;
const PROTO: usize = 5;
const STATE: usize = 11;
const DIR: usize = 3;
const BYTES: usize = 13;
/// Width assumed when output is redirected to a file in table format.
const NON_CONSOLE_WIDTH: usize = 220;
/// Below this the mandatory columns cannot fit; lines are then hard-truncated (uncolored).
pub const MIN_WIDTH: usize = 1 + TS + PID + PROTO + STATE + 8 + 15 + 6 * GAP + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    pub width: usize,
    pub process: usize,
    pub path: usize,
    pub local: usize,
    pub remote: usize,
    pub domain: usize,
    pub dir: bool,
    pub bytes: bool,
}

impl Layout {
    pub fn for_width(width: usize) -> Layout {
        let w = width.saturating_sub(1); // never touch the last column: avoids auto-wrap
                                         // Mandatory: glyph, TIMESTAMP, PROCESS, PID, PROTO, REMOTE, STATE.
        let fixed = 1 + TS + PID + PROTO + STATE;
        let mut l = Layout {
            width: w,
            process: 8,
            path: 0,
            local: 0,
            remote: 15,
            domain: 0,
            dir: false,
            bytes: false,
        };
        let used = |l: &Layout| {
            let mut cols = 7usize;
            let mut sum = fixed + l.process + l.remote;
            for (on, v) in [
                (l.path > 0, l.path),
                (l.local > 0, l.local),
                (l.domain > 0, l.domain),
            ] {
                if on {
                    cols += 1;
                    sum += v;
                }
            }
            if l.dir {
                cols += 1;
                sum += DIR;
            }
            if l.bytes {
                cols += 1;
                sum += BYTES;
            }
            sum + (cols - 1) * GAP
        };
        // Add optional columns at their minimum, most valuable first.
        for step in 0..3 {
            let mut t = l;
            match step {
                0 => t.domain = 12,
                1 => t.local = 15,
                _ => t.path = 14,
            }
            if used(&t) <= w {
                l = t;
            }
        }
        // Grow towards ideal widths in priority order.
        let grow = |l: &mut Layout, field: fn(&mut Layout) -> &mut usize, target: usize| {
            while *field(l) < target && used(l) < w {
                *field(l) += 1;
            }
        };
        grow(&mut l, |l| &mut l.remote, 21);
        if l.domain > 0 {
            grow(&mut l, |l| &mut l.domain, 30);
        }
        grow(&mut l, |l| &mut l.process, 15);
        if l.local > 0 {
            grow(&mut l, |l| &mut l.local, 21);
        }
        if l.path > 0 {
            grow(&mut l, |l| &mut l.path, 40);
        }
        for extra in 0..2 {
            let mut t = l;
            if extra == 0 {
                t.dir = true
            } else {
                t.bytes = true
            }
            if used(&t) <= w {
                l = t;
            }
        }
        // Remaining space: IPv6 endpoints and long paths/domains benefit most.
        if l.path > 0 {
            grow(&mut l, |l| &mut l.path, 90);
        }
        if l.domain > 0 {
            grow(&mut l, |l| &mut l.domain, 48);
        }
        grow(&mut l, |l| &mut l.remote, 47);
        if l.local > 0 {
            grow(&mut l, |l| &mut l.local, 47);
        }
        if l.path > 0 {
            grow(&mut l, |l| &mut l.path, usize::MAX);
        }
        l
    }
}

pub struct StreamTable {
    console: bool,
    color: bool,
    /// Window narrower than `MIN_WIDTH`: render plain and truncate.
    narrow: bool,
    layout: Option<Layout>,
    last_check: Instant,
    last_date: String,
}

/// Keeps the *end* of a host name (its registrable domain is the informative part).
fn ellipsize_start(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n <= width {
        return s.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let mut out = String::from("…");
    out.extend(s.chars().skip(n - (width - 1)));
    out
}

impl StreamTable {
    pub fn new(console: bool, color: bool) -> Self {
        StreamTable {
            console,
            color: color && console,
            narrow: false,
            layout: None,
            last_check: Instant::now() - Duration::from_secs(1),
            last_date: String::new(),
        }
    }

    fn current_width(&self) -> usize {
        if self.console {
            crate::console::size().map(|(w, _)| w).unwrap_or(120)
        } else {
            NON_CONSOLE_WIDTH
        }
    }

    fn paint(&self, code: &str, s: &str) -> String {
        if self.color && !self.narrow {
            format!("\x1b[{}m{}\x1b[0m", code, s)
        } else {
            s.to_string()
        }
    }

    fn header(&self, l: &Layout, out: &mut String) {
        let mut cols: Vec<String> = vec![
            " ".into(),
            pad("TIMESTAMP", TS),
            pad("PROCESS", l.process),
            rpad("PID", PID),
        ];
        if l.path > 0 {
            cols.push(pad("PATH", l.path));
        }
        cols.push(pad("PROTO", PROTO));
        if l.local > 0 {
            cols.push(pad("LOCAL", l.local));
        }
        cols.push(pad("REMOTE", l.remote));
        if l.domain > 0 {
            cols.push(pad("DOMAIN", l.domain));
        }
        cols.push(pad("STATE", STATE));
        if l.dir {
            cols.push(pad("DIR", DIR));
        }
        if l.bytes {
            cols.push(rpad("TX/RX", BYTES));
        }
        let line = ellipsize_end(&cols.join(" "), l.width);
        let line = format!("{:<w$}", line, w = l.width);
        out.push_str(&self.paint("7", &line));
        out.push('\n');
    }

    pub fn render(&mut self, r: &Record, e: &Enricher, out: &mut String) {
        let d = date(r.ts);
        if d != self.last_date {
            out.push_str(&self.paint("2", &format!("-- {} (UTC)", d)));
            out.push('\n');
            self.last_date = d;
        }
        if self.layout.is_none() || self.last_check.elapsed() >= Duration::from_millis(500) {
            self.last_check = Instant::now();
            let width = self.current_width();
            self.narrow = width < MIN_WIDTH;
            let l = Layout::for_width(width);
            if self.layout != Some(l) {
                self.layout = Some(l);
                self.header(&l, out);
            }
        }
        let l = self.layout.unwrap();

        let p = &r.proc;
        let glyph = r.kind.glyph().to_string();
        let glyph = match r.kind {
            EventKind::Open => self.paint("32", &glyph),
            EventKind::Close => self.paint("31", &glyph),
            EventKind::State => self.paint("33", &glyph),
            EventKind::Listen => self.paint("36", &glyph),
            EventKind::Dns => self.paint("35", &glyph),
        };
        let mut line = String::with_capacity(l.width + 32);
        line.push_str(&glyph);
        let mut plain: Vec<String> = Vec::with_capacity(12);
        plain.push(self.paint("2", &pad(&hms_millis(r.ts), TS)));
        let mut name = p.name.clone();
        if let Some(svc) = e.services(p) {
            name = format!("{}:{}", name, svc);
        }
        plain.push(pad(&name, l.process));
        plain.push(rpad(&p.pid.to_string(), PID));
        if l.path > 0 {
            let path = if p.path.is_empty() {
                "-"
            } else {
                p.path.as_str()
            };
            plain.push(pad(&ellipsize_middle(path, l.path), l.path));
        }
        plain.push(pad(proto_label(r), PROTO));
        if l.local > 0 {
            let local = if r.kind == EventKind::Dns {
                "-".to_string()
            } else {
                fmt_endpoint(&r.key.local)
            };
            plain.push(pad(&ellipsize_middle(&local, l.local), l.local));
        }
        let remote = if r.key.remote.ip().is_unspecified() {
            if r.kind == EventKind::Listen || r.kind == EventKind::Close && r.key.remote.port() == 0
            {
                "*:*".into()
            } else {
                "-".into()
            }
        } else if r.kind == EventKind::Dns {
            r.key.remote.ip().to_string()
        } else {
            fmt_endpoint(&r.key.remote)
        };
        plain.push(pad(&ellipsize_middle(&remote, l.remote), l.remote));
        if l.domain > 0 {
            let dom = e.domain(r).map(|d| d.0.to_string()).unwrap_or_default();
            plain.push(pad(&ellipsize_start(&dom, l.domain), l.domain));
        }
        let state = state_label(r);
        plain.push(match r.kind {
            EventKind::Close => self.paint("31", &pad(&state, STATE)),
            _ => pad(&state, STATE),
        });
        if l.dir {
            plain.push(pad(r.direction.label(), DIR));
        }
        if l.bytes {
            let b = if r.bytes_sent + r.bytes_recv > 0 {
                format!(
                    "{}/{}",
                    human_bytes(r.bytes_sent),
                    human_bytes(r.bytes_recv)
                )
            } else {
                String::new()
            };
            plain.push(rpad(&b, BYTES));
        }
        for c in plain {
            line.push(' ');
            line.push_str(&c);
        }
        let line = line.trim_end();
        if self.narrow {
            out.push_str(&ellipsize_end(line, l.width));
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn total(l: &Layout) -> usize {
        let mut cols = 7;
        let mut sum = 1 + TS + PID + PROTO + STATE + l.process + l.remote;
        for v in [l.path, l.local, l.domain] {
            if v > 0 {
                cols += 1;
                sum += v;
            }
        }
        if l.dir {
            cols += 1;
            sum += DIR;
        }
        if l.bytes {
            cols += 1;
            sum += BYTES;
        }
        sum + cols - 1
    }

    #[test]
    fn layout_never_exceeds_width() {
        for w in [MIN_WIDTH, 80, 100, 120, 160, 200, 300] {
            let l = Layout::for_width(w);
            assert!(total(&l) < w, "width {} -> {:?} uses {}", w, l, total(&l));
        }
    }

    #[test]
    fn narrow_drops_optional_columns_first() {
        let l = Layout::for_width(80);
        assert_eq!(l.path, 0);
        assert!(!l.bytes);
        let wide = Layout::for_width(220);
        assert!(wide.path >= 40 && wide.domain >= 30 && wide.local >= 21 && wide.bytes);
    }

    #[test]
    fn domain_keeps_suffix() {
        assert_eq!(
            ellipsize_start("login.microsoftonline.com", 12),
            "…tonline.com"
        );
    }
}
