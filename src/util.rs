//! Small, dependency-free helpers: FILETIME clock, ISO-8601 formatting, UTF-16
//! conversion, case-insensitive globbing and compact human-readable numbers.

use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;

/// 100 ns ticks since 1601-01-01 UTC (the native Windows/ETW timestamp unit).
pub type FileTime = u64;

pub const TICKS_PER_MS: u64 = 10_000;
pub const TICKS_PER_SEC: u64 = 10_000_000;
const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;

pub fn now() -> FileTime {
    let mut ft = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    unsafe { GetSystemTimePreciseAsFileTime(&mut ft) };
    filetime_to_u64(&ft)
}

pub fn filetime_to_u64(ft: &FILETIME) -> FileTime {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

/// Howard Hinnant's days-from-civil inverse: days since 1970-01-01 -> (y, m, d).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

struct Parts {
    y: i64,
    mo: u32,
    d: u32,
    h: u64,
    mi: u64,
    s: u64,
    micros: u64,
}

fn split(ft: FileTime) -> Parts {
    let unix_ticks = ft.saturating_sub(UNIX_EPOCH_TICKS);
    let secs = unix_ticks / TICKS_PER_SEC;
    let micros = (unix_ticks % TICKS_PER_SEC) / 10;
    let (y, mo, d) = civil_from_days((secs / 86_400) as i64);
    let sod = secs % 86_400;
    Parts {
        y,
        mo,
        d,
        h: sod / 3600,
        mi: (sod % 3600) / 60,
        s: sod % 60,
        micros,
    }
}

/// `2026-10-21T14:03:22.123456Z`
pub fn iso8601(ft: FileTime) -> String {
    let p = split(ft);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        p.y, p.mo, p.d, p.h, p.mi, p.s, p.micros
    )
}

/// `14:03:22.123Z` - compact form for the console table.
pub fn hms_millis(ft: FileTime) -> String {
    let p = split(ft);
    format!("{:02}:{:02}:{:02}.{:03}Z", p.h, p.mi, p.s, p.micros / 1000)
}

/// `2026-10-21`
pub fn date(ft: FileTime) -> String {
    let p = split(ft);
    format!("{:04}-{:02}-{:02}", p.y, p.mo, p.d)
}

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Decodes UTF-16 up to the first NUL (or the end of the slice).
pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Decodes a NUL-terminated UTF-16 string from a raw pointer.
///
/// # Safety
/// `p` must be null or point to a NUL-terminated UTF-16 string.
pub unsafe fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

/// Case-insensitive wildcard matcher supporting `*` and `?`.
#[derive(Debug, Clone)]
pub struct Glob {
    pat: Vec<char>,
    raw: String,
}

impl Glob {
    pub fn new(pattern: &str) -> Self {
        Glob {
            pat: pattern.to_lowercase().chars().collect(),
            raw: pattern.to_string(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn is_literal(&self) -> bool {
        !self.pat.iter().any(|&c| c == '*' || c == '?')
    }

    /// `text` must already be lower-cased by the caller (hot path, avoids re-allocating).
    pub fn matches_lc(&self, text: &str) -> bool {
        let t: Vec<char> = text.chars().collect();
        let (p, mut pi, mut ti) = (&self.pat, 0usize, 0usize);
        let (mut star, mut mark) = (usize::MAX, 0usize);
        while ti < t.len() {
            if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
                pi += 1;
                ti += 1;
            } else if pi < p.len() && p[pi] == '*' {
                star = pi;
                mark = ti;
                pi += 1;
            } else if star != usize::MAX {
                pi = star + 1;
                mark += 1;
                ti = mark;
            } else {
                return false;
            }
        }
        while pi < p.len() && p[pi] == '*' {
            pi += 1;
        }
        pi == p.len()
    }
}

/// 1023 -> "1023", 1536 -> "1.5K", 3_400_000 -> "3.2M".
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["K", "M", "G", "T", "P"];
    if n < 1024 {
        return n.to_string();
    }
    let mut v = n as f64 / 1024.0;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 {
        format!("{:.0}{}", v, UNITS[i])
    } else {
        format!("{:.1}{}", v, UNITS[i])
    }
}

/// 999 -> "999", 12_345 -> "12.3k", 4_500_000 -> "4.5M".
pub fn human_count(n: u64) -> String {
    match n {
        0..=9_999 => n.to_string(),
        10_000..=999_999 => format!("{:.1}k", n as f64 / 1e3),
        _ => format!("{:.1}M", n as f64 / 1e6),
    }
}

pub fn human_duration(ticks: u64) -> String {
    let s = ticks / TICKS_PER_SEC;
    if s < 60 {
        format!("{}s", s)
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    }
}

/// Number of terminal cells a string occupies. Treats every char as one cell, which is
/// exact for the ASCII-dominated content we render (paths, IPs, host names).
pub fn cells(s: &str) -> usize {
    s.chars().count()
}

/// Truncates to `width` cells keeping the head and the tail: `C:\Program…\WINWORD.EXE`.
pub fn ellipsize_middle(s: &str, width: usize) -> String {
    let n = cells(s);
    if n <= width {
        return s.to_string();
    }
    if width <= 1 {
        return "…".chars().take(width).collect();
    }
    let keep = width - 1;
    let head = keep * 2 / 5;
    let tail = keep - head;
    let chars: Vec<char> = s.chars().collect();
    let mut out: String = chars[..head].iter().collect();
    out.push('…');
    out.extend(&chars[n - tail..]);
    out
}

/// Truncates to `width` cells, marking the cut with `…`.
pub fn ellipsize_end(s: &str, width: usize) -> String {
    if cells(s) <= width {
        return s.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let mut out: String = s.chars().take(width - 1).collect();
    out.push('…');
    out
}

/// Left-aligned cell padded/truncated to exactly `width` cells.
pub fn pad(s: &str, width: usize) -> String {
    let t = ellipsize_end(s, width);
    let n = cells(&t);
    format!("{}{}", t, " ".repeat(width - n))
}

/// Right-aligned cell padded/truncated to exactly `width` cells.
pub fn rpad(s: &str, width: usize) -> String {
    let t = ellipsize_end(s, width);
    let n = cells(&t);
    format!("{}{}", " ".repeat(width - n), t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_formatting() {
        // 2026-10-21T14:03:22.123456Z
        let unix = 1_792_591_402u64; // seconds
        let ft = UNIX_EPOCH_TICKS + unix * TICKS_PER_SEC + 1_234_560;
        assert_eq!(iso8601(ft), "2026-10-21T14:03:22.123456Z");
        assert_eq!(hms_millis(ft), "14:03:22.123Z");
        assert_eq!(iso8601(UNIX_EPOCH_TICKS), "1970-01-01T00:00:00.000000Z");
        // leap day
        assert_eq!(
            date(UNIX_EPOCH_TICKS + 1_709_164_800 * TICKS_PER_SEC),
            "2024-02-29"
        );
    }

    #[test]
    fn glob_matching() {
        let g = Glob::new("WinWord*");
        assert!(g.matches_lc("winword.exe"));
        assert!(!g.matches_lc("excel.exe"));
        let g = Glob::new("*\\office16\\*.exe");
        assert!(g.matches_lc("c:\\program files\\microsoft office\\root\\office16\\winword.exe"));
        let g = Glob::new("w?nword.exe");
        assert!(g.matches_lc("winword.exe"));
        assert!(!g.matches_lc("winword.exe.bak"));
        assert!(Glob::new("*").matches_lc(""));
        assert!(Glob::new("a*b*c").matches_lc("axxbyyc"));
        assert!(!Glob::new("a*b*c").matches_lc("axxbyy"));
    }

    #[test]
    fn ellipsis() {
        let p = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE";
        let e = ellipsize_middle(p, 30);
        assert_eq!(cells(&e), 30);
        assert!(e.starts_with("C:\\Program"));
        assert!(e.ends_with("WINWORD.EXE"));
        assert_eq!(ellipsize_end("abcdef", 4), "abc…");
        assert_eq!(pad("ab", 4), "ab  ");
        assert_eq!(rpad("ab", 4), "  ab");
    }

    #[test]
    fn humanize() {
        assert_eq!(human_bytes(512), "512");
        assert_eq!(human_bytes(1536), "1.5K");
        assert_eq!(human_bytes(150 * 1024 * 1024), "150M");
        assert_eq!(human_count(12_345), "12.3k");
    }
}
