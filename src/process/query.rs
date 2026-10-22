//! Process metadata queries.
//!
//! Path resolution is layered so it degrades gracefully across permission boundaries:
//! 1. `QueryFullProcessImageNameW` with `PROCESS_QUERY_LIMITED_INFORMATION` (documented;
//!    works for most processes, including PPL, when elevated).
//! 2. `NtQuerySystemInformation(SystemProcessIdInformation)` - returns the NT image path for
//!    *any* PID without opening a handle, so it also works non-elevated and for protected
//!    processes. The NT path (`\Device\HarddiskVolume3\...`) is mapped back to a DOS path.
//! 3. The short image name from the process snapshot.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use windows_sys::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SystemProcessInformation,
};
use windows_sys::Win32::Foundation::{LocalFree, FILETIME, HANDLE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountSidW, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::util::{filetime_to_u64, from_wide, wide, FileTime};
use crate::win::Handle;

const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
const SYSTEM_PROCESS_ID_INFORMATION: i32 = 88;

#[derive(Debug, Clone)]
pub struct SnapEntry {
    pub pid: u32,
    pub ppid: u32,
    pub create_time: FileTime,
    pub session_id: u32,
    pub name: String,
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

/// Leading, stable part of `SYSTEM_PROCESS_INFORMATION` (x64 offsets are ABI-frozen).
#[repr(C)]
struct SystemProcessInfo {
    next_entry_offset: u32,
    number_of_threads: u32,
    working_set_private_size: i64,
    hard_fault_count: u32,
    number_of_threads_high_watermark: u32,
    cycle_time: u64,
    create_time: i64,
    user_time: i64,
    kernel_time: i64,
    image_name: UnicodeString,
    base_priority: i32,
    unique_process_id: usize,
    inherited_from_unique_process_id: usize,
    handle_count: u32,
    session_id: u32,
}

#[repr(C)]
struct SystemProcessIdInfo {
    process_id: usize,
    image_name: UnicodeString,
}

/// Full process list with creation times in one syscall; needs no handles or privileges.
pub fn snapshot() -> std::io::Result<Vec<SnapEntry>> {
    Snapshotter::default().take()
}

/// Reusable snapshot buffer: the kernel output (which includes per-thread records) is
/// megabytes on busy hosts, so repeated polling must not re-allocate and re-zero it.
#[derive(Default)]
pub struct Snapshotter {
    buf: Vec<u64>,
}

impl Snapshotter {
    pub fn take(&mut self) -> std::io::Result<Vec<SnapEntry>> {
        if self.buf.is_empty() {
            self.buf.resize(64 * 1024, 0);
        }
        loop {
            let bytes = (self.buf.len() * 8).min(u32::MAX as usize) as u32;
            let mut needed = 0u32;
            let st = unsafe {
                NtQuerySystemInformation(
                    SystemProcessInformation,
                    self.buf.as_mut_ptr() as *mut _,
                    bytes,
                    &mut needed,
                )
            };
            if st == STATUS_INFO_LENGTH_MISMATCH {
                // Headroom for processes/threads created before the retry.
                self.buf.resize((needed as usize * 5 / 4) / 8 + 1, 0);
                continue;
            }
            if st < 0 {
                return Err(std::io::Error::other(format!(
                    "NtQuerySystemInformation: 0x{:08X}",
                    st as u32
                )));
            }
            break;
        }
        Ok(parse_snapshot(&self.buf))
    }
}

fn parse_snapshot(buf: &[u64]) -> Vec<SnapEntry> {
    let base = buf.as_ptr() as *const u8;
    let mut out = Vec::with_capacity(512);
    let mut off = 0usize;
    loop {
        let info = unsafe { &*(base.add(off) as *const SystemProcessInfo) };
        let pid = info.unique_process_id as u32;
        let name = if info.image_name.buffer.is_null() || info.image_name.length == 0 {
            if pid == 0 {
                "System Idle Process".to_string()
            } else {
                String::new()
            }
        } else {
            let s = unsafe {
                std::slice::from_raw_parts(
                    info.image_name.buffer,
                    info.image_name.length as usize / 2,
                )
            };
            String::from_utf16_lossy(s)
        };
        out.push(SnapEntry {
            pid,
            ppid: info.inherited_from_unique_process_id as u32,
            create_time: info.create_time as u64,
            session_id: info.session_id,
            name,
        });
        if info.next_entry_offset == 0 {
            break;
        }
        off += info.next_entry_offset as usize;
    }
    out
}

pub fn open_limited(pid: u32) -> Option<Handle> {
    Handle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })
}

pub fn create_time_of(h: &Handle) -> Option<FileTime> {
    let z = || FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut c, mut e, mut k, mut u) = (z(), z(), z(), z());
    if unsafe { GetProcessTimes(h.0, &mut c, &mut e, &mut k, &mut u) } == 0 {
        return None;
    }
    Some(filetime_to_u64(&c))
}

pub fn image_path_win32(h: &Handle) -> Option<String> {
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    if unsafe { QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) }
        == 0
    {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..len as usize]))
}

/// NT image path for any live PID, no handle required.
pub fn image_path_nt(pid: u32) -> Option<String> {
    let mut cap: usize = 1024;
    for _ in 0..2 {
        let mut buf = vec![0u16; cap];
        let mut info = SystemProcessIdInfo {
            process_id: pid as usize,
            image_name: UnicodeString {
                length: 0,
                maximum_length: (cap * 2) as u16,
                buffer: buf.as_mut_ptr(),
            },
        };
        let st = unsafe {
            NtQuerySystemInformation(
                SYSTEM_PROCESS_ID_INFORMATION,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<SystemProcessIdInfo>() as u32,
                std::ptr::null_mut(),
            )
        };
        if st == STATUS_INFO_LENGTH_MISMATCH && (info.image_name.maximum_length as usize) / 2 > cap
        {
            cap = info.image_name.maximum_length as usize / 2 + 1;
            continue;
        }
        if st < 0 || info.image_name.length == 0 {
            return None;
        }
        return Some(String::from_utf16_lossy(
            &buf[..info.image_name.length as usize / 2],
        ));
    }
    None
}

/// Best-effort full DOS path for a live PID: documented API first, then the NT fallback.
pub fn image_path(pid: u32, handle: Option<&Handle>) -> Option<String> {
    if let Some(h) = handle {
        if let Some(p) = image_path_win32(h) {
            return Some(p);
        }
    }
    image_path_nt(pid).map(|nt| normalize_nt_path(&nt))
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub sid: String,
    pub account: Option<String>,
}

/// Owner of the process token. Requires `PROCESS_QUERY_LIMITED_INFORMATION` + `TOKEN_QUERY`;
/// typically fails non-elevated for SYSTEM/service processes (reported as unknown).
pub fn token_user(
    h: &Handle,
    account_cache: &mut HashMap<String, Option<String>>,
) -> Option<UserInfo> {
    let mut tok: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(h.0, TOKEN_QUERY, &mut tok) } == 0 {
        return None;
    }
    let tok = Handle::new(tok)?;
    let mut buf = vec![0u64; 64];
    let mut ret = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            tok.0,
            TokenUser,
            buf.as_mut_ptr() as *mut _,
            (buf.len() * 8) as u32,
            &mut ret,
        )
    };
    if ok == 0 {
        return None;
    }
    let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let psid = tu.User.Sid;
    let mut sid_str: *mut u16 = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(psid, &mut sid_str) } == 0 {
        return None;
    }
    let sid = unsafe { crate::util::from_wide_ptr(sid_str) };
    unsafe { LocalFree(sid_str as *mut _) };
    let account = account_cache
        .entry(sid.clone())
        .or_insert_with(|| lookup_account(psid))
        .clone();
    Some(UserInfo { sid, account })
}

fn lookup_account(psid: *mut core::ffi::c_void) -> Option<String> {
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let (mut n, mut d, mut use_) = (name.len() as u32, domain.len() as u32, 0i32);
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            psid,
            name.as_mut_ptr(),
            &mut n,
            domain.as_mut_ptr(),
            &mut d,
            &mut use_,
        )
    };
    if ok == 0 {
        return None;
    }
    let (name, domain) = (from_wide(&name), from_wide(&domain));
    Some(if domain.is_empty() {
        name
    } else {
        format!("{}\\{}", domain, name)
    })
}

/// `\Device\HarddiskVolumeN` -> `C:` mapping, refreshed lazily when a lookup misses
/// (new volume mounted) at most every 30 s.
struct DeviceMap {
    entries: Vec<(String, String)>,
    loaded: Instant,
}

fn load_device_map() -> DeviceMap {
    let mut entries = Vec::new();
    let mut target = vec![0u16; 1024];
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:", letter as char);
        let n = unsafe {
            QueryDosDeviceW(
                wide(&drive).as_ptr(),
                target.as_mut_ptr(),
                target.len() as u32,
            )
        };
        if n == 0 {
            continue;
        }
        let dev = from_wide(&target);
        if !dev.is_empty() {
            entries.push((dev.to_lowercase(), drive));
        }
    }
    // Longest device names first so `\Device\HarddiskVolume1` never shadows `...Volume10`.
    entries.sort_by_key(|e| std::cmp::Reverse(e.0.len()));
    DeviceMap {
        entries,
        loaded: Instant::now(),
    }
}

fn device_map() -> &'static RwLock<DeviceMap> {
    static MAP: OnceLock<RwLock<DeviceMap>> = OnceLock::new();
    MAP.get_or_init(|| RwLock::new(load_device_map()))
}

fn map_device(nt: &str, map: &DeviceMap) -> Option<String> {
    let lc = nt.to_lowercase();
    for (dev, drive) in &map.entries {
        if lc.starts_with(dev.as_str()) && lc.as_bytes().get(dev.len()) == Some(&b'\\') {
            return Some(format!("{}{}", drive, &nt[dev.len()..]));
        }
    }
    None
}

/// Converts kernel image paths into user-facing DOS paths.
pub fn normalize_nt_path(nt: &str) -> String {
    if let Some(rest) = nt.strip_prefix("\\??\\") {
        return rest.to_string();
    }
    let lc = nt.to_lowercase();
    if lc.starts_with("\\systemroot\\") {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        return format!("{}{}", root, &nt["\\SystemRoot".len()..]);
    }
    if lc.starts_with("\\device\\mup\\") {
        return format!("\\\\{}", &nt["\\Device\\Mup\\".len()..]);
    }
    if !lc.starts_with("\\device\\") {
        return nt.to_string();
    }
    if let Some(p) = map_device(nt, &device_map().read().unwrap()) {
        return p;
    }
    {
        let mut m = device_map().write().unwrap();
        if m.loaded.elapsed() > Duration::from_secs(30) {
            *m = load_device_map();
        }
        if let Some(p) = map_device(nt, &m) {
            return p;
        }
    }
    nt.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_contains_self() {
        let snap = snapshot().expect("snapshot");
        let me = std::process::id();
        let entry = snap.iter().find(|e| e.pid == me).expect("own pid present");
        assert!(entry.create_time > 0);
        assert!(snap.iter().any(|e| e.pid == 4), "System process present");
    }

    #[test]
    fn nt_path_roundtrip_for_self() {
        let me = std::process::id();
        let nt = image_path_nt(me).expect("nt path");
        assert!(nt.starts_with("\\Device\\"), "{}", nt);
        let dos = normalize_nt_path(&nt);
        let exe = std::env::current_exe().unwrap();
        assert_eq!(dos.to_lowercase(), exe.to_string_lossy().to_lowercase());
        let h = open_limited(me).unwrap();
        assert_eq!(
            image_path_win32(&h).unwrap().to_lowercase(),
            dos.to_lowercase()
        );
    }

    #[test]
    fn own_token_user() {
        let h = open_limited(std::process::id()).unwrap();
        let mut cache = HashMap::new();
        let u = token_user(&h, &mut cache).expect("own token readable");
        assert!(u.sid.starts_with("S-1-"));
        assert!(u.account.is_some());
    }

    #[test]
    fn nt_prefixes() {
        assert_eq!(normalize_nt_path("\\??\\C:\\x\\y.exe"), "C:\\x\\y.exe");
        assert_eq!(
            normalize_nt_path("\\Device\\Mup\\srv\\share\\a.exe"),
            "\\\\srv\\share\\a.exe"
        );
        assert_eq!(normalize_nt_path("Registry"), "Registry");
    }
}

#[cfg(test)]
mod bench {
    #[test]
    #[ignore]
    fn cost_of_poll_primitives() {
        let t = std::time::Instant::now();
        for _ in 0..50 {
            let _ = super::snapshot().unwrap();
        }
        println!("snapshot (fresh buffer): {:?}/call", t.elapsed() / 50);
        let mut s = super::Snapshotter::default();
        let t = std::time::Instant::now();
        for _ in 0..50 {
            let _ = s.take().unwrap();
        }
        println!("snapshot (reused buffer): {:?}/call", t.elapsed() / 50);
        let mut h = crate::capture::iphlp::IpHelper::default();
        let mut rows = Vec::new();
        let t = std::time::Instant::now();
        for _ in 0..50 {
            h.tcp(&mut rows).unwrap();
        }
        println!(
            "tcp tables: {:?}/call ({} rows)",
            t.elapsed() / 50,
            rows.len()
        );
    }
}
