//! Event Tracing for Windows real-time consumer.
//!
//! One private real-time session (not the singleton "NT Kernel Logger", so it coexists with
//! Process Monitor / System Informer / WPR) with three manifest providers:
//!
//! | Provider                          | Events                          | Purpose                        |
//! |-----------------------------------|---------------------------------|--------------------------------|
//! | Microsoft-Windows-Kernel-Network  | TCP/UDP send/recv/connect/...   | per-socket activity + bytes    |
//! | Microsoft-Windows-Kernel-Process  | 1 ProcessStart, 2 ProcessStop   | PID generations (reuse safety) |
//! | Microsoft-Windows-DNS-Client      | 3008 query completed            | passive name <- IP mapping     |
//!
//! Overhead control happens in the kernel, before events reach us: keyword masks plus an
//! `EVENT_FILTER_TYPE_EVENT_ID` allow-list (drops e.g. the TCPCopy events that would double
//! count bytes). Kernel-Network payloads have been frozen at version 0 since Vista and are
//! decoded at fixed offsets on the hot path; the low-rate process and DNS events, whose
//! layouts change across Windows builds (Kernel-Process start is v0..v4), are decoded by
//! property name through TDH.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};
use std::thread::JoinHandle;

use windows_sys::core::{GUID, PCWSTR};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND,
};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, QueryAllTracesW,
    StartTraceW, TdhGetProperty, TdhGetPropertySize, CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS,
    ENABLE_TRACE_PARAMETERS_VERSION_2, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR,
    EVENT_FILTER_TYPE_EVENT_ID, EVENT_RECORD, EVENT_TRACE_CONTROL_FLUSH, EVENT_TRACE_CONTROL_QUERY,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, PROPERTY_DATA_DESCRIPTOR, WNODE_FLAG_TRACED_GUID,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL,
};

use crate::aggregate::Engine;
use crate::dns::{parse_query_results, Dns};
use crate::model::{canonical, DnsAnswer, FlowKey, Proto};
use crate::process::query::normalize_nt_path;
use crate::process::Seed;
use crate::util::{from_wide, wide, FileTime};

pub const KERNEL_NETWORK: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
pub const KERNEL_PROCESS: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
pub const DNS_CLIENT: GUID = GUID::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);

const KN_KEYWORD_IPV4: u64 = 0x10;
const KN_KEYWORD_IPV6: u64 = 0x20;
const KP_KEYWORD_PROCESS: u64 = 0x10;
const LEVEL_INFO: u8 = 4;
const INVALID_PROCESSTRACE_HANDLE: u64 = u64::MAX;

pub const SESSION_PREFIX: &str = "NetAttrib-";

/// Kernel-Network event IDs (TCPv4 10-18, TCPv6 26-34, UDPv4 42/43, UDPv6 58/59).
/// Excluded on purpose: 17/49 (connect failure, carries no tuple/PID) and 18/34 (TCPCopy:
/// bytes already counted by the receive event).
const KN_LIFECYCLE: [u16; 10] = [12, 13, 15, 16, 14, 28, 29, 31, 32, 30];
const KN_TCP_DATA: [u16; 4] = [10, 11, 26, 27];
const KN_UDP_DATA: [u16; 4] = [42, 43, 58, 59];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetOp {
    Send,
    Recv,
    Connect,
    Accept,
    Disconnect,
    Reconnect,
    Retransmit,
}

#[derive(Clone, Copy, Debug)]
pub struct NetEvent {
    pub ts: FileTime,
    pub pid: u32,
    pub op: NetOp,
    pub key: FlowKey,
    pub size: u32,
}

/// Decodes a Kernel-Network payload. Layout (all v0):
/// `PID u32 | size u32 | daddr (4|16) | saddr (4|16) | dport u16be | sport u16be | ...`
/// `saddr/sport` are always the local endpoint and `daddr/dport` the remote one, for both
/// directions.
pub fn parse_kernel_network(id: u16, data: &[u8], ts: FileTime) -> Option<NetEvent> {
    use NetOp::*;
    let (op, proto, v6) = match id {
        10 => (Send, Proto::Tcp, false),
        11 => (Recv, Proto::Tcp, false),
        12 => (Connect, Proto::Tcp, false),
        13 => (Disconnect, Proto::Tcp, false),
        14 => (Retransmit, Proto::Tcp, false),
        15 => (Accept, Proto::Tcp, false),
        16 => (Reconnect, Proto::Tcp, false),
        26 => (Send, Proto::Tcp, true),
        27 => (Recv, Proto::Tcp, true),
        28 => (Connect, Proto::Tcp, true),
        29 => (Disconnect, Proto::Tcp, true),
        30 => (Retransmit, Proto::Tcp, true),
        31 => (Accept, Proto::Tcp, true),
        32 => (Reconnect, Proto::Tcp, true),
        42 => (Send, Proto::Udp, false),
        43 => (Recv, Proto::Udp, false),
        58 => (Send, Proto::Udp, true),
        59 => (Recv, Proto::Udp, true),
        _ => return None,
    };
    let u32_at = |o: usize| u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
    let be16_at = |o: usize| u16::from_be_bytes([data[o], data[o + 1]]);
    let (local, remote) = if v6 {
        if data.len() < 44 {
            return None;
        }
        let d: [u8; 16] = data[8..24].try_into().ok()?;
        let s: [u8; 16] = data[24..40].try_into().ok()?;
        (
            SocketAddr::from((Ipv6Addr::from(s), be16_at(42))),
            SocketAddr::from((Ipv6Addr::from(d), be16_at(40))),
        )
    } else {
        if data.len() < 20 {
            return None;
        }
        let d: [u8; 4] = data[8..12].try_into().ok()?;
        let s: [u8; 4] = data[12..16].try_into().ok()?;
        (
            SocketAddr::from((Ipv4Addr::from(s), be16_at(18))),
            SocketAddr::from((Ipv4Addr::from(d), be16_at(16))),
        )
    };
    Some(NetEvent {
        ts,
        pid: u32_at(0),
        op,
        key: FlowKey {
            proto,
            local: canonical(local),
            remote: canonical(remote),
        },
        size: u32_at(4),
    })
}

// ---------------------------------------------------------------------------------------
// Session control
// ---------------------------------------------------------------------------------------

/// `EVENT_TRACE_PROPERTIES` followed by room for the logger and log file names.
struct Props {
    buf: Vec<u64>,
}

impl Props {
    const NAME_BYTES: usize = 1024 * 2;

    fn new() -> Self {
        let size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + 2 * Self::NAME_BYTES;
        let mut p = Props {
            buf: vec![0u64; size / 8 + 1],
        };
        let props = p.get_mut();
        props.Wnode.BufferSize = size as u32;
        props.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        props.LogFileNameOffset =
            (std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + Self::NAME_BYTES) as u32;
        p
    }

    fn get_mut(&mut self) -> &mut EVENT_TRACE_PROPERTIES {
        unsafe { &mut *(self.buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES) }
    }

    fn ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES
    }

    fn logger_name(&self) -> String {
        let props = unsafe { &*(self.buf.as_ptr() as *const EVENT_TRACE_PROPERTIES) };
        let off = props.LoggerNameOffset as usize;
        let bytes = unsafe {
            std::slice::from_raw_parts((self.buf.as_ptr() as *const u8).add(off), Self::NAME_BYTES)
        };
        let wide: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        from_wide(&wide)
    }
}

pub struct SessionStats {
    pub events_lost: u32,
    pub realtime_buffers_lost: u32,
}

pub struct EtwSession {
    name: String,
    name_w: Vec<u16>,
    handle: CONTROLTRACE_HANDLE,
}

/// Session name used by the console control handler for an emergency stop on window close.
static ACTIVE_SESSION: OnceLock<Vec<u16>> = OnceLock::new();

impl EtwSession {
    /// Starts a real-time session. Fails with `ERROR_ACCESS_DENIED` (5) unless the caller is
    /// an administrator or a member of *Performance Log Users*.
    pub fn start(name: &str) -> Result<Self, u32> {
        fn session_props() -> Props {
            let cpus = std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(4);
            let mut props = Props::new();
            let p = props.get_mut();
            p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            p.Wnode.ClientContext = 1; // QPC timestamps (converted to FILETIME on delivery)
            p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            p.LogFileNameOffset = 0; // real-time only: no log file
                                     // A deep pool absorbs bursts (every TCP send/receive is an event) while the consumer
                                     // catches up. Per-CPU buffering needs >= 2 buffers per processor. Kernel memory:
                                     // 4 MB up front, at most 32 MB (128 KB x 256) up to 64 logical CPUs.
            p.BufferSize = 128; // KB
            p.MinimumBuffers = (2 * cpus).max(32);
            p.MaximumBuffers = (4 * cpus).max(256);
            p.FlushTimer = 1; // seconds; bounds delivery latency when traffic is light
            props
        }
        let name_w = wide(name);
        let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
        let mut rc = unsafe { StartTraceW(&mut handle, name_w.as_ptr(), session_props().ptr()) };
        if rc == ERROR_ALREADY_EXISTS {
            // Leftover from a crashed run with the same PID-derived name: replace it.
            stop_by_name(name);
            rc = unsafe { StartTraceW(&mut handle, name_w.as_ptr(), session_props().ptr()) };
        }
        if rc != ERROR_SUCCESS {
            return Err(rc);
        }
        let _ = ACTIVE_SESSION.set(name_w.clone());
        Ok(EtwSession {
            name: name.to_string(),
            name_w,
            handle,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Enables a provider, with an event-ID allow-list applied in the kernel when supported.
    pub fn enable(&self, provider: &GUID, keywords: u64, event_ids: &[u16]) -> Result<(), u32> {
        let mut filter_buf: Vec<u8> = Vec::with_capacity(4 + 2 * event_ids.len());
        filter_buf.push(1); // FilterIn = TRUE
        filter_buf.push(0); // Reserved
        filter_buf.extend_from_slice(&(event_ids.len() as u16).to_le_bytes());
        for id in event_ids {
            filter_buf.extend_from_slice(&id.to_le_bytes());
        }
        let mut desc = EVENT_FILTER_DESCRIPTOR {
            Ptr: filter_buf.as_ptr() as u64,
            Size: filter_buf.len() as u32,
            Type: EVENT_FILTER_TYPE_EVENT_ID,
        };
        let mut params: ENABLE_TRACE_PARAMETERS = unsafe { std::mem::zeroed() };
        params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
        if !event_ids.is_empty() {
            params.EnableFilterDesc = &mut desc;
            params.FilterDescCount = 1;
        }
        let call = |p: *const ENABLE_TRACE_PARAMETERS| unsafe {
            EnableTraceEx2(
                self.handle,
                provider,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                LEVEL_INFO,
                keywords,
                0,
                0,
                p,
            )
        };
        let rc = call(&params);
        if rc == ERROR_SUCCESS {
            return Ok(());
        }
        // Pre-8.1 or filter rejected: fall back to callback-side filtering.
        params.EnableFilterDesc = std::ptr::null_mut();
        params.FilterDescCount = 0;
        match call(&params) {
            ERROR_SUCCESS => Ok(()),
            e => Err(e),
        }
    }

    pub fn stats(&self) -> Option<SessionStats> {
        let mut props = Props::new();
        let rc = unsafe {
            ControlTraceW(
                self.handle,
                std::ptr::null(),
                props.ptr(),
                EVENT_TRACE_CONTROL_QUERY,
            )
        };
        if rc != ERROR_SUCCESS {
            return None;
        }
        let p = props.get_mut();
        Some(SessionStats {
            events_lost: p.EventsLost,
            realtime_buffers_lost: p.RealTimeBuffersLost,
        })
    }

    /// Delivers all non-empty buffers to the consumer now instead of at the next FlushTimer
    /// tick (1 s is the documented minimum for the timer itself).
    pub fn flush(&self) {
        let mut props = Props::new();
        unsafe {
            ControlTraceW(
                self.handle,
                std::ptr::null(),
                props.ptr(),
                EVENT_TRACE_CONTROL_FLUSH,
            )
        };
    }

    pub fn stop(&self) {
        let mut props = Props::new();
        unsafe {
            ControlTraceW(
                self.handle,
                self.name_w.as_ptr(),
                props.ptr(),
                EVENT_TRACE_CONTROL_STOP,
            )
        };
    }
}

impl Drop for EtwSession {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn stop_by_name(name: &str) -> u32 {
    let w = wide(name);
    let mut props = Props::new();
    unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            w.as_ptr(),
            props.ptr(),
            EVENT_TRACE_CONTROL_STOP,
        )
    }
}

/// Called from the console control handler when the window is closing: there is no time
/// for an orderly shutdown, but a real-time session must not outlive us.
pub fn emergency_stop() {
    if let Some(w) = ACTIVE_SESSION.get() {
        let mut props = Props::new();
        unsafe {
            ControlTraceW(
                CONTROLTRACE_HANDLE { Value: 0 },
                w.as_ptr(),
                props.ptr(),
                EVENT_TRACE_CONTROL_STOP,
            )
        };
    }
}

/// Stops `NetAttrib-<pid>` sessions whose owning PID is no longer a running netattrib.
/// Real-time sessions survive process death and the system-wide limit is 64.
pub fn cleanup_stale_sessions(is_ours_alive: impl Fn(u32) -> bool) -> Vec<String> {
    const MAX: usize = 64;
    let mut storage: Vec<Props> = (0..MAX).map(|_| Props::new()).collect();
    let mut ptrs: Vec<*mut EVENT_TRACE_PROPERTIES> = storage.iter_mut().map(|p| p.ptr()).collect();
    let mut count = 0u32;
    let rc = unsafe { QueryAllTracesW(ptrs.as_mut_ptr(), MAX as u32, &mut count) };
    if rc != ERROR_SUCCESS {
        return Vec::new();
    }
    let mut stopped = Vec::new();
    for p in storage.iter().take(count as usize) {
        let name = p.logger_name();
        let Some(pid) = name
            .strip_prefix(SESSION_PREFIX)
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid != std::process::id() && !is_ours_alive(pid) {
            let rc = stop_by_name(&name);
            if rc == ERROR_SUCCESS || rc == ERROR_WMI_INSTANCE_NOT_FOUND {
                stopped.push(name);
            }
        }
    }
    stopped
}

// ---------------------------------------------------------------------------------------
// Consumer
// ---------------------------------------------------------------------------------------

pub struct Consumer {
    pub engine: Arc<Engine>,
    pub dns: Arc<Dns>,
}

pub struct ConsumerThread {
    handle: PROCESSTRACE_HANDLE,
    join: Option<JoinHandle<u32>>,
    _ctx: Arc<Consumer>,
}

impl ConsumerThread {
    pub fn close(mut self) -> Option<u32> {
        unsafe { CloseTrace(self.handle) };
        self.join.take().and_then(|j| j.join().ok())
    }
}

pub fn enable_providers(s: &EtwSession, bytes: bool) -> Result<(), (String, u32)> {
    let mut net_ids: Vec<u16> = KN_LIFECYCLE.to_vec();
    net_ids.extend_from_slice(&KN_UDP_DATA);
    if bytes {
        net_ids.extend_from_slice(&KN_TCP_DATA);
    }
    s.enable(&KERNEL_PROCESS, KP_KEYWORD_PROCESS, &[1, 2])
        .map_err(|e| ("Microsoft-Windows-Kernel-Process".to_string(), e))?;
    s.enable(&KERNEL_NETWORK, KN_KEYWORD_IPV4 | KN_KEYWORD_IPV6, &net_ids)
        .map_err(|e| ("Microsoft-Windows-Kernel-Network".to_string(), e))?;
    // DNS-Client is optional enrichment; failure is not fatal.
    if let Err(e) = s.enable(&DNS_CLIENT, u64::MAX, &[3008]) {
        eprintln!(
            "netattrib: warning: DNS-Client provider not enabled (error {}); domains via PTR only",
            e
        );
    }
    Ok(())
}

pub fn start_consumer(session: &EtwSession, ctx: Arc<Consumer>) -> Result<ConsumerThread, u32> {
    let mut name_w = wide(session.name());
    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
    logfile.LoggerName = name_w.as_mut_ptr();
    logfile.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(on_event);
    logfile.Context = Arc::as_ptr(&ctx) as *mut _;
    let handle = unsafe { OpenTraceW(&mut logfile) };
    if handle.Value == INVALID_PROCESSTRACE_HANDLE {
        return Err(crate::win::last_error());
    }
    let h = handle.Value;
    let join = std::thread::Builder::new()
        .name("etw-consumer".into())
        .spawn(move || {
            // A consumer starved by the UI or other busy threads is the other way to lose
            // real-time buffers; the callback itself only holds the engine lock briefly.
            unsafe { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL) };
            let handles = [PROCESSTRACE_HANDLE { Value: h }];
            unsafe { ProcessTrace(handles.as_ptr(), 1, std::ptr::null(), std::ptr::null()) }
        })
        .map_err(|_| 0u32)?;
    Ok(ConsumerThread {
        handle,
        join: Some(join),
        _ctx: ctx,
    })
}

fn guid_eq(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    let rec = &*rec;
    if rec.UserContext.is_null() {
        return;
    }
    let ctx = &*(rec.UserContext as *const Consumer);
    let hdr = &rec.EventHeader;
    let id = hdr.EventDescriptor.Id;
    let ts = hdr.TimeStamp as u64;
    ctx.engine
        .counters
        .etw_events
        .fetch_add(1, Ordering::Relaxed);

    if guid_eq(&hdr.ProviderId, &KERNEL_NETWORK) {
        let data = if rec.UserData.is_null() {
            &[][..]
        } else {
            std::slice::from_raw_parts(rec.UserData as *const u8, rec.UserDataLength as usize)
        };
        if let Some(ev) = parse_kernel_network(id, data, ts) {
            ctx.engine.on_net(ev);
        }
    } else if guid_eq(&hdr.ProviderId, &KERNEL_PROCESS) {
        match id {
            1 => {
                let (Some(pid), Some(ct)) =
                    (tdh_u32(rec, w("ProcessID")), tdh_u64(rec, w("CreateTime")))
                else {
                    return;
                };
                let ppid = tdh_u32(rec, w("ParentProcessID")).unwrap_or(0);
                let session_id = tdh_u32(rec, w("SessionID")).unwrap_or(0);
                let nt = tdh_wstr(rec, w("ImageName")).unwrap_or_default();
                let path = normalize_nt_path(&nt);
                let name = path.rsplit('\\').next().unwrap_or(&path).to_string();
                ctx.engine.on_process_start(Seed {
                    pid,
                    ppid,
                    create_time: ct,
                    session_id,
                    name,
                    path,
                    attribution: crate::model::Attribution::Exact,
                    exit_time: None,
                });
            }
            2 => {
                let Some(pid) = tdh_u32(rec, w("ProcessID")) else {
                    return;
                };
                let ct = tdh_u64(rec, w("CreateTime")).unwrap_or(0);
                let name = tdh_astr(rec, w("ImageName")).unwrap_or_default();
                ctx.engine.on_process_stop(pid, ct, ts, &name);
            }
            _ => {}
        }
    } else if guid_eq(&hdr.ProviderId, &DNS_CLIENT) && id == 3008 {
        let (Some(name), Some(results)) = (
            tdh_wstr(rec, w("QueryName")),
            tdh_wstr(rec, w("QueryResults")),
        ) else {
            return;
        };
        let status = tdh_u32(rec, w("QueryStatus")).unwrap_or(0);
        let addrs: Vec<IpAddr> = parse_query_results(&results);
        if !addrs.is_empty() {
            ctx.dns.observe_answer(hdr.ProcessId, &name, &addrs);
        }
        ctx.engine.on_dns(
            hdr.ProcessId,
            ts,
            DnsAnswer {
                query: name.trim_end_matches('.').to_string(),
                status,
                addrs,
            },
        );
    }
}

// ---------------------------------------------------------------------------------------
// TDH property access (low-rate events only)
// ---------------------------------------------------------------------------------------

/// Interned, NUL-terminated UTF-16 property names.
fn w(name: &'static str) -> PCWSTR {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static NAMES: OnceLock<Mutex<HashMap<&'static str, &'static [u16]>>> = OnceLock::new();
    let mut m = NAMES.get_or_init(Default::default).lock().unwrap();
    m.entry(name)
        .or_insert_with(|| Box::leak(wide(name).into_boxed_slice()))
        .as_ptr()
}

unsafe fn tdh_raw(rec: &EVENT_RECORD, name: PCWSTR) -> Option<Vec<u8>> {
    let desc = PROPERTY_DATA_DESCRIPTOR {
        PropertyName: name as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };
    let mut size = 0u32;
    if TdhGetPropertySize(rec, 0, std::ptr::null(), 1, &desc, &mut size) != ERROR_SUCCESS
        || size == 0
    {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    if TdhGetProperty(rec, 0, std::ptr::null(), 1, &desc, size, buf.as_mut_ptr()) != ERROR_SUCCESS {
        return None;
    }
    Some(buf)
}

unsafe fn tdh_u32(rec: &EVENT_RECORD, name: PCWSTR) -> Option<u32> {
    let b = tdh_raw(rec, name)?;
    Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
}

unsafe fn tdh_u64(rec: &EVENT_RECORD, name: PCWSTR) -> Option<u64> {
    let b = tdh_raw(rec, name)?;
    Some(u64::from_le_bytes(b.get(..8)?.try_into().ok()?))
}

unsafe fn tdh_wstr(rec: &EVENT_RECORD, name: PCWSTR) -> Option<String> {
    let b = tdh_raw(rec, name)?;
    let w: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(from_wide(&w))
}

unsafe fn tdh_astr(rec: &EVENT_RECORD, name: PCWSTR) -> Option<String> {
    let b = tdh_raw(rec, name)?;
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    Some(String::from_utf8_lossy(&b[..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_payload(
        pid: u32,
        size: u32,
        daddr: [u8; 4],
        saddr: [u8; 4],
        dport: u16,
        sport: u16,
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&pid.to_le_bytes());
        v.extend_from_slice(&size.to_le_bytes());
        v.extend_from_slice(&daddr);
        v.extend_from_slice(&saddr);
        v.extend_from_slice(&dport.to_be_bytes());
        v.extend_from_slice(&sport.to_be_bytes());
        v.extend_from_slice(&[0u8; 16]); // startime/endtime/seqnum/connid
        v
    }

    #[test]
    fn tcpv4_send() {
        let p = v4_payload(4512, 1460, [52, 109, 8, 21], [192, 168, 1, 5], 443, 50123);
        let ev = parse_kernel_network(10, &p, 7).unwrap();
        assert_eq!(ev.pid, 4512);
        assert_eq!(ev.size, 1460);
        assert_eq!(ev.op, NetOp::Send);
        assert_eq!(ev.key.proto, Proto::Tcp);
        assert_eq!(ev.key.local, "192.168.1.5:50123".parse().unwrap());
        assert_eq!(ev.key.remote, "52.109.8.21:443".parse().unwrap());
    }

    #[test]
    fn udpv6_recv_and_mapped_v4() {
        let mut p = Vec::new();
        p.extend_from_slice(&77u32.to_le_bytes());
        p.extend_from_slice(&512u32.to_le_bytes());
        let remote: Ipv6Addr = "::ffff:8.8.8.8".parse().unwrap();
        let local: Ipv6Addr = "::ffff:10.0.0.2".parse().unwrap();
        p.extend_from_slice(&remote.octets());
        p.extend_from_slice(&local.octets());
        p.extend_from_slice(&53u16.to_be_bytes());
        p.extend_from_slice(&61000u16.to_be_bytes());
        p.extend_from_slice(&[0u8; 8]);
        let ev = parse_kernel_network(59, &p, 1).unwrap();
        assert_eq!(ev.op, NetOp::Recv);
        assert_eq!(ev.key.proto, Proto::Udp);
        assert_eq!(ev.key.remote, "8.8.8.8:53".parse().unwrap());
        assert_eq!(ev.key.local, "10.0.0.2:61000".parse().unwrap());
    }

    #[test]
    fn rejects_truncated_and_unknown() {
        assert!(parse_kernel_network(10, &[0u8; 10], 0).is_none());
        assert!(parse_kernel_network(26, &[0u8; 30], 0).is_none());
        assert!(parse_kernel_network(18, &[0u8; 64], 0).is_none()); // TCPCopy ignored
    }
}
