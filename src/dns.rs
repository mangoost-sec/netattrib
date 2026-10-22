//! Remote address -> domain name resolution that never blocks the capture loop.
//!
//! Two sources, in order of preference:
//! 1. **Passive (DNS-Client ETW)**: the name the application itself asked for, captured from
//!    `Microsoft-Windows-DNS-Client` event 3008 and keyed by `(ip, pid)`. This is what you
//!    want for CDN-fronted services where PTR records are meaningless.
//! 2. **Active PTR**: `GetNameInfoW(NI_NAMEREQD)` on a small worker pool fed by a bounded
//!    queue. Lookups are de-duplicated while in flight and cached with positive/negative TTLs.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Networking::WinSock::{
    GetNameInfoW, WSAStartup, NI_NAMEREQD, SOCKADDR, WSADATA,
};

use crate::model::skip_rdns;
use crate::util::from_wide;

const PASSIVE_TTL: Duration = Duration::from_secs(3600);
const PTR_POSITIVE_TTL: Duration = Duration::from_secs(3600);
const PTR_NEGATIVE_TTL: Duration = Duration::from_secs(600);
const MAX_ENTRIES: usize = 100_000;
const QUEUE_DEPTH: usize = 4096;
const NAMES_PER_IP: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainSource {
    DnsClient,
    Ptr,
}

impl DomainSource {
    pub fn label(&self) -> &'static str {
        match self {
            DomainSource::DnsClient => "dns-client",
            DomainSource::Ptr => "ptr",
        }
    }
}

struct PassiveEntry {
    /// Most recent first: `(pid, name)`.
    names: Vec<(u32, Arc<str>)>,
    expires: Instant,
}

struct PtrEntry {
    name: Option<Arc<str>>,
    expires: Instant,
}

#[derive(Default)]
pub struct DnsStats {
    pub passive_answers: AtomicU64,
    pub ptr_lookups: AtomicU64,
    pub ptr_hits: AtomicU64,
    pub ptr_dropped: AtomicU64,
}

pub struct Dns {
    passive: Mutex<HashMap<IpAddr, PassiveEntry>>,
    ptr: Mutex<HashMap<IpAddr, PtrEntry>>,
    inflight: Mutex<HashSet<IpAddr>>,
    queue: Option<SyncSender<IpAddr>>,
    pub stats: DnsStats,
}

impl Dns {
    pub fn new(rdns: bool, workers: usize) -> Arc<Self> {
        let (queue, rx) = if rdns {
            let (tx, rx) = sync_channel::<IpAddr>(QUEUE_DEPTH);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };
        let dns = Arc::new(Dns {
            passive: Mutex::new(HashMap::new()),
            ptr: Mutex::new(HashMap::new()),
            inflight: Mutex::new(HashSet::new()),
            queue,
            stats: DnsStats::default(),
        });
        if let Some(rx) = rx {
            winsock_init();
            let rx = Arc::new(Mutex::new(rx));
            for i in 0..workers.max(1) {
                let (dns, rx) = (Arc::downgrade(&dns), rx.clone());
                std::thread::Builder::new()
                    .name(format!("rdns-{}", i))
                    .spawn(move || ptr_worker(dns, rx))
                    .expect("spawn rdns worker");
            }
        }
        dns
    }

    /// Records the answer of a DNS query made by `pid`.
    pub fn observe_answer(&self, pid: u32, name: &str, addrs: &[IpAddr]) {
        if addrs.is_empty() {
            return;
        }
        let name: Arc<str> = Arc::from(name.trim_end_matches('.').to_lowercase());
        let expires = Instant::now() + PASSIVE_TTL;
        let mut map = self.passive.lock().unwrap();
        for ip in addrs {
            let e = map.entry(*ip).or_insert_with(|| PassiveEntry {
                names: Vec::new(),
                expires,
            });
            e.expires = expires;
            e.names.retain(|(p, n)| !(*p == pid && *n == name));
            e.names.insert(0, (pid, name.clone()));
            e.names.truncate(NAMES_PER_IP);
        }
        self.stats.passive_answers.fetch_add(1, Ordering::Relaxed);
        if map.len() > MAX_ENTRIES {
            evict(&mut map, |e| e.expires);
        }
    }

    /// Non-blocking. Prefers the name *this* process resolved, then any process's, then PTR.
    /// A miss schedules a background PTR lookup.
    pub fn lookup(&self, ip: IpAddr, pid: u32) -> Option<(Arc<str>, DomainSource)> {
        let now = Instant::now();
        {
            let map = self.passive.lock().unwrap();
            if let Some(e) = map.get(&ip).filter(|e| e.expires > now) {
                let hit = e
                    .names
                    .iter()
                    .find(|(p, _)| *p == pid)
                    .or_else(|| e.names.first());
                if let Some((_, n)) = hit {
                    return Some((n.clone(), DomainSource::DnsClient));
                }
            }
        }
        {
            let map = self.ptr.lock().unwrap();
            if let Some(e) = map.get(&ip).filter(|e| e.expires > now) {
                return e.name.clone().map(|n| (n, DomainSource::Ptr));
            }
        }
        self.prefetch(ip);
        None
    }

    /// True while a PTR lookup for `ip` is queued or running.
    pub fn in_flight(&self, ip: &IpAddr) -> bool {
        self.inflight.lock().unwrap().contains(ip)
    }

    /// Schedules a PTR lookup unless cached, in flight, or not worth resolving.
    pub fn prefetch(&self, ip: IpAddr) {
        let Some(q) = &self.queue else { return };
        if skip_rdns(&ip) {
            return;
        }
        if self
            .ptr
            .lock()
            .unwrap()
            .get(&ip)
            .is_some_and(|e| e.expires > Instant::now())
        {
            return;
        }
        if !self.inflight.lock().unwrap().insert(ip) {
            return;
        }
        match q.try_send(ip) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                // Queue saturated: drop and retry on a later sighting rather than block.
                self.inflight.lock().unwrap().remove(&ip);
                self.stats.ptr_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn store_ptr(&self, ip: IpAddr, name: Option<String>) {
        let ttl = if name.is_some() {
            PTR_POSITIVE_TTL
        } else {
            PTR_NEGATIVE_TTL
        };
        let mut map = self.ptr.lock().unwrap();
        map.insert(
            ip,
            PtrEntry {
                name: name.map(|n| Arc::from(n.to_lowercase())),
                expires: Instant::now() + ttl,
            },
        );
        if map.len() > MAX_ENTRIES {
            evict(&mut map, |e| e.expires);
        }
        drop(map);
        self.inflight.lock().unwrap().remove(&ip);
    }
}

fn evict<V>(map: &mut HashMap<IpAddr, V>, expires: impl Fn(&V) -> Instant) {
    let now = Instant::now();
    map.retain(|_, v| expires(v) > now);
    if map.len() > MAX_ENTRIES {
        // Still oversized: drop the entries closest to expiry.
        let mut by_age: Vec<(Instant, IpAddr)> =
            map.iter().map(|(k, v)| (expires(v), *k)).collect();
        by_age.sort();
        for (_, k) in by_age.into_iter().take(MAX_ENTRIES / 4) {
            map.remove(&k);
        }
    }
}

fn ptr_worker(dns: std::sync::Weak<Dns>, rx: Arc<Mutex<Receiver<IpAddr>>>) {
    loop {
        let ip = match rx.lock().unwrap().recv() {
            Ok(ip) => ip,
            Err(_) => return,
        };
        let name = reverse_lookup(ip);
        let Some(dns) = dns.upgrade() else { return };
        dns.stats.ptr_lookups.fetch_add(1, Ordering::Relaxed);
        if name.is_some() {
            dns.stats.ptr_hits.fetch_add(1, Ordering::Relaxed);
        }
        dns.store_ptr(ip, name);
    }
}

fn winsock_init() {
    let mut data: WSADATA = unsafe { std::mem::zeroed() };
    unsafe { WSAStartup(0x0202, &mut data) };
}

/// SOCKADDR_IN6-sized, suitably aligned storage for either address family.
#[repr(C, align(8))]
struct SockAddrBuf([u8; 28]);

fn sockaddr(ip: IpAddr) -> (SockAddrBuf, i32) {
    let mut b = SockAddrBuf([0; 28]);
    match ip {
        IpAddr::V4(v4) => {
            b.0[0..2].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
            b.0[4..8].copy_from_slice(&v4.octets());
            (b, 16)
        }
        IpAddr::V6(v6) => {
            b.0[0..2].copy_from_slice(&23u16.to_le_bytes()); // AF_INET6
            b.0[8..24].copy_from_slice(&v6.octets());
            (b, 28)
        }
    }
}

pub fn reverse_lookup(ip: IpAddr) -> Option<String> {
    let (sa, len) = sockaddr(ip);
    let mut host = vec![0u16; 1025];
    let rc = unsafe {
        GetNameInfoW(
            sa.0.as_ptr() as *const SOCKADDR,
            len,
            host.as_mut_ptr(),
            host.len() as u32,
            std::ptr::null_mut(),
            0,
            NI_NAMEREQD as i32,
        )
    };
    if rc != 0 {
        return None;
    }
    let h = from_wide(&host);
    (!h.is_empty() && h.parse::<IpAddr>().is_err()).then_some(h)
}

/// Parses DNS-Client `QueryResults`, e.g.
/// `type:  5 edge.example.net;::ffff:13.107.42.14;2620:1ec:bdf::14;`
pub fn parse_query_results(s: &str) -> Vec<IpAddr> {
    s.split(';')
        .filter_map(|tok| {
            let t = tok.trim();
            if t.is_empty() || t.starts_with("type:") {
                return None;
            }
            t.parse::<IpAddr>().ok().map(crate::model::canonical_ip)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mixed_results() {
        let ips = parse_query_results("type:  5 a.b.net;::ffff:13.107.42.14;2620:1ec:bdf::14;");
        assert_eq!(
            ips,
            vec![
                "13.107.42.14".parse::<IpAddr>().unwrap(),
                "2620:1ec:bdf::14".parse().unwrap()
            ]
        );
        assert!(parse_query_results("").is_empty());
    }

    #[test]
    fn passive_prefers_own_pid() {
        let d = Dns::new(false, 0);
        let ip: IpAddr = "13.107.42.14".parse().unwrap();
        d.observe_answer(100, "ecs.office.com.", &[ip]);
        d.observe_answer(200, "other.example", &[ip]);
        assert_eq!(&*d.lookup(ip, 100).unwrap().0, "ecs.office.com");
        assert_eq!(&*d.lookup(ip, 200).unwrap().0, "other.example");
        // Unknown pid gets the most recent name.
        assert_eq!(&*d.lookup(ip, 999).unwrap().0, "other.example");
    }

    #[test]
    fn localhost_ptr() {
        winsock_init();
        // Loopback always reverse-resolves to the local host name; just ensure no crash.
        let _ = reverse_lookup("127.0.0.1".parse().unwrap());
    }
}
