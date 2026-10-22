//! IP Helper table polling (`GetExtendedTcpTable` / `GetExtendedUdpTable`).
//!
//! Provides authoritative TCP *state* (SYN_SENT, TIME_WAIT, CLOSE_WAIT, ...), seeds
//! connections that predate monitoring, and is the sole source when ETW is unavailable
//! (non-elevated). Buffers are reused across polls so steady-state polling is allocation-free.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};

use crate::model::{canonical, ConnState};

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

#[derive(Debug, Clone, Copy)]
pub struct TcpRow {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: ConnState,
    pub pid: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct UdpRow {
    pub local: SocketAddr,
    pub pid: u32,
}

#[derive(Default)]
pub struct IpHelper {
    buf: Vec<u64>,
}

/// Ports are stored in network byte order in the low 16 bits of a DWORD.
fn port(dw: u32) -> u16 {
    u16::from_be(dw as u16)
}

impl IpHelper {
    fn fetch(
        &mut self,
        call: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32,
    ) -> Result<usize, u32> {
        if self.buf.is_empty() {
            self.buf.resize(16 * 1024, 0);
        }
        for _ in 0..8 {
            let mut size = (self.buf.len() * 8) as u32;
            match call(self.buf.as_mut_ptr() as *mut _, &mut size) {
                0 => return Ok(size as usize),
                ERROR_INSUFFICIENT_BUFFER => {
                    // Table grows between the size probe and the copy under churn: add headroom.
                    self.buf.resize((size as usize * 5 / 4) / 8 + 64, 0);
                }
                e => return Err(e),
            }
        }
        Err(ERROR_INSUFFICIENT_BUFFER)
    }

    fn rows<T: Copy>(&self) -> impl Iterator<Item = T> + '_ {
        let base = self.buf.as_ptr() as *const u8;
        let n = unsafe { std::ptr::read_unaligned(base as *const u32) } as usize;
        let max = (self.buf.len() * 8 - 4) / std::mem::size_of::<T>();
        (0..n.min(max)).map(move |i| unsafe {
            std::ptr::read_unaligned(base.add(4 + i * std::mem::size_of::<T>()) as *const T)
        })
    }

    pub fn tcp(&mut self, out: &mut Vec<TcpRow>) -> Result<(), u32> {
        out.clear();
        self.fetch(|p, s| unsafe {
            GetExtendedTcpTable(p, s, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        })?;
        out.extend(self.rows::<MIB_TCPROW_OWNER_PID>().map(|r| TcpRow {
            local: SocketAddr::from((
                Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()),
                port(r.dwLocalPort),
            )),
            remote: SocketAddr::from((
                Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes()),
                port(r.dwRemotePort),
            )),
            state: ConnState::from_mib(r.dwState),
            pid: r.dwOwningPid,
        }));
        self.fetch(|p, s| unsafe {
            GetExtendedTcpTable(p, s, 0, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)
        })?;
        out.extend(self.rows::<MIB_TCP6ROW_OWNER_PID>().map(|r| TcpRow {
            local: canonical(SocketAddr::from((
                Ipv6Addr::from(r.ucLocalAddr),
                port(r.dwLocalPort),
            ))),
            remote: canonical(SocketAddr::from((
                Ipv6Addr::from(r.ucRemoteAddr),
                port(r.dwRemotePort),
            ))),
            state: ConnState::from_mib(r.dwState),
            pid: r.dwOwningPid,
        }));
        Ok(())
    }

    pub fn udp(&mut self, out: &mut Vec<UdpRow>) -> Result<(), u32> {
        out.clear();
        self.fetch(|p, s| unsafe {
            GetExtendedUdpTable(p, s, 0, AF_INET, UDP_TABLE_OWNER_PID, 0)
        })?;
        out.extend(self.rows::<MIB_UDPROW_OWNER_PID>().map(|r| UdpRow {
            local: SocketAddr::from((
                Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()),
                port(r.dwLocalPort),
            )),
            pid: r.dwOwningPid,
        }));
        self.fetch(|p, s| unsafe {
            GetExtendedUdpTable(p, s, 0, AF_INET6, UDP_TABLE_OWNER_PID, 0)
        })?;
        out.extend(self.rows::<MIB_UDP6ROW_OWNER_PID>().map(|r| UdpRow {
            local: canonical(SocketAddr::from((
                Ipv6Addr::from(r.ucLocalAddr),
                port(r.dwLocalPort),
            ))),
            pid: r.dwOwningPid,
        }));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn sees_own_listener_with_pid() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let mut h = IpHelper::default();
        let mut rows = Vec::new();
        h.tcp(&mut rows).unwrap();
        let mine = rows
            .iter()
            .find(|r| r.local.port() == port && r.state == ConnState::Listen)
            .expect("listener present");
        assert_eq!(mine.pid, std::process::id());
        assert_eq!(mine.local.ip(), std::net::IpAddr::from([127, 0, 0, 1]));
    }

    #[test]
    fn sees_own_udp_socket() {
        let s = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = s.local_addr().unwrap().port();
        let mut h = IpHelper::default();
        let mut rows = Vec::new();
        h.udp(&mut rows).unwrap();
        assert!(rows
            .iter()
            .any(|r| r.local.port() == port && r.pid == std::process::id()));
    }
}
