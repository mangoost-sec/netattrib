//! PID -> hosted Windows services, so traffic from shared `svchost.exe` instances can be
//! attributed to e.g. `Dnscache` or `wuauserv` instead of an anonymous host process.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use windows_sys::Win32::System::Services::{
    CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW,
    SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
};

use crate::util::from_wide_ptr;

#[derive(Default)]
pub struct ServiceMap {
    map: RwLock<HashMap<u32, Arc<str>>>,
}

impl ServiceMap {
    pub fn get(&self, pid: u32) -> Option<Arc<str>> {
        self.map.read().unwrap().get(&pid).cloned()
    }

    pub fn refresh(&self) {
        if let Some(m) = enumerate() {
            *self.map.write().unwrap() = m;
        }
    }
}

fn enumerate() -> Option<HashMap<u32, Arc<str>>> {
    let scm = unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_ENUMERATE_SERVICE,
        )
    };
    if scm.is_null() {
        return None;
    }
    let mut buf: Vec<u64> = vec![0; 32 * 1024];
    let mut by_pid: HashMap<u32, Vec<String>> = HashMap::new();
    let mut resume = 0u32;
    loop {
        let (mut needed, mut count) = (0u32, 0u32);
        let ok = unsafe {
            EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_ACTIVE,
                buf.as_mut_ptr() as *mut u8,
                (buf.len() * 8) as u32,
                &mut needed,
                &mut count,
                &mut resume,
                std::ptr::null(),
            )
        };
        let more =
            ok == 0 && crate::win::last_error() == windows_sys::Win32::Foundation::ERROR_MORE_DATA;
        if ok == 0 && !more {
            break;
        }
        let entries = unsafe {
            std::slice::from_raw_parts(
                buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                count as usize,
            )
        };
        for e in entries {
            let pid = e.ServiceStatusProcess.dwProcessId;
            if pid != 0 {
                by_pid
                    .entry(pid)
                    .or_default()
                    .push(unsafe { from_wide_ptr(e.lpServiceName) });
            }
        }
        if !more {
            break;
        }
        if count == 0 {
            if (needed as usize) <= buf.len() * 8 {
                break;
            }
            buf.resize(needed as usize / 8 + 1, 0);
        }
    }
    unsafe { CloseServiceHandle(scm) };
    Some(
        by_pid
            .into_iter()
            .map(|(pid, mut names)| {
                names.sort();
                (pid, Arc::from(names.join(",")))
            })
            .collect(),
    )
}
