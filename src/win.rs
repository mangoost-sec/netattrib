//! Thin RAII and privilege helpers over raw Win32 handles.

use std::ptr::null_mut;

use windows_sys::core::w;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenElevation,
    LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::LibraryLoader::{
    SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Owned kernel handle, closed on drop.
pub struct Handle(pub HANDLE);

impl Handle {
    pub fn new(h: HANDLE) -> Option<Self> {
        if h.is_null() || h as isize == -1 {
            None
        } else {
            Some(Handle(h))
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

// Process/token handles are plain kernel object references and may be used from any thread.
unsafe impl Send for Handle {}

pub fn last_error() -> u32 {
    unsafe { GetLastError() }
}

/// Restricts DLLs loaded at run time (`LoadLibrary` without explicit search flags, as used by
/// opengl32, winit and the shell dialogs) to System32: never the executable's directory, the
/// current directory or PATH, where a planted DLL would run with netattrib's (often elevated)
/// rights. The imports resolved before `main` are covered by `/DEPENDENTLOADFLAG:0x800`
/// (.cargo/config.toml).
pub fn restrict_dll_search() -> bool {
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != 0 }
}

fn current_token(access: u32) -> Option<Handle> {
    let mut h: HANDLE = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut h) } == 0 {
        return None;
    }
    Handle::new(h)
}

pub fn is_elevated() -> bool {
    let Some(tok) = current_token(TOKEN_QUERY) else {
        return false;
    };
    let mut elev = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            tok.0,
            TokenElevation,
            &mut elev as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
    };
    ok != 0 && elev.TokenIsElevated != 0
}

/// Enables SeDebugPrivilege so non-protected processes of other users/SYSTEM can be opened.
/// Only succeeds for elevated administrators; returns whether the privilege is now active.
pub fn enable_debug_privilege() -> bool {
    let Some(tok) = current_token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) else {
        return false;
    };
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    if unsafe { LookupPrivilegeValueW(std::ptr::null(), w!("SeDebugPrivilege"), &mut luid) } == 0 {
        return false;
    }
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    let ok = unsafe { AdjustTokenPrivileges(tok.0, 0, &tp, 0, null_mut(), null_mut()) };
    // AdjustTokenPrivileges "succeeds" even when the privilege is not held.
    ok != 0 && last_error() != ERROR_NOT_ALL_ASSIGNED
}
