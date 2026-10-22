//! Console plumbing: VT mode, live window size, Ctrl+C / window-close handling.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Console::{
    GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle, SetConsoleCtrlHandler,
    SetConsoleMode, CONSOLE_SCREEN_BUFFER_INFO, ENABLE_PROCESSED_OUTPUT,
    ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
};

static STOP: AtomicBool = AtomicBool::new(false);
static CTRL_C_COUNT: AtomicU32 = AtomicU32::new(0);
/// Set while the alternate-screen TUI owns the terminal, so panics/forced exits restore it.
pub static TUI_ACTIVE: AtomicBool = AtomicBool::new(false);

pub const LEAVE_TUI: &str = "\x1b[?25h\x1b[?1049l";

fn stdout_handle() -> HANDLE {
    unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }
}

fn is_console(h: HANDLE) -> bool {
    let mut mode = 0u32;
    unsafe { GetConsoleMode(h, &mut mode) != 0 }
}

pub fn stdout_is_console() -> bool {
    is_console(stdout_handle())
}

/// Enables ANSI escape processing (Windows 10 1511+). Returns false on legacy consoles.
pub fn enable_vt() -> bool {
    let mut ok = true;
    for h in [stdout_handle(), unsafe { GetStdHandle(STD_ERROR_HANDLE) }] {
        let mut mode = 0u32;
        if unsafe { GetConsoleMode(h, &mut mode) } == 0 {
            continue;
        }
        let want = mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT;
        if unsafe { SetConsoleMode(h, want) } == 0 {
            ok = false;
        }
    }
    ok
}

/// Visible window size `(columns, rows)`; `None` when stdout is not a console.
pub fn size() -> Option<(usize, usize)> {
    let mut info: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
    if unsafe { GetConsoleScreenBufferInfo(stdout_handle(), &mut info) } == 0 {
        return None;
    }
    let w = (info.srWindow.Right - info.srWindow.Left + 1).max(1) as usize;
    let h = (info.srWindow.Bottom - info.srWindow.Top + 1).max(1) as usize;
    Some((w, h))
}

pub fn request_stop() {
    STOP.store(true, Ordering::SeqCst);
}

pub fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

unsafe extern "system" fn handler(ctrl: u32) -> i32 {
    const CTRL_C: u32 = 0;
    const CTRL_BREAK: u32 = 1;
    match ctrl {
        CTRL_C | CTRL_BREAK => {
            if CTRL_C_COUNT.fetch_add(1, Ordering::SeqCst) == 0 {
                request_stop();
            } else {
                // Second Ctrl+C: the user wants out now.
                crate::capture::etw::emergency_stop();
                if TUI_ACTIVE.load(Ordering::SeqCst) {
                    eprint!("{}", LEAVE_TUI);
                }
                std::process::exit(130);
            }
            1
        }
        // Close / logoff / shutdown: we get ~5 s; never leak the kernel session.
        _ => {
            crate::capture::etw::emergency_stop();
            request_stop();
            0
        }
    }
}

pub fn install_ctrl_handler() {
    unsafe { SetConsoleCtrlHandler(Some(handler), 1) };
}
