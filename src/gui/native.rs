//! Win32 pieces the GUI needs beyond eframe: console detach, the Save dialog, UAC relaunch,
//! Explorer / browser hand-off, process termination, closing a TCP connection and a
//! last-resort error box.

use std::ffi::OsStr;
use std::net::SocketAddrV4;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use windows_sys::core::w;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_MR_MID_NOT_FOUND, ERROR_NOT_FOUND,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCP_STATE_DELETE_TCB,
};
use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
use windows_sys::Win32::System::Threading::{
    IsProcessCritical, OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE,
};
use windows_sys::Win32::UI::Controls::Dialogs::{
    GetSaveFileNameW, OFN_EXPLORER, OFN_NOCHANGEDIR, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST,
    OPENFILENAMEW,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::GetActiveWindow;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, MessageBoxW, MB_ICONERROR, MB_OK, SM_CXMAXIMIZED, SM_CYMAXIMIZED,
    SW_SHOWNORMAL,
};

use crate::process::query;
use crate::util::{from_wide, wide, FileTime};
use crate::win::{last_error, Handle};

/// Size of a maximized window on the primary monitor. Called before eframe makes the process
/// DPI aware, so the values are in 96-DPI units: the same points egui sizes windows in.
pub fn work_area() -> (f32, f32) {
    unsafe {
        (
            GetSystemMetrics(SM_CXMAXIMIZED) as f32,
            GetSystemMetrics(SM_CYMAXIMIZED) as f32,
        )
    }
}

/// `%SystemRoot%\explorer.exe`, by absolute path. `Command` looks a bare `explorer.exe` up in
/// netattrib's own directory first, so a copy planted next to netattrib.exe would run with its
/// (often elevated) rights.
fn explorer() -> PathBuf {
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let dir = if n > 0 && n < buf.len() {
        from_wide(&buf[..n])
    } else {
        r"C:\Windows".to_string()
    };
    PathBuf::from(dir).join("explorer.exe")
}

/// `explorer.exe /select,"<path>"`. Explorer parses the quotes itself, so the argument must not
/// be re-quoted by `Command` (Windows paths cannot contain `"`).
fn select_arg(path: &str) -> String {
    format!("/select,\"{}\"", path)
}

/// A child process started by the GUI, with no standard handles. Started from Explorer,
/// netattrib frees its console (`detach_private_console`), and the standard handles it was
/// given go stale: `Command` would duplicate them for the child and fail with
/// ERROR_INVALID_HANDLE ("os error 6"). Explorer does not use them anyway.
fn detached(program: impl AsRef<OsStr>) -> Command {
    let mut c = Command::new(program);
    c.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    c
}

/// Opens an Explorer window with `path` selected. Explorer hands the request to the user's
/// running shell, so the window opens un-elevated even when netattrib is elevated.
pub fn show_in_explorer(path: &str) -> std::io::Result<()> {
    detached(explorer())
        .raw_arg(select_arg(path))
        .spawn()
        .map(drop)
}

/// Opens `url` in the default browser through the shell, never as a child of an elevated
/// netattrib.
pub fn open_url(url: &str) -> std::io::Result<()> {
    detached(explorer()).arg(url).spawn().map(drop)
}

/// The `SetTcpEntry` row that deletes the connection `local -> remote`: addresses and ports in
/// network byte order (only the low 16 bits of a port field count).
fn delete_tcb_row(local: SocketAddrV4, remote: SocketAddrV4) -> MIB_TCPROW_LH {
    MIB_TCPROW_LH {
        Anonymous: MIB_TCPROW_LH_0 {
            State: MIB_TCP_STATE_DELETE_TCB,
        },
        dwLocalAddr: u32::from_ne_bytes(local.ip().octets()),
        dwLocalPort: local.port().to_be() as u32,
        dwRemoteAddr: u32::from_ne_bytes(remote.ip().octets()),
        dwRemotePort: remote.port().to_be() as u32,
    }
}

/// Closes the IPv4 TCP connection `local -> remote`, as System Informer's "Close" does: the
/// stack drops it and resets the peer. Windows offers this for IPv4 only, to administrators.
pub fn close_tcp(local: SocketAddrV4, remote: SocketAddrV4) -> Result<(), String> {
    // Unelevated, Windows 11 answers ERROR_MR_MID_NOT_FOUND ("no such connection") rather than
    // ERROR_ACCESS_DENIED, which would misreport a live connection as closed.
    if !crate::win::is_elevated() {
        return Err("access denied (run as administrator)".into());
    }
    let row = delete_tcb_row(local, remote);
    match unsafe { SetTcpEntry(&row) } {
        0 => Ok(()),
        ERROR_ACCESS_DENIED => Err("access denied (run as administrator)".into()),
        // A connection that no longer exists comes back as ERROR_MR_MID_NOT_FOUND.
        ERROR_MR_MID_NOT_FOUND | ERROR_NOT_FOUND => Err("the connection is already closed".into()),
        e => Err(format!("SetTcpEntry failed (error {})", e)),
    }
}

/// Terminates the process instance `(pid, create_time)`. Refuses a PID that now belongs to a
/// different process, and critical system processes (killing one crashes Windows).
pub fn terminate_process(pid: u32, create_time: FileTime) -> Result<(), String> {
    let h = Handle::new(unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            pid,
        )
    })
    .ok_or_else(|| match last_error() {
        ERROR_ACCESS_DENIED => "access denied (protected process, or run as administrator)".into(),
        ERROR_INVALID_PARAMETER => "the process has already exited".into(),
        e => format!("cannot open the process (error {})", e),
    })?;
    if create_time != 0 && query::create_time_of(&h) != Some(create_time) {
        return Err("the process has already exited (its PID now belongs to another one)".into());
    }
    let mut critical = 0;
    if unsafe { IsProcessCritical(h.0, &mut critical) } != 0 && critical != 0 {
        return Err("it is a critical system process; terminating it would crash Windows".into());
    }
    if unsafe { TerminateProcess(h.0, 1) } == 0 {
        return Err(format!("TerminateProcess failed (error {})", last_error()));
    }
    Ok(())
}

/// netattrib is a console-subsystem binary so pipes and exit codes keep working. When it was
/// started from Explorer, Windows created a console just for us: release it so only the GUI
/// window remains. A console shared with a shell (started from a terminal) is kept.
pub fn detach_private_console() {
    let mut pids = [0u32; 2];
    if unsafe { GetConsoleProcessList(pids.as_mut_ptr(), pids.len() as u32) } == 1 {
        unsafe { FreeConsole() };
    }
}

/// Startup failures in GUI mode may have no console to print to.
pub fn error_box(msg: &str) {
    let text = wide(msg);
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            w!("netattrib"),
            MB_OK | MB_ICONERROR,
        )
    };
}

/// Modal "Save as" dialog owned by the active window. Returns `None` when cancelled.
pub fn save_dialog(default_name: &str) -> Option<PathBuf> {
    let filter = wide("CSV (*.csv)\0*.csv\0JSON (*.json)\0*.json\0");
    let mut file = vec![0u16; 32_768];
    for (dst, src) in file.iter_mut().zip(default_name.encode_utf16()) {
        *dst = src;
    }
    let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.hwndOwner = unsafe { GetActiveWindow() };
    ofn.lpstrFilter = filter.as_ptr();
    ofn.nFilterIndex = 1;
    ofn.lpstrFile = file.as_mut_ptr();
    ofn.nMaxFile = file.len() as u32;
    ofn.lpstrTitle = w!("Export connections");
    // Appended when no extension is typed; the dialog substitutes the selected filter's.
    ofn.lpstrDefExt = w!("csv");
    ofn.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if unsafe { GetSaveFileNameW(&mut ofn) } == 0 {
        return None;
    }
    Some(PathBuf::from(from_wide(&file)))
}

/// Starts this executable again through the UAC "runas" verb with the same arguments and
/// working directory. `Err(1223)` (`ERROR_CANCELLED`) means the user declined the prompt.
pub fn relaunch_elevated() -> Result<(), u32> {
    let exe = std::env::current_exe().map_err(|e| e.raw_os_error().unwrap_or(0) as u32)?;
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|a| quote_arg(&a.to_string_lossy()))
        .collect();
    let dir = std::env::current_dir().unwrap_or_default();
    let (exe, args, dir) = (
        wide(&exe.to_string_lossy()),
        wide(&args.join(" ")),
        wide(&dir.to_string_lossy()),
    );
    let h = unsafe {
        ShellExecuteW(
            GetActiveWindow(),
            w!("runas"),
            exe.as_ptr(),
            args.as_ptr(),
            dir.as_ptr(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecute reports success as a pseudo-HINSTANCE greater than 32.
    if h as usize > 32 {
        Ok(())
    } else {
        Err(last_error())
    }
}

/// Quotes one argument for `CommandLineToArgvW` / the MSVC runtime parser.
fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '"']) {
        return a.to_string();
    }
    let mut out = String::from('"');
    let mut backslashes = 0usize;
    for c in a.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(2 * backslashes + 1));
                out.push('"');
                backslashes = 0;
            }
            c => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(2 * backslashes));
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::quote_arg;
    use std::net::SocketAddr;

    /// Regression: "Cannot open the browser: os error 6". Started from Explorer, the GUI frees
    /// its console and its standard handles go stale; `Command` duplicated them for the child
    /// and failed. Re-runs this test in a child process whose standard handles are closed.
    #[test]
    fn launches_with_stale_standard_handles() {
        use std::os::windows::io::IntoRawHandle;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::System::Console::{
            SetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };
        const CHILD: &str = "NETATTRIB_TEST_STALE_STDIO";
        let me = std::env::current_exe().unwrap();
        let cmd = super::explorer().with_file_name(r"System32\cmd.exe");
        if std::env::var_os(CHILD).is_some() {
            let stale = std::fs::File::open(&me).unwrap().into_raw_handle() as HANDLE;
            unsafe {
                CloseHandle(stale);
                for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
                    SetStdHandle(id, stale);
                }
            }
            let ran = super::detached(&cmd).args(["/d", "/c", "exit 0"]).status();
            // Nothing can be printed from here on: the exit code is the verdict.
            std::process::exit(match ran {
                Ok(s) if s.success() => 0,
                Ok(_) => 2,
                Err(e) => 100 + e.raw_os_error().unwrap_or(0),
            });
        }
        let status = std::process::Command::new(&me)
            .args([
                "gui::native::tests::launches_with_stale_standard_handles",
                "--exact",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        // 106: CreateProcess failed with ERROR_INVALID_HANDLE.
        assert_eq!(status.code(), Some(0), "child exit code (100 + os error)");
    }

    #[test]
    fn explorer_is_launched_by_absolute_path() {
        let exe = super::explorer();
        assert!(exe.is_absolute(), "{}", exe.display());
        assert!(exe.is_file(), "{}", exe.display());
        assert!(exe.ends_with("explorer.exe"));
    }

    #[test]
    fn delete_tcb_row_is_in_network_byte_order() {
        use windows_sys::Win32::NetworkManagement::IpHelper::MIB_TCP_STATE_DELETE_TCB;
        let row = super::delete_tcb_row(
            "192.168.0.5:2892".parse().unwrap(),
            "203.0.113.10:2052".parse().unwrap(),
        );
        assert_eq!(unsafe { row.Anonymous.State }, MIB_TCP_STATE_DELETE_TCB);
        assert_eq!(row.dwLocalAddr.to_ne_bytes(), [192, 168, 0, 5]);
        assert_eq!(row.dwRemoteAddr.to_ne_bytes(), [203, 0, 113, 10]);
        assert_eq!(
            (row.dwLocalPort as u16).to_ne_bytes(),
            2892u16.to_be_bytes()
        );
        assert_eq!(
            (row.dwRemotePort as u16).to_ne_bytes(),
            2052u16.to_be_bytes()
        );
        assert_eq!(row.dwLocalPort >> 16, 0);
    }

    /// Elevated: the connection is reset and a second close finds nothing. Not elevated:
    /// refused with a hint to run as administrator.
    #[test]
    fn closes_an_ipv4_tcp_connection() {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let server = listener.local_addr().unwrap();
        let mut client = std::net::TcpStream::connect(server).unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        let (SocketAddr::V4(local), SocketAddr::V4(remote)) =
            (client.local_addr().unwrap(), server)
        else {
            unreachable!("bound to 127.0.0.1")
        };
        let result = super::close_tcp(local, remote);
        if crate::win::is_elevated() {
            result.expect("close as administrator");
            client
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut buf = [0u8; 1];
            assert!(matches!(client.read(&mut buf), Ok(0) | Err(_)), "reset");
            assert!(super::close_tcp(local, remote)
                .unwrap_err()
                .contains("already closed"));
        } else {
            let e = result.unwrap_err();
            assert!(e.contains("administrator"), "{e}");
        }
    }

    #[test]
    fn terminates_only_the_exact_instance() {
        use crate::process::query;
        let mut child = std::process::Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn ping");
        let pid = child.id();
        let created = query::open_limited(pid)
            .and_then(|h| query::create_time_of(&h))
            .expect("creation time");
        // The PID now belonging to a different instance (wrong creation time) is refused.
        assert!(super::terminate_process(pid, created + 1).is_err());
        assert!(child.try_wait().unwrap().is_none(), "still running");
        super::terminate_process(pid, created).expect("terminate");
        assert_eq!(child.wait().unwrap().code(), Some(1));
        // It is gone now.
        assert!(super::terminate_process(pid, created).is_err());
    }

    #[test]
    fn explorer_select_argument() {
        assert_eq!(
            super::select_arg(r"C:\Program Files\Microsoft Office\WINWORD.EXE"),
            r#"/select,"C:\Program Files\Microsoft Office\WINWORD.EXE""#
        );
    }

    #[test]
    fn argument_quoting() {
        assert_eq!(quote_arg("--gui"), "--gui");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("C:\\My Logs\\"), "\"C:\\My Logs\\\\\"");
        assert_eq!(quote_arg("say \"hi\""), "\"say \\\"hi\\\"\"");
    }
}
