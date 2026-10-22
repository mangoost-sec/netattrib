//! Embeds the Windows resources: the icon (Explorer, taskbar, Alt+Tab), version information
//! (Explorer's Details tab, Task Manager's process name) and the application manifest.

/// * `asInvoker`: never auto-elevated by installer detection; elevation is an explicit choice
///   ("Run as administrator", or the GUI's restart button).
/// * Common Controls 6: themed message boxes and Save dialog.
/// * `supportedOS` Windows 10/11: the real OS version and current behaviour, not a
///   compatibility shim.
/// * `longPathAware`: paths beyond MAX_PATH where the system allows them.
///
/// DPI awareness is deliberately *not* declared: winit makes the process per-monitor aware when
/// the window is created, and `gui::initial_size` reads the work area before that, in the 96-DPI
/// points egui sizes windows in.
const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"
        processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </windowsSettings>
  </application>
</assembly>
"#;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/netattrib.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set_language(0x0409)
        .set_icon("assets/netattrib.ico")
        .set("FileDescription", "netattrib network attribution")
        .set("ProductName", "netattrib")
        .set("InternalName", "netattrib")
        .set("OriginalFilename", "netattrib.exe")
        .set("Comments", env!("CARGO_PKG_DESCRIPTION"))
        .set("LegalCopyright", "MIT License")
        .set_manifest(MANIFEST);
    if let Err(e) = res.compile() {
        // rc.exe ships with the Windows SDK, which linking against kernel32.lib needs anyway.
        panic!("embedding Windows resources failed (is the Windows SDK installed?): {e}");
    }
}
