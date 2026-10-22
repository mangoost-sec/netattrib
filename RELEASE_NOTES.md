# netattrib v1.0.0

[English](README.md) | [Русский](README_RU.md)

The first public release of **netattrib**: per-executable network attribution for Windows. It
answers *which binary talked to whom, when, as which user, and how much*, including sockets that
live for only a few milliseconds. It ships as one statically linked executable with a desktop GUI and
a console mode for scripts and SIEM pipelines. No installer, no VC++ redistributable, no .NET.

## Highlights

**Capture and attribution**
- Real-time ETW consumer (Kernel-Network, Kernel-Process, DNS-Client) fused with IP Helper table
  polling: short-lived connections are caught, and each one is tied to the exact process instance
  (PID plus creation time), so a recycled PID never inherits someone else's traffic.
- Per-connection byte counters, TCP states, the owning user and SID, svchost services, and the
  domain *the application itself* resolved, with reverse DNS as the fallback.
- Fake-IP aware: behind TUN-mode proxies (v2rayN, Xray, sing-box), `198.18.0.0/15` destinations are
  labelled with the real domain from the DNS-Client cache.
- Without administrator rights it falls back to polling automatically and says so.

**Desktop GUI**
- Process tree (parent → child, PID-reuse safe) with All / User / System scopes, a process search
  that prunes the tree, and live connection counts.
- Connection table with spreadsheet-style columns: independent resizing, horizontal scrolling,
  double-click auto-fit, and widths remembered across restarts.
- Excel-style AutoFilter on every column: a search box plus a checklist of distinct values with
  counts. Filters combine across columns, and each column's list follows the others' filters.
- Local proxy pairing: an application's `127.0.0.1` socket shows *via xray.exe (pid)*, and the
  proxy's side shows who connected to it. Self-loopback noise (`esrv_svc.exe`) is hidden; proxy
  loopback never is.
- Authenticode checks (embedded, catalog and MSIX package) with a warning on unsigned or invalidly
  signed processes that talk to the internet.
- Context menus: open file location, VirusTotal lookups for IPs, domains and executable hashes (only
  the hash leaves the machine), Close Connection (`SetTcpEntry`, IPv4 TCP, administrator), and a
  PID-reuse-safe Terminate process.
- CSV / JSON export of the rows shown, settings persistence, and a portable mode
  (`netattrib.settings.ron` next to the exe).

**Console and SIEM**
- Live connection table, a per-executable live view (`--group`), JSON Lines and CSV streams,
  per-interval aggregates and an exit summary, process filters by name, path, PID and process tree.

## Security

netattrib is meant to run elevated, so the binary is hardened against the attacks that matter there:

- **DLL planting:** imported DLLs load from System32 only (`/DEPENDENTLOADFLAG:0x800`), and runtime
  loads are restricted with `SetDefaultDllDirectories`. Verified: with `tdh.dll`, `wintrust.dll` and
  `iphlpapi.dll` planted next to the exe, it starts normally and ignores them.
- **Executable planting:** Explorer and the browser hand-off use `%SystemRoot%\explorer.exe` by
  absolute path, and the browser opens un-elevated even when netattrib is elevated.
- **Exploit mitigations:** Control Flow Guard and Intel CET shadow-stack compatibility (`/CETCOMPAT`),
  on top of ASLR (high entropy) and DEP.
- **Manifest:** `asInvoker`, so Windows never auto-elevates it.
- Signature checks are offline: no certificate downloads, no traffic of netattrib's own.

## Download

| File | Size |
|---|---|
| `netattrib-v1.0.0-windows-x64.zip` (netattrib.exe, README.md, README_RU.md, LICENSE) | 3,276,701 bytes |
| `netattrib-v1.0.0-windows-x64.zip.sha256` | 99 bytes |

**SHA-256** of `netattrib-v1.0.0-windows-x64.zip`:

```
20d94b39256cd8ff69da173ea8768ed3ab36736c919a8b487a3169dc7800e3fe
```

### Verifying the download

PowerShell:

```powershell
(Get-FileHash .\netattrib-v1.0.0-windows-x64.zip -Algorithm SHA256).Hash
```

Command Prompt:

```bat
certutil -hashfile netattrib-v1.0.0-windows-x64.zip SHA256
```

Git Bash, WSL or Linux (with the `.sha256` file in the same folder):

```sh
sha256sum -c netattrib-v1.0.0-windows-x64.zip.sha256
```

The printed hash must equal the one above (letter case does not matter). If it does not, do not run
the file.

## Requirements

- Windows 10/11 or Windows Server, x64.
- Run it as administrator for full capture (short-lived sockets, byte counters, DNS-Client domain
  names); `SeDebugPrivilege` is then enabled automatically for owner lookups. Without elevation it
  runs in polling mode.
- Building from source: Rust 1.95+ (MSVC toolchain) and Visual Studio Build Tools with the Windows
  SDK; `cargo build --release`, or `scripts\package-release.ps1` for the release zip.

## Known limitations

- DNS that bypasses the Windows resolver (DNS-over-HTTPS, browsers' own resolvers) produces no
  DNS-Client names; those flows fall back to reverse DNS.
- Byte counters exist only in ETW (elevated) mode, from the moment monitoring starts.
- Close Connection works for IPv4 TCP only; the application may reconnect.
- Signature revocation is not checked (verification is offline).

See the [README](README.md) for the full documentation, design notes and verification status.

---

## Кратко по-русски

Первый публичный выпуск **netattrib** — утилиты сетевой атрибуции для Windows: какой исполняемый
файл, когда, от имени какого пользователя, с кем и сколько данных обменялся, включая сокеты,
живущие миллисекунды. Захват через ETW ядра с точной привязкой к экземпляру процесса, учёт байтов,
домены, запрошенные самим приложением (включая fake-IP за TUN-прокси), графический интерфейс с
деревом процессов, фильтрами столбцов в стиле Excel, проверкой цифровых подписей и контекстными
меню, а также консольный режим для скриптов и SIEM. Сборка защищена от подмены DLL, использует
Control Flow Guard и аппаратный теневой стек Intel CET.

Проверка загруженного архива: `(Get-FileHash .\netattrib-v1.0.0-windows-x64.zip -Algorithm SHA256).Hash`
должен совпасть с хешем выше. Полная документация на русском — в [README_RU.md](README_RU.md).
