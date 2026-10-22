# netattrib — per-executable network attribution for Windows

Answer *"which binary talked to whom, when, as which user, and how much"* on Windows 10/11 and
Windows Server (x64), including sockets that live for a few milliseconds.

* **Track 1** — evaluation of existing battle-tested tools for the same job (§1).
* **Track 2** — `netattrib`, a single 7 MB static executable: an ETW real-time consumer fused with
  IP Helper polling, a PID-reuse-safe process resolver, passive + active DNS, a console table, a
  grouped live view, and JSON Lines / CSV streaming for SIEM pipelines (§2–§8).

```text
> netattrib --filter-exe winword.exe --dns-events          (illustrative output)
-- 2026-10-21 (UTC)
  TIMESTAMP     PROCESS          PID PATH                              PROTO LOCAL              REMOTE            DOMAIN                     STATE       DIR
? 14:03:22.101Z WINWORD.EXE     4512 C:\Program Files\…\WINWORD.EXE    DNS   -                  52.109.8.21       ecs.office.com             NOERROR     out
+ 14:03:22.123Z WINWORD.EXE     4512 C:\Program Files\…\WINWORD.EXE    TCP4  10.0.0.5:50123     52.109.8.21:443   ecs.office.com             ESTABLISHED out
- 14:03:29.870Z WINWORD.EXE     4512 C:\Program Files\…\WINWORD.EXE    TCP4  10.0.0.5:50123     52.109.8.21:443   ecs.office.com             CLOSED      out
```
(`+` open, `~` TCP state change, `-` close, `L` listen, `?` DNS query. Microsoft Word's binary is
`WINWORD.EXE`; `--filter-exe word.exe` prints a hint pointing at it.)

---

## 1. Track 1 — existing tools

### 1.1 Sysinternals TCPView / Tcpvcon

| | |
|---|---|
| Interface | GUI (`tcpview64.exe`) and a one-shot CLI (`tcpvcon64.exe`). |
| Word example | `tcpvcon64 -a -c -n winword.exe` (`-a` all endpoints, `-c` CSV, `-n` no name resolution). For a timeline, loop it: `while(1){ tcpvcon64 -a -c -n winword.exe >> w.csv; sleep 1 }`. GUI: type `winword` in the filter box. |
| Mechanism | Polls `GetExtendedTcpTable`/`GetExtendedUdpTable` on a refresh timer (1/2/5 s; new rows green, closing rows red). |
| Transient processes | Weak. A connection that opens and closes between two refreshes never appears. If the owning process has exited by render time, the row shows `<non-existent>`. Nothing ties a PID to a process *instance*. |
| Verdict | Best for a quick interactive look at long-lived connections. Not an audit trail. |

### 1.2 System Informer (formerly Process Hacker)

| | |
|---|---|
| Interface | GUI only. The *Network* tab has a search box (`winword`); lists can be saved as text/CSV. There is no headless export. |
| Mechanism | **Hybrid.** The connection list is polled from the IP Helper tables at the update interval (1 s by default). Per-process network I/O rates come from an ETW kernel session (TCP/IP events), and the optional kernel driver opens protected processes. |
| Transient processes | Byte counters and per-process graphs reflect short bursts, because ETW is event-driven. The connection **list** still misses sockets shorter than the update interval, and an exited process disappears from the view with its history. |
| Verdict | The best interactive per-process explorer (services, hostnames, highlighting). Not built for capture-and-forward telemetry. |

### 1.3 ETW-native workflows (logman / WPR / netsh / pktmon → WPA / Wireshark)

| Workflow | Command sketch | Process attribution |
|---|---|---|
| **logman + Kernel-Network** (zero install, event-driven) | `logman start na -pf providers.txt -o C:\t\na.etl -ets` … `logman stop na -ets`, with `providers.txt` containing `{7DD42A49-5329-4832-8DFD-43D979153A88} 0x30 0x4` (Kernel-Network) and `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716} 0x10 0x4` (Kernel-Process). Read it back with `Get-WinEvent -Path C:\t\na.etl -Oldest`. | Yes. Every TCP/UDP event carries the owning `PID`, and Kernel-Process start events map PID → image path. |
| **WPR → WPA** | `wpr -start Network -filemode` … `wpr -stop C:\t\net.etl`, then open in Windows Performance Analyzer. | Yes (TCP/IP graphs grouped by process). Excellent for post-mortems; offline only. |
| **netsh trace / pktmon → Wireshark** | `pktmon start --capture --pkt-size 0 --trace --provider Microsoft-Windows-Kernel-Network --keywords 0x30 --file-name C:\t\c.etl` … `pktmon stop`, then `pktmon etl2pcap C:\t\c.etl --out c.pcapng`. Or `netsh trace start capture=yes tracefile=C:\t\n.etl` + `etl2pcapng`. | **Packets have none.** NDIS/pktmon capture happens below the socket layer, and the PID in the event header is just the thread context (often `4`/System on receive). You must join the packets to the Kernel-Network events by 5-tuple and time yourself. Wireshark has no native process column on Windows. |
| Verdict | | Authoritative and complete, since every socket is seen. But it is file-based and offline, and correlation is manual. |

### 1.4 Also worth knowing

* **Sysmon** — Event ID 3 (*NetworkConnect*: `Image`, `User`, `ProcessGuid`, 5-tuple, `Initiated`) and
  Event ID 22 (*DNSQuery*: `QueryName`, `QueryResults`, `Image`). It is event-driven, and the `ProcessGuid`
  makes it immune to PID reuse. Events go to the Windows Event Log, so they are SIEM-native. For
  fleet-wide *auditing* it is the standard answer, e.g.
  `<NetworkConnect onmatch="include"><Image condition="end with">\WINWORD.EXE</Image></NetworkConnect>`.
  It has no byte counters and no TCP state, and it requires installing a driver.
* **WFP auditing** (built in): `auditpol /set /subcategory:"Filtering Platform Connection" /success:enable`
  writes Security events 5156/5157 with *Application Name*, PID, direction and the 5-tuple. It is
  event-driven, but extremely noisy and has no bytes.
* `Get-NetTCPConnection -OwningProcess (Get-Process WINWORD).Id`, or `netstat -abno` (elevated):
  one-shot polling snapshots.

### 1.5 Polling vs event-driven: the trade-off

| | Polling (IP Helper tables) | Event-driven (ETW kernel providers) |
|---|---|---|
| Short-lived sockets | Missed if shorter than the interval. **Measured here:** 5 HTTP connections of ~50 ms each were all missed at a 5 s interval (`scripts/etw-selftest.ps1`, non-elevated run). | Every connect/accept/send/recv/disconnect is an event. |
| TCP state | Exact (`SYN_SENT`, `TIME_WAIT`, `CLOSE_WAIT` …). | Lifecycle only (connect, accept, disconnect, SYN retry). |
| Bytes | None (per-connection `ESTATS` needs admin and per-connection enablement). | Per-send/receive sizes. |
| PID → process | Resolved *after* the fact, so it races process exit and PID reuse. | Process start/stop events in the same stream give generation-exact binding. |
| Privilege | Any user. | Administrator or *Performance Log Users*. |
| Cost | Fixed, proportional to table size × frequency. | Proportional to traffic; needs kernel-side filtering and a fast consumer, or events are dropped. |

The two are complementary, so netattrib uses both (§3).

---

## 2. Track 2 — design decisions

### 2.1 Stack: Rust (stable, MSVC target)

* **Native API reach without a runtime.** `windows-sys` exposes ETW, TDH, IP Helper, CNG and the SCM as raw
  bindings resolved through `raw-dylib`, so nothing extra links in. The release build is one statically
  linked 7 MB `.exe` (`+crt-static`, GUI included) with no VC++ redistributable and no .NET/Go
  runtime.
* **No GC in the ETW callback.** A real-time consumer that stalls loses kernel buffers
  (`RealTimeBuffersLost`). Rust has no collector pauses. Go needs `syscall.NewCallback` plus a GC'd heap
  on the hot path. In C#, TraceEvent (the de-facto .NET ETW library) is not designed for NativeAOT
  trimming.
* **Safety where it matters.** All `unsafe` is confined to FFI marshalling. The state machine,
  filtering and output are safe code, covered by the unit tests (§7).

### 2.2 Telemetry sources

| Source | Used for | Why |
|---|---|---|
| `Microsoft-Windows-Kernel-Network` (ETW) | Per-socket lifecycle + bytes, owning PID | Event-driven; fixed v0 payloads since Vista, so they are decoded at fixed offsets. |
| `Microsoft-Windows-Kernel-Process` (ETW) | Process start/stop → PID generations | Same stream and same clock as the network events; this is what makes PID reuse tractable. |
| `Microsoft-Windows-DNS-Client` (ETW, event 3008) | name ↔ IP as **the app** resolved it, plus per-process DNS audit | PTR records for CDNs are useless; the queried name is what matters. |
| `GetExtendedTcpTable/UdpTable` | Exact TCP states, pre-existing connections, listeners, fallback | Cheap (≈110 µs for both TCP tables here) and works without privileges. With ETW active it only *reconciles* (every 5 s), and never front-runs ETW (§4.5). |
| `NtQuerySystemInformation` | Process snapshot with creation times; image path of any PID without a handle | Works across permission boundaries. |

Rejected: the singleton *NT Kernel Logger* (conflicts with Procmon, System Informer and WPR — netattrib runs
its own private session instead), WFP callouts (would need a signed driver), and packet capture (no PID).

---

## 3. Architecture & data flow

```text
                ┌──────────────────────── kernel ───────────────────────────────┐
                │ Kernel-Network  Kernel-Process  DNS-Client        TCP/UDP tables│
                │   (keyword + event-ID allow-list filters applied in-kernel)     │
                └──────┬──────────────────────────────────────────────┬──────────┘
                 ETW real-time session "NetAttrib-<pid>"              │ GetExtendedTcp/UdpTable
                 128 KB buffers, 32–256 (×CPU above 64), 1 s flush    │ ETW: every 5 s, after a forced flush
                 (+ EVENT_TRACE_CONTROL_FLUSH before every poll)      │ (1 s while ETW reports losses)
                                                                      │ poll-only: every 250 ms
                       │                                              │
            ┌──────────▼──────────┐                         ┌─────────▼──────────┐
            │ etw-consumer thread │  fixed-offset decode    │   poller thread    │ + process snapshot
            │ (ProcessTrace cb)   │  TDH for process/DNS    │                    │   only when a new
            └──────────┬──────────┘                         └─────────┬──────────┘   socket appears
                       │ NetEvent / Seed / DnsAnswer                  │ rows (t1 = read time)
                       ▼                                              ▼
            ┌────────────────────────────── Engine (one Mutex) ────────────────────────────┐
            │ ProcessTable: pid → [generation(create_time, exit_time, path, filter verdict)] │
            │ flows: (proto, local, remote) → state, dir, bytes, owner                       │
            │ pending: events whose PID is not yet known (≤1.5 s, reorder tolerance)         │
            │ confirmation window: poll-found sockets wait ≤3 s for ETW before open/close    │
            │ tombstones: closed tuples (suppress teardown echoes)                           │
            │ per-exe aggregates: pids, active/total, remotes, DNS names, bytes              │
            └───────┬──────────────────────────────┬───────────────────────────┬────────────┘
                    │ outbox → try_send (bounded,   │ snapshot()                │ enrich queue
                    │ drops counted, never blocks)  │                           ▼
                    ▼                               ▼                 ┌────────────────────┐
         ┌──────────────────────┐       ┌──────────────────────┐      │ enrich thread      │
         │ writer thread        │       │ Mode B renderer      │      │ token user + SID,  │
         │ order-preserving     │       │ (main thread, 1 Hz,  │      │ account (LSA)      │
         │ hold ≤ --dns-wait-ms │       │ alt screen, resize-  │      │ → enrich-files:    │
         │ → table | JSONL | CSV│       │ safe)                │      │ SHA-256, signature │
         │ → --log JSONL        │       └──────────┬───────────┘      └────────────────────┘
         └──────────┬───────────┘                  │
                    └───────────► Dns cache ◄───────┘   passive (DNS-Client, keyed by ip+pid, 1 h)
                                     │                  PTR (positive 1 h / negative 10 min)
                                     └─► rdns-0..3 workers (bounded queue 4096, in-flight dedupe)
```

**Records** (`event` field): `open` · `state` · `close` (`reason`: `disconnect` | `gone` | `idle` |
`shutdown`, with final byte counters) · `listen` · `dns`. Mode B emits `aggregate` records per
interval (only executables that changed) and `summary` records at exit.

**Source code map**

| Module | Responsibility |
|---|---|
| `src/capture/etw.rs` | Session lifecycle, stale-session cleanup, provider enablement with event-ID filters, consumer callback, Kernel-Network decoder, TDH helpers |
| `src/capture/iphlp.rs` | TCP/UDP table polling with reusable buffers |
| `src/process/` | Generation table (`mod.rs`), NT/Win32 queries + NT→DOS path mapping (`query.rs`), owner worker plus hash/signature file worker (`enrich.rs`), CNG SHA-256 (`hash.rs`), Authenticode verification: embedded, catalog and MSIX package (`signature.rs`), svchost service map (`services.rs`) |
| `src/aggregate.rs` | The thread-safe state machine: flows, deferral, tombstones, per-executable aggregation, snapshots |
| `src/dns.rs` | Passive/PTR caches, worker pool, DNS-Client result parsing |
| `src/output/` | Writer thread and JSON/CSV encoders (`mod.rs`), stream table (`table.rs`), Mode B frame renderer (`top.rs`) |
| `src/filter.rs` | `--filter-exe/-path/-pid`, PID-instance binding, `--tree`, "did you mean WINWORD.EXE" hints |
| `src/console.rs`, `src/win.rs` | VT mode, window size, Ctrl+C / window-close handling, elevation, `SeDebugPrivilege`, DLL search lockdown |
| `src/gui/` | Desktop GUI: window, process tree, table, filters, signature badges (`mod.rs`); background sampler, record feed, PID-reuse-safe tree builder (`snapshot.rs`); CSV/JSON export (`export.rs`); Excel-style column AutoFilters (`autofilter.rs`); persisted settings and portable mode (`settings.rs`); console detach, Save dialog, UAC relaunch, Explorer by absolute path, process termination, `SetTcpEntry` close (`native.rs`) |
| `build.rs`, `assets/` | Embeds the icon, version information and application manifest (`winresource`) |

---

## 4. Edge cases and how they are handled

### 4.1 PID reuse race
Windows recycles a PID as soon as the last handle to the dead process closes. netattrib never treats a
PID as an identity:

1. **Generations.** Every process is `(pid, create_time)`. The startup snapshot, ETW ProcessStart/Stop
   and (in polling mode) post-poll snapshots maintain a sorted list of generations per PID. A network
   event at time *T* binds to the generation with `create_time ≤ T` that had not exited before *T*. A new
   generation retires older ones.
2. **Reordering tolerance.** Real-time ETW delivers per-CPU buffers out of order, so a socket event can
   arrive before its process's start event. Unknown-PID events wait in a *pending* map keyed by flow
   (bytes keep accumulating) for up to 1.5 s, and are released the moment the matching ProcessStart
   arrives.
3. **On-demand verification.** If a PID is still unknown, the process is opened and `GetProcessTimes` is
   compared with the event time. A process **created after the event** is a recycled PID, and is never
   blamed; the event is attributed as `"attribution":"exited"` (named from the ProcessStop event when one
   was seen).
4. **Polling mode.** Tables are read at *t1*, and the process snapshot is taken *after* *t1*, so an
   instance created after *t1* cannot be the owner the table reported.
5. **Filters and enrichment are instance-bound.** `--filter-pid 4512` pins the instance alive at
   startup, so a later process that reuses 4512 does not match. The enrichment worker checks the
   creation time again before it reads a token, so it never reads the owner of a different process.

Unit tests: `process::tests::pid_reuse_is_resolved_by_generation`,
`aggregate::tests::unknown_pid_is_deferred_until_process_start`, `filter::tests::pid_bound_to_instance`.

### 4.2 Permission boundaries

| Data | Administrator (elevated) | Standard user |
|---|---|---|
| ETW capture (short-lived sockets, bytes, DNS names) | ✔ | ✘ → automatic fallback to polling, with a warning (or join *Performance Log Users*) |
| Owning PID of every TCP/UDP socket | ✔ | ✔ (IP Helper) |
| Full image path of any process, incl. SYSTEM/PPL | ✔ | ✔ via `SystemProcessIdInformation` (no handle needed) |
| Process owner (token user/SID) | ✔ for nearly all (`SeDebugPrivilege` is enabled automatically) | Own processes only; others report `user: null` instead of failing |
| SHA-256 of the image (`--hash`, or on demand in the GUI) | ✔ | ✔ where the file is readable |
| Authenticode signature of the image (GUI) | ✔ | ✔ where the file is readable |
| *Close Connection* (GUI, IPv4 TCP) | ✔ | ✘ (the menu item is disabled) |

Access-denied is never fatal. Each field degrades on its own and stays `null` in exports.

### 4.3 DNS resolution latency
* Capture threads never resolve anything. The ETW callback only records DNS-Client answers into a map.
* A PTR lookup runs on 4 worker threads behind a **bounded** queue (4096). Lookups are de-duplicated
  while in flight; when the queue is full the lookup is dropped (and counted), not blocked.
* Caches: passive names for 1 h, keyed by `(ip, pid)`, so two apps hitting the same CDN IP each keep their
  own name. PTR results are cached for 1 h if found and 10 min if not. Both caches are capped at 100 k
  entries.
* The writer may hold records **in arrival order** for at most `--dns-wait-ms` (default 400 ms) while a
  PTR lookup for that record is in flight. The domain then lands on the `open` line, and output order and
  bounded latency are preserved. `close` records always carry it.

### 4.4 Resource constraints (target < 1 % CPU)
* **Kernel-side reduction.** Keyword masks plus an `EVENT_FILTER_TYPE_EVENT_ID` allow-list: TCPCopy (which
  would double-count bytes) and connect-failure events never leave the kernel. `--no-bytes` additionally
  drops per-segment TCP send/receive events.
* **Hot path.** For a packet on a known flow: a fixed-offset decode, one hash lookup and counter
  increments. There is no allocation, no string work and no syscall; process lookup happens only when a
  flow is created.
* **Lock discipline.** One mutex held for microseconds. Records are built into a local outbox and sent
  after unlock with `try_send` (a slow console or pipe causes counted drops, never ETW buffer loss).
  Output is flushed once per batch.
* **Bounded memory.** ETW buffers 128 KB × 32–256 (4–32 MB; more only beyond 64 logical CPUs), with the
  consumer thread at above-normal priority so it drains them during bursts. Output queue 65 536 records, pending map
  50 k, ≤ 4096 remotes per executable, DNS caches 100 k, exited processes garbage-collected after 2 min
  once unreferenced.
* **Polling-only mode.** The process snapshot costs ≈5.4 ms on this machine (thousands of threads), so
  it runs only when a *new* socket needs attributing (plus every 5 s for bookkeeping).

**Measured on the development machine** (24 logical CPUs, ~140 TCP connections, non-elevated, 250 ms
polling, `--group --json-lines`): **0.62 % of one core = 0.026 % of the machine**, 10 MB working set.
Before the snapshot-on-demand optimisation the same run used 5.1 % of one core. (ETW-mode CPU has not
been measured yet.)

### 4.5 Poll/ETW race: one socket, one `open`, one `close`
Real-time ETW delivers buffers when they fill or when the session's `FlushTimer` fires. The timer's
documented minimum is 1 s, and netattrib already uses it. A table poll is an instant snapshot, so it can
see a socket *before* that socket's ETW Connect has been delivered. The first elevated self-test run
showed exactly this: 2 of 5 short connections were announced as `source: poll`, although ETW captured
them fully (their closes carried ETW byte counts and `reason: disconnect`). Even a 5 s poll interval
landed inside a live connection twice, so slowing the poller cannot fix it alone. The engine
de-duplicates instead:

1. **Confirmation window.** In ETW mode, a socket first found by a table poll is tracked immediately,
   so the Mode B view shows it right away, but its `open` record is withheld for up to 3 s
   (`ETW_CONFIRM_WINDOW`).
2. **Promotion.** Any Kernel-Network event for such a flow re-labels it `source: etw` and announces it
   at once, with the ETW start time and the authoritative direction (Connect → `out`, Accept → `in`).
   If nothing arrives within the window, it is announced as `poll`. A connection present in the
   startup snapshot is re-labelled only by a Connect/Accept/Reconnect event, which proves it opened
   while monitoring was starting; data on an old connection does not make it ETW-born.
3. **The mirror case for closes.** A socket that vanishes from the table is closed as `gone` only if ETW
   has not closed it within the same window. Otherwise late-delivered Disconnect and byte events would
   be discarded, and the close would carry `reason: gone` with incomplete counters.
4. **Order is preserved.** A flow that closes inside its window still emits `open` before `close`. No
   `state` record is emitted before its `open`.
5. **Fresh ETW state at each poll.** `EVENT_TRACE_CONTROL_FLUSH` is issued immediately before every
   table read.
6. **Polling as a safety net.** With ETW active, the default poll interval is 5 s (TCP states and
   closes ETW may not report). If the session reports kernel-side losses (`EventsLost` /
   `RealTimeBuffersLost`), polling tightens to 1 s for 60 s and a warning is printed. `--poll-ms`
   overrides the healthy-state interval.

Regression tests: `aggregate::tests::etw_claims_socket_the_poll_saw_first`,
`etw_disconnect_wins_over_poll_disappearance`, `unconfirmed_poll_flow_is_announced_after_window`,
`provisional_flow_closing_early_emits_open_then_close`, `vanished_flow_without_etw_close_is_gone_after_window`,
`snapshot_flows_promote_only_on_lifecycle_start`. The self-test now polls every **250 ms** on purpose,
so that polls front-run ETW on nearly every connection, and it requires exactly one ETW-sourced `open`
and one `close` per socket.

### 4.6 TUN proxies and fake-IP addresses (v2rayN / Xray / sing-box)
TUN-mode proxy clients commonly run DNS in **fake-IP** mode. Every DNS answer the client returns is a
synthetic address from `198.18.0.0/15`, a range reserved for network benchmarking (RFC 2544) and never
routed on the internet, so it cannot collide with a real destination. The proxy core remembers the
fake-IP → domain mapping. When the application connects to the fake IP through the virtual TUN
adapter, the core intercepts the connection, looks up the domain, and opens its own upstream
connection to the proxy server. What netattrib sees on such a host:

* The **application's own socket** goes to the fake IP and is attributed correctly to the application,
  e.g. `powershell.exe → 198.18.0.17:80` in the self-test.
* The **upstream connection** belongs to the proxy core, e.g. `xray.exe` / `sing-box.exe →
  203.0.113.10:2052`. Both flows are real; together they show who asked for what and how it left
  the machine.
* **PTR is useless** for fake IPs, since no reverse zone exists, and the pool is recycled, so the same
  fake IP maps to different domains over time.
* **DNS-Client ETW restores the names.** The application's resolver call (event 3008) records the
  answer it received, which is the fake IP. netattrib keys that answer by `(ip, pid)`, so the
  connection that follows is labelled with the domain the application asked for:
  `domain: example.com, domain_source: dns-client` for `remote_ip: 198.18.0.17`. The self-test
  verified this on this machine. A newer answer for the same IP and PID replaces the older one, which
  follows the proxy's pool recycling.

```powershell
netattrib -e winword --dns-events          # dns rows show 198.18.x.x answers, then the matching connections
netattrib --group                          # DESTINATIONS for apps: domains; for xray/sing-box: proxy server
```

Without ETW (non-elevated), only PTR is available, so fake-IP destinations show no domain.

---

### 4.7 Running elevated safely: binary planting and exploit mitigations
netattrib is meant to run as administrator, and it is often started from wherever it was
downloaded. Windows looks for an executable's DLLs **in the executable's own folder first**. Before
this was fixed, a dummy `tdh.dll` placed next to `netattrib.exe` was loaded instead of the system's
(the process failed with `0xC0000139`), so a malicious DLL dropped beside it would have run with
administrator rights. Rust's `std::process::Command` searches the same folder for a bare program
name: a planted `explorer.exe` there ran when the GUI opened a URL or Explorer.

* **Imported DLLs**: linked with `/DEPENDENTLOADFLAG:0x800` (`.cargo/config.toml`), as System
  Informer is. The loader resolves `tdh`, `iphlpapi`, `wintrust`, `opengl32` and the rest from
  System32 only. Verified with `tdh.dll`, `wintrust.dll` and `iphlpapi.dll` planted beside the
  release exe: it runs normally.
* **DLLs loaded at run time**: `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` is the
  first call in `main()`.
* **Explorer and the browser hand-off**: started as `%SystemRoot%\explorer.exe` by absolute path.
* **Exploit mitigations**: Control Flow Guard (`-C control-flow-guard=checks`; the prebuilt
  standard library is not instrumented) and CET shadow-stack compatibility (`/CETCOMPAT`, x64), on
  top of the defaults (ASLR with high entropy, DEP). `dumpbin` shows *Control Flow Guard* and *CET
  compatible*, and `Get-ProcessMitigation` reports *UserShadowStack: ON* for the running GUI on a
  CET-capable CPU.
* **Manifest** (`build.rs`): `asInvoker` (never auto-elevated by installer detection), Common
  Controls 6, Windows 10/11 `supportedOS`, `longPathAware`. DPI awareness is left to winit, which
  sets it when the window opens.

## 5. Usage

```text
netattrib [--gui | --no-gui]
          [--filter-exe NAME]... [--filter-pid PID]... [--filter-path GLOB]... [--tree]
          [--group] [--json-lines | --csv] [-o FILE] [--log FILE] [--summary FILE]
          [--dns-events] [--hash] [--listening] [--include-loopback] [--no-bytes]
          [--no-etw] [--poll-ms MS] [--no-rdns] [--dns-wait-ms MS] [--duration SECS] ...
```

| Goal | Command |
|---|---|
| **Desktop GUI** (default without arguments, e.g. double-click) | `netattrib` or `netattrib --gui` |
| …limited to Word and its children, with a JSONL audit log | `netattrib --gui -e winword --tree --log C:\logs\net.jsonl` |
| Console live table of everything (the old no-argument behavior) | `netattrib --no-gui` |
| **Mode A**: Word's connections, live | `netattrib --filter-exe winword.exe` |
| …including child processes and its DNS lookups | `netattrib -e winword --tree --dns-events` |
| …one specific instance | `netattrib --filter-pid 4512` |
| …anything under the Office install | `netattrib --filter-path "*\Microsoft Office\*"` |
| **Mode B**: live per-executable view | `netattrib --group` (`--sort tx\|rx\|conns\|remotes\|name`) |
| SIEM: event stream | `netattrib --json-lines -o C:\logs\net.jsonl` or `… \| your-shipper` |
| SIEM: per-binary aggregates every 60 s + full summary at exit | `netattrib --group --json-lines --interval 60000` |
| Console view **and** a JSONL audit log at once | `netattrib --group --log C:\logs\net.jsonl --summary C:\logs\summary.jsonl` |
| Inventory capture for 10 minutes as CSV | `netattrib --csv --duration 600 -o inventory.csv` |
| Include listeners / bound UDP sockets | `--listening` |
| Word behind a local system proxy (`127.0.0.1:10808`) | `netattrib -e winword` (loopback is included with any process filter) |
| Loopback in an unfiltered console run | `--include-loopback` |

Mode B (TUI): the top pane shows executables (PIDS, ACT active, TOTAL connections, RMT unique remotes,
TX/RX, USER, DESTINATIONS collapsed by domain, PATH). The bottom pane shows live connections, most
recent activity first; rows that moved data in the last 2 s are highlighted. The window size is
re-read every frame and immediately after a resize. Press Ctrl+C to quit; a plain-text summary is
printed after the alternate screen closes.

Stream table: columns adapt to the window width. Low-value columns (TX/RX, DIR, PATH, LOCAL, DOMAIN)
are dropped first on narrow terminals, the header is re-printed on resize, and lines never wrap.
Timestamps in the table are `HH:MM:SS.mmmZ` (UTC) under a date banner; exports use full ISO-8601
UTC with microseconds.

**Desktop GUI** (egui/eframe, OpenGL). It is laid out like Resource Monitor's Network tab next to
Process Explorer's tree, and runs on the same capture engine as the console modes:

* **Top bar**: toggles and actions on the left, the capture status on the right. Filtering by
  address, domain, protocol or state is done from the column headers (*Column filters* below).
  *Hide background noise* (on by default) hides multicast/broadcast destinations, ports 137, 138, 1900, 5353 and 5355 on either
  end, and **self-loopback**: a process connected to itself on 127.0.0.1 (Intel's `esrv_svc.exe`
  does this constantly). Loopback between two *different* processes, such as an application and
  its proxy, is never hidden. *Keep closed history* (on by default) keeps closed
  connections in the table, the newest 2000 of them. Turned off, they disappear 10 s after
  closing. *Clear history* empties it at once. *Export…* saves the rows currently shown (after
  filters and sort) as CSV or a JSON array through the standard Save dialog. Field names follow
  §5.1, byte counts are raw, `state` is the displayed state and `tcp_state` the socket's,
  `peer_process`/`peer_pid` name the other end of loopback rows, and `signature`
  (`signed`/`unsigned`/`invalid`) and `signer` describe the process's image. *Clear filters*
  appears while any column is filtered and removes all column filters. On the right, a
  status indicator shows *ETW capture active* (green) or *Polling only* (amber), plus
  elevation; hover it for the reason ETW is off and for where settings are stored. When not elevated, *Restart as administrator* relaunches through
  UAC with the same arguments. If the window is too narrow for one row, the status moves to a
  row of its own.
* **Process tree** (left, at least 220 px wide). *All / User / System* scopes the tree **and**
  the table by the account a process runs as. *User* means the current user's SID; *System*
  covers SYSTEM, LOCAL/NETWORK SERVICE and the per-service, DWM and font-driver accounts. When
  a token cannot be read, session 0 counts as system. In *User*, system processes that are
  parents of user processes stay visible, dimmed, to keep the hierarchy. The **process search**
  (Ctrl+F, with a clear `×` inside the box) matches a name, a hosted service, or an exact PID.
  It prunes the tree to the matches, their parents and their children, and highlights and
  scrolls to them, but it never changes the table. The table follows only a click on a
  process: that process **and all its descendants**; click it again or `×` to clear. The
  tree is parent → child by PPID, ordered by creation time; a parent must predate its child,
  so a recycled PPID never adopts unrelated processes. Processes with active connections are
  green with a count, and collapsed nodes show `+N` for connections below them. *Only with
  connections* prunes everything else, and `+`/`−` expand or collapse all. Right-click a
  process for *Open file location* (Explorer with the file selected), *Copy executable path*,
  *Copy PID*, *Check Executable Hash on VirusTotal* and *Terminate process…*. The VirusTotal
  item hashes the image (SHA-256, in the background, unless `--hash` already did) and opens
  its report in the browser. Only the hash leaves the machine, as part of the URL; the file is
  never uploaded. Terminating asks for confirmation, refuses a PID that now belongs to a
  different process, and refuses critical system processes, which would crash Windows.
* **Signatures** (System Informer style). Every image's Authenticode signature is checked in
  the background (about 14 ms per distinct file; 144 images took 2 s here). A file without an
  embedded signature is looked up in the system's security catalogs, where most Windows binaries
  are signed. A packaged (MSIX/Store) app takes the status Windows verified when it installed the
  package. Verification is offline: no revocation checks and no certificate downloads. A process
  whose image is **unsigned** (amber) or has a signature that **does not verify** (red: modified
  after signing, revoked, untrusted root, …) and that talks to a public internet address gets a
  warning badge in the tree, and a warning triangle before its name on those rows of the table.
  The process tooltip shows *Signed by …* (with *catalog* or *app package* where that applies),
  *Not signed*, or the reason the signature is invalid.
* **Connection table**: Process · PID · Local Address · Remote Address · Domain · Proto · State ·
  Sent · Recv. Sizes are shown as B/KB/MB/GB, or `—` where nothing is counted (polling mode, or
  TCP with `--no-bytes`). The domain comes from the DNS-Client cache first, so fake-IP
  destinations (`198.18.x.x` and the like, §4.6) show the name the application resolved; reverse
  DNS is the fallback. Click a header to sort. Rows with traffic in the last 2 s are bold, and
  closed connections show a red `CLOSED`. Columns work like a spreadsheet's. Drag a column's
  right edge to resize it on its own: the columns after it move along, and once they no longer
  fit the table scrolls horizontally. Double-click a column's header or right edge to fit it to
  its contents: the widest of its title and its text in every row the filters leave, not only
  those on screen. (The double-click's first click would re-sort; that is undone.) Defaults and
  minimums: Process 140/60 px, PID 65/45, Local and Remote Address 150/70, Domain 200/90,
  Proto 60/40, State 90/50, Sent and Recv 75/50. Values never widen a column by themselves: long
  ones are cut off, because a column that grows with its widest value shifts every column to
  its right. Titles too narrow for their column end in `…`. The window opens wide enough for
  every column at its default width (1440 px, less on smaller screens).
  **Column filters**, Excel's AutoFilter: every header has a funnel button at its right edge,
  gray while the column is unfiltered and cyan while it is filtered. A click on it opens a popup
  and never sorts. The popup has a *Contains…* search box, a case-insensitive substring of
  what the column shows, applied as you type. It also lists the column's distinct values with
  their row counts, *(Blanks)* last, to tick and untick, with *(Select All)* above them and
  *Clear Filter* below. As in Excel, a column's list shows the values left by the filters on the
  *other* columns, and filters on several columns combine. The table is live, so what you
  tick also decides what happens to values that appear later. Untick a few, and new values
  still show. Clear *(Select All)* and tick a few, and nothing else does. Sent and Recv have no
  list (byte counts are too varied), only the search box. While any column is filtered, the
  status bar names the columns and the top bar shows *Clear filters*. Column filters last for
  the session, and *Export…* saves what they leave. Right-click a row to *Copy remote IP:port*, *Copy
  resolved domain*, *Copy row*, or *Look up* the IP or domain on VirusTotal (reputation, passive
  DNS, WHOIS). The IP lookup is offered only for public addresses, not private, loopback or
  fake-IP ones. The menu can also filter the table to the row's process, or to the process at
  the other end of a loopback connection. *Close Connection* drops an IPv4 TCP connection and
  resets the remote end (`SetTcpEntry` with `MIB_TCP_STATE_DELETE_TCB`, as System Informer
  does); the application may simply reconnect. It needs administrator rights, and Windows has
  no equivalent for IPv6 or UDP, so the item is disabled, with the reason on hover, in those
  cases and for closed rows. The menu stays with the row it was opened on, even if the table
  re-sorts while it is open.
* **Local proxies and loopback.** Behind a system proxy (v2rayN, Clash and similar in "System
  Proxy" mode), an application's only sockets go to `127.0.0.1:<port>`. netattrib pairs both
  ends of every loopback connection. The application's row shows the State `PROXY/LOCAL` and,
  in the Domain column, *via xray.exe (64056)*, the process that owns the port. The proxy's
  accepting end shows `LOCAL/IN` with *from WINWORD.EXE (4512)*. The proxy's own upstream
  connections show where the traffic actually went. Loopback capture is always on in the GUI.
* **Settings** survive restarts: window position, size and maximized state, the width of the
  process panel, the table's column widths, *Hide background noise*, *Keep closed history*,
  *Only with connections* and the *All / User / System* scope. They are stored in
  `%APPDATA%\netattrib\data\app.ron`.
  **Portable mode**, as in System Informer: create an empty `netattrib.settings.ron` next to
  `netattrib.exe` and settings are kept in that file instead, with nothing written to the
  profile. *Restart as administrator* saves them first, so the elevated window opens the same
  way.

The window samples the engine once a second on a background thread (`gui-sampler`) and renders
an immutable snapshot, so the UI never holds the lock the ETW consumer needs. `--log` and
`--summary` work alongside the window, including the final `shutdown` close records. Started
from Explorer, the console window netattrib was given is released at startup. Its standard
handles are then invalid, so the processes it starts (Explorer, the browser) get none. (Before
this was fixed, opening a URL failed with "os error 6", `ERROR_INVALID_HANDLE`.) Started from a
terminal, the console stays attached for diagnostics, and Ctrl+C there closes the window.

### 5.1 Event record schema (`--json-lines`)

CSV carries the same fields in the same order, with three differences: `proto` merges the IP version
(`TCP4` `TCP6` `UDP4` `UDP6` `DNS`), and `ip_version`, `session_id` and the DNS-only fields are omitted.

| Field | Example | Notes |
|---|---|---|
| `ts` | `2026-10-21T14:03:22.123456Z` | UTC, event time (ETW timestamp or poll time) |
| `event` | `open` | `open` `state` `close` `listen` `dns` |
| `pid`, `ppid`, `session_id` | `4512`, `1200`, `1` | |
| `process`, `path` | `WINWORD.EXE`, `C:\Program Files\…\WINWORD.EXE` | `path` null if undeterminable |
| `user`, `sid` | `CONTOSO\alice`, `S-1-5-21-…` | null when access is denied |
| `sha256` | | with `--hash`, once computed |
| `services` | `Dnscache` | svchost-hosted services sharing the PID |
| `proto`, `ip_version` | `TCP`, `4` | `DNS` for dns records |
| `local_ip`, `local_port`, `remote_ip`, `remote_port` | | IPv4-mapped IPv6 normalized to IPv4 |
| `domain`, `domain_source` | `ecs.office.com`, `dns-client` | `dns-client` (name the app queried) or `ptr` |
| `state`, `direction` | `ESTABLISHED`, `out` | `direction`: `out` `in` `?` |
| `bytes_sent`, `bytes_recv`, `retransmits` | | ETW mode; cumulative at the time of the record |
| `duration_ms` | | close records: connection lifetime |
| `source` | `etw` | `etw`: ETW observed the socket, including sockets a poll found first and ETW then confirmed (§4.5); `poll`: seen only by table polls; `snapshot`: existed before start |
| `attribution` | `exact` | `exact` `inferred` `exited` (see §4.1) |
| `reason` | `disconnect` | close records |
| `dns_status`, `answers` | `0`, `["13.107.42.14"]` | dns records only |

Aggregate/summary records (`--group` with an export format, `--summary`): `process`, `path`, `user`,
`sha256`, `pids[]`, `active`, `connections`, `tcp`, `udp`, `bytes_sent`, `bytes_recv`, `unique_remotes`,
`first_seen`, `last_seen`, `remotes[]` (`ip`, `domain`, `last_port`, `connections`, bytes, `last_seen`),
and `dns_queries[]` (`name`, `count`).

---

## 6. Build & run

**Prerequisites**
* Rust ≥ 1.95 with the MSVC toolchain: `rustup default stable-x86_64-pc-windows-msvc`. (1.95 is
  required by egui/eframe 0.37, which the GUI uses.)
* Visual Studio Build Tools (the "Desktop development with C++" workload, which includes the Windows SDK)
  so the MSVC linker is available.

```powershell
cargo build --release          # -> target\release\netattrib.exe (static CRT, no runtime deps)
cargo test                     # 80 unit tests (parsers, PID reuse, poll/ETW races, state machine, layout, encoders, GUI, signatures)
```

Release profile: `opt-level = 3`, fat LTO, one codegen unit, stripped, `panic = "abort"`. Measured
on this project: thin LTO gave a **6 % larger** exe and only builds faster, so fat LTO stays. Abort
gives a **20 % smaller** exe than unwind. The panic hook still runs before the abort and stops the
ETW session; in GUI mode it also shows the error in a message box.

Hardening (`.cargo/config.toml`, applied to every build): `/DEPENDENTLOADFLAG:0x800`, Control Flow
Guard and `/CETCOMPAT` (§4.7). `build.rs` embeds the icon (`assets/netattrib.ico`, drawn by
`scripts/make-icon.ps1`), version information (Explorer's *Details* tab, Task Manager) and the
manifest. It needs `rc.exe` from the Windows SDK, which the Build Tools workload installs. The
hardening, signature checks, settings persistence and resources together took the exe from
6.1 MB to 6.8 MB (+12 %); the parts were not measured separately.

**Run**
* **Recommended: an elevated prompt** (Run as Administrator). ETW capture is enabled and
  `SeDebugPrivilege` is turned on automatically for owner lookups.
* Alternatively, add the account to *Performance Log Users* (`net localgroup "Performance Log Users"
  <user> /add`, then log off and on) for ETW without full admin. Owner lookups for other users'
  processes will then be limited.
* Non-elevated: it works in polling mode and says so on stderr. Status and diagnostics always go to
  **stderr**, so stdout stays clean for pipes.
* Each run uses a private ETW session `NetAttrib-<pid>`. It is stopped on exit, Ctrl+C, console close or
  panic. Sessions orphaned by a killed process (e.g. Task Manager → End task) are cleaned up on the next
  start. To remove one manually: `logman stop NetAttrib-<pid> -ets`.

**ETW self-test** (elevated): `powershell -ExecutionPolicy Bypass -File scripts\etw-selftest.ps1`.
It drives a child process through DNS resolution plus five short HTTP connections while a deliberately
aggressive 250 ms table poll races ETW delivery. It checks capture, ETW sourcing, exactly one open and
one close per socket, local/remote orientation, byte counters, attribution and DNS correlation. The
result is written to `selftest-result.txt`.

---

## 7. Verification status

| Area | Status |
|---|---|
| Unit tests | 80 passing (plus 2 ignored benchmarks): Kernel-Network decoding (v4/v6, IPv4-mapped, truncation), PID-generation logic, deferral, tombstones, poll/ETW confirmation and promotion, state machine, filters, DNS parsing and caches, JSON/CSV encoding, table/TUI layout at 40–300 columns, GUI process tree (PID reuse), loopback end pairing, self-loopback noise, account scopes (token SID and session fallbacks), tree pruning, column search boxes (domain, remote address, loopback peer in both directions), sort, closed-history retention, public-address check, export schema, UAC argument quoting, Explorer `/select` quoting and launch by absolute path, terminating a real spawned process (including refusing a reused PID), Authenticode results (catalog-signed `cmd.exe`, an unsigned binary, a one-byte-tampered copy of an embedded-signed binary, running MSIX apps signed through their package, manifest publisher parsing), `SetTcpEntry` row byte order and the non-elevated refusal, settings round trip with damaged values, column-width validation, portable-file detection, the unsigned-with-internet-traffic badge rule, column specs, fit-to-contents limits and cell text, AutoFilter tick/untick semantics for live data, text plus ticks, value counting and sorting, column filters combining and each list following the other columns' filters, launching a child process with stale standard handles (re-runs itself in a child process, reproducing the "os error 6" failure without the fix), and the embedded window icon |
| Hardening | Verified on the release exe: `dumpbin` shows *Control Flow Guard*, *CET compatible* and *Dependent Load Flag 0800*. With `tdh.dll`, `wintrust.dll` and `iphlpapi.dll` planted beside it, the exe runs normally (before the fix it failed with `0xC0000139`). `Get-ProcessMitigation` reports *UserShadowStack: ON* for the running GUI. Version information and the manifest read back correctly. The aarch64 flags are configured but not build-tested. |
| Polling path, live | Verified on Windows 11 (build 26300): new-process attribution, listeners, open→close lifecycle, path/user/SID/service enrichment, PTR, Mode B JSON/CSV/text summary, CPU/memory numbers above |
| ETW path, live | First elevated self-test run (Windows 11 build 26300): 6 of 7 checks passed, with 0 events lost in the kernel. Passing: short-lived capture, local/remote orientation, byte counters (56/928 B per connection), exact attribution, DNS-Client PID attribution and domain correlation through a fake-IP TUN proxy. The failure was the poll/ETW race in §4.5, now fixed and covered by regression tests. **The self-test has not been re-run since the fix.** |
| Mode B interactive TUI | Frame rendering is unit-tested for line width and height. It has not been exercised in an interactive console session. |
| Desktop GUI | Checked live **non-elevated (polling mode)** on Windows 11 build 26300 after this round's changes. It opens at 1440 px with every column visible. Self-loopback (`esrv_svc.exe`) is hidden while proxy loopback (`sing-box → 127.0.0.1:10808` *via xray.exe*) stays. *System* and *User* scope both tree and table, with system parents of user processes dimmed. The process search prunes the tree to the matches and their parents and children without touching the table, and its inline `×` clears it. The release build (`panic = "abort"`) starts and shuts down cleanly. This round, also checked live: OpenGL starts normally with DLL loading restricted to System32 (NVIDIA RTX 4070 + Intel UHD 770). `xray.exe` and `sing-box.exe` (unsigned, with public upstream connections) get the *unsigned* badge and the table's warning triangle, while signed processes with internet traffic do not. Scope and *Only with connections* survive a restart (written to `%APPDATA%\netattrib\data\app.ron` on close), and portable mode writes to the file beside the exe and leaves `%APPDATA%` untouched. Columns, checked live: dragging Domain's right edge widened only Domain (200 → 600 px) and brought up horizontal scrolling. Double-clicking PID's right edge fitted PID (to its 45 px minimum), and double-clicking a header fitted that column without changing the sort. The widths were saved on close and restored on relaunch. AutoFilter, checked live: the funnel opens the popup without sorting, the list shows the State values with counts, unticking ESTABLISHED hides those rows, turns the funnel cyan, makes *(Select All)* indeterminate and shows *Column filters: State* in the status bar, and *Clear filters* restores everything and closes the popup. (*Clear filters* has since moved from the status bar to the top bar, which no longer has the traffic filter box.) The search box was not exercised live (synthetic typing is unreliable with this machine's keyboard layout); its matching is unit-tested. The "os error 6" cause was reproduced outside the app (a program that frees its own console, then spawns a child: inherited stdio fails with error 6, null stdio works). **Not verified live:** the right-click menus (including *Check Executable Hash on VirusTotal* and *Close Connection*), the terminate confirmation dialog and hover tooltips, because synthetic mouse input does not reach widgets inside egui scroll areas reliably. Their actions are covered by unit tests instead (including a real `TerminateProcess`). An actual connection close is not tested either, because this session is not elevated. Earlier rounds verified the loopback pairing, history, two-row top bar and `--log` forwarding. The ETW buffer sizes and consumer priority have not been measured under load. |

---

## 8. Known limitations

* **DNS that bypasses the Windows resolver** (DNS-over-HTTPS, or browsers' built-in resolvers) produces no
  DNS-Client events. Those flows fall back to PTR names, which are often CDN hostnames.
* **QUIC/HTTP3** traffic appears as UDP flows (closed after `--udp-idle`, default 60 s). There is no TCP
  state for it.
* **Proxies and VMs**: traffic is attributed to the process that owns each *socket*. With a TUN proxy
  you see both the application's connection to a fake IP and the proxy core's upstream connection
  (§4.6). With a system-proxy setup, the application talks to `127.0.0.1:<port>`. That
  connection is shown, attributed to the application and labelled with the proxy process (GUI:
  `PROXY/LOCAL`). The proxy's upstream connections show where the traffic went, but which
  application caused which upstream connection is not knowable from socket data alone. WSL/Hyper-V guest
  traffic appears under `vmmem`/`vmcompute`, not under the process inside the VM.
* **Bytes** exist only in ETW mode, and only from when monitoring starts. Connections that predate
  startup report bytes from that point on.
* **Several services in one svchost** share a PID; `services` lists all of them.
* Loopback traffic is excluded only in the unfiltered console modes, unless `--include-loopback` is
  given. The GUI and any `--filter-exe/-pid/-path` run include it.
* **Signature checks are offline**: certificate revocation is not checked, so a binary signed with a
  certificate revoked after the fact still shows as signed. Signatures are checked in the GUI only;
  the console outputs carry no signature fields.
* **Close Connection** works for IPv4 TCP only (Windows offers no API for IPv6 or UDP), and an
  application may reconnect at once.
