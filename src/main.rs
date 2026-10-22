//! netattrib - per-executable network connection attribution for Windows.
//!
//! Data flow (see README.md for the full diagram):
//!
//! ```text
//!  ETW real-time session ──► etw-consumer ──┐
//!  (Kernel-Network/Process, DNS-Client)     │          ┌─► writer ──► console table / JSONL / CSV
//!                                           ├─► Engine ┤
//!  IP Helper tables ───────► poller ────────┘ (mutex)  ├─► Mode B frame renderer (main thread)
//!                                 │                    └─► GUI: gui-sampler ─► window (main thread)
//!                           ProcessTable ──► enrich (user) ──► enrich-files (sha256, signature)
//!  rdns-N (PTR) ◄── Dns cache ◄── DNS-Client events
//! ```

mod aggregate;
mod capture;
mod console;
mod dns;
mod filter;
mod gui;
mod model;
mod output;
mod process;
mod util;
mod win;

use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, sync_channel};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};

use aggregate::{Engine, EngineConfig, SnapshotOpts, SortKey};
use capture::etw::{self, EtwSession};
use capture::iphlp::IpHelper;
use output::{Enricher, Format, Sink};
use process::services::ServiceMap;
use process::ProcessTable;
use util::{TICKS_PER_MS, TICKS_PER_SEC};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SortArg {
    Activity,
    Conns,
    Active,
    Tx,
    Rx,
    Remotes,
    Name,
}

impl From<SortArg> for SortKey {
    fn from(s: SortArg) -> Self {
        match s {
            SortArg::Activity => SortKey::Activity,
            SortArg::Conns => SortKey::Conns,
            SortArg::Active => SortKey::Active,
            SortArg::Tx => SortKey::Tx,
            SortArg::Rx => SortKey::Rx,
            SortArg::Remotes => SortKey::Remotes,
            SortArg::Name => SortKey::Name,
        }
    }
}

/// Per-executable network connection attribution (ETW + IP Helper).
///
/// Without filters every process is monitored. Run elevated for event-driven ETW capture
/// (short-lived sockets, byte counters, DNS names); otherwise netattrib falls back to
/// IP Helper polling automatically. Started without arguments it opens the desktop GUI.
#[derive(Parser, Debug)]
#[command(name = "netattrib", version, about, long_about = None, after_help = EXAMPLES)]
struct Cli {
    /// Open the desktop GUI (the default when started without arguments). Combines with the
    /// capture options (filters, --no-etw, --include-loopback, --log, --summary, ...).
    #[arg(long, conflicts_with_all = ["group", "json_lines", "csv", "output", "duration"])]
    gui: bool,

    /// Stay in the console even without other arguments (live table of all connections).
    #[arg(long = "no-gui", conflicts_with = "gui")]
    no_gui: bool,

    /// Mode A: only processes whose image file name matches (glob, case-insensitive,
    /// repeatable; ".exe" optional). Microsoft Word is WINWORD.EXE.
    #[arg(short = 'e', long = "filter-exe", value_name = "NAME")]
    filter_exe: Vec<String>,

    /// Mode A: only this process instance (repeatable). Bound to the instance's creation
    /// time, so a recycled PID never matches.
    #[arg(short = 'p', long = "filter-pid", value_name = "PID")]
    filter_pid: Vec<u32>,

    /// Mode A: only images whose full path matches (glob, case-insensitive, repeatable),
    /// e.g. "*\Microsoft Office\*".
    #[arg(long = "filter-path", value_name = "GLOB")]
    filter_path: Vec<String>,

    /// Also include child processes of matched processes.
    #[arg(long)]
    tree: bool,

    /// Mode B: aggregated live view grouped by executable path.
    #[arg(short = 'g', long)]
    group: bool,

    /// Emit JSON Lines (one object per event; per executable with --group).
    #[arg(long = "json-lines", conflicts_with = "csv")]
    json_lines: bool,

    /// Emit CSV with a header row.
    #[arg(long)]
    csv: bool,

    /// Write the primary output to FILE (appends) instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Additionally stream every event as JSON Lines to FILE (works with any mode).
    #[arg(long, value_name = "FILE")]
    log: Option<PathBuf>,

    /// On exit, write a per-executable summary (JSON Lines) to FILE.
    #[arg(long, value_name = "FILE")]
    summary: Option<PathBuf>,

    /// Do not use ETW; poll IP Helper tables only (no elevation needed).
    #[arg(long = "no-etw")]
    no_etw: bool,

    /// Table poll interval in ms [default: 5000 with ETW (1000 while the session reports
    /// lost events), 250 polling-only].
    #[arg(long = "poll-ms", value_name = "MS", value_parser = clap::value_parser!(u64).range(50..=60_000))]
    poll_ms: Option<u64>,

    /// Skip per-packet TCP send/receive events (lowest overhead; no TCP byte counters).
    #[arg(long = "no-bytes")]
    no_bytes: bool,

    /// Disable reverse DNS (PTR) lookups; names observed via DNS-Client ETW are still used.
    #[arg(long = "no-rdns")]
    no_rdns: bool,

    /// Max time a record may wait for an in-flight PTR lookup before being written without
    /// a domain (0 = never wait). Output order is always preserved.
    #[arg(long = "dns-wait-ms", value_name = "MS", default_value_t = 400, value_parser = clap::value_parser!(u64).range(0..=10_000))]
    dns_wait_ms: u64,

    /// Emit DNS query records made by monitored processes (ETW only).
    #[arg(long = "dns-events")]
    dns_events: bool,

    /// Compute SHA-256 of each monitored executable (background, cached).
    #[arg(long)]
    hash: bool,

    /// Include listening TCP sockets and bound UDP sockets.
    #[arg(long)]
    listening: bool,

    /// Include loopback (127.0.0.0/8, ::1) traffic. Always on in the GUI and with a process
    /// filter, so applications behind a local proxy (127.0.0.1:10808 ...) stay visible.
    #[arg(long = "include-loopback")]
    include_loopback: bool,

    /// Do not emit TCP state-transition records.
    #[arg(long = "no-states")]
    no_states: bool,

    /// Close UDP flows after this many idle seconds.
    #[arg(long = "udp-idle", value_name = "SECS", default_value_t = 60)]
    udp_idle: u64,

    /// Stop after SECS seconds.
    #[arg(long, value_name = "SECS")]
    duration: Option<u64>,

    /// Mode B refresh / export interval in ms.
    #[arg(long, value_name = "MS", default_value_t = 1000, value_parser = clap::value_parser!(u64).range(100..=3_600_000))]
    interval: u64,

    /// Mode B sort order.
    #[arg(long, value_enum, default_value = "activity")]
    sort: SortArg,

    /// Disable ANSI colors (also honored: NO_COLOR environment variable).
    #[arg(long = "no-color")]
    no_color: bool,
}

const EXAMPLES: &str = "\
Examples (elevated prompt recommended):
  netattrib                                          desktop GUI (same as --gui)
  netattrib --no-gui                                 live table of every connection in the console
  netattrib --filter-exe winword.exe                 live Word connections
  netattrib -e winword --tree --dns-events           Word, its children, and its DNS lookups
  netattrib --filter-pid 4512 --json-lines -o w.jsonl
  netattrib --group                                  live per-executable view
  netattrib --group --json-lines --interval 10000    aggregate records every 10 s (SIEM)
  netattrib --csv --duration 60 > conns.csv          one-minute capture of everything";

fn open_append(p: &PathBuf) -> std::io::Result<Box<dyn Write + Send>> {
    let f = OpenOptions::new().create(true).append(true).open(p)?;
    Ok(Box::new(BufWriter::with_capacity(64 * 1024, f)))
}

fn note(msg: impl AsRef<str>) {
    eprintln!("netattrib: {}", msg.as_ref());
}

fn main() -> ExitCode {
    // First, before any thread starts or library loads on demand.
    win::restrict_dll_search();
    // No arguments at all (e.g. double-clicked in Explorer): open the GUI.
    let bare = std::env::args_os().len() <= 1;
    let mut cli = Cli::parse();
    cli.gui |= bare;
    let gui = cli.gui;
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            note(format!("error: {}", e));
            if gui {
                gui::error_box(&format!("netattrib: {}", e));
            }
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let format = if cli.json_lines {
        Format::JsonLines
    } else if cli.csv {
        Format::Csv
    } else {
        Format::Table
    };
    let stdout_console = cli.output.is_none() && console::stdout_is_console();
    let color = !cli.no_color && std::env::var_os("NO_COLOR").is_none() && console::enable_vt();
    let tui = cli.group && format == Format::Table && stdout_console;
    let gui = cli.gui;
    if gui {
        gui::detach_private_console();
    }

    std::panic::set_hook({
        let default = std::panic::take_hook();
        Box::new(move |info| {
            etw::emergency_stop();
            if console::TUI_ACTIVE.load(Ordering::SeqCst) {
                eprint!("{}", console::LEAVE_TUI);
            }
            default(info);
            // The release build aborts right after this; a GUI started from Explorer has no
            // console to show why.
            if gui {
                gui::error_box(&format!("netattrib stopped unexpectedly:\n{}", info));
            }
        })
    });
    console::install_ctrl_handler();

    let elevated = win::is_elevated();
    let debug_priv = elevated && win::enable_debug_privilege();

    let services = Arc::new(ServiceMap::default());
    services.refresh();
    let dns = dns::Dns::new(!cli.no_rdns, 4);
    let enricher = Arc::new(Enricher {
        dns: dns.clone(),
        services: services.clone(),
    });

    // ETW first, snapshot second: any process born in between shows up in both and is
    // de-duplicated by (pid, create_time) - there is no blind window.
    let mut etw_reason = String::new();
    let session = if cli.no_etw {
        etw_reason = "disabled by --no-etw".into();
        None
    } else {
        let snap_for_cleanup = process::query::snapshot().unwrap_or_default();
        let stale = etw::cleanup_stale_sessions(|pid| {
            snap_for_cleanup
                .iter()
                .any(|e| e.pid == pid && e.name.eq_ignore_ascii_case("netattrib.exe"))
        });
        if !stale.is_empty() {
            note(format!(
                "stopped {} stale ETW session(s): {}",
                stale.len(),
                stale.join(", ")
            ));
        }
        let name = format!("{}{}", etw::SESSION_PREFIX, std::process::id());
        match EtwSession::start(&name) {
            Ok(s) => match etw::enable_providers(&s, !cli.no_bytes) {
                Ok(()) => Some(Arc::new(s)),
                Err((prov, e)) => {
                    etw_reason = format!("enabling {} failed (error {})", prov, e);
                    None
                }
            },
            Err(5) => {
                etw_reason =
                    "access denied - run elevated (or join 'Performance Log Users') for ETW".into();
                None
            }
            Err(e) => {
                etw_reason = format!("StartTrace failed (error {})", e);
                None
            }
        }
    };
    let etw_on = session.is_some();
    // With ETW, table polls only reconcile TCP states and closes ETW may not report, so a
    // slow cadence suffices; polling-only mode needs it fast to catch short connections.
    let poll_ms = cli.poll_ms.unwrap_or(if etw_on { 5000 } else { 250 });

    let snap = process::query::snapshot().map_err(|e| format!("process snapshot: {}", e))?;
    let mut filter =
        filter::Filter::new(&cli.filter_exe, &cli.filter_path, &cli.filter_pid, cli.tree);
    for pid in filter.bind_pids(&snap) {
        note(format!(
            "warning: PID {} is not running; it will match a future process with that PID",
            pid
        ));
    }
    for (pat, similar) in filter.suggestions(&snap) {
        if similar.is_empty() {
            note(format!(
                "no running process matches --filter-exe '{}' yet (waiting for it to start)",
                pat
            ));
        } else {
            note(format!(
                "no running process matches --filter-exe '{}'; similar: {} (patterns like '*word*' also work)",
                pat,
                similar.join(", ")
            ));
        }
    }
    let filter_desc = filter.describe();
    // Through a system proxy (v2rayN & co.) an application's only sockets go to 127.0.0.1:
    // dropping loopback would hide the very process being watched.
    let include_loopback = cli.include_loopback || gui || !filter.is_empty();

    let (enrich_tx, enrich_rx) = channel();
    // The GUI flags unsigned processes, so it verifies every image's signature.
    let enrich_join = process::enrich::spawn(enrich_rx, cli.hash, gui);
    let mut table = ProcessTable::new(filter, enrich_tx);
    table.load_snapshot(snap);

    // Sinks: the primary stream (unless the TUI or GUI owns the output) plus an optional
    // JSONL log.
    let mut sinks: Vec<Sink> = Vec::new();
    if !cli.group && !gui {
        let w: Box<dyn Write + Send> = match &cli.output {
            Some(p) => open_append(p).map_err(|e| format!("{}: {}", p.display(), e))?,
            None => Box::new(BufWriter::with_capacity(64 * 1024, std::io::stdout())),
        };
        sinks.push(match format {
            Format::Table => Sink::Table(output::table::StreamTable::new(stdout_console, color), w),
            Format::JsonLines => Sink::JsonLines(w),
            Format::Csv => Sink::Csv { w, header: false },
        });
    }
    if let Some(p) = &cli.log {
        sinks.push(Sink::JsonLines(
            open_append(p).map_err(|e| format!("{}: {}", p.display(), e))?,
        ));
    }
    let (out_tx, out_rx) = sync_channel(65_536);
    let writer_opts = output::WriterOpts {
        dns_wait: Duration::from_millis(if cli.no_rdns { 0 } else { cli.dns_wait_ms }),
    };
    let has_sinks = !sinks.is_empty();
    // GUI: the engine's records go to the window's feed (recently closed connections), which
    // forwards them to the `--log` writer.
    let (out_tx, writer, gui_feed) = if gui {
        let (log_tx, log_rx) = sync_channel(65_536);
        let writer =
            has_sinks.then(|| output::spawn_writer(log_rx, sinks, enricher.clone(), writer_opts));
        let feed = gui::Feed::spawn(out_rx, has_sinks.then_some(log_tx));
        (Some(out_tx), writer, Some(feed))
    } else {
        let writer =
            has_sinks.then(|| output::spawn_writer(out_rx, sinks, enricher.clone(), writer_opts));
        (has_sinks.then_some(out_tx), writer, None)
    };

    let cfg = EngineConfig {
        include_loopback,
        listening: cli.listening,
        udp_idle: cli.udp_idle.max(1) * TICKS_PER_SEC,
        poll_interval: poll_ms * TICKS_PER_MS,
        states: !cli.no_states,
        dns_events: cli.dns_events,
        etw: etw_on,
    };
    let engine = Arc::new(Engine::new(cfg, table, out_tx, dns.clone()));

    let mode = if etw_on { "ETW+poll" } else { "poll-only" };
    note(format!(
        "mode {} | {} | SeDebugPrivilege {} | poll {} ms | filter: {}",
        mode,
        if elevated { "elevated" } else { "not elevated" },
        if debug_priv { "on" } else { "off" },
        poll_ms,
        filter_desc
    ));
    if !etw_on {
        note(format!(
            "ETW unavailable ({}): connections shorter than {} ms may be missed; no byte counters or DNS-observed names",
            etw_reason, poll_ms
        ));
    }

    let consumer = match &session {
        Some(s) => {
            let ctx = Arc::new(etw::Consumer {
                engine: engine.clone(),
                dns: dns.clone(),
            });
            Some(
                etw::start_consumer(s, ctx)
                    .map_err(|e| format!("OpenTrace failed (error {})", e))?,
            )
        }
        None => None,
    };

    let poller = {
        let (engine, services, session) = (engine.clone(), services.clone(), session.clone());
        std::thread::Builder::new()
            .name("poller".into())
            .spawn(move || poll_loop(engine, services, session, poll_ms, cli.listening))
            .map_err(|e| e.to_string())?
    };

    let deadline = cli
        .duration
        .map(|s| Instant::now() + Duration::from_secs(s));
    let timed_out = || deadline.is_some_and(|d| Instant::now() >= d);
    let sort: SortKey = cli.sort.into();
    let mut csv_header = true;
    // A window failure must still go through the orderly shutdown below.
    let mut gui_result = Ok(());

    if let Some(feed) = &gui_feed {
        let info = gui::Info {
            etw: etw_on,
            tcp_bytes: etw_on && !cli.no_bytes,
            elevated,
            debug_priv,
            etw_reason: etw_reason.clone(),
            poll_ms,
            filter: filter_desc.clone(),
        };
        gui_result = gui::run(engine.clone(), enricher.clone(), feed, info);
    } else if tui {
        run_tui(
            &engine,
            &enricher,
            &filter_desc,
            mode,
            sort,
            cli.interval,
            color,
            &timed_out,
        );
    } else if cli.group {
        run_group_export(
            &engine,
            &enricher,
            format,
            cli.output.as_ref(),
            sort,
            cli.interval,
            &timed_out,
            &mut csv_header,
        )?;
    } else {
        while !console::stop_requested() && !timed_out() {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    // ---- orderly shutdown -------------------------------------------------------------
    console::request_stop();
    let _ = poller.join();
    if let Some(s) = &session {
        s.stop();
    }
    if let Some(c) = consumer {
        c.close();
    }
    let now = util::now();
    engine.tick(now);

    let summary_opts = SnapshotOpts {
        sort,
        max_rows: usize::MAX,
        remotes_per_row: 1000,
        dns_per_row: 1000,
        live_limit: 0,
        changed_since: 0,
    };
    let final_snap = engine.snapshot(&summary_opts);
    engine.shutdown(now);

    if let Some(p) = &cli.summary {
        let mut w = open_append(p).map_err(|e| format!("{}: {}", p.display(), e))?;
        let mut s = String::new();
        for row in &final_snap.rows {
            s.clear();
            output::json_aggregate(&mut s, "summary", now, row, &enricher);
            s.push('\n');
            let _ = w.write_all(s.as_bytes());
        }
        let _ = w.flush();
    }
    if cli.group {
        match format {
            Format::Table => {
                let w = console::size().map(|(w, _)| w).unwrap_or(160);
                print!("{}", output::top::render_summary(&final_snap, &enricher, w));
            }
            _ => emit_aggregates(
                &final_snap,
                "summary",
                now,
                format,
                cli.output.as_ref(),
                &enricher,
                &mut csv_header,
            )?,
        }
    }

    let c = &engine.counters;
    let (events, lost, dropped, emitted, unattributed) = (
        c.etw_events.load(Ordering::Relaxed),
        c.etw_lost.load(Ordering::Relaxed),
        c.dropped.load(Ordering::Relaxed),
        c.emitted.load(Ordering::Relaxed),
        c.unattributed.load(Ordering::Relaxed),
    );
    drop(engine);
    // The feed drains the final `shutdown` closes into `--log`, then ends with the channel.
    if let Some(f) = gui_feed {
        f.join();
    }
    if let Some(w) = writer {
        let _ = w.join();
    }
    // The enrichment worker exits once the engine (and its sender) is gone; never block
    // shutdown on an in-progress hash of a large binary.
    drop(enrich_join);
    note(format!(
        "done: {} ETW events, {} lost in kernel, {} records written, {} dropped (slow sink), {} unattributed",
        events,
        lost,
        emitted,
        dropped,
        unattributed,
    ));
    gui_result
}

fn poll_loop(
    engine: Arc<Engine>,
    services: Arc<ServiceMap>,
    session: Option<Arc<EtwSession>>,
    poll_ms: u64,
    listening: bool,
) {
    /// While ETW reports kernel-side losses, polling tightens to this interval for
    /// `DEGRADED_HOLD` so the tables cover for the events that were dropped.
    const DEGRADED_POLL_MS: u64 = 1000;
    const DEGRADED_HOLD: Duration = Duration::from_secs(60);
    let mut iph = IpHelper::default();
    let (mut tcp, mut udp) = (Vec::with_capacity(1024), Vec::new());
    let etw_on = session.is_some();
    let mut last_services = Instant::now();
    let mut last_stats = Instant::now();
    let mut last_snapshot = Instant::now();
    let mut snapper = process::query::Snapshotter::default();
    let mut warned = false;
    let mut lost_seen = 0u64;
    let mut degraded_until: Option<Instant> = None;
    while !console::stop_requested() {
        let started = Instant::now();
        if let Some(s) = &session {
            // Push buffered events to the consumer before reading the tables, so sockets the
            // tables report are, as far as possible, already known from ETW.
            s.flush();
        }
        let t1 = util::now();
        let tcp_ok = iph.tcp(&mut tcp);
        if listening {
            let _ = iph.udp(&mut udp);
        }
        // Snapshot *after* reading the tables: a PID whose current instance was created
        // after t1 cannot be the owner the table reported (PID reuse in between). It costs
        // milliseconds on busy hosts, so only when a new socket needs attributing (plus a
        // slow periodic refresh for exit bookkeeping).
        if !etw_on
            && (engine.has_unknown_rows(&tcp, &udp)
                || last_snapshot.elapsed() >= Duration::from_secs(5))
        {
            if let Ok(snap) = snapper.take() {
                engine.on_process_snapshot(&snap, util::now());
                last_snapshot = Instant::now();
            }
        }
        match tcp_ok {
            Ok(()) => engine.on_poll(&tcp, &udp, t1),
            Err(e) if !warned => {
                warned = true;
                note(format!("warning: GetExtendedTcpTable failed (error {})", e));
            }
            Err(_) => {}
        }
        engine.tick(util::now());
        if last_services.elapsed() >= Duration::from_secs(10) {
            last_services = Instant::now();
            services.refresh();
        }
        if let Some(s) = &session {
            if last_stats.elapsed() >= Duration::from_secs(2) {
                last_stats = Instant::now();
                if let Some(st) = s.stats() {
                    let lost = st.events_lost as u64 + st.realtime_buffers_lost as u64;
                    engine.counters.etw_lost.store(lost, Ordering::Relaxed);
                    if lost > lost_seen {
                        if degraded_until.is_none() && poll_ms > DEGRADED_POLL_MS {
                            note(format!(
                                "warning: ETW lost {} event(s)/buffer(s); polling every {} ms for {} s",
                                lost - lost_seen,
                                DEGRADED_POLL_MS,
                                DEGRADED_HOLD.as_secs()
                            ));
                        }
                        lost_seen = lost;
                        degraded_until = Some(Instant::now() + DEGRADED_HOLD);
                    }
                }
            }
        }
        if degraded_until.is_some_and(|t| Instant::now() >= t) {
            degraded_until = None;
        }
        // Housekeeping (confirmation windows, UDP idle, pending attribution) must run at
        // least once a second even when table polls are infrequent.
        let poll_period = Duration::from_millis(if degraded_until.is_some() {
            poll_ms.min(DEGRADED_POLL_MS)
        } else {
            poll_ms
        });
        let mut last_tick = Instant::now();
        while started.elapsed() < poll_period && !console::stop_requested() {
            std::thread::sleep(Duration::from_millis(20).min(poll_period));
            if last_tick.elapsed() >= Duration::from_secs(1) {
                last_tick = Instant::now();
                engine.tick(util::now());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_tui(
    engine: &Engine,
    enricher: &Enricher,
    filter: &str,
    mode: &'static str,
    sort: SortKey,
    interval_ms: u64,
    color: bool,
    timed_out: &dyn Fn() -> bool,
) {
    let mut stdout = std::io::stdout();
    console::TUI_ACTIVE.store(true, Ordering::SeqCst);
    let _ = write!(stdout, "\x1b[?1049h\x1b[?25l\x1b[2J");
    let _ = stdout.flush();
    let mut last_events = engine.counters.etw_events.load(Ordering::Relaxed);
    let mut last_t = Instant::now();
    let mut rate = 0u64;
    let frame_period = Duration::from_millis(interval_ms);
    while !console::stop_requested() && !timed_out() {
        let (w, h) = console::size().unwrap_or((120, 40));
        let ev = engine.counters.etw_events.load(Ordering::Relaxed);
        let dt = last_t.elapsed().as_secs_f64();
        if dt >= 0.5 {
            rate = ((ev - last_events) as f64 / dt) as u64;
            last_events = ev;
            last_t = Instant::now();
        }
        let snap = engine.snapshot(&output::top::frame_opts(sort, h));
        let status = output::top::Status {
            mode,
            now: util::now(),
            started: engine.started,
            events_per_sec: rate,
            lost: engine.counters.etw_lost.load(Ordering::Relaxed),
            dropped: engine.counters.dropped.load(Ordering::Relaxed),
            filter: filter.to_string(),
            sort,
        };
        let frame = output::top::render_frame(&snap, &status, enricher, w, h, color);
        let _ = stdout.write_all(frame.as_bytes());
        let _ = stdout.flush();
        let t = Instant::now();
        while t.elapsed() < frame_period && !console::stop_requested() && !timed_out() {
            std::thread::sleep(Duration::from_millis(50));
            // Redraw promptly after a resize instead of waiting for the next tick.
            if console::size().unwrap_or((w, h)) != (w, h) {
                break;
            }
        }
    }
    let _ = write!(stdout, "{}", console::LEAVE_TUI);
    let _ = stdout.flush();
    console::TUI_ACTIVE.store(false, Ordering::SeqCst);
}

fn emit_aggregates(
    snap: &aggregate::TopSnapshot,
    kind: &str,
    ts: util::FileTime,
    format: Format,
    output: Option<&PathBuf>,
    enricher: &Enricher,
    csv_header: &mut bool,
) -> Result<(), String> {
    let mut w: Box<dyn Write> = match output {
        Some(p) => open_append(p).map_err(|e| format!("{}: {}", p.display(), e))?,
        None => Box::new(std::io::stdout().lock()),
    };
    let mut s = String::new();
    for row in &snap.rows {
        s.clear();
        match format {
            Format::Csv => {
                if *csv_header {
                    *csv_header = false;
                    s.push_str(output::CSV_AGG_HEADER);
                    s.push('\n');
                }
                output::csv_aggregate(&mut s, kind, ts, row, enricher);
            }
            _ => output::json_aggregate(&mut s, kind, ts, row, enricher),
        }
        s.push('\n');
        if w.write_all(s.as_bytes()).is_err() {
            console::request_stop();
            break;
        }
    }
    let _ = w.flush();
    Ok(())
}

/// Mode B without a TUI: periodic incremental aggregate records (only executables with
/// activity since the previous interval), suitable for SIEM ingestion.
#[allow(clippy::too_many_arguments)]
fn run_group_export(
    engine: &Engine,
    enricher: &Enricher,
    format: Format,
    output: Option<&PathBuf>,
    sort: SortKey,
    interval_ms: u64,
    timed_out: &dyn Fn() -> bool,
    csv_header: &mut bool,
) -> Result<(), String> {
    let mut since = 0u64;
    let period = Duration::from_millis(interval_ms);
    while !console::stop_requested() && !timed_out() {
        let t = Instant::now();
        while t.elapsed() < period && !console::stop_requested() && !timed_out() {
            std::thread::sleep(Duration::from_millis(50));
        }
        if format == Format::Table {
            continue; // summary only, printed at exit
        }
        let now = util::now();
        let snap = engine.snapshot(&SnapshotOpts {
            sort,
            max_rows: usize::MAX,
            remotes_per_row: 50,
            dns_per_row: 50,
            live_limit: 0,
            changed_since: since,
        });
        since = now;
        emit_aggregates(
            &snap,
            "aggregate",
            now,
            format,
            output,
            enricher,
            csv_header,
        )?;
    }
    Ok(())
}
