//! Desktop GUI (egui + eframe, OpenGL renderer), modelled on Resource Monitor's Network tab
//! and Process Explorer's tree.
//!
//! ```text
//!  [x] Hide background noise [x] Keep closed history [Clear history] [Export…] [Clear filters]   ● ETW capture active · Administrator
//!  Processes (321)       [+][−] │ Process      PID    Local Address     Remote Address       Domain             State
//!  [Find process or PID       ] │ WINWORD.EXE  4512   127.0.0.1:50123   127.0.0.1:10808      via xray.exe (…)   PROXY/LOCAL
//!  [ ] Only with connections    │ xray.exe     19208  192.168.0.5:2892  203.0.113.10:2052    vps.example.net    ESTABLISHED
//!  ⏷ explorer.exe  10352        │
//!      WINWORD.EXE  4512   3    │
//!  412 of 980 connections · 287 processes · 4.5k events/s · 0 lost · up 12m03s
//! ```
//!
//! The capture engine runs exactly as in console mode (ETW consumer + IP Helper poller).
//! `snapshot.rs` samples it once a second on a background thread; this module only renders
//! the latest immutable sample, so the UI thread never holds the engine lock.

mod autofilter;
mod export;
mod native;
mod settings;
mod snapshot;

use std::cmp::Ordering;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use eframe::egui::{self, Align, Color32, Key, Layout, Modifiers, RichText, Sense};
use egui_extras::{Column, TableBuilder};

use crate::aggregate::Engine;
use crate::console;
use crate::dns::DomainSource;
use crate::model::{FlowKey, Proto};
use crate::output::{user_display, Enricher};
use crate::process::hash::Sha256Provider;
use crate::process::signature::{Signature, Via};
use crate::process::Process;
use crate::util::{human_count, human_duration, iso8601, TICKS_PER_SEC};
use autofilter::ColumnFilter;
use settings::Settings;
use snapshot::{
    ident, Account, Conn, Control, Ident, Node, Shared, Snapshot, CLOSED_RETENTION, HISTORY_CAP,
    STATE_LOCAL_IN, STATE_PROXY,
};

pub use native::{detach_private_console, error_box};
pub use snapshot::Feed;

/// Startup facts for the capture status indicator.
pub struct Info {
    pub etw: bool,
    /// TCP byte counters are captured (ETW without `--no-bytes`).
    pub tcp_bytes: bool,
    pub elevated: bool,
    pub debug_priv: bool,
    /// Why ETW is off, when it is.
    pub etw_reason: String,
    pub poll_ms: u64,
    pub filter: String,
}

/// Runs the window on the calling thread until it is closed (or Ctrl+C in the console).
/// The sampler is stopped and joined before returning, so the caller can shut the engine down.
pub fn run(
    engine: Arc<Engine>,
    enricher: Arc<Enricher>,
    feed: &Feed,
    info: Info,
) -> Result<(), String> {
    let shared = Shared::default();
    let control = Arc::new(Control::new(KEEP_HISTORY));
    let repaint = Arc::new(OnceLock::new());
    let sampler = snapshot::spawn_sampler(
        engine,
        enricher,
        feed,
        shared.clone(),
        control.clone(),
        repaint.clone(),
    );
    let title = if info.elevated {
        "netattrib (Administrator)"
    } else {
        "netattrib"
    };
    // Window geometry and settings persist; see settings.rs for where.
    let portable = settings::portable_file();
    let settings_file = settings::location(portable.as_deref());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_icon(Arc::new(window_icon()))
            .with_inner_size(initial_size())
            .with_min_inner_size([760.0, 420.0]),
        persistence_path: portable,
        ..Default::default()
    };
    let result = eframe::run_native(
        settings::APP_ID,
        options,
        Box::new(move |cc| {
            let _ = repaint.set(cc.egui_ctx.clone());
            Ok(Box::new(App::new(
                shared,
                control,
                info,
                cc.storage,
                settings_file,
            )))
        }),
    );
    console::request_stop();
    let _ = sampler.join();
    result.map_err(|e| format!("cannot open the GUI window: {}", e))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Col {
    Process,
    Pid,
    Local,
    Remote,
    Domain,
    Proto,
    State,
    Sent,
    Recv,
}

/// The table's columns: title, initial width, minimum width. Like a spreadsheet, every column
/// is resized on its own by dragging its right edge (the columns after it move along, and the
/// table scrolls sideways once they no longer fit), and double-clicking its header or right
/// edge fits it to its contents. Content never widens a column by itself: cells are clipped,
/// because a column that grows with its widest value shifts everything to its right.
const COLUMNS: [(Col, &str, f32, f32); 9] = [
    (Col::Process, "Process", 140.0, 60.0),
    (Col::Pid, "PID", 65.0, 45.0),
    (Col::Local, "Local Address", 150.0, 70.0),
    (Col::Remote, "Remote Address", 150.0, 70.0),
    (Col::Domain, "Domain", 200.0, 90.0),
    (Col::Proto, "Proto", 60.0, 40.0),
    (Col::State, "State", 90.0, 50.0),
    (Col::Sent, "Sent", 75.0, 50.0),
    (Col::Recv, "Recv", 75.0, 50.0),
];
const MAX_COLUMN_WIDTH: f32 = 1200.0;
/// Room after the widest value when a column is fitted to its contents.
const FIT_PADDING: f32 = 6.0;
/// The connection table's id salt (egui_extras derives its column-resize handles' ids from it).
const TABLE_ID: &str = "connections-table";

/// Current width of each column, in [`COLUMNS`] order (persisted in the settings).
type ColumnWidths = [f32; 9];
/// The AutoFilter of each column, in [`COLUMNS`] order.
type ColumnFilters = [ColumnFilter; 9];

/// Which byte counters exist; Sent and Recv show `—` otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Counting {
    etw: bool,
    tcp: bool,
}

impl Counting {
    /// Without ETW nothing is counted; with `--no-bytes` only UDP is.
    fn known(self, c: &Conn) -> bool {
        self.etw && (self.tcp || c.key.proto == Proto::Udp)
    }
}

fn default_column_widths() -> ColumnWidths {
    COLUMNS.map(|(_, _, initial, _)| initial)
}

fn column_index(col: Col) -> usize {
    COLUMNS
        .iter()
        .position(|&(c, ..)| c == col)
        .expect("every column is in COLUMNS")
}

/// LAN discovery chatter: NetBIOS name/datagram, SSDP, mDNS, LLMNR.
const NOISE_PORTS: [u16; 5] = [137, 138, 1900, 5353, 5355];

/// Multicast/broadcast destinations and the discovery ports, on either end. Loopback is never
/// noise by address: behind a system proxy it carries the application's real traffic.
fn is_noise(k: &FlowKey) -> bool {
    let ip = k.remote.ip();
    !ip.is_loopback()
        && (ip.is_multicast()
            || matches!(ip, IpAddr::V4(v4) if v4.is_broadcast())
            || NOISE_PORTS.contains(&k.local.port())
            || NOISE_PORTS.contains(&k.remote.port()))
}

/// A loopback connection whose two ends belong to the same process, such as Intel's
/// `esrv_svc.exe` talking to itself. A connection to *another* local process (a proxy) is not.
fn is_self_loopback(c: &Conn) -> bool {
    c.link
        .as_ref()
        .and_then(|l| l.peer.as_ref())
        .is_some_and(|p| ident(p) == ident(&c.proc))
}

/// What "Hide background noise" hides.
fn row_is_noise(c: &Conn) -> bool {
    is_noise(&c.key) || is_self_loopback(c)
}

/// The All / User / System toggle above the tree; it scopes the tree and the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    All,
    User,
    System,
}

impl Scope {
    fn admits(self, account: Account) -> bool {
        match self {
            Scope::All => true,
            Scope::User => account == Account::User,
            Scope::System => account == Account::System,
        }
    }
}

/// Process filter (`q` lower-cased): substring of the name or hosted services, or an exact PID.
fn proc_matches(node: &Node, q: &str) -> bool {
    q.is_empty() || node.search.contains(q) || q.parse::<u32>() == Ok(node.proc.pid)
}

/// "Keep closed history" starts on: closed connections stay until cleared or capped.
const KEEP_HISTORY: bool = true;
const TREE_MIN_WIDTH: f32 = 220.0;
/// Rows that moved data this recently are drawn in bold.
const RECENT: u64 = 2 * TICKS_PER_SEC;
const MESSAGE_TTL: Duration = Duration::from_secs(10);
const TREE_INDENT: f32 = 14.0;

#[derive(Clone, PartialEq)]
struct RowsKey {
    seq: u64,
    hide_noise: bool,
    scope: Scope,
    selected: Option<Ident>,
    /// Bumped on every change to a column filter.
    filters_version: u64,
    sort: Col,
    descending: bool,
}

enum RowAction {
    Copy(String),
    Select(Ident),
    OpenUrl(String),
    CloseTcp {
        local: SocketAddrV4,
        remote: SocketAddrV4,
        name: String,
    },
}

enum NodeAction {
    Copy(String),
    ShowInExplorer(String),
    VirusTotal(Arc<Process>),
    Terminate(KillTarget),
}

/// A connection that stays identifiable across refreshes (rows are re-sorted every second).
#[derive(Clone, PartialEq)]
struct RowRef {
    key: FlowKey,
    proc: Ident,
    closed: bool,
}

impl RowRef {
    fn of(c: &Conn) -> Self {
        RowRef {
            key: c.key,
            proc: ident(&c.proc),
            closed: c.closed.is_some(),
        }
    }

    fn find<'a>(&self, snap: &'a Snapshot) -> Option<&'a Conn> {
        snap.conns.iter().find(|c| RowRef::of(c) == *self)
    }
}

#[derive(Clone)]
struct KillTarget {
    id: Ident,
    name: String,
}

struct App {
    shared: Shared,
    control: Arc<Control>,
    info: Arc<Info>,
    snap: Arc<Snapshot>,
    /// Left panel: process name or PID. Prunes and highlights the tree; never the table.
    proc_query: String,
    hide_noise: bool,
    keep_history: bool,
    network_only: bool,
    scope: Scope,
    /// Tree selection: the table shows this process and its descendants.
    selected: Option<Ident>,
    collapsed: HashSet<Ident>,
    sort: Col,
    descending: bool,
    /// The sort a header click replaced: `(clicked column, previous sort, previous order)`.
    /// A double-click (fit to contents) undoes its first click's re-sort.
    sort_undo: Option<(Col, Col, bool)>,
    /// Table column widths: read back from the table every frame, persisted in the settings.
    col_widths: ColumnWidths,
    /// `col_widths` changed here (fit to contents): hand them to the table next frame.
    apply_widths: bool,
    /// Header AutoFilters (session only), and a counter bumped whenever one changes.
    filters: ColumnFilters,
    filters_version: u64,
    /// `(seq, hide_noise)` the per-process counts below were computed for.
    counts_key: Option<(u64, bool)>,
    /// Per tree node, noise excluded: its own rows and active connections, and the rows in
    /// its whole subtree.
    own_rows: Vec<u32>,
    active: Vec<u32>,
    subtree: Vec<u32>,
    /// Rows to public (internet) addresses, history included: with an unsigned image, the
    /// process gets a warning badge.
    external: Vec<u32>,
    /// `(seq, process query)` the tree matches below were computed for.
    matches_key: Option<(u64, String)>,
    matches: Vec<bool>,
    /// Matches whose ancestors were already expanded for the current query, so a node the
    /// user collapses again is not re-expanded every second.
    revealed: HashSet<Ident>,
    scroll_to_match: bool,
    /// Tree nodes left after scope, process filter and "only with connections".
    visible_key: Option<(u64, bool, String, Scope, bool)>,
    visible: Vec<bool>,
    /// "Terminate process" awaiting confirmation.
    confirm_kill: Option<KillTarget>,
    /// The row a table context menu was opened on.
    row_menu: Option<RowRef>,
    rows_key: Option<RowsKey>,
    /// Indices into `snap.conns`: filtered and sorted.
    rows: Vec<usize>,
    message: Option<(String, bool, Instant)>,
    /// Messages from background work (the VirusTotal hash lookup), shown like `message`.
    notice_tx: Sender<(String, bool)>,
    notice_rx: Receiver<(String, bool)>,
    /// Where settings are kept (shown in the capture status tooltip).
    settings_file: Option<PathBuf>,
    /// "Restart as administrator" was clicked; handled where the settings can be saved first.
    restart: bool,
    /// Top bar widths measured last frame: the toggles and buttons, and the capture status.
    /// They decide whether the bar fits on one row.
    controls_w: f32,
    status_w: f32,
}

impl App {
    fn new(
        shared: Shared,
        control: Arc<Control>,
        info: Info,
        storage: Option<&dyn eframe::Storage>,
        settings_file: Option<PathBuf>,
    ) -> Self {
        let snap = shared.read().unwrap_or_else(|e| e.into_inner()).clone();
        let saved = Settings::load(storage);
        control.set_keep_history(saved.keep_history);
        let (notice_tx, notice_rx) = channel();
        App {
            shared,
            control,
            info: Arc::new(info),
            snap,
            proc_query: String::new(),
            hide_noise: saved.hide_noise,
            keep_history: saved.keep_history,
            network_only: saved.network_only,
            scope: saved.scope,
            selected: None,
            collapsed: HashSet::new(),
            sort: Col::Process,
            descending: false,
            sort_undo: None,
            col_widths: saved.column_widths,
            apply_widths: false,
            filters: ColumnFilters::default(),
            filters_version: 0,
            counts_key: None,
            own_rows: Vec::new(),
            active: Vec::new(),
            subtree: Vec::new(),
            external: Vec::new(),
            matches_key: None,
            matches: Vec::new(),
            revealed: HashSet::new(),
            scroll_to_match: false,
            visible_key: None,
            visible: Vec::new(),
            confirm_kill: None,
            row_menu: None,
            rows_key: None,
            rows: Vec::new(),
            message: None,
            notice_tx,
            notice_rx,
            settings_file,
            restart: false,
            controls_w: 0.0,
            status_w: 0.0,
        }
    }

    fn settings(&self) -> Settings {
        Settings {
            hide_noise: self.hide_noise,
            keep_history: self.keep_history,
            network_only: self.network_only,
            scope: self.scope,
            column_widths: self.col_widths,
        }
    }

    fn notify(&mut self, text: impl Into<String>, error: bool) {
        self.message = Some((text.into(), error, Instant::now()));
    }

    fn open_url(&mut self, url: &str) {
        if let Err(e) = native::open_url(url) {
            self.notify(format!("Cannot open the browser: {}", e), true);
        }
    }

    /// Opens the VirusTotal report of the process's image. The file is hashed off the UI thread
    /// unless its SHA-256 is already known (`--hash`, or an earlier lookup). Only the hash
    /// leaves the machine, as part of the URL; the file is never uploaded.
    fn check_hash(&mut self, p: Arc<Process>, ctx: &egui::Context) {
        if let Some(h) = p.sha256() {
            self.open_url(&virustotal_file(h));
            return;
        }
        self.notify(format!("Computing the SHA-256 of {}…", p.name), false);
        let (tx, ctx) = (self.notice_tx.clone(), ctx.clone());
        let spawned = std::thread::Builder::new()
            .name("vt-hash".into())
            .spawn(move || {
                let digest = Sha256Provider::open()
                    .ok_or_else(|| "SHA-256 (CNG) is unavailable".to_string())
                    .and_then(|prov| prov.hash_file(&p.path).map_err(|e| e.to_string()));
                let notice = match digest {
                    Ok(h) => {
                        let url = virustotal_file(&h);
                        let _ = p.sha256.set(Some(h));
                        match native::open_url(&url) {
                            Ok(()) => {
                                (format!("Opened the VirusTotal report of {}", p.name), false)
                            }
                            Err(e) => (format!("Cannot open the browser: {}", e), true),
                        }
                    }
                    Err(e) => (format!("Cannot hash {}: {}", p.path, e), true),
                };
                let _ = tx.send(notice);
                ctx.request_repaint();
            });
        if let Err(e) = spawned {
            self.notify(format!("Cannot hash the executable: {}", e), true);
        }
    }

    /// Saves the settings first: the elevated instance reads them as it starts.
    fn restart_elevated(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if let Some(st) = frame.storage_mut() {
            self.settings().save(st);
            st.flush();
        }
        match native::relaunch_elevated() {
            Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            Err(1223) => self.notify("Elevation was cancelled", false),
            Err(e) => self.notify(format!("Could not restart elevated (error {})", e), true),
        }
    }

    /// Picks up the newest sample and recomputes derived views only when an input changed.
    fn refresh(&mut self) {
        let latest = self
            .shared
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if !Arc::ptr_eq(&latest, &self.snap) {
            self.snap = latest;
            let index = &self.snap.index;
            if self.selected.is_some_and(|id| !index.contains_key(&id)) {
                self.selected = None;
            }
            self.collapsed.retain(|id| index.contains_key(id));
        }
        while let Ok((text, error)) = self.notice_rx.try_recv() {
            self.notify(text, error);
        }
        if self
            .message
            .as_ref()
            .is_some_and(|m| m.2.elapsed() > MESSAGE_TTL)
        {
            self.message = None;
        }
        let snap = &self.snap;

        let counts_key = (snap.seq, self.hide_noise);
        if self.counts_key != Some(counts_key) {
            self.counts_key = Some(counts_key);
            let c = row_counts(snap, self.hide_noise);
            (self.own_rows, self.active, self.subtree, self.external) =
                (c.own, c.active, c.subtree, c.external);
        }

        let proc_query = self.proc_query.trim().to_lowercase();
        let matches_key = (snap.seq, proc_query.clone());
        if self.matches_key.as_ref() != Some(&matches_key) {
            if self
                .matches_key
                .as_ref()
                .is_none_or(|(_, old)| *old != proc_query)
            {
                // A new query reveals and scrolls to its matches afresh.
                self.revealed.clear();
                self.scroll_to_match = !proc_query.is_empty();
            }
            self.matches = snap
                .procs
                .iter()
                .map(|n| !proc_query.is_empty() && proc_matches(n, &proc_query))
                .collect();
            for i in (0..snap.procs.len()).filter(|&i| self.matches[i]) {
                if self.revealed.insert(ident(&snap.procs[i].proc)) {
                    let mut up = snap.procs[i].parent;
                    while let Some(p) = up {
                        self.collapsed.remove(&ident(&snap.procs[p].proc));
                        up = snap.procs[p].parent;
                    }
                }
            }
            self.matches_key = Some(matches_key);
        }

        let visible_key = (
            snap.seq,
            self.hide_noise,
            proc_query,
            self.scope,
            self.network_only,
        );
        if self.visible_key.as_ref() != Some(&visible_key) {
            self.visible = tree_visibility(
                snap,
                &self.matches,
                !visible_key.2.is_empty(),
                self.scope,
                self.network_only,
                &self.own_rows,
            );
            self.visible_key = Some(visible_key);
        }

        let rows_key = RowsKey {
            seq: snap.seq,
            hide_noise: self.hide_noise,
            scope: self.scope,
            selected: self.selected,
            filters_version: self.filters_version,
            sort: self.sort,
            descending: self.descending,
        };
        if self.rows_key.as_ref() != Some(&rows_key) {
            self.rows = filter_rows(snap, &rows_key, &self.filters, self.counting());
            self.rows_key = Some(rows_key);
        }
    }

    // ------------------------------------------------------------------------------------
    // Top bar
    // ------------------------------------------------------------------------------------

    fn controls(&mut self, ui: &mut egui::Ui) {
        let closed_rows = self
            .snap
            .conns
            .iter()
            .filter(|c| c.closed.is_some())
            .count();
        let info = self.info.clone();
        let settings_file = self.settings_file.clone();
        let settings_file = settings_file.as_deref();
        let (mut export, mut restart, mut status_w) = (false, false, self.status_w);
        // Widths measured last frame decide between one row and two; a row that does not fit
        // would make the controls run into the status.
        let one_row =
            ui.available_width() >= self.controls_w + self.status_w + ui.spacing().item_spacing.x;
        if one_row {
            egui::Sides::new().shrink_left().show(
                ui,
                |ui| export = self.toolbar(ui, closed_rows),
                |ui| {
                    restart = capture_status(ui, &info, settings_file);
                    status_w = ui.min_rect().width();
                },
            );
        } else {
            let row = egui::vec2(ui.available_width(), ui.spacing().interact_size.y);
            ui.allocate_ui_with_layout(row, Layout::right_to_left(Align::Center), |ui| {
                restart = capture_status(ui, &info, settings_file);
                status_w = ui.min_rect().width();
            });
            ui.horizontal(|ui| export = self.toolbar(ui, closed_rows));
        }
        self.status_w = status_w;
        if export {
            self.export();
        }
        self.restart |= restart;
    }

    /// Toggles and buttons, left to right. Returns true when "Export…" was clicked. Records how
    /// much room they take. (Filtering by address, domain, state... is done from the column
    /// headers.)
    fn toolbar(&mut self, ui: &mut egui::Ui, closed_rows: usize) -> bool {
        let x0 = ui.cursor().min.x;
        ui.checkbox(&mut self.hide_noise, "Hide background noise")
            .on_hover_text(
                "Hide multicast and broadcast traffic, LAN discovery chatter (NetBIOS 137/138,\n\
                 SSDP 1900, mDNS 5353, LLMNR 5355) and self-loopback: a process talking to\n\
                 itself on 127.0.0.1. Loopback to another process, such as a local proxy,\n\
                 is never hidden.",
            );
        if ui
            .checkbox(&mut self.keep_history, "Keep closed history")
            .on_hover_text(format!(
                "On: closed connections stay in the table (last {} kept).\n\
                 Off: they disappear {} s after closing.",
                HISTORY_CAP,
                CLOSED_RETENTION / TICKS_PER_SEC
            ))
            .changed()
        {
            self.control.set_keep_history(self.keep_history);
        }
        if ui
            .add_enabled(closed_rows > 0, egui::Button::new("Clear history"))
            .on_hover_text("Remove closed connections from the table now")
            .clicked()
        {
            self.control.clear_history();
        }
        ui.separator();
        let export = ui
            .button("Export…")
            .on_hover_text("Save the rows shown in the table as CSV or JSON")
            .clicked();
        let filtered: Vec<&str> = COLUMNS
            .iter()
            .zip(&self.filters)
            .filter(|(_, f)| f.is_active())
            .map(|(&(_, title, ..), _)| title)
            .collect();
        if !filtered.is_empty() {
            let accent = autofilter::accent(ui.visuals());
            if ui
                .button(RichText::new("Clear filters").color(accent))
                .on_hover_text(format!(
                    "Remove the column filters on: {}",
                    filtered.join(", ")
                ))
                .clicked()
            {
                self.filters = ColumnFilters::default();
                self.filters_version += 1;
            }
        }
        self.controls_w = ui.cursor().min.x - x0;
        export
    }

    fn export(&mut self) {
        let Some(path) =
            native::save_dialog(&format!("{}.csv", export::default_stem(crate::util::now())))
        else {
            return;
        };
        let format = export::Format::for_path(&path);
        let rows: Vec<&Conn> = self.rows.iter().map(|&i| &self.snap.conns[i]).collect();
        let n = rows.len();
        match export::write(&path, format, &rows) {
            Ok(()) => self.notify(
                format!(
                    "Exported {} rows as {} to {}",
                    n,
                    format.label(),
                    path.display()
                ),
                false,
            ),
            Err(e) => self.notify(format!("Export to {} failed: {}", path.display(), e), true),
        }
    }

    // ------------------------------------------------------------------------------------
    // Bottom bar
    // ------------------------------------------------------------------------------------

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        let snap = &self.snap;
        let s = &snap.stats;
        let warn = ui.visuals().warn_fg_color;
        let filtered: Vec<&str> = COLUMNS
            .iter()
            .zip(&self.filters)
            .filter(|(_, f)| f.is_active())
            .map(|(&(_, title, ..), _)| title)
            .collect();
        ui.horizontal(|ui| {
            ui.label(format!(
                "{} of {} connections",
                self.rows.len(),
                snap.conns.len()
            ));
            let closed = snap.conns.iter().filter(|c| c.closed.is_some()).count();
            if closed > 0 {
                ui.weak(if self.keep_history {
                    format!("({} closed kept, up to {})", closed, HISTORY_CAP)
                } else {
                    format!(
                        "({} closed in the last {} s)",
                        closed,
                        CLOSED_RETENTION / TICKS_PER_SEC
                    )
                });
            }
            if !filtered.is_empty() {
                ui.separator();
                ui.colored_label(
                    autofilter::accent(ui.visuals()),
                    format!("Column filters: {}", filtered.join(", ")),
                );
            }
            ui.separator();
            ui.label(format!("{} processes", s.procs_alive));
            if self.info.etw {
                ui.separator();
                ui.label(format!("{} events/s", human_count(s.events_per_sec)));
                let lost = RichText::new(format!("{} lost", human_count(s.etw_lost)));
                ui.label(if s.etw_lost > 0 {
                    lost.color(warn)
                } else {
                    lost
                })
                .on_hover_text("Events the kernel dropped before delivery");
            }
            if s.dropped > 0 {
                ui.separator();
                ui.colored_label(warn, format!("{} records dropped", human_count(s.dropped)));
            }
            ui.separator();
            ui.label(format!("up {}", human_duration(s.uptime)));
            if let Some((text, error, _)) = &self.message {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let color = if *error {
                        ui.visuals().error_fg_color
                    } else {
                        ui.visuals().text_color()
                    };
                    ui.add(egui::Label::new(RichText::new(text).color(color)).truncate());
                });
            }
        });
    }

    // ------------------------------------------------------------------------------------
    // Process tree (left)
    // ------------------------------------------------------------------------------------

    fn process_tree(&mut self, ui: &mut egui::Ui) {
        let snap = self.snap.clone();
        egui::Sides::new().shrink_left().truncate().show(
            ui,
            |ui| {
                ui.strong(format!("Processes ({})", snap.stats.procs_alive));
            },
            |ui| {
                if ui.small_button("−").on_hover_text("Collapse all").clicked() {
                    self.collapsed = snap
                        .procs
                        .iter()
                        .filter(|n| !n.children.is_empty())
                        .map(|n| ident(&n.proc))
                        .collect();
                }
                if ui.small_button("+").on_hover_text("Expand all").clicked() {
                    self.collapsed.clear();
                }
            },
        );

        ui.horizontal(|ui| {
            for (scope, label, tip) in [
                (Scope::All, "All", "Every process"),
                (Scope::User, "User", "Processes running as the current user"),
                (
                    Scope::System,
                    "System",
                    "SYSTEM, LOCAL SERVICE, NETWORK SERVICE and per-service accounts",
                ),
            ] {
                ui.selectable_value(&mut self.scope, scope, label)
                    .on_hover_text(format!("{tip}. Applies to the tree and the table."));
            }
        });
        let search = search_box(
            ui,
            &mut self.proc_query,
            "Find process or PID  (Ctrl+F)",
            ui.available_width(),
        );
        if ui.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::F)) {
            search.request_focus();
        }
        search.on_hover_text(
            "Shows only matching processes (name, service or exact PID) with their parents\n\
             and children. The table changes only when you click a process.",
        );
        ui.checkbox(&mut self.network_only, "Only with connections")
            .on_hover_text("Hide processes without connections (or history) in their subtree");
        if let Some(&i) = self.selected.and_then(|id| snap.index.get(&id)) {
            let p = &snap.procs[i].proc;
            egui::Sides::new().shrink_left().truncate().show(
                ui,
                |ui| {
                    ui.label(
                        RichText::new(format!("Table: {} ({}) + children", p.name, p.pid)).strong(),
                    );
                },
                |ui| {
                    if ui
                        .small_button("×")
                        .on_hover_text("Show all processes")
                        .clicked()
                    {
                        self.selected = None;
                    }
                },
            );
        }
        ui.separator();

        let lines = self.flatten(&snap);
        let is_match = |i: usize| self.matches.get(i).copied().unwrap_or(false);
        let row_h = ui.spacing().interact_size.y;
        let mut area = egui::ScrollArea::both()
            .id_salt("process-tree")
            .auto_shrink(false);
        if std::mem::take(&mut self.scroll_to_match) {
            if let Some(line) = lines.iter().position(|&(i, _)| is_match(i)) {
                // The first match a third of the way down the view.
                let pitch = row_h + ui.spacing().item_spacing.y;
                let y = line as f32 * pitch - ui.available_height() / 3.0;
                area = area.vertical_scroll_offset(y.max(0.0));
            }
        }
        area.show_rows(ui, row_h, lines.len(), |ui, range| {
            for &(i, depth) in &lines[range] {
                self.tree_line(ui, &snap.procs[i], i, depth);
            }
        });
    }

    /// Visible tree lines `(node, depth)`, honoring pruning and collapsed nodes.
    fn flatten(&self, snap: &Snapshot) -> Vec<(usize, usize)> {
        let mut out = Vec::with_capacity(snap.procs.len());
        let mut stack: Vec<(usize, usize)> = snap.roots.iter().rev().map(|&r| (r, 0)).collect();
        while let Some((i, depth)) = stack.pop() {
            if !self.visible.get(i).copied().unwrap_or(true) {
                continue;
            }
            out.push((i, depth));
            if !self.collapsed.contains(&ident(&snap.procs[i].proc)) {
                stack.extend(snap.procs[i].children.iter().rev().map(|&c| (c, depth + 1)));
            }
        }
        out
    }

    fn tree_line(&mut self, ui: &mut egui::Ui, node: &Node, i: usize, depth: usize) {
        let p = &node.proc;
        let id = ident(p);
        let good = good_color(ui.visuals());
        let mut action = None;
        // Ids from the process identity, not the line's position: lines shift as processes
        // come and go, and an open context menu must stay with the process it was opened on.
        ui.push_id(id, |ui| {
            ui.horizontal(|ui| {
                ui.add_space(depth as f32 * TREE_INDENT);
                let toggle_w = ui.spacing().icon_width;
                let open = !self.collapsed.contains(&id);
                if node.children.is_empty() {
                    ui.add_space(toggle_w);
                } else {
                    let (_, mut resp) =
                        ui.allocate_exact_size(egui::vec2(toggle_w, toggle_w), Sense::click());
                    if resp.clicked() {
                        if open {
                            self.collapsed.insert(id);
                        } else {
                            self.collapsed.remove(&id);
                        }
                    }
                    resp.rect = egui::Rect::from_center_size(
                        resp.rect.center(),
                        egui::Vec2::splat(ui.spacing().icon_width_inner),
                    );
                    egui::collapsing_header::paint_default_icon(
                        ui,
                        if open { 1.0 } else { 0.0 },
                        &resp,
                    );
                }

                let active = self.active[i];
                let mut text = RichText::new(format!("{}  {}", p.name, p.pid));
                if active > 0 {
                    text = text.strong().color(good);
                } else if !p.is_alive() {
                    text = text.weak().strikethrough();
                } else if !self.scope.admits(node.account) {
                    // Shown only as the parent of something in scope.
                    text = text.weak();
                }
                if self.matches.get(i).copied().unwrap_or(false) {
                    text = text.background_color(match_color(ui.visuals()));
                }
                let selected = self.selected == Some(id);
                let resp = ui
                    .add(egui::Button::selectable(selected, text))
                    .on_hover_ui(|ui| process_tooltip(ui, node));
                if resp.clicked() {
                    self.selected = if selected { None } else { Some(id) };
                }
                resp.context_menu(|ui| action = process_menu(ui, p));
                if self.external[i] > 0 {
                    if let Some(sig) = untrusted(p) {
                        signature_badge(ui, sig);
                    }
                }
                if active > 0 {
                    ui.label(RichText::new(active.to_string()).small().color(good))
                        .on_hover_text("Active connections");
                } else if !open && self.subtree[i] > 0 {
                    ui.weak(format!("+{}", self.subtree[i]))
                        .on_hover_text("Connections in collapsed child processes");
                }
            })
        });
        match action {
            Some(NodeAction::Copy(text)) => ui.ctx().copy_text(text),
            Some(NodeAction::ShowInExplorer(path)) => {
                if let Err(e) = native::show_in_explorer(&path) {
                    self.notify(format!("Cannot open Explorer: {}", e), true);
                }
            }
            Some(NodeAction::VirusTotal(p)) => self.check_hash(p, ui.ctx()),
            Some(NodeAction::Terminate(target)) => self.confirm_kill = Some(target),
            None => {}
        }
    }

    // ------------------------------------------------------------------------------------
    // Connection table (centre)
    // ------------------------------------------------------------------------------------

    fn connection_table(&mut self, ui: &mut egui::Ui) {
        // Always-visible bars: hidden floating ones give no hint that columns lie off-screen.
        ui.spacing_mut().scroll = egui::style::ScrollStyle::solid();
        let spacing = ui.spacing();
        let columns_width = self.col_widths.iter().sum::<f32>()
            + COLUMNS.len() as f32 * spacing.item_spacing.x
            + spacing.scroll.allocated_width();
        let width = ui.available_width().max(columns_width);
        egui::ScrollArea::horizontal()
            .id_salt("connections")
            .auto_shrink(false)
            .show(ui, |ui| {
                // As wide as the columns: past the window's edge they scroll into view. (The
                // table's own vertical scroll area would clip them otherwise.)
                ui.set_width(width);
                self.table(ui);
            });
    }

    fn table(&mut self, ui: &mut egui::Ui) {
        let snap = self.snap.clone();
        let row_h = ui.text_style_height(&egui::TextStyle::Body) + 4.0;
        let weak = ui.visuals().weak_text_color();
        let closed_color = ui.visuals().error_fg_color;
        let local_color = local_color(ui.visuals());
        let mut sort_by = None;
        let mut fit = None;
        let mut action = None;
        let mut menu_target = self.row_menu.clone();
        let mut widths = self.col_widths;
        let mut filter_buttons: [Option<egui::Response>; 9] = Default::default();

        let mut builder = TableBuilder::new(ui)
            .id_salt(TABLE_ID)
            .striped(true)
            .resizable(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .auto_shrink(false);
        for (&(_, _, _, min), &width) in COLUMNS.iter().zip(&self.col_widths) {
            builder = builder.column(
                Column::initial(width)
                    .at_least(min)
                    .at_most(MAX_COLUMN_WIDTH)
                    .clip(true)
                    .resizable(true),
            );
        }
        // The table keeps the widths the user dragged to; `initial` only applies after a reset.
        if std::mem::take(&mut self.apply_widths) {
            builder.reset();
        }
        builder
            .header(row_h + 2.0, |mut header| {
                for (i, &(col, title, _, _)) in COLUMNS.iter().enumerate() {
                    // The whole header cell is the sort button (the table senses clicks).
                    let sorted = (self.sort == col).then_some(self.descending);
                    let filtered = self.filters[i].is_active();
                    let (_, resp) = header.col(|ui| {
                        // The cell is exactly as wide as the column. (The response's rect is
                        // not: egui_extras widens it past the content to catch clicks.)
                        widths[i] = ui.max_rect().width();
                        // Its own widget on top of the cell: a click on it never sorts.
                        filter_buttons[i] = Some(header_cell(
                            ui,
                            i,
                            title,
                            col == Col::Proto,
                            sorted,
                            filtered,
                        ));
                    });
                    let resp = match col {
                        Col::Sent | Col::Recv => resp.on_hover_text(
                            "Bytes since monitoring started (ETW). — = not captured",
                        ),
                        Col::Domain => resp.on_hover_text(
                            "The name this process resolved (DNS-Client ETW), else reverse DNS.\n\
                             Loopback rows show the local process at the other end instead.",
                        ),
                        Col::State => resp.on_hover_text(format!(
                            "TCP state, or for loopback connections:\n\
                             {}  connecting to a local proxy or service\n\
                             {}  the local proxy or service accepting it",
                            STATE_PROXY, STATE_LOCAL_IN
                        )),
                        _ => resp,
                    };
                    if resp.double_clicked() {
                        fit = Some(col);
                    } else if resp.clicked() {
                        sort_by = Some(col);
                    }
                }
            })
            .body(|body| {
                body.rows(row_h, self.rows.len(), |mut row| {
                    let c = &snap.conns[self.rows[row.index()]];
                    let closed = c.closed.is_some();
                    let recent = !closed && snap.taken.saturating_sub(c.last_activity) < RECENT;
                    let styled = |s: &str| {
                        let t = RichText::new(s);
                        if closed {
                            t.color(weak)
                        } else if recent {
                            t.strong()
                        } else {
                            t
                        }
                    };
                    let cell = |ui: &mut egui::Ui, t: RichText| {
                        ui.add(egui::Label::new(t).selectable(false).truncate())
                    };
                    let num = |ui: &mut egui::Ui, s: &str| {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.add(egui::Label::new(styled(s)).selectable(false));
                        });
                    };
                    let bytes = |n: u64| bytes_text(self.bytes_known(c), n);

                    row.col(|ui| {
                        if is_public(c.key.remote.ip()) {
                            if let Some(sig) = untrusted(&c.proc) {
                                let color = signature_color(ui.visuals(), sig);
                                warning_icon(ui, color).on_hover_text(signature_warning(sig));
                            }
                        }
                        cell(ui, styled(&c.proc.name))
                            .on_hover_ui(|ui| process_tooltip(ui, &snap.procs[c.node]));
                    });
                    row.col(|ui| num(ui, &c.proc.pid.to_string()));
                    row.col(|ui| {
                        cell(ui, styled(&c.local));
                    });
                    row.col(|ui| {
                        cell(ui, styled(&c.remote));
                    });
                    row.col(|ui| match (&c.domain, &c.link) {
                        (Some((name, src)), _) => {
                            cell(ui, styled(name)).on_hover_text(match src {
                                DomainSource::DnsClient => {
                                    "Resolved by this process (DNS-Client ETW)"
                                }
                                DomainSource::Ptr => "Reverse DNS (PTR) lookup",
                            });
                        }
                        (None, Some(link)) => {
                            cell(ui, styled(&link.label()).italics()).on_hover_text(
                                if link.inbound {
                                    "Accepted loopback connection from this local process"
                                } else {
                                    "Loopback connection to a local proxy or service owned by\n\
                                     this process. The proxy decides the real destination:\n\
                                     its own connections show where the traffic went."
                                },
                            );
                        }
                        (None, None) => {
                            cell(ui, RichText::new(""));
                        }
                    });
                    row.col(|ui| {
                        ui.centered_and_justified(|ui| cell(ui, styled(c.key.proto_label())));
                    });
                    row.col(|ui| {
                        let state = if closed {
                            RichText::new(c.state).color(closed_color)
                        } else if c.link.is_some() {
                            styled(c.state).color(local_color)
                        } else {
                            styled(c.state)
                        };
                        cell(ui, state).on_hover_text(format!(
                            "Socket state: {} · direction: {}{}",
                            c.tcp_state,
                            c.dir.label(),
                            if closed { " · closed" } else { "" }
                        ));
                    });
                    row.col(|ui| num(ui, &bytes(c.tx)));
                    row.col(|ui| num(ui, &bytes(c.rx)));

                    let resp = row.response();
                    if resp.secondary_clicked() {
                        menu_target = Some(RowRef::of(c));
                    }
                    resp.context_menu(|ui| {
                        // The table re-sorts every second, so the row under an open menu can
                        // change: act on the connection that was right-clicked.
                        let target = menu_target
                            .as_ref()
                            .and_then(|r| r.find(&snap))
                            .unwrap_or(c);
                        action = self.row_menu(ui, target);
                    });
                });
            });

        self.row_menu = menu_target;
        self.col_widths = widths;
        for (i, button) in filter_buttons.into_iter().enumerate() {
            if let Some(button) = button {
                self.filter_popup(i, &button);
            }
        }
        // A double-click on a column's right edge (egui_extras' resize handle) fits it too.
        let table_id = ui.scope_id().with(egui::IdSalt::new(TABLE_ID));
        for (i, &(col, ..)) in COLUMNS.iter().enumerate() {
            let handle = table_id.with("resize_column").with(i);
            if ui
                .ctx()
                .read_response(handle)
                .is_some_and(|r| r.double_clicked())
            {
                fit = Some(col);
            }
        }
        if let Some(col) = fit {
            // The double-click's first click re-sorted by this column: undo that.
            if let Some((clicked, sort, descending)) = self.sort_undo.take() {
                if clicked == col {
                    (self.sort, self.descending) = (sort, descending);
                }
            }
            self.col_widths[column_index(col)] = self.fit_width(ui, col);
            self.apply_widths = true;
            ui.ctx().request_repaint();
        }
        if let Some(col) = sort_by {
            self.sort_undo = Some((col, self.sort, self.descending));
            if self.sort == col {
                self.descending = !self.descending;
            } else {
                self.sort = col;
                // Biggest talkers first.
                self.descending = matches!(col, Col::Sent | Col::Recv);
            }
        }
        match action {
            Some(RowAction::Copy(text)) => ui.ctx().copy_text(text),
            Some(RowAction::Select(id)) => self.selected = Some(id),
            Some(RowAction::OpenUrl(url)) => self.open_url(&url),
            Some(RowAction::CloseTcp {
                local,
                remote,
                name,
            }) => match native::close_tcp(local, remote) {
                Ok(()) => self.notify(
                    format!("Closed the connection {} to {} ({})", local, remote, name),
                    false,
                ),
                Err(e) => self.notify(format!("Cannot close the connection: {}", e), true),
            },
            None => {}
        }
    }

    /// Right-click menu of a connection row.
    fn row_menu(&self, ui: &mut egui::Ui, c: &Conn) -> Option<RowAction> {
        let mut action = None;
        if ui.button("Copy remote IP:port").clicked() {
            action = Some(RowAction::Copy(c.remote.clone()));
        }
        if let Some((name, _)) = &c.domain {
            if ui.button("Copy resolved domain").clicked() {
                action = Some(RowAction::Copy(name.to_string()));
            }
        }
        if ui.button("Copy row").clicked() {
            action = Some(RowAction::Copy(self.row_text(c)));
        }
        ui.separator();
        let ip = c.key.remote.ip();
        if ui
            .add_enabled(
                is_public(ip),
                egui::Button::new(format!("Look up {} on VirusTotal", ip)),
            )
            .on_hover_text("Reputation, passive DNS and WHOIS, in your browser")
            .on_disabled_hover_text(
                "Not a public address: loopback, private, link-local, or a\n\
                 TUN proxy's fake IP (198.18.0.0/15). Look up the domain instead.",
            )
            .clicked()
        {
            action = Some(RowAction::OpenUrl(virustotal_ip(ip)));
        }
        if let Some((name, _)) = &c.domain {
            if ui
                .button(format!("Look up {} on VirusTotal", name))
                .clicked()
            {
                action = Some(RowAction::OpenUrl(virustotal_domain(name)));
            }
        }
        ui.separator();
        if ui
            .button(format!("Show only {} ({})", c.proc.name, c.proc.pid))
            .clicked()
        {
            action = Some(RowAction::Select(ident(&c.proc)));
        }
        if let Some(p) = c.link.as_ref().and_then(|l| l.peer.as_ref()) {
            if ui
                .button(format!("Show only {} ({})", p.name, p.pid))
                .clicked()
            {
                action = Some(RowAction::Select(ident(p)));
            }
        }
        ui.separator();
        let tcp4 = match (c.key.proto, c.key.local, c.key.remote) {
            (Proto::Tcp, SocketAddr::V4(l), SocketAddr::V4(r)) if !r.ip().is_unspecified() => {
                Some((l, r))
            }
            _ => None,
        };
        let why_not = if c.closed.is_some() {
            Some("The connection is already closed")
        } else if tcp4.is_none() {
            Some("Windows can close IPv4 TCP connections only")
        } else if !self.info.elevated {
            Some("Requires administrator rights: use Restart as administrator")
        } else {
            None
        };
        if ui
            .add_enabled(why_not.is_none(), egui::Button::new("Close Connection"))
            .on_hover_text(
                "Drops the connection and resets the remote end.\n\
                 The application may simply reconnect.",
            )
            .on_disabled_hover_text(why_not.unwrap_or_default())
            .clicked()
        {
            if let Some((local, remote)) = tcp4 {
                action = Some(RowAction::CloseTcp {
                    local,
                    remote,
                    name: c.proc.name.clone(),
                });
            }
        }
        if action.is_some() {
            ui.close();
        }
        action
    }

    fn counting(&self) -> Counting {
        Counting {
            etw: self.info.etw,
            tcp: self.info.tcp_bytes,
        }
    }

    fn bytes_known(&self, c: &Conn) -> bool {
        self.counting().known(c)
    }

    /// The AutoFilter popup of column `i`, opened and closed by its header button.
    fn filter_popup(&mut self, i: usize, button: &egui::Response) {
        let just_opened = button.clicked();
        egui::Popup::from_toggle_button_response(button)
            .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
            .width(280.0)
            .show(|ui| {
                let (col, title, ..) = COLUMNS[i];
                // Byte counts are too varied to list; the search box still applies.
                let values = (!matches!(col, Col::Sent | Col::Recv)).then(|| self.column_values(i));
                let filter = &mut self.filters[i];
                if autofilter::popup(ui, title, filter, values.as_deref(), just_opened) {
                    self.filters_version += 1;
                }
            });
    }

    /// Column `i`'s distinct values, with counts, among the rows every other filter leaves (as
    /// in Excel, each column's list follows the filters on the others).
    fn column_values(&self, i: usize) -> Vec<(String, usize)> {
        let Some(key) = &self.rows_key else {
            return Vec::new();
        };
        let counting = self.counting();
        let col = COLUMNS[i].0;
        let rows = shown_rows(&self.snap, key, &self.filters, counting, Some(i));
        autofilter::tally(
            rows.into_iter().map(|r| {
                let c = &self.snap.conns[r];
                cell_text(c, col, counting.known(c))
            }),
            col == Col::Pid,
        )
    }

    /// Fit to contents: the widest of the column's title and its text in every row the table
    /// shows (after filters, not only those on screen), in the table's font.
    fn fit_width(&self, ui: &egui::Ui, col: Col) -> f32 {
        let font = egui::TextStyle::Body.resolve(ui.style());
        let measure = |text: String| {
            ui.painter()
                .layout_no_wrap(text, font.clone(), Color32::WHITE)
                .size()
                .x
        };
        let (_, title, _, min) = COLUMNS[column_index(col)];
        // The header also holds the sort arrow and the filter button; flagged processes carry a
        // warning icon.
        let header = measure(title.to_string()) + 2.0 * (ui.spacing().icon_width_inner + 2.0);
        let icon =
            ui.text_style_height(&egui::TextStyle::Body) * 0.85 + ui.spacing().item_spacing.x;
        let widest = self
            .rows
            .iter()
            .map(|&i| {
                let c = &self.snap.conns[i];
                let flagged = col == Col::Process
                    && is_public(c.key.remote.ip())
                    && untrusted(&c.proc).is_some();
                measure(cell_text(c, col, self.bytes_known(c))) + if flagged { icon } else { 0.0 }
            })
            .fold(header, f32::max);
        fit(widest, min)
    }

    fn row_text(&self, c: &Conn) -> String {
        let known = self.bytes_known(c);
        COLUMNS
            .iter()
            .map(|&(col, ..)| match col {
                // Raw byte counts, blank where nothing is counted.
                Col::Sent if known => c.tx.to_string(),
                Col::Recv if known => c.rx.to_string(),
                Col::Sent | Col::Recv => String::new(),
                _ => cell_text(c, col, known),
            })
            .collect::<Vec<_>>()
            .join("\t")
    }
}

impl eframe::App for App {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        self.settings().save(storage);
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        if console::stop_requested() {
            // Ctrl+C in the console the GUI was started from.
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
        self.refresh();
        egui::Panel::top("controls").show(ui, |ui| self.controls(ui));
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui));
        egui::Panel::left("processes")
            .default_size(280.0)
            .size_range(TREE_MIN_WIDTH..=640.0)
            .show(ui, |ui| self.process_tree(ui));
        egui::CentralPanel::default_margins().show(ui, |ui| self.connection_table(ui));
        self.confirm_terminate(ui.ctx());
        if std::mem::take(&mut self.restart) {
            self.restart_elevated(ui.ctx(), frame);
        }
    }
}

impl App {
    fn confirm_terminate(&mut self, ctx: &egui::Context) {
        let Some(target) = self.confirm_kill.clone() else {
            return;
        };
        let (mut terminate, mut cancel) = (false, false);
        let modal = egui::Modal::new(egui::Id::unique("terminate-process")).show(ctx, |ui| {
            ui.set_width(380.0);
            ui.heading("Terminate process?");
            ui.add_space(4.0);
            ui.label(format!(
                "{} (PID {}) will be stopped immediately. Unsaved work in it is lost.",
                target.name, target.id.0
            ));
            ui.add_space(8.0);
            egui::Sides::new().show(
                ui,
                |_| {},
                |ui| {
                    cancel = ui.button("Cancel").clicked();
                    let red = RichText::new("Terminate").color(ui.visuals().error_fg_color);
                    terminate = ui.button(red).clicked();
                },
            );
        });
        if terminate {
            match native::terminate_process(target.id.0, target.id.1) {
                Ok(()) => self.notify(
                    format!("Terminated {} ({})", target.name, target.id.0),
                    false,
                ),
                Err(e) => self.notify(format!("Cannot terminate {}: {}", target.name, e), true),
            }
            self.confirm_kill = None;
        } else if cancel || modal.should_close() {
            self.confirm_kill = None;
        }
    }
}

/// Right-click menu of a process in the tree (System Informer style).
fn process_menu(ui: &mut egui::Ui, p: &Arc<Process>) -> Option<NodeAction> {
    let mut action = None;
    let has_path = !p.path.is_empty();
    if ui
        .add_enabled(has_path, egui::Button::new("Open file location"))
        .on_disabled_hover_text("The image path is unknown")
        .clicked()
    {
        action = Some(NodeAction::ShowInExplorer(p.path.clone()));
    }
    if ui
        .add_enabled(has_path, egui::Button::new("Copy executable path"))
        .on_disabled_hover_text("The image path is unknown")
        .clicked()
    {
        action = Some(NodeAction::Copy(p.path.clone()));
    }
    if ui.button("Copy PID").clicked() {
        action = Some(NodeAction::Copy(p.pid.to_string()));
    }
    ui.separator();
    let vt = ui
        .add_enabled(
            has_path,
            egui::Button::new("Check Executable Hash on VirusTotal"),
        )
        .on_disabled_hover_text("The image path is unknown");
    let vt = match p.sha256() {
        Some(h) => vt.on_hover_text(format!(
            "SHA-256 {}\nOpens its VirusTotal report in your browser. Nothing is uploaded.",
            h
        )),
        None => vt.on_hover_text(
            "Computes the file's SHA-256 and opens its VirusTotal report in your\n\
             browser. Only the hash is sent; the file is never uploaded.",
        ),
    };
    if vt.clicked() {
        action = Some(NodeAction::VirusTotal(p.clone()));
    }
    ui.separator();
    let killable = p.is_alive() && p.pid > 4 && p.pid != std::process::id();
    if ui
        .add_enabled(killable, egui::Button::new("Terminate process…"))
        .on_disabled_hover_text("Exited, a kernel pseudo-process, or netattrib itself")
        .clicked()
    {
        action = Some(NodeAction::Terminate(KillTarget {
            id: ident(p),
            name: p.name.clone(),
        }));
    }
    if action.is_some() {
        ui.close();
    }
    action
}

/// A single-line search box with a clear button drawn inside its right end.
fn search_box(ui: &mut egui::Ui, text: &mut String, hint: &str, width: f32) -> egui::Response {
    let button = ui.spacing().interact_size.y;
    let mut resp = ui.add(
        egui::TextEdit::singleline(text)
            .hint_text(hint)
            .desired_width(width)
            // Room for the button, so long text never runs under it.
            .margin(egui::Margin {
                left: 4,
                right: button as i8 + 2,
                top: 2,
                bottom: 2,
            }),
    );
    if !text.is_empty() {
        let rect = egui::Rect::from_min_size(
            egui::pos2(resp.rect.right() - button, resp.rect.top()),
            egui::vec2(button, resp.rect.height()),
        );
        // Registered after the text edit, so it wins clicks inside its rect.
        let clear = ui
            .interact(rect, resp.id.with("clear"), Sense::click())
            .on_hover_text("Clear")
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        let color = if clear.hovered() {
            ui.visuals().strong_text_color()
        } else {
            ui.visuals().weak_text_color()
        };
        let font = egui::TextStyle::Body.resolve(ui.style());
        ui.painter()
            .text(rect.center(), egui::Align2::CENTER_CENTER, "×", font, color);
        if clear.clicked() {
            text.clear();
            resp.mark_changed();
        }
    }
    resp
}

/// Tree pruning. A node is kept when it is in scope, has rows (with "only with connections")
/// and, while the process filter is active, matches it or descends from a match. Ancestors of
/// kept nodes stay visible to show where they sit.
fn tree_visibility(
    snap: &Snapshot,
    matches: &[bool],
    query: bool,
    scope: Scope,
    network_only: bool,
    own_rows: &[u32],
) -> Vec<bool> {
    let n = snap.procs.len();
    let mut under_match = vec![false; n];
    for &i in &snap.preorder {
        under_match[i] = matches[i] || snap.procs[i].parent.is_some_and(|p| under_match[p]);
    }
    let mut visible = vec![false; n];
    // Reverse pre-order visits every child before its parent.
    for &i in snap.preorder.iter().rev() {
        let node = &snap.procs[i];
        visible[i] |= scope.admits(node.account)
            && (!network_only || own_rows[i] > 0)
            && (!query || under_match[i]);
        if visible[i] {
            if let Some(p) = node.parent {
                visible[p] = true;
            }
        }
    }
    visible
}

/// Per tree node, noise excluded when hidden: its own rows, its live connections, the rows in
/// its whole subtree, and its rows to public addresses.
struct RowCounts {
    own: Vec<u32>,
    active: Vec<u32>,
    subtree: Vec<u32>,
    external: Vec<u32>,
}

fn row_counts(snap: &Snapshot, hide_noise: bool) -> RowCounts {
    let n = snap.procs.len();
    let (mut own, mut active, mut external) = (vec![0; n], vec![0; n], vec![0; n]);
    for c in snap
        .conns
        .iter()
        .filter(|c| !hide_noise || !row_is_noise(c))
    {
        own[c.node] += 1;
        if c.closed.is_none() {
            active[c.node] += 1;
        }
        if is_public(c.key.remote.ip()) {
            external[c.node] += 1;
        }
    }
    let mut subtree = own.clone();
    // Reverse pre-order visits every child before its parent.
    for &i in snap.preorder.iter().rev() {
        if let Some(p) = snap.procs[i].parent {
            subtree[p] += subtree[i];
        }
    }
    RowCounts {
        own,
        active,
        subtree,
        external,
    }
}

/// The image's signature, when it is missing or does not verify.
fn untrusted(p: &Process) -> Option<&Signature> {
    p.signature().filter(|s| s.is_untrusted())
}

/// Unsigned: a caution. A signature that fails to verify: an error.
fn signature_color(v: &egui::Visuals, sig: &Signature) -> Color32 {
    match sig {
        Signature::Invalid { .. } => v.error_fg_color,
        _ => v.warn_fg_color,
    }
}

fn signature_warning(sig: &Signature) -> String {
    match sig {
        Signature::Invalid { reason, .. } => format!(
            "Invalid signature ({}), and this process talks to internet addresses",
            reason
        ),
        _ => "Not signed, and this process talks to internet addresses".into(),
    }
}

/// Badge after a tree entry: an unsigned or invalidly signed image with internet connections.
fn signature_badge(ui: &mut egui::Ui, sig: &Signature) {
    let text = match sig {
        Signature::Invalid { .. } => "bad signature",
        _ => "unsigned",
    };
    let color = signature_color(ui.visuals(), sig);
    let tip = signature_warning(sig);
    warning_icon(ui, color).on_hover_text(&tip);
    ui.label(RichText::new(text).small().color(color))
        .on_hover_text(tip);
}

/// Worth a reputation lookup: not loopback, private, link-local, CGNAT, multicast, or the
/// 198.18.0.0/15 benchmark range TUN proxies hand out as fake IPs.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 198 && (o[1] & 0xfe) == 18))
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local())
        }
    }
}

fn virustotal_ip(ip: IpAddr) -> String {
    format!("https://www.virustotal.com/gui/ip-address/{}", ip)
}

fn virustotal_domain(domain: &str) -> String {
    format!("https://www.virustotal.com/gui/domain/{}", domain)
}

fn virustotal_file(sha256: &str) -> String {
    format!("https://www.virustotal.com/gui/file/{}", sha256)
}

fn window_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../../assets/netattrib.png"))
        .expect("the embedded icon is a valid PNG")
}

/// What a cell of `col` shows for `c` (the sizes as formatted for display).
fn cell_text(c: &Conn, col: Col, bytes_known: bool) -> String {
    match col {
        Col::Process => c.proc.name.clone(),
        Col::Pid => c.proc.pid.to_string(),
        Col::Local => c.local.clone(),
        Col::Remote => c.remote.clone(),
        Col::Domain => match (&c.domain, &c.link) {
            (Some((d, _)), _) => d.to_string(),
            (None, Some(link)) => link.label(),
            (None, None) => String::new(),
        },
        Col::Proto => c.key.proto_label().into(),
        Col::State => c.state.into(),
        Col::Sent => bytes_text(bytes_known, c.tx),
        Col::Recv => bytes_text(bytes_known, c.rx),
    }
}

/// B/KB/MB/GB, or `—` where nothing is counted.
fn bytes_text(known: bool, n: u64) -> String {
    if known {
        fmt_bytes(n)
    } else {
        "—".into()
    }
}

/// A fitted column: the content plus a little room, within the column's limits.
fn fit(content: f32, min: f32) -> f32 {
    (content + FIT_PADDING).ceil().clamp(min, MAX_COLUMN_WIDTH)
}

/// A header cell of column `i`: the title, truncated to the column ("Remote Ad…" when narrow,
/// never spilling into the next header), then the sort arrow and the filter button at its right
/// edge. Returns the filter button's response.
fn header_cell(
    ui: &mut egui::Ui,
    i: usize,
    title: &str,
    centered: bool,
    sorted: Option<bool>,
    filtered: bool,
) -> egui::Response {
    let s = ui.spacing().icon_width_inner;
    let cell = ui.max_rect();
    let button_room = s + 2.0;
    let arrow_room = if sorted.is_some() { s + 2.0 } else { 0.0 };
    let layout = if centered {
        Layout::centered_and_justified(egui::Direction::LeftToRight)
    } else {
        Layout::left_to_right(Align::Center)
    };
    let size = egui::vec2(
        (cell.width() - button_room - arrow_room).max(0.0),
        cell.height(),
    );
    ui.allocate_ui_with_layout(size, layout, |ui| {
        ui.add(
            egui::Label::new(RichText::new(title).strong())
                .selectable(false)
                .truncate(),
        );
    });
    if let Some(descending) = sorted {
        let at = egui::pos2(cell.right() - button_room - s * 0.6, cell.center().y);
        paint_sort_arrow(ui, at, s, descending);
    }
    let button = egui::Rect::from_center_size(
        egui::pos2(cell.right() - s * 0.5 - 1.0, cell.center().y),
        egui::vec2(s, s),
    );
    // The cell's id is stable (egui_extras salts it with the column), and so is the popup's.
    let id = ui.scope_id().with(("autofilter", i));
    autofilter::button(ui, button, id, filtered)
}

/// Wide enough for the tree and every column at its default width, within the work area.
fn initial_size() -> [f32; 2] {
    let (w, h) = native::work_area();
    [
        1440f32.min(w - 40.0).max(760.0),
        820f32.min(h - 40.0).max(420.0),
    ]
}

/// The rows the table shows, sorted.
fn filter_rows(
    snap: &Snapshot,
    k: &RowsKey,
    filters: &ColumnFilters,
    counting: Counting,
) -> Vec<usize> {
    let mut rows = shown_rows(snap, k, filters, counting, None);
    rows.sort_by(|&a, &b| {
        let (a, b) = (&snap.conns[a], &snap.conns[b]);
        let o = compare(k.sort, a, b);
        // Fixed tie-break so equal rows keep their places between samples.
        (if k.descending { o.reverse() } else { o })
            .then_with(|| compare(Col::Process, a, b))
            .then_with(|| a.proc.pid.cmp(&b.proc.pid))
            .then_with(|| a.key.remote.cmp(&b.key.remote))
            .then_with(|| a.key.local.cmp(&b.key.local))
            .then_with(|| a.closed.is_some().cmp(&b.closed.is_some()))
    });
    rows
}

/// Rows passing "Hide background noise", the scope, the tree selection and every column filter
/// except column `skip`'s (for that column's AutoFilter list), unsorted.
fn shown_rows(
    snap: &Snapshot,
    k: &RowsKey,
    filters: &ColumnFilters,
    counting: Counting,
    skip: Option<usize>,
) -> Vec<usize> {
    let columns: Vec<(Col, &ColumnFilter)> = COLUMNS
        .iter()
        .zip(filters)
        .enumerate()
        .filter(|&(i, (_, f))| Some(i) != skip && f.is_active())
        .map(|(_, (&(col, ..), f))| (col, f))
        .collect();
    let scope: Option<Vec<bool>> = k.selected.and_then(|id| snap.index.get(&id)).map(|&root| {
        let mut inside = vec![false; snap.procs.len()];
        let mut stack = vec![root];
        while let Some(i) = stack.pop() {
            inside[i] = true;
            stack.extend(&snap.procs[i].children);
        }
        inside
    });
    snap.conns
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            !(k.hide_noise && row_is_noise(c))
                && k.scope.admits(snap.procs[c.node].account)
                && scope.as_ref().is_none_or(|s| s[c.node])
                && columns
                    .iter()
                    .all(|&(col, f)| f.admits(&cell_text(c, col, counting.known(c))))
        })
        .map(|(i, _)| i)
        .collect()
}

fn compare(col: Col, a: &Conn, b: &Conn) -> Ordering {
    let ci = |x: &str, y: &str| {
        x.bytes()
            .map(|c| c.to_ascii_lowercase())
            .cmp(y.bytes().map(|c| c.to_ascii_lowercase()))
    };
    // Domains first, then loopback rows by their peer process, then rows with neither.
    let domain = |c: &Conn| -> (u8, String) {
        match (&c.domain, c.link.as_ref().and_then(|l| l.peer.as_ref())) {
            (Some((d, _)), _) => (0, d.to_string()),
            (None, Some(p)) => (1, p.name.to_ascii_lowercase()),
            (None, None) => (2, String::new()),
        }
    };
    match col {
        Col::Process => ci(&a.proc.name, &b.proc.name),
        Col::Pid => a.proc.pid.cmp(&b.proc.pid),
        Col::Local => a.key.local.cmp(&b.key.local),
        Col::Remote => a.key.remote.cmp(&b.key.remote),
        Col::Domain => domain(a).cmp(&domain(b)),
        Col::Proto => a.key.proto_label().cmp(b.key.proto_label()),
        Col::State => a.state.cmp(b.state),
        Col::Sent => a.tx.cmp(&b.tx),
        Col::Recv => a.rx.cmp(&b.rx),
    }
}

/// The capture status, laid out right to left: [dot] [text] [restart button].
/// Returns true when "Restart as administrator" was clicked.
fn capture_status(ui: &mut egui::Ui, info: &Info, settings_file: Option<&Path>) -> bool {
    let (color, text) = match (info.etw, info.elevated) {
        (true, true) => (
            good_color(ui.visuals()),
            "ETW capture active · Administrator",
        ),
        (true, false) => (
            good_color(ui.visuals()),
            "ETW capture active · standard user",
        ),
        (false, true) => (ui.visuals().warn_fg_color, "Polling only · Administrator"),
        (false, false) => (ui.visuals().warn_fg_color, "Polling only · not elevated"),
    };
    let mut details = if info.etw {
        format!(
            "Event-driven ETW capture (Kernel-Network, Kernel-Process, DNS-Client):\n\
             short-lived connections, byte counters and the domains each process resolved.\n\
             IP Helper tables reconcile TCP states every {} ms.",
            info.poll_ms
        )
    } else {
        format!(
            "ETW unavailable: {}.\n\
             Polling IP Helper tables every {} ms: connections shorter than that may be\n\
             missed, and there are no byte counters or DNS-Client domain names.",
            info.etw_reason, info.poll_ms
        )
    };
    details.push_str(&format!(
        "\nSeDebugPrivilege: {}\nCapture filter: {}",
        if info.debug_priv { "on" } else { "off" },
        info.filter
    ));
    if let Some(f) = settings_file {
        details.push_str(&format!("\nSettings: {}", f.display()));
    }
    let restart = !info.elevated
        && ui
            .button("Restart as administrator")
            .on_hover_text(
                "Relaunch elevated (UAC prompt) to enable ETW capture: short-lived\n\
                 connections, byte counters and DNS-Client domain names",
            )
            .clicked();
    ui.label(RichText::new(text).strong().color(color))
        .on_hover_text(details);
    status_dot(ui, color);
    restart
}

fn process_tooltip(ui: &mut egui::Ui, node: &Node) {
    let p = &node.proc;
    ui.strong(&p.name);
    if !p.path.is_empty() {
        ui.label(&p.path);
    }
    ui.label(format!("PID {} · parent PID {}", p.pid, p.ppid));
    match user_display(p) {
        Some(user) => ui.label(format!("User: {} ({})", user, node.account.label())),
        None => ui.label(format!("User: {}", node.account.label())),
    };
    if let Some(s) = &node.services {
        ui.label(format!("Services: {}", s));
    }
    if !p.path.is_empty() {
        signature_line(ui, p);
    }
    if p.create_time > 0 {
        ui.label(format!("Started: {}", iso8601(p.create_time)));
    }
    if !p.is_alive() {
        ui.weak("Exited");
    }
}

fn signature_line(ui: &mut egui::Ui, p: &Process) {
    match p.signature.get() {
        None => {
            ui.weak("Signature: checking…");
        }
        Some(None) => {
            ui.weak("Signature: the file cannot be read");
        }
        Some(Some(Signature::Signed { signer, via })) => {
            ui.label(format!(
                "Signed by {}{}",
                signer,
                match via {
                    Via::File => "",
                    Via::Catalog => " (catalog)",
                    Via::Package => " (app package)",
                }
            ));
        }
        Some(Some(sig @ Signature::Unsigned)) => {
            ui.colored_label(signature_color(ui.visuals(), sig), "Not signed");
        }
        Some(Some(sig @ Signature::Invalid { reason, signer })) => {
            let text = match signer {
                Some(s) => format!("Invalid signature: {} (signer: {})", reason, s),
                None => format!("Invalid signature: {}", reason),
            };
            ui.colored_label(signature_color(ui.visuals(), sig), text);
        }
    }
}

fn good_color(v: &egui::Visuals) -> Color32 {
    if v.dark_mode {
        Color32::from_rgb(110, 205, 120)
    } else {
        Color32::from_rgb(20, 130, 50)
    }
}

/// State of loopback rows (local proxy / service traffic).
fn local_color(v: &egui::Visuals) -> Color32 {
    if v.dark_mode {
        Color32::from_rgb(110, 175, 255)
    } else {
        Color32::from_rgb(0, 95, 190)
    }
}

/// Background of tree entries matching the process filter.
fn match_color(v: &egui::Visuals) -> Color32 {
    if v.dark_mode {
        Color32::from_rgba_unmultiplied(230, 180, 0, 70)
    } else {
        Color32::from_rgba_unmultiplied(255, 210, 0, 120)
    }
}

/// Painted rather than a glyph: the default fonts have no reliable arrow characters.
fn paint_sort_arrow(ui: &egui::Ui, c: egui::Pos2, s: f32, descending: bool) {
    let h = s * 0.45;
    let (tip, base) = if descending { (h, -h) } else { (-h, h) };
    let points = vec![
        egui::pos2(c.x - h, c.y + base * 0.6),
        egui::pos2(c.x + h, c.y + base * 0.6),
        egui::pos2(c.x, c.y + tip * 0.6),
    ];
    let color = ui.visuals().strong_text_color();
    ui.painter().add(egui::Shape::convex_polygon(
        points,
        color,
        egui::Stroke::NONE,
    ));
}

fn status_dot(ui: &mut egui::Ui, color: Color32) {
    let d = ui.spacing().interact_size.y * 0.5;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(d, d), Sense::hover());
    ui.painter().circle_filled(rect.center(), d * 0.5, color);
}

/// A warning triangle with an exclamation mark, painted for the same reason as the sort arrows:
/// the default fonts have no "⚠".
fn warning_icon(ui: &mut egui::Ui, color: Color32) -> egui::Response {
    let s = ui.text_style_height(&egui::TextStyle::Body) * 0.85;
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(s, s), Sense::hover());
    let (c, h) = (rect.center(), s * 0.9);
    let painter = ui.painter();
    painter.add(egui::Shape::convex_polygon(
        vec![
            egui::pos2(c.x, c.y - h / 2.0),
            egui::pos2(c.x + s / 2.0, c.y + h / 2.0),
            egui::pos2(c.x - s / 2.0, c.y + h / 2.0),
        ],
        color,
        egui::Stroke::NONE,
    ));
    let mark = ui.visuals().panel_fill;
    painter.line_segment(
        [
            egui::pos2(c.x, c.y - h * 0.14),
            egui::pos2(c.x, c.y + h * 0.18),
        ],
        egui::Stroke::new(s * 0.13, mark),
    );
    painter.circle_filled(egui::pos2(c.x, c.y + h * 0.33), s * 0.075, mark);
    resp
}

/// 512 -> "512 B", 1536 -> "1.5 KB", 157286400 -> "150 MB".
fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["KB", "MB", "GB", "TB", "PB"];
    if n < 1024 {
        return format!("{} B", n);
    }
    let mut v = n as f64 / 1024.0;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 {
        format!("{:.0} {}", v, UNITS[i])
    } else {
        format!("{:.1} {}", v, UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn key(local: &str, remote: &str) -> FlowKey {
        FlowKey {
            proto: Proto::Udp,
            local: local.parse::<SocketAddr>().unwrap(),
            remote: remote.parse::<SocketAddr>().unwrap(),
        }
    }

    #[test]
    fn background_noise() {
        assert!(is_noise(&key("10.0.0.2:5353", "224.0.0.251:5353")));
        assert!(is_noise(&key("10.0.0.2:61000", "239.255.255.250:1900")));
        assert!(is_noise(&key("10.0.0.2:137", "10.0.0.255:137")));
        assert!(is_noise(&key("10.0.0.2:61000", "255.255.255.255:67")));
        assert!(is_noise(&key("[fe80::1]:61000", "[ff02::1:3]:5355")));
        assert!(!is_noise(&key("10.0.0.2:61000", "1.1.1.1:443")));
        assert!(!is_noise(&key("10.0.0.2:61000", "198.18.0.17:80")));
        // A local proxy is never noise, whatever its port.
        assert!(!is_noise(&key("127.0.0.1:50123", "127.0.0.1:10808")));
        assert!(!is_noise(&key("127.0.0.1:61000", "127.0.0.1:5353")));
    }

    const ME: &str = "S-1-5-21-1-2-3-1001";

    /// services(SYSTEM) -> svchost, esrv_svc; explorer(user) -> pwsh -> curl; explorer ->
    /// WINWORD, xray. Word goes through xray's local proxy; esrv_svc talks to itself.
    fn fixture() -> (Snapshot, Vec<Arc<crate::process::Process>>) {
        use crate::dns::Dns;
        use crate::filter::Filter;
        use crate::model::Attribution;
        use crate::process::query::UserInfo;
        use crate::process::services::ServiceMap;
        use crate::process::{ProcessTable, Seed};
        use snapshot::{finish_rows, TreeBuilder};

        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let mut t = ProcessTable::new(Filter::default(), tx);
        let mut spawn = |pid, ppid, create_time, session_id, name: &str, sid: &str| {
            let p = t.insert(Seed {
                pid,
                ppid,
                create_time,
                session_id,
                name: name.into(),
                path: format!("C:\\Apps\\{}", name),
                attribution: Attribution::Exact,
                exit_time: None,
            });
            let _ = p.user.set(Some(UserInfo {
                sid: sid.into(),
                account: None,
            }));
            p
        };
        let procs = vec![
            spawn(10, 1, 100, 0, "services.exe", "S-1-5-18"),
            spawn(11, 10, 110, 0, "svchost.exe", "S-1-5-18"),
            spawn(12, 10, 120, 0, "esrv_svc.exe", "S-1-5-18"),
            spawn(20, 1, 200, 1, "explorer.exe", ME),
            spawn(21, 20, 210, 1, "pwsh.exe", ME),
            spawn(30, 21, 300, 1, "curl.exe", ME),
            spawn(40, 20, 400, 1, "WINWORD.EXE", ME),
            spawn(50, 20, 500, 1, "xray.exe", ME),
        ];
        let by = |name: &str| procs.iter().find(|p| p.name == name).unwrap().clone();
        let enr = Enricher {
            dns: Dns::new(false, 0),
            services: Arc::new(ServiceMap::default()),
        };
        // curl resolved a fake-IP answer through a TUN proxy.
        enr.dns
            .observe_answer(30, "Example.COM.", &["198.18.0.17".parse().unwrap()]);
        let tcp = |l: &str, r: &str| FlowKey {
            proto: Proto::Tcp,
            ..key(l, r)
        };
        let mut b = TreeBuilder::new(Some(ME));
        for p in &procs {
            b.add(p.clone(), &enr);
        }
        let mut conns = vec![
            b.conn(
                &enr,
                by("curl.exe"),
                tcp("10.0.0.2:50000", "198.18.0.17:443"),
            ),
            b.conn(
                &enr,
                by("WINWORD.EXE"),
                tcp("10.0.0.2:50001", "52.109.8.21:443"),
            ),
            b.conn(
                &enr,
                by("pwsh.exe"),
                key("10.0.0.2:5353", "224.0.0.251:5353"),
            ),
            b.conn(
                &enr,
                by("WINWORD.EXE"),
                tcp("127.0.0.1:50123", "127.0.0.1:10808"),
            ),
            b.conn(
                &enr,
                by("xray.exe"),
                tcp("127.0.0.1:10808", "127.0.0.1:50123"),
            ),
            b.conn(
                &enr,
                by("esrv_svc.exe"),
                tcp("127.0.0.1:49350", "127.0.0.1:44253"),
            ),
            b.conn(
                &enr,
                by("esrv_svc.exe"),
                tcp("127.0.0.1:44253", "127.0.0.1:49350"),
            ),
            b.conn(
                &enr,
                by("svchost.exe"),
                tcp("10.0.0.2:50002", "20.1.1.1:443"),
            ),
        ];
        for (c, tx) in conns.iter_mut().zip([10, 500, 1, 7, 7, 3, 3, 40]) {
            c.tx = tx;
        }
        finish_rows(&mut conns);
        let (nodes, roots, preorder, index) = b.finish();
        let snap = Snapshot {
            seq: 1,
            conns,
            procs: nodes,
            roots,
            preorder,
            index,
            ..Default::default()
        };
        (snap, procs)
    }

    fn view() -> RowsKey {
        RowsKey {
            seq: 1,
            hide_noise: true,
            scope: Scope::All,
            selected: None,
            filters_version: 0,
            sort: Col::Process,
            descending: false,
        }
    }

    const COUNTED: Counting = Counting {
        etw: true,
        tcp: true,
    };

    fn rows(snap: &Snapshot, k: RowsKey) -> Vec<String> {
        filtered(snap, k, &ColumnFilters::default())
    }

    fn filtered(snap: &Snapshot, k: RowsKey, filters: &ColumnFilters) -> Vec<String> {
        filter_rows(snap, &k, filters, COUNTED)
            .into_iter()
            .map(|i| {
                let c = &snap.conns[i];
                format!("{} {}", c.proc.name, c.remote)
            })
            .collect()
    }

    #[test]
    fn table_filters_noise_scope_selection_and_sort() {
        let (snap, procs) = fixture();
        // Noise: mDNS and esrv_svc's self-loopback hidden; Word -> xray proxy loopback kept.
        let all = rows(&snap, view());
        assert_eq!(
            all,
            [
                "curl.exe 198.18.0.17:443",
                "svchost.exe 20.1.1.1:443",
                "WINWORD.EXE 52.109.8.21:443",
                "WINWORD.EXE 127.0.0.1:10808",
                "xray.exe 127.0.0.1:50123",
            ]
        );
        let noisy = RowsKey {
            hide_noise: false,
            ..view()
        };
        assert_eq!(rows(&snap, noisy).len(), 8);
        // Scope: by the account each process runs as.
        let user = RowsKey {
            scope: Scope::User,
            ..view()
        };
        assert_eq!(rows(&snap, user).len(), 4);
        let system = RowsKey {
            scope: Scope::System,
            ..view()
        };
        assert_eq!(rows(&snap, system), ["svchost.exe 20.1.1.1:443"]);
        // Column search boxes: domain, part of the remote address, the loopback peer.
        let search = |col: Col, text: &str| {
            let mut filters = ColumnFilters::default();
            filters[column_index(col)].text = text.into();
            filtered(&snap, view(), &filters)
        };
        assert_eq!(search(Col::Domain, "example"), ["curl.exe 198.18.0.17:443"]);
        assert_eq!(search(Col::Remote, "198.18"), ["curl.exe 198.18.0.17:443"]);
        assert_eq!(search(Col::Remote, ":443").len(), 3);
        assert_eq!(search(Col::Domain, "xray"), ["WINWORD.EXE 127.0.0.1:10808"]);
        // ... in both directions: Word is the far end of the proxy's accepted socket.
        assert_eq!(search(Col::Domain, "winword"), ["xray.exe 127.0.0.1:50123"]);
        // Selecting pwsh scopes the table to pwsh and its child curl.
        let pwsh = procs.iter().find(|p| p.name == "pwsh.exe").unwrap();
        let selected = RowsKey {
            selected: Some(ident(pwsh)),
            ..view()
        };
        assert_eq!(rows(&snap, selected), ["curl.exe 198.18.0.17:443"]);
        let by_sent = RowsKey {
            sort: Col::Sent,
            descending: true,
            ..view()
        };
        assert_eq!(rows(&snap, by_sent)[0], "WINWORD.EXE 52.109.8.21:443");
        let word_proxy = snap
            .conns
            .iter()
            .find(|c| c.remote == "127.0.0.1:10808")
            .unwrap();
        assert_eq!(word_proxy.state, STATE_PROXY);
        assert_eq!(
            word_proxy.link.as_ref().unwrap().label(),
            "via xray.exe (50)"
        );
    }

    #[test]
    fn column_filters_combine_and_lists_follow_the_other_columns() {
        let (mut snap, _) = fixture();
        // The fixture's connected rows carry no TCP state; give them one.
        for c in snap.conns.iter_mut().filter(|c| c.state.is_empty()) {
            c.state = "ESTABLISHED";
        }
        let idx = column_index;
        let mut filters = ColumnFilters::default();
        // State: untick PROXY/LOCAL and LOCAL/IN, the loopback pair.
        filters[idx(Col::State)].pick.set(STATE_PROXY, false);
        filters[idx(Col::State)].pick.set(STATE_LOCAL_IN, false);
        assert_eq!(
            filtered(&snap, view(), &filters),
            [
                "curl.exe 198.18.0.17:443",
                "svchost.exe 20.1.1.1:443",
                "WINWORD.EXE 52.109.8.21:443"
            ]
        );
        // And a Domain search on top (AND across columns; empty domains do not match).
        filters[idx(Col::Domain)].text = "EXAMPLE".into();
        assert_eq!(
            filtered(&snap, view(), &filters),
            ["curl.exe 198.18.0.17:443"]
        );
        // Only UDP4: the mDNS row, which also needs noise shown, and no State restriction.
        let mut udp = ColumnFilters::default();
        udp[idx(Col::Proto)].pick = autofilter::Pick::Only(["UDP4".to_string()].into());
        assert!(filtered(&snap, view(), &udp).is_empty());
        let noisy = RowsKey {
            hide_noise: false,
            ..view()
        };
        assert_eq!(filtered(&snap, noisy, &udp), ["pwsh.exe 224.0.0.251:5353"]);

        // A column's value list ignores its own filter but follows the others'.
        let mut filters = ColumnFilters::default();
        filters[idx(Col::Process)].pick =
            autofilter::Pick::Only(["WINWORD.EXE".to_string()].into());
        filters[idx(Col::State)].pick.set("ESTABLISHED", false);
        let k = view();
        let values = |i: usize| {
            let rows = shown_rows(&snap, &k, &filters, COUNTED, Some(i));
            autofilter::tally(
                rows.into_iter()
                    .map(|r| cell_text(&snap.conns[r], COLUMNS[i].0, true)),
                false,
            )
        };
        assert_eq!(
            values(idx(Col::State)),
            [("ESTABLISHED".to_string(), 1), (STATE_PROXY.to_string(), 1)]
        );
        // Process list: every process still showing once ESTABLISHED is unticked.
        let procs: Vec<String> = values(idx(Col::Process))
            .into_iter()
            .map(|(v, _)| v)
            .collect();
        assert_eq!(procs, ["WINWORD.EXE", "xray.exe"]);
    }

    #[test]
    fn tree_prunes_by_search_scope_and_connections() {
        let (snap, _) = fixture();
        let shown = |query: &str, scope: Scope, network_only: bool| -> Vec<String> {
            let matches: Vec<bool> = snap
                .procs
                .iter()
                .map(|n| !query.is_empty() && proc_matches(n, query))
                .collect();
            let mut own_rows = vec![0u32; snap.procs.len()];
            for c in snap.conns.iter().filter(|c| !row_is_noise(c)) {
                own_rows[c.node] += 1;
            }
            let visible = tree_visibility(
                &snap,
                &matches,
                !query.is_empty(),
                scope,
                network_only,
                &own_rows,
            );
            snap.preorder
                .iter()
                .filter(|&&i| visible[i])
                .map(|&i| snap.procs[i].proc.name.clone())
                .collect()
        };
        assert_eq!(shown("", Scope::All, false).len(), 8);
        // A match keeps its ancestors (context) and its descendants.
        assert_eq!(
            shown("pwsh", Scope::All, false),
            ["explorer.exe", "pwsh.exe", "curl.exe"]
        );
        assert_eq!(
            shown("30", Scope::All, false),
            ["explorer.exe", "pwsh.exe", "curl.exe"]
        );
        assert!(shown("nothing-like-this", Scope::All, false).is_empty());
        assert_eq!(
            shown("", Scope::System, false),
            ["services.exe", "svchost.exe", "esrv_svc.exe"]
        );
        // Only with connections: esrv_svc's only rows are self-loopback noise.
        assert_eq!(
            shown("", Scope::System, true),
            ["services.exe", "svchost.exe"]
        );
        assert_eq!(
            shown("", Scope::User, true),
            [
                "explorer.exe",
                "pwsh.exe",
                "curl.exe",
                "WINWORD.EXE",
                "xray.exe"
            ]
        );
    }

    #[test]
    fn accounts_from_token_or_session() {
        use crate::filter::Filter;
        use crate::model::Attribution;
        use crate::process::query::UserInfo;
        use crate::process::{ProcessTable, Seed};
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let mut t = ProcessTable::new(Filter::default(), tx);
        let mut make = |pid: u32, session_id, sid: Option<Option<&str>>| {
            let p = t.insert(Seed {
                pid,
                ppid: 1,
                create_time: pid as u64,
                session_id,
                name: "x.exe".into(),
                path: String::new(),
                attribution: Attribution::Exact,
                exit_time: None,
            });
            if let Some(sid) = sid {
                let _ = p.user.set(sid.map(|s| UserInfo {
                    sid: s.into(),
                    account: None,
                }));
            }
            p
        };
        let of = |p: &crate::process::Process| Account::of(p, Some(ME));
        assert_eq!(of(&make(1, 1, Some(Some(ME)))), Account::User);
        assert_eq!(of(&make(2, 0, Some(Some("S-1-5-19")))), Account::System);
        assert_eq!(
            of(&make(3, 0, Some(Some("S-1-5-80-123-456")))),
            Account::System
        );
        assert_eq!(
            of(&make(4, 2, Some(Some("S-1-5-21-9-9-9-1002")))),
            Account::Other
        );
        // Token unreadable: a live system process (csrss in the user's session, say).
        assert_eq!(of(&make(5, 1, Some(None))), Account::System);
        // Not looked up yet: decided by the session.
        assert_eq!(of(&make(6, 0, None)), Account::System);
        assert_eq!(of(&make(7, 1, None)), Account::User);
        // Exited before its token could be read: the session again, not "system".
        let gone = make(8, 1, Some(None));
        gone.mark_exited(100);
        assert_eq!(of(&gone), Account::User);
    }

    #[test]
    fn public_addresses_for_lookup() {
        for ip in ["8.8.8.8", "52.109.8.21", "198.20.0.1", "2620:1ec:bdf::14"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "10.0.0.1",
            "192.168.0.5",
            "172.18.0.1",
            "100.64.0.1",
            "198.18.0.17",
            "198.19.255.1",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.251",
            "::1",
            "fe80::1",
            "fd00::1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        assert_eq!(
            virustotal_ip("8.8.8.8".parse().unwrap()),
            "https://www.virustotal.com/gui/ip-address/8.8.8.8"
        );
    }

    #[test]
    fn unsigned_images_with_internet_connections_are_flagged() {
        let (snap, procs) = fixture();
        let by = |name: &str| procs.iter().find(|p| p.name == name).unwrap();
        let sign = |name: &str, sig: Signature| by(name).signature.set(Some(sig)).unwrap();
        sign("WINWORD.EXE", Signature::Unsigned);
        sign(
            "svchost.exe",
            Signature::Signed {
                signer: "Microsoft Windows".into(),
                via: Via::Catalog,
            },
        );
        sign("curl.exe", Signature::Unsigned);
        sign(
            "xray.exe",
            Signature::Invalid {
                reason: "the file was modified after it was signed",
                signer: None,
            },
        );
        let counts = row_counts(&snap, true);
        let node = |name: &str| snap.index[&ident(by(name))];
        let flagged = |name: &str| counts.external[node(name)] > 0 && untrusted(by(name)).is_some();
        // Word: unsigned and talking to a public address.
        assert!(flagged("WINWORD.EXE"));
        // svchost talks to the internet too, but is signed.
        assert!(!flagged("svchost.exe"));
        // curl's only peer is a TUN proxy's fake IP; xray (invalid) only talks on loopback.
        assert!(!flagged("curl.exe") && !flagged("xray.exe"));
        assert_eq!(counts.active[node("WINWORD.EXE")], 2);
        // explorer's subtree: curl, Word (2) and xray; pwsh's mDNS is noise.
        assert_eq!(counts.subtree[node("explorer.exe")], 4);
    }

    #[test]
    fn columns_resize_independently_within_limits() {
        // One spec per column, in the order the table draws them.
        let order: Vec<Col> = COLUMNS.iter().map(|&(c, ..)| c).collect();
        assert_eq!(
            order,
            [
                Col::Process,
                Col::Pid,
                Col::Local,
                Col::Remote,
                Col::Domain,
                Col::Proto,
                Col::State,
                Col::Sent,
                Col::Recv
            ]
        );
        for (i, &(col, title, initial, min)) in COLUMNS.iter().enumerate() {
            assert!(
                min > 0.0 && min <= initial && initial <= MAX_COLUMN_WIDTH,
                "{title}"
            );
            assert_eq!(column_index(col), i);
        }
        assert_eq!(
            default_column_widths(),
            [140.0, 65.0, 150.0, 150.0, 200.0, 60.0, 90.0, 75.0, 75.0]
        );
        // Fitting adds a little room and stays within the column's limits.
        assert_eq!(fit(100.0, 60.0), 100.0 + FIT_PADDING);
        assert_eq!(fit(100.2, 60.0), (100.2 + FIT_PADDING).ceil());
        assert_eq!(fit(10.0, 60.0), 60.0);
        assert_eq!(fit(5000.0, 60.0), MAX_COLUMN_WIDTH);
    }

    #[test]
    fn cell_text_is_what_the_table_shows() {
        let (snap, _) = fixture();
        let row = |remote: &str| snap.conns.iter().find(|c| c.remote == remote).unwrap();
        let word = row("52.109.8.21:443");
        let text = |c: &Conn, col| cell_text(c, col, true);
        assert_eq!(text(word, Col::Process), "WINWORD.EXE");
        assert_eq!(text(word, Col::Pid), "40");
        assert_eq!(text(word, Col::Local), "10.0.0.2:50001");
        assert_eq!(text(word, Col::Proto), "TCP4");
        assert_eq!(text(word, Col::Sent), "500 B");
        assert_eq!(cell_text(word, Col::Sent, false), "—");
        // Loopback rows show the peer process; resolved rows the domain.
        assert_eq!(
            text(row("127.0.0.1:10808"), Col::Domain),
            "via xray.exe (50)"
        );
        assert_eq!(text(row("127.0.0.1:10808"), Col::State), STATE_PROXY);
        assert_eq!(text(row("198.18.0.17:443"), Col::Domain), "example.com");
    }

    #[test]
    fn window_icon_and_file_report_url() {
        let icon = window_icon();
        assert_eq!((icon.width, icon.height), (256, 256));
        assert_eq!(icon.rgba.len(), 256 * 256 * 4);
        assert_eq!(
            virustotal_file("e3b0c442"),
            "https://www.virustotal.com/gui/file/e3b0c442"
        );
    }

    #[test]
    fn byte_formatting() {
        assert_eq!(fmt_bytes(0), "0 B");
        assert_eq!(fmt_bytes(1023), "1023 B");
        assert_eq!(fmt_bytes(1536), "1.5 KB");
        assert_eq!(fmt_bytes(150 * 1024 * 1024), "150 MB");
        assert_eq!(fmt_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }
}
