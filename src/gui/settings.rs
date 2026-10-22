//! Settings that survive restarts, kept in eframe's persistence store: window position, size and
//! maximized state (eframe itself), egui's memory (the process panel's width), and the toggles,
//! scope and table column widths below.
//!
//! The store is `%APPDATA%\netattrib\data\app.ron`. Portable mode, as in System Informer: when
//! a file named [`PORTABLE_FILE`] exists next to the executable (an empty one will do), settings
//! are read from and written to it instead, and nothing goes to the profile.

use std::path::{Path, PathBuf};

use eframe::Storage;

use super::{ColumnWidths, Scope, COLUMNS, MAX_COLUMN_WIDTH};

pub const PORTABLE_FILE: &str = "netattrib.settings.ron";
/// eframe's app id: names the default store's directory.
pub const APP_ID: &str = "netattrib";

const KEY_HIDE_NOISE: &str = "netattrib.hide_noise";
const KEY_KEEP_HISTORY: &str = "netattrib.keep_history";
const KEY_NETWORK_ONLY: &str = "netattrib.network_only";
const KEY_SCOPE: &str = "netattrib.scope";
/// Comma-separated pixel widths, in table column order.
const KEY_COLUMN_WIDTHS: &str = "netattrib.column_widths";

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Settings {
    pub hide_noise: bool,
    pub keep_history: bool,
    pub network_only: bool,
    pub scope: Scope,
    pub column_widths: ColumnWidths,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            hide_noise: true,
            keep_history: super::KEEP_HISTORY,
            network_only: false,
            scope: Scope::All,
            column_widths: super::default_column_widths(),
        }
    }
}

impl Settings {
    /// Missing or unreadable values keep their defaults.
    pub fn load(storage: Option<&dyn Storage>) -> Self {
        let mut s = Settings::default();
        let Some(st) = storage else {
            return s;
        };
        let flag = |key: &str, default: bool| match st.get_string(key).as_deref() {
            Some("true") => true,
            Some("false") => false,
            _ => default,
        };
        s.hide_noise = flag(KEY_HIDE_NOISE, s.hide_noise);
        s.keep_history = flag(KEY_KEEP_HISTORY, s.keep_history);
        s.network_only = flag(KEY_NETWORK_ONLY, s.network_only);
        s.scope = match st.get_string(KEY_SCOPE).as_deref() {
            Some("user") => Scope::User,
            Some("system") => Scope::System,
            _ => Scope::All,
        };
        if let Some(widths) = st
            .get_string(KEY_COLUMN_WIDTHS)
            .and_then(|v| parse_widths(&v))
        {
            s.column_widths = widths;
        }
        s
    }

    pub fn save(&self, st: &mut dyn Storage) {
        st.set_string(KEY_HIDE_NOISE, self.hide_noise.to_string());
        st.set_string(KEY_KEEP_HISTORY, self.keep_history.to_string());
        st.set_string(KEY_NETWORK_ONLY, self.network_only.to_string());
        let scope = match self.scope {
            Scope::All => "all",
            Scope::User => "user",
            Scope::System => "system",
        };
        st.set_string(KEY_SCOPE, scope.into());
        let widths: Vec<String> = self
            .column_widths
            .iter()
            .map(|w| format!("{:.0}", w))
            .collect();
        st.set_string(KEY_COLUMN_WIDTHS, widths.join(","));
    }
}

/// One width per column, each kept within that column's limits; anything else (a different
/// column count from another version, text) is rejected as a whole.
fn parse_widths(v: &str) -> Option<ColumnWidths> {
    let parsed: Vec<f32> = v
        .split(',')
        .map(|w| w.trim().parse::<f32>().ok().filter(|w| w.is_finite()))
        .collect::<Option<_>>()?;
    let mut widths: ColumnWidths = parsed.try_into().ok()?;
    for (w, &(_, _, _, min)) in widths.iter_mut().zip(&COLUMNS) {
        *w = w.clamp(min, MAX_COLUMN_WIDTH);
    }
    Some(widths)
}

/// `netattrib.settings.ron` beside the executable, when it exists.
pub fn portable_file() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    portable_file_in(exe.parent()?)
}

fn portable_file_in(dir: &Path) -> Option<PathBuf> {
    let f = dir.join(PORTABLE_FILE);
    f.is_file().then_some(f)
}

/// Where settings are kept: the portable file, else eframe's default for this app id.
pub fn location(portable: Option<&Path>) -> Option<PathBuf> {
    portable
        .map(Path::to_path_buf)
        .or_else(|| eframe::storage_dir(APP_ID).map(|d| d.join("app.ron")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Memory(HashMap<String, String>);

    impl Storage for Memory {
        fn get_string(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
        fn set_string(&mut self, key: &str, value: String) {
            self.0.insert(key.into(), value);
        }
        fn remove_string(&mut self, key: &str) {
            self.0.remove(key);
        }
        fn flush(&mut self) {}
    }

    #[test]
    fn settings_round_trip_and_defaults() {
        // Nothing stored yet, or no storage at all: defaults.
        assert_eq!(Settings::load(None), Settings::default());
        let mut st = Memory::default();
        assert_eq!(Settings::load(Some(&st)), Settings::default());

        let changed = Settings {
            hide_noise: false,
            keep_history: false,
            network_only: true,
            scope: Scope::System,
            column_widths: [210.0, 50.0, 120.0, 260.0, 90.0, 40.0, 100.0, 60.0, 61.0],
        };
        changed.save(&mut st);
        assert_eq!(Settings::load(Some(&st)), changed);
        assert_eq!(st.0[KEY_SCOPE], "system");
        assert_eq!(st.0[KEY_COLUMN_WIDTHS], "210,50,120,260,90,40,100,60,61");

        // A hand-edited or damaged value falls back to its default; the rest still load.
        st.0.insert(KEY_HIDE_NOISE.into(), "maybe".into());
        st.0.insert(KEY_SCOPE.into(), "everyone".into());
        let loaded = Settings::load(Some(&st));
        assert!(loaded.hide_noise && loaded.network_only);
        assert_eq!(loaded.scope, Scope::All);
        assert_eq!(loaded.column_widths, changed.column_widths);
    }

    #[test]
    fn column_widths_are_validated() {
        let defaults = crate::gui::default_column_widths();
        // Too few or too many columns, or text: all defaults.
        assert_eq!(parse_widths("100,100"), None);
        assert_eq!(parse_widths(&["100"; 10].join(",")), None);
        assert_eq!(parse_widths("1,2,3,4,x,6,7,8,9"), None);
        assert_eq!(parse_widths("1,2,3,4,NaN,6,7,8,9"), None);
        // Each width is held within its column's limits.
        let w = parse_widths("1,2,3,4,5,6,7,8,99999").unwrap();
        for (i, &(_, title, _, min)) in COLUMNS.iter().enumerate().take(8) {
            assert_eq!(w[i], min, "{title}");
        }
        assert_eq!(w[8], MAX_COLUMN_WIDTH);
        let mut st = Memory::default();
        st.0.insert(KEY_COLUMN_WIDTHS.into(), "garbage".into());
        assert_eq!(Settings::load(Some(&st)).column_widths, defaults);
    }

    #[test]
    fn portable_file_beside_the_executable() {
        let dir = std::env::temp_dir().join(format!("netattrib-portable-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(portable_file_in(&dir), None);
        assert!(location(None).unwrap().ends_with(r"netattrib\data\app.ron"));
        std::fs::write(dir.join(PORTABLE_FILE), "").unwrap();
        let found = portable_file_in(&dir).expect("portable file");
        assert_eq!(location(Some(&found)), Some(dir.join(PORTABLE_FILE)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
