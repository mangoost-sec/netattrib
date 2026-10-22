//! Excel-style AutoFilter. Every column header has a filter button that opens a popup with a
//! search box (a case-insensitive substring of the cell text) and the column's distinct values
//! with their row counts, to tick or untick. Filters on several columns combine (AND), and with
//! "Hide background noise", the scope and the tree selection; they last for the session.

use std::collections::{HashMap, HashSet};

use eframe::egui::{self, Align, Color32, Layout, RichText, Sense};

/// Which of a column's values pass. The table is live, so the choice also decides what happens
/// to values that appear later: after *unticking* a few (`Except`), new values show up as usual;
/// after ticking only some (`Only`), nothing else does. `(Select All)` returns to `All`.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Pick {
    #[default]
    All,
    /// Only these values (empty: none).
    Only(HashSet<String>),
    /// Every value but these (never empty: that is `All`).
    Except(HashSet<String>),
}

impl Pick {
    pub fn admits(&self, value: &str) -> bool {
        match self {
            Pick::All => true,
            Pick::Only(set) => set.contains(value),
            Pick::Except(set) => !set.contains(value),
        }
    }

    /// Ticks (`on`) or unticks one value.
    pub fn set(&mut self, value: &str, on: bool) {
        match self {
            Pick::All if !on => *self = Pick::Except(HashSet::from([value.to_string()])),
            Pick::All => {}
            Pick::Only(set) => {
                if on {
                    set.insert(value.to_string());
                } else {
                    set.remove(value);
                }
            }
            Pick::Except(set) => {
                if on {
                    set.remove(value);
                } else {
                    set.insert(value.to_string());
                }
                if set.is_empty() {
                    *self = Pick::All;
                }
            }
        }
    }
}

/// The AutoFilter of one column. The default lets everything through.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ColumnFilter {
    /// Case-insensitive substring of the cell text (blank: any).
    pub text: String,
    pub pick: Pick,
}

impl ColumnFilter {
    pub fn is_active(&self) -> bool {
        !self.text.trim().is_empty() || self.pick != Pick::All
    }

    /// `cell` is the text the table shows in this column.
    pub fn admits(&self, cell: &str) -> bool {
        let q = self.text.trim();
        (q.is_empty() || cell.to_lowercase().contains(&q.to_lowercase())) && self.pick.admits(cell)
    }
}

/// Distinct cell texts with how many rows show each. Numbers sort numerically, the rest
/// alphabetically (case-insensitive); empty cells, listed as `(Blanks)`, come last.
pub fn tally(cells: impl Iterator<Item = String>, numeric: bool) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for c in cells {
        *counts.entry(c).or_default() += 1;
    }
    let mut values: Vec<(String, usize)> = counts.into_iter().collect();
    values.sort_by(|(a, _), (b, _)| {
        a.is_empty().cmp(&b.is_empty()).then_with(|| {
            match (numeric, a.parse::<u64>(), b.parse::<u64>()) {
                (true, Ok(x), Ok(y)) => x.cmp(&y),
                _ => a
                    .to_lowercase()
                    .cmp(&b.to_lowercase())
                    .then_with(|| a.cmp(b)),
            }
        })
    });
    values
}

fn value_label(v: &str) -> &str {
    if v.is_empty() {
        "(Blanks)"
    } else {
        v
    }
}

/// The highlight of a filtered column's button.
pub fn accent(v: &egui::Visuals) -> Color32 {
    if v.dark_mode {
        Color32::from_rgb(80, 200, 255)
    } else {
        Color32::from_rgb(0, 115, 210)
    }
}

/// The filter button: a funnel, neutral gray, or in the accent color while the column is
/// filtered. Painted, like the sort arrows: the default fonts have no funnel glyph.
pub fn button(ui: &mut egui::Ui, rect: egui::Rect, id: egui::Id, active: bool) -> egui::Response {
    let resp = ui
        .interact(rect, id, Sense::click())
        .on_hover_text(if active {
            "Filtered: click to change or clear"
        } else {
            "Filter this column"
        });
    let v = ui.visuals();
    let color = if active {
        accent(v)
    } else if resp.hovered() {
        v.strong_text_color()
    } else {
        v.weak_text_color()
    };
    let painter = ui.painter();
    if resp.hovered() {
        painter.rect_filled(rect.expand(1.0), 2.0, v.widgets.hovered.weak_bg_fill);
    }
    let s = rect.width();
    let (l, r, t, b) = (
        rect.left() + s * 0.1,
        rect.right() - s * 0.1,
        rect.top() + s * 0.15,
        rect.bottom() - s * 0.1,
    );
    let (cx, neck) = (rect.center().x, (s * 0.12).max(1.0));
    let mid = t + (b - t) * 0.5;
    painter.add(egui::Shape::convex_polygon(
        vec![
            egui::pos2(l, t),
            egui::pos2(r, t),
            egui::pos2(cx + neck, mid),
            egui::pos2(cx - neck, mid),
        ],
        color,
        egui::Stroke::NONE,
    ));
    painter.rect_filled(
        egui::Rect::from_min_max(egui::pos2(cx - neck, mid), egui::pos2(cx + neck, b)),
        0.0,
        color,
    );
    resp
}

/// The popup's contents for the column `title`. `values` are the column's distinct values among
/// the rows the other filters leave, with counts; `None` for columns without a useful list
/// (byte counts). Returns true when the filter changed.
pub fn popup(
    ui: &mut egui::Ui,
    title: &str,
    filter: &mut ColumnFilter,
    values: Option<&[(String, usize)]>,
    just_opened: bool,
) -> bool {
    let mut changed = false;
    ui.label(RichText::new(format!("Filter: {}", title)).strong());
    let search = ui.add(
        egui::TextEdit::singleline(&mut filter.text)
            .hint_text("Contains…")
            .desired_width(f32::INFINITY),
    );
    if just_opened {
        search.request_focus();
    }
    changed |= search.changed();

    if let Some(values) = values {
        let q = filter.text.trim().to_lowercase();
        let listed: Vec<&(String, usize)> = values
            .iter()
            .filter(|(v, _)| q.is_empty() || v.to_lowercase().contains(&q))
            .collect();
        ui.separator();
        let all = filter.pick == Pick::All;
        let none = matches!(&filter.pick, Pick::Only(set) if set.is_empty());
        let mut ticked = all;
        // Indeterminate while some values are ticked; a click then selects all, as in Excel.
        if ui
            .add(egui::Checkbox::new(&mut ticked, "(Select All)").indeterminate(!all && !none))
            .changed()
        {
            filter.pick = if ticked {
                Pick::All
            } else {
                Pick::Only(HashSet::new())
            };
            changed = true;
        }
        let row_h = ui.spacing().interact_size.y;
        egui::ScrollArea::vertical()
            .id_salt("values")
            .max_height(row_h * 12.0)
            .auto_shrink([false, true])
            .show_rows(ui, row_h, listed.len(), |ui, range| {
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
                for (value, count) in &listed[range] {
                    let mut on = filter.pick.admits(value);
                    // One fixed-height row: the count on the right, the checkbox in the rest.
                    let row = egui::vec2(ui.available_width(), row_h);
                    let resp = ui
                        .allocate_ui_with_layout(row, Layout::right_to_left(Align::Center), |ui| {
                            ui.weak(count.to_string());
                            let rest = egui::vec2(ui.available_width(), row_h);
                            ui.allocate_ui_with_layout(
                                rest,
                                Layout::left_to_right(Align::Center),
                                |ui| ui.checkbox(&mut on, value_label(value)),
                            )
                            .inner
                        })
                        .inner;
                    if resp.changed() {
                        filter.pick.set(value, on);
                        changed = true;
                    }
                }
            });
        if listed.len() < values.len() {
            ui.weak(format!(
                "{} of {} values match the search",
                listed.len(),
                values.len()
            ));
        }
    }

    ui.separator();
    if ui
        .add_enabled(filter.is_active(), egui::Button::new("Clear Filter"))
        .clicked()
    {
        *filter = ColumnFilter::default();
        changed = true;
        ui.close();
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unticking_keeps_new_values_ticking_only_does_not() {
        let mut p = Pick::All;
        assert!(p.admits("TCP4"));
        // Untick one: everything else, including values not seen yet, still passes.
        p.set("UDP4", false);
        assert_eq!(p, Pick::Except(HashSet::from(["UDP4".to_string()])));
        assert!(!p.admits("UDP4") && p.admits("TCP4") && p.admits("TCP6"));
        // Ticking it again is "all" once more.
        p.set("UDP4", true);
        assert_eq!(p, Pick::All);
        // (Select All) off, then tick one: only that one, new values stay hidden.
        let mut p = Pick::Only(HashSet::new());
        assert!(!p.admits("TCP4"));
        p.set("TCP6", true);
        assert!(p.admits("TCP6") && !p.admits("TCP4"));
        p.set("TCP6", false);
        assert_eq!(p, Pick::Only(HashSet::new()));
        // Ticking an already-ticked value under "all" changes nothing.
        let mut p = Pick::All;
        p.set("TCP4", true);
        assert_eq!(p, Pick::All);
    }

    #[test]
    fn text_and_ticks_combine() {
        let mut f = ColumnFilter::default();
        assert!(!f.is_active() && f.admits("anything"));
        f.text = "  MICROSOFT ".into();
        assert!(f.is_active());
        assert!(f.admits("login.microsoftonline.com") && !f.admits("google.com"));
        f.pick.set("login.microsoftonline.com", false);
        assert!(!f.admits("login.microsoftonline.com") && f.admits("www.microsoft.com"));
        // Blanks are a value like any other.
        let mut f = ColumnFilter::default();
        f.pick.set("", false);
        assert!(!f.admits("") && f.admits("example.com"));
    }

    #[test]
    fn values_are_counted_and_sorted() {
        let cells = ["UDP4", "TCP4", "tcp6", "TCP4", ""].map(String::from);
        assert_eq!(
            tally(cells.into_iter(), false),
            [
                ("TCP4".to_string(), 2),
                ("tcp6".to_string(), 1),
                ("UDP4".to_string(), 1),
                (String::new(), 1)
            ]
        );
        // PIDs as numbers: 9 before 10.
        let pids = ["10", "9", "10"].map(String::from);
        assert_eq!(
            tally(pids.into_iter(), true),
            [("9".to_string(), 1), ("10".to_string(), 2)]
        );
        assert_eq!(value_label(""), "(Blanks)");
    }
}
