//! The final cut over the settled views, after every applicable shed rank.

use super::frame::{BoardPart, BoardSection, SectionView, ShedSection};
use std::collections::BTreeSet;

#[derive(Clone, Copy)]
pub(super) struct CutBudget {
    cap_tok: usize,
    reserved_tok: usize,
}

/// What the final cut took.
#[derive(Default)]
pub(super) struct KeyframeCut {
    /// The rendered lines cut.
    pub(super) rows: usize,
    /// The typed rows cut: each shown before the cut and shown by no
    /// section after it, once, in frame order.
    pub(super) ids: Vec<crate::EntityId>,
}

impl CutBudget {
    pub(super) fn new(cap_tok: usize, reserved_tok: usize) -> Self {
        Self {
            cap_tok,
            reserved_tok,
        }
    }

    pub(super) fn over_cap(self, rendered_tok: usize) -> bool {
        self.cap_tok
            .checked_sub(self.reserved_tok)
            .is_none_or(|available| rendered_tok > available)
    }

    /// Cuts settled rows from the end of the render until it fits, and
    /// returns what it cut. Each step takes one typed row whole, with every
    /// line it rendered as, so no row is left half shown. Only rows below
    /// each section's pinned floor are cut, and none of a pinned section: a
    /// pinned row is never budget-shed (ARCH-0067:48), so a board whose
    /// pinned rows alone are over the cap renders them in full and stays
    /// over it. The fewest fitting steps are found run by run (see the
    /// search below) in O(sections + log n) renders.
    pub(super) fn trim(
        self,
        sections: &[BoardSection],
        parts: &[BoardPart],
        views: &mut [ShedSection],
        rendered_tok: &mut usize,
        mut render: impl FnMut(&[ShedSection], &str) -> usize,
    ) -> KeyframeCut {
        if !self.over_cap(*rendered_tok) {
            return KeyframeCut::default();
        }
        let order = render_order(sections, parts);
        let steps = cut_steps(sections, &order, views);
        if steps.is_empty() {
            return KeyframeCut::default();
        }
        let settled: Vec<Vec<String>> = views.iter().map(|view| view.rows.clone()).collect();
        let cap_tok = self.cap_tok;
        let mut probe = |views: &mut [ShedSection], taken: usize| -> (usize, usize) {
            for (view, rows) in views.iter_mut().zip(&settled) {
                view.rows.clone_from(rows);
            }
            for &(index, kept) in &steps[..taken] {
                views[index].rows.truncate(kept);
            }
            let mut cut_rows = 0;
            let mut seen = BTreeSet::new();
            let mut names = Vec::new();
            for &index in &order {
                let cut = settled[index].len() - views[index].rows.len();
                cut_rows += cut;
                let name = sections[index].name();
                if cut > 0 && seen.insert(name) {
                    names.push(name);
                }
            }
            let mark = cut_mark(cut_rows, &names, cap_tok);
            (cut_rows, render(&*views, &mark))
        };
        // The fewest steps whose render fits; every step when none does. The
        // render is not monotone in the step count: the step that first cuts
        // a section adds that section's name to the mark, which can cost
        // more than the row it removed, and a later section's first step can
        // bring the render back under the cap. Within one section's run of
        // steps the mark names the same sections, and each step removes a
        // whole row while the count in the mark gains at most a digit, so
        // the render does not grow there. Each run is therefore tried in cut
        // order by its last step: the first run that fits holds the fewest
        // fitting steps, found by a binary search inside it.
        let mut taken = steps.len();
        let mut start = 0;
        while start < steps.len() {
            let section = steps[start].0;
            let run = steps[start..]
                .iter()
                .take_while(|&&(index, _)| index == section)
                .count();
            let end = start + run;
            let (_, tok) = probe(&mut *views, end);
            if !self.over_cap(tok) {
                let (mut low, mut high) = (start + 1, end);
                while low < high {
                    let mid = low + (high - low) / 2;
                    let (_, tok) = probe(&mut *views, mid);
                    if self.over_cap(tok) {
                        low = mid + 1;
                    } else {
                        high = mid;
                    }
                }
                taken = low;
                break;
            }
            start = end;
        }
        // The chosen count is probed last, so its text is the one kept.
        let (cut_rows, tok) = probe(&mut *views, taken);
        *rendered_tok = tok;
        let mut cut_ids = Vec::new();
        for ((section, view), rows) in sections.iter().zip(views.iter_mut()).zip(&settled) {
            let cut = view.rows.len() < rows.len();
            // What the section showed before the cut, read the same way.
            let before = cut.then(|| {
                let mut whole = view.clone();
                whole.rows.clone_from(rows);
                retain_shown_ids(section, &mut whole);
                whole.shown_ids.unwrap_or_default()
            });
            if cut || !section.pinned_row_ids.is_empty() {
                retain_shown_ids(section, view);
            }
            if let Some(before) = before {
                let after = view.shown_ids.as_deref().unwrap_or_default();
                cut_ids.extend(before.into_iter().filter(|id| !after.contains(id)));
            }
        }
        // A row another section still shows was not taken.
        let still_shown: BTreeSet<_> = views
            .iter()
            .flat_map(|view| view.shown_ids.iter().flatten().copied())
            .collect();
        let mut seen = BTreeSet::new();
        cut_ids.retain(|id| !still_shown.contains(id) && seen.insert(*id));
        KeyframeCut {
            rows: cut_rows,
            ids: cut_ids,
        }
    }
}

/// Section indices in render order: the state part (or the whole unsplit
/// frame) before the query part, and within each part memory before guest
/// evidence, each in frame order.
fn render_order(sections: &[BoardSection], parts: &[BoardPart]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..sections.len()).collect();
    order.sort_by_key(|&index| {
        (
            parts.get(index) == Some(&BoardPart::Query),
            sections[index].foreign_host.is_some(),
        )
    });
    order
}

/// The cut order: every row below a section's pinned floor, across all
/// sections, last rendered first; never a pinned row, and no row of a
/// pinned section, which never sheds. Each step is (section index, rows the
/// section keeps after it); one section's steps are consecutive.
fn cut_steps(
    sections: &[BoardSection],
    order: &[usize],
    views: &[ShedSection],
) -> Vec<(usize, usize)> {
    let mut steps = Vec::new();
    for &index in order.iter().rev() {
        if sections[index].policy().pinned {
            continue;
        }
        let ids = line_ids(&sections[index], &views[index]);
        let id_at = |line: usize| ids.get(line).copied().flatten();
        let mut kept = views[index].rows.len();
        let floor = sections[index].pinned_rows().len().min(kept);
        while kept > floor {
            kept -= 1;
            if let Some(id) = id_at(kept) {
                while kept > floor && id_at(kept - 1) == Some(id) {
                    kept -= 1;
                }
            }
            steps.push((index, kept));
        }
    }
    steps
}

/// The typed id behind each settled line of `view`, where its producer
/// knows one: the pinned floor's leading producer pins, then a full view's
/// detail rows. A count row or a discovery hint has none.
fn line_ids(section: &BoardSection, view: &ShedSection) -> Vec<Option<crate::EntityId>> {
    let mut ids = section.pinned_row_ids.clone();
    ids.resize(section.pinned_rows().len(), None);
    if view.view == SectionView::Full && section.row_ids.len() == section.detail_rows().len() {
        ids.extend(section.row_ids.iter().copied());
    }
    ids
}

/// The one mark line: `names` are the cut sections in render order, each once.
fn cut_mark(cut_rows: usize, names: &[&str], cap_tok: usize) -> String {
    let first = names[0];
    let names = names.join(", ");
    format!(
        "cut for size: {cut_rows} rows of {names} (budget_tok {cap_tok}); describe({{ key: \"{first}\" }}) shows a section in full"
    )
}

fn retain_shown_ids(section: &BoardSection, view: &mut ShedSection) {
    let pinned_len = section.pinned_rows().len();
    let pinned_kept = view.rows.len().min(pinned_len);
    let detail_kept = if view.view == SectionView::Full {
        view.rows
            .len()
            .saturating_sub(pinned_len)
            .min(section.row_ids.len())
    } else {
        0
    };
    let pinned_ids = &section.pinned_row_ids;
    let pinned_id_count = pinned_kept.min(pinned_ids.len());
    // A typed row split across multiple lines was not shown in full if any
    // of its lines were cut. The layout's kept ids have no per-line map.
    let mut not_shown: BTreeSet<_> = pinned_ids[pinned_id_count..]
        .iter()
        .flatten()
        .copied()
        .collect();
    if view.view == SectionView::Full {
        not_shown.extend(section.row_ids[detail_kept..].iter().flatten().copied());
    }
    if pinned_kept < pinned_len {
        not_shown.extend(section.kept_ids.iter().copied());
    }
    let layout_allows =
        |&id: &&crate::EntityId| view.shown_ids.as_ref().is_none_or(|ids| ids.contains(id));
    let mut seen = BTreeSet::new();
    let shown = pinned_ids[..pinned_id_count]
        .iter()
        .flatten()
        .chain(section.kept_ids.iter().filter(&layout_allows))
        .chain(
            section.row_ids[..detail_kept]
                .iter()
                .flatten()
                .filter(&layout_allows),
        )
        .filter(|&&id| !not_shown.contains(&id) && seen.insert(id))
        .copied()
        .collect();
    view.shown_ids = Some(shown);
}
