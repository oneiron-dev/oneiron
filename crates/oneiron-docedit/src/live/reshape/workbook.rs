//! A rewritten chart's own embedded workbook, edited in place (OF-510, FIX
//! 3493). The rewrite writes only the cells the live series read: each held
//! sequence at its held reference, grown or shrunk from its first cell the
//! way it runs (a shrunk range's tail keeps its cells), and a new series'
//! name and values in the first free cells beside its template's, the
//! chart's categories shared. A cell that already reads as the live data
//! is not written; a written cell keeps its format, and a new one takes
//! its neighbour's. A literal or absent sequence stays literal. Other
//! sheets, formulas, formats, defined names and tables keep their bytes: a
//! formula that may read a written cell keeps its expression and stale
//! result, and the workbook asks the opening application to recalculate.
//! What the edit cannot do (write a formula or read-only cell, grow into
//! other data, write one cell twice) leaves the workbook to the rebuild,
//! its reason named.

mod range;

use super::dataset::Refs;
use super::layout::{Layout, Resolved};
use crate::design_plan::Cell;
use crate::edit::xml::{self, R};
use crate::live::LiveError;
use crate::live::conversion::{Conversion, RebuildReason};
use crate::live::held::{self, C};
use crate::live::pptx::{ChartKind, ChartSource, NodePayload};
use crate::native_patch::{NativeRefusal, chart_data, number};
use crate::ooxml::XmlTree;
use crate::retained_opc::Package;
use crate::xlsx_body::{
    XlsxArea, XlsxBook, XlsxCell, XlsxChange, XlsxSheet, XlsxValue, header_rename, mark_full_calc,
    project_xlsx, read_xlsx_cells,
};
use range::Line;
use std::collections::{BTreeMap, BTreeSet};

/// The embedded workbook a written chart's rewrite touches.
pub(super) enum Original {
    /// None of the deck's: no workbook, a link outside the deck, or a
    /// literal chart that stays literal.
    Absent,
    /// The chart's own workbook, which the rewrite edits in place.
    Own(String),
    /// A workbook the rewrite replaces with one rebuilt from the live data,
    /// and why it cannot edit it.
    Replaced(String, RebuildReason),
}

/// The workbook `chart`'s rewrite to `payload` touches: its own when every
/// reference it holds is series data the chart reader reads there, as the
/// rebuild's own-workbook test has it.
pub(super) fn original(
    package: &Package,
    chart: &str,
    payload: &NodePayload,
) -> Result<Original, LiveError> {
    let (_, tree) = xml::read(package, chart)?;
    let Some(link) =
        xml::child(&tree, 0, C, "externalData").and_then(|data| tree.nodes[data].attr_ns(R, "id"))
    else {
        return Ok(Original::Absent);
    };
    let Some(part) = package
        .relationships(chart)?
        .into_iter()
        .find(|rel| rel.id == link && !rel.external)
        .map(|rel| rel.target)
    else {
        return Ok(Original::Absent);
    };
    let literal = matches!(
        payload,
        NodePayload::Chart {
            source: ChartSource::Literal,
            ..
        }
    );
    let referenced = tree.nodes.iter().any(|node| node.is(C, "f"));
    Ok(match chart_data(package, chart) {
        Ok(_) if referenced => Original::Own(part),
        _ if literal => Original::Absent,
        Ok(_) => Original::Replaced(part, RebuildReason::NoCells),
        Err(NativeRefusal::SharedChartData) => Original::Replaced(part, RebuildReason::Shared),
        Err(_) => Original::Replaced(part, RebuildReason::Unreadable),
    })
}

/// A chart's own workbook as the rewrite edits it: each live series'
/// references, by its index in the live order the one resolution seats
/// ([`Resolved`]); the edited workbook, `None` when no cell changes; and
/// what the edit did.
pub(super) struct InPlace {
    pub(super) part: String,
    pub(super) refs: Vec<Refs>,
    pub(super) bytes: Option<Vec<u8>>,
    pub(super) notes: Vec<Conversion>,
}

/// Plan the edit of a chart's own workbook `part`, reading the chart's
/// series as the one resolution seats them, each on its own series' cells
/// by identity ([`Resolved`]).
pub(super) fn in_place(
    package: &Package,
    part: &str,
    resolved: &Resolved,
) -> Result<InPlace, RebuildReason> {
    let Resolved {
        tree,
        wanted,
        layout: Layout { seats, .. },
        ..
    } = resolved;
    let source = package
        .part(part)
        .ok()
        .flatten()
        .ok_or(RebuildReason::Unreadable)?;
    let limits = package.limits();
    let book = read_xlsx_cells(&source, limits).map_err(|_| RebuildReason::Projection)?;
    let mut plan = Plan::new(&book, tree)?;
    let wants: Vec<Want<'_>> = wanted
        .data
        .iter()
        .zip(&wanted.resolved)
        .map(|(line, kind)| Want {
            name: &line.name,
            first: match (&line.x, *kind == ChartKind::Scatter, line.set) {
                (Some(x), true, _) => Some(First {
                    levels: std::slice::from_ref(x),
                    numeric: true,
                    set: None,
                }),
                (None, false, Some(set)) => wanted.sets.get(set).map(|held| First {
                    levels: &held.levels,
                    numeric: held.numeric,
                    set: Some(set),
                }),
                _ => None,
            },
            values: &line.values,
        })
        .collect();
    let mut refs = vec![Refs::default(); wants.len()];
    // Held series first, at their own cells: each category set takes the
    // cells of the first held series that draws it, and a set whose cells
    // another set holds moves to free ones.
    let mut placed: BTreeMap<usize, Vec<Line>> = BTreeMap::new();
    for ((want, seat), refs) in wants.iter().zip(seats).zip(&mut refs) {
        if let Some(ser) = seat.cells
            && let Some((set, lines)) = plan.held(&held_refs(tree, ser)?, want, refs)?
        {
            placed.entry(set).or_insert(lines);
        }
    }
    // Then a held series' categories it had no cells for, and each new
    // series beside its template.
    for ((want, seat), refs) in wants.iter().zip(seats).zip(&mut refs) {
        let set = want.first.as_ref().and_then(|first| first.set);
        match (seat.cells, seat.template) {
            (Some(_), _) => {
                if refs.first.is_none()
                    && let (Some(first), Some(lines)) =
                        (&want.first, set.and_then(|set| placed.get(&set)))
                {
                    plan.fill(lines, first)?;
                    refs.first = Line::around(lines).map(|line| line.formula());
                }
            }
            (None, Some(template)) => {
                let shared = set.and_then(|set| placed.get(&set)).cloned();
                if let Some((set, lines)) =
                    plan.added(&held_refs(tree, template)?, want, shared.as_deref(), refs)?
                {
                    placed.entry(set).or_insert(lines);
                }
            }
            (None, None) => {}
        }
    }
    let changes = plan.changes()?;
    let mut notes = Vec::new();
    let bytes = if changes.is_empty() {
        None
    } else {
        let projected = project_xlsx(&source, &changes, limits)
            .map_err(|_| RebuildReason::Projection)?
            .bytes;
        let formulas = book
            .sheets
            .iter()
            .flat_map(|sheet| &sheet.cells)
            .any(|cell| cell.formula.is_some());
        Some(if formulas {
            notes.push(Conversion::WorkbookRecalcDeferred {
                part: part.to_owned(),
            });
            mark_full_calc(&projected, limits).map_err(|_| RebuildReason::Projection)?
        } else {
            projected
        })
    };
    Ok(InPlace {
        part: part.to_owned(),
        refs,
        bytes,
        notes,
    })
}

/// A worksheet cell: sheet, 1-based column and row.
type Key = (String, u32, u32);

/// A held sequence's reference: its range and its text as the chart holds
/// it, and its line of cells for each level, leaf first (a flat one's is
/// its range), with the way its points run when its shape says.
#[derive(Debug, Clone)]
struct Held {
    line: Line,
    text: String,
    levels: Vec<Line>,
    down: Option<bool>,
}

impl Held {
    /// The reference to `line`: the held text when it names the same range.
    fn to(&self, line: &Line) -> String {
        if *line == self.line {
            self.text.clone()
        } else {
            line.formula()
        }
    }

    /// The reference to the block `lines` cover.
    fn to_block(&self, lines: &[Line]) -> Option<String> {
        Line::around(lines).map(|line| self.to(&line))
    }
}

/// A held series' references: its name, its categories or x values, its
/// values; `None` for a literal or absent slot.
#[derive(Debug, Default)]
struct HeldRefs {
    name: Option<Held>,
    first: Option<Held>,
    values: Option<Held>,
}

/// A held series' references, read without expanding any cache's points.
fn held_refs(tree: &XmlTree, ser: usize) -> Result<HeldRefs, RebuildReason> {
    let slot = |names: &[&str]| -> Result<Option<Held>, RebuildReason> {
        let Some(at) = names.iter().find_map(|name| xml::child(tree, ser, C, name)) else {
            return Ok(None);
        };
        let read = held::descriptor(tree, at).ok_or(RebuildReason::Unreadable)?;
        read.formula
            .map(|text| {
                let line = if read.levels > 1 {
                    Line::parse_block(&text)
                } else {
                    Line::parse(&text)
                }
                .ok_or(RebuildReason::Unreadable)?;
                let (levels, down) = line.levels(read.levels).ok_or(RebuildReason::Unreadable)?;
                Ok(Held {
                    line,
                    text,
                    levels,
                    down,
                })
            })
            .transpose()
    };
    Ok(HeldRefs {
        name: slot(&["tx"])?,
        first: slot(&["cat", "xVal"])?,
        values: slot(&["val", "yVal"])?,
    })
}

/// What one live series writes: its name, its categories or x values when
/// it draws them, and its values.
struct Want<'a> {
    name: &'a str,
    first: Option<First<'a>>,
    values: &'a [Cell],
}

/// A series' categories (one category set, `set`, level by level, leaf
/// first) or x values (one level, no set).
struct First<'a> {
    levels: &'a [Vec<Cell>],
    numeric: bool,
    set: Option<usize>,
}

impl First<'_> {
    /// How many points it holds.
    fn count(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }
}

/// One cell the edit writes: its value, whether its sequence holds
/// numbers, and the cell whose format a new cell takes.
#[derive(Debug)]
struct Planned {
    cell: Cell,
    numeric: bool,
    like: Option<Key>,
}

/// A worksheet as the edit reads it.
struct Sheet<'b> {
    cells: BTreeMap<(u32, u32), &'b XlsxCell>,
    locked: &'b [XlsxArea],
    /// Each table's corners, and whether the chart reads a cell in it.
    tables: Vec<((u32, u32), (u32, u32), bool)>,
    /// The sheet as read, whose table headers a series name may rename.
    held: &'b XlsxSheet,
}

fn inside(first: (u32, u32), last: (u32, u32), (col, row): (u32, u32)) -> bool {
    (first.0..=last.0).contains(&col) && (first.1..=last.1).contains(&row)
}

/// The edit as it is planned: the workbook's sheets, every cell a reference
/// of the chart names, the way a one-cell range runs when nothing else
/// says (the chart's first longer range's), and the cells planned so far.
struct Plan<'b> {
    sheets: BTreeMap<&'b str, Sheet<'b>>,
    named: BTreeSet<Key>,
    down: bool,
    planned: BTreeMap<Key, Planned>,
    /// The category set each planned category cell holds.
    owners: BTreeMap<Key, usize>,
    /// The cells a held series' name is planned into.
    names: BTreeSet<Key>,
}

impl<'b> Plan<'b> {
    fn new(book: &'b XlsxBook, tree: &XmlTree) -> Result<Self, RebuildReason> {
        let mut named = BTreeSet::new();
        let mut down = None;
        for node in tree.nodes.iter().filter(|node| node.is(C, "f")) {
            let line = Line::parse_block(&node.text).ok_or(RebuildReason::Unreadable)?;
            if Line::parse(&node.text).is_some() {
                down = down.or(line.down());
            }
            named.extend(line.keys());
        }
        let sheets = book
            .sheets
            .iter()
            .map(|sheet| {
                let tables = sheet
                    .tables
                    .iter()
                    .map(|table| {
                        let ours = named.iter().any(|(name, col, row)| {
                            *name == sheet.name && inside(table.first, table.last, (*col, *row))
                        });
                        (table.first, table.last, ours)
                    })
                    .collect();
                let view = Sheet {
                    cells: sheet
                        .cells
                        .iter()
                        .map(|cell| ((cell.col, cell.row), cell))
                        .collect(),
                    locked: &sheet.locked,
                    tables,
                    held: sheet,
                };
                (sheet.name.as_str(), view)
            })
            .collect();
        Ok(Self {
            sheets,
            named,
            down: down.unwrap_or(true),
            planned: BTreeMap::new(),
            owners: BTreeMap::new(),
            names: BTreeSet::new(),
        })
    }

    fn stored(&self, (sheet, col, row): &Key) -> Option<&'b XlsxCell> {
        self.sheets
            .get(sheet.as_str())
            .and_then(|view| view.cells.get(&(*col, *row)).copied())
    }

    /// Whether a new cell may go at `key`: an empty, writable cell outside
    /// every table but one the chart reads from, which no reference of the
    /// chart names and the edit has not taken. A range that `grows` may
    /// also take the cells the chart names or the edit planned, each
    /// written once.
    fn free(&self, key: &Key, grows: bool) -> bool {
        if self.named.contains(key) || self.planned.contains_key(key) {
            return grows;
        }
        let (sheet, col, row) = (key.0.as_str(), key.1, key.2);
        let Some(view) = self.sheets.get(sheet) else {
            return false;
        };
        view.cells.get(&(col, row)).is_none_or(|cell| {
            cell.value == XlsxValue::Blank && cell.formula.is_none() && cell.locked.is_none()
        }) && !view.locked.iter().any(|area| area.contains(col, row))
            && view
                .tables
                .iter()
                .all(|&(first, last, ours)| ours || !inside(first, last, (col, row)))
    }

    /// Which way `line` runs: its own way, else down a column when its
    /// name sits above it and along a row when beside it, else the chart's.
    fn down_of(&self, line: &Line, name: Option<&Line>) -> bool {
        line.down()
            .or_else(|| {
                let name = name.filter(|name| name.sheet == line.sheet)?;
                let (col, row) = line.first;
                if row.checked_sub(1).map(|row| (col, row)) == Some(name.first) {
                    Some(true)
                } else if col.checked_sub(1).map(|col| (col, row)) == Some(name.first) {
                    Some(false)
                } else {
                    None
                }
            })
            .unwrap_or(self.down)
    }

    /// `held` grown or shrunk to `count` cells; refused when a cell it
    /// grows into is not free.
    fn grown(&self, held: &Line, count: usize, down: bool) -> Result<Option<Line>, RebuildReason> {
        let Some(line) = held.fit(count, down)? else {
            return Ok(None);
        };
        let had: BTreeSet<Key> = held.keys().collect();
        if line
            .keys()
            .any(|key| !had.contains(&key) && !self.free(&key, true))
        {
            return Err(RebuildReason::NoRoom);
        }
        Ok(Some(line))
    }

    /// Plan `cells` into `line`; a new cell takes the format of `like`'s
    /// cell at its place, else of `like`'s last. A cell planned twice must
    /// read the same.
    fn take(
        &mut self,
        line: &Line,
        cells: &[Cell],
        numeric: bool,
        like: &Line,
    ) -> Result<(), RebuildReason> {
        let like: Vec<Key> = like.keys().collect();
        for (at, (key, cell)) in line.keys().zip(cells).enumerate() {
            match self.planned.get(&key) {
                Some(planned) if planned.cell != *cell => return Err(RebuildReason::Overlap),
                Some(_) => {}
                None => {
                    let like = like.get(at).or(like.last()).cloned();
                    self.planned.insert(
                        key,
                        Planned {
                            cell: cell.clone(),
                            numeric,
                            like,
                        },
                    );
                }
            }
        }
        Ok(())
    }

    /// Whether `line` is the chart's own cells (named by a reference, or
    /// planned) and they hold the numbers `cells` already.
    fn holds(&self, line: &Line, cells: &[Cell]) -> bool {
        line.keys()
            .zip(cells)
            .all(|(key, cell)| match self.planned.get(&key) {
                Some(planned) => planned.cell == *cell,
                None => self.named.contains(&key) && same(self.stored(&key), cell, true),
            })
    }

    /// The least shift (columns right of a series down a column, rows
    /// below one along a row) that puts every one of `lines` in free cells.
    fn room(&self, lines: &[Line], down: bool) -> Result<Vec<Line>, RebuildReason> {
        let mut by = 1_u32;
        loop {
            let moved: Vec<Line> = lines
                .iter()
                .map(|line| line.shifted(by, down))
                .collect::<Option<_>>()
                .ok_or(RebuildReason::NoRoom)?;
            if moved
                .iter()
                .all(|line| line.keys().all(|key| self.free(&key, false)))
            {
                return Ok(moved);
            }
            by = by.checked_add(1).ok_or(RebuildReason::NoRoom)?;
        }
    }

    /// A held series' sequences at its held references, grown or shrunk:
    /// its name in the first cell of its name's, its values, its categories
    /// (each level's line) or x values. The category set it planned and its
    /// lines, if it drew one.
    fn held(
        &mut self,
        held: &HeldRefs,
        want: &Want<'_>,
        refs: &mut Refs,
    ) -> Result<Option<(usize, Vec<Line>)>, RebuildReason> {
        if let Some(name) = &held.name {
            let line = name.line.head();
            self.take(
                &line,
                &[Cell::Text(want.name.to_owned())],
                false,
                &name.line,
            )?;
            self.names.extend(line.keys());
            refs.name = Some(name.to(&line));
        }
        if let Some(values) = &held.values {
            let down = self.down_of(&values.line, held.name.as_ref().map(|name| &name.line));
            if let Some(line) = self.grown(&values.line, want.values.len(), down)? {
                self.take(&line, want.values, true, &values.line)?;
                refs.values = Some(values.to(&line));
            }
        }
        let (Some(at), Some(first)) = (&held.first, &want.first) else {
            return Ok(None);
        };
        if at.levels.len() != first.levels.len() {
            return Err(RebuildReason::LevelsChanged);
        }
        let down = at.down.unwrap_or_else(|| self.down_of(&at.line, None));
        let mut grown = Vec::with_capacity(at.levels.len());
        for line in &at.levels {
            match self.grown(line, first.count(), down)? {
                Some(line) => grown.push(line),
                None => return Ok(None),
            }
        }
        let lines = self.place(first, grown, &at.levels, down)?;
        refs.first = at.to_block(&lines);
        Ok(first.set.map(|set| (set, lines)))
    }

    /// Plan `first`'s levels into `lines` (leaf first), each formatted
    /// after its line of `like`: a category set whose cells another set
    /// holds moves to the first free cells beside them, so changing one
    /// series' categories never writes over another's. The lines planned.
    fn place(
        &mut self,
        first: &First<'_>,
        lines: Vec<Line>,
        like: &[Line],
        down: bool,
    ) -> Result<Vec<Line>, RebuildReason> {
        let lines = match first.set {
            Some(set)
                if lines
                    .iter()
                    .flat_map(Line::keys)
                    .any(|key| self.owners.get(&key).is_some_and(|owner| *owner != set)) =>
            {
                self.room(&lines, down)?
            }
            _ => lines,
        };
        for ((line, cells), like) in lines.iter().zip(first.levels).zip(like) {
            self.take(line, cells, first.numeric, like)?;
            if let Some(set) = first.set {
                for key in line.keys() {
                    self.owners.insert(key, set);
                }
            }
        }
        Ok(lines)
    }

    /// Plan `first`'s levels into a set's planned `lines`.
    fn fill(&mut self, lines: &[Line], first: &First<'_>) -> Result<(), RebuildReason> {
        for (line, cells) in lines.iter().zip(first.levels) {
            self.take(line, cells, first.numeric, line)?;
        }
        Ok(())
    }

    /// A new series' sequences: its categories the cells its set already
    /// took (else its template's, moved where another set holds them), its
    /// x values the template's where those cells already hold them, and
    /// its values, name and other x values shifted from the template's into
    /// the first free cells beside them. The category set it planned and
    /// its lines, when it planned one.
    fn added(
        &mut self,
        template: &HeldRefs,
        want: &Want<'_>,
        shared: Option<&[Line]>,
        refs: &mut Refs,
    ) -> Result<Option<(usize, Vec<Line>)>, RebuildReason> {
        let mut x = None;
        let mut planned = None;
        match (&want.first, shared, &template.first) {
            (Some(first), Some(lines), _) if first.set.is_some() => {
                self.fill(lines, first)?;
                refs.first = Line::around(lines).map(|line| line.formula());
            }
            (Some(first), _, Some(at)) if first.set.is_some() => {
                if at.levels.len() != first.levels.len() {
                    return Err(RebuildReason::LevelsChanged);
                }
                let down = at.down.unwrap_or_else(|| self.down_of(&at.line, None));
                let mut grown = Vec::with_capacity(at.levels.len());
                for line in &at.levels {
                    grown.extend(self.grown(line, first.count(), down)?);
                }
                if grown.len() == at.levels.len() {
                    let lines = self.place(first, grown, &at.levels, down)?;
                    refs.first = Line::around(&lines).map(|line| line.formula());
                    planned = first.set.map(|set| (set, lines));
                }
            }
            (Some(first), _, Some(at)) => {
                let down = self.down_of(&at.line, None);
                let cells = first.levels.first().map_or(&[][..], Vec::as_slice);
                match at.line.fit(cells.len(), down)? {
                    Some(line) if self.holds(&line, cells) => {
                        self.take(&line, cells, first.numeric, &at.line)?;
                        refs.first = Some(line.formula());
                    }
                    Some(line) => x = Some((line, at.line.clone(), cells)),
                    None => {}
                }
            }
            _ => {}
        }
        let Some(values) = &template.values else {
            return Ok(planned);
        };
        let name = template.name.as_ref().map(|name| name.line.head());
        let down = self.down_of(&values.line, name.as_ref());
        let Some(line) = values.line.fit(want.values.len(), down)? else {
            return Ok(planned);
        };
        let mut lines = vec![line];
        lines.extend(name.clone());
        lines.extend(x.as_ref().map(|(line, _, _)| line.clone()));
        let mut moved = self.room(&lines, down)?.into_iter();
        if let Some(line) = moved.next() {
            self.take(&line, want.values, true, &values.line)?;
            refs.values = Some(line.formula());
        }
        if let (Some(like), Some(line)) = (&name, name.as_ref().and_then(|_| moved.next())) {
            self.take(&line, &[Cell::Text(want.name.to_owned())], false, like)?;
            refs.name = Some(line.formula());
        }
        if let (Some((_, like, cells)), Some(line)) = (&x, moved.next()) {
            self.take(&line, cells, true, like)?;
            refs.first = Some(line.formula());
        }
        Ok(planned)
    }

    /// The cell writes: each planned cell that does not already read as
    /// planned, in its own format (a new cell in its model's). A formula
    /// or read-only cell refuses, but for a held series' name in a table's
    /// header cell, which renames the table's column with it (FIX 6399).
    fn changes(&self) -> Result<Vec<XlsxChange>, RebuildReason> {
        let mut out = Vec::new();
        for (key, planned) in &self.planned {
            let stored = self.stored(key);
            if same(stored, &planned.cell, planned.numeric) {
                continue;
            }
            if stored.is_some_and(|cell| cell.formula.is_some()) {
                return Err(RebuildReason::FormulaCell);
            }
            let locked = self
                .sheets
                .get(key.0.as_str())
                .is_some_and(|view| view.locked.iter().any(|area| area.contains(key.1, key.2)));
            if locked || stored.is_some_and(|cell| cell.locked.is_some()) {
                let rename = self
                    .sheets
                    .get(key.0.as_str())
                    .filter(|_| self.names.contains(key))
                    .and_then(|view| {
                        header_rename(view.held, key.1, key.2, &value(&planned.cell, stored))
                    });
                out.push(rename.ok_or(RebuildReason::ReadOnlyCell)?);
            }
            let style = stored
                .or_else(|| planned.like.as_ref().and_then(|like| self.stored(like)))
                .and_then(|cell| cell.style);
            out.push(XlsxChange::Cell {
                sheet: key.0.clone(),
                col: key.1,
                row: key.2,
                value: value(&planned.cell, stored),
                formula: None,
                style,
            });
        }
        Ok(out)
    }
}

/// Whether a stored cell already reads as `cell` in its sequence's kind: a
/// number as that number, text as that text (in a text sequence a number
/// reads as its digits), and an empty one as missing.
fn same(stored: Option<&XlsxCell>, cell: &Cell, numeric: bool) -> bool {
    match (cell, stored.map(|stored| &stored.value)) {
        (Cell::Missing, None | Some(XlsxValue::Blank)) => true,
        (Cell::Number(want), Some(XlsxValue::Number(held))) => want == held,
        (Cell::Text(want) | Cell::Date(want), Some(XlsxValue::Text(held))) => want == held,
        (Cell::Text(want) | Cell::Date(want), Some(XlsxValue::Number(held))) => {
            !numeric && number(*held) == *want
        }
        _ => false,
    }
}

/// A planned cell's stored value: a number category stays a number.
fn value(cell: &Cell, stored: Option<&XlsxCell>) -> XlsxValue {
    match cell {
        Cell::Missing => XlsxValue::Blank,
        Cell::Number(value) => XlsxValue::Number(*value),
        Cell::Text(text) | Cell::Date(text) => match text.trim().parse::<f64>() {
            Ok(value)
                if number(value) == *text
                    && stored.is_some_and(|cell| matches!(cell.value, XlsxValue::Number(_))) =>
            {
                XlsxValue::Number(value)
            }
            _ => XlsxValue::Text(text.clone()),
        },
    }
}
