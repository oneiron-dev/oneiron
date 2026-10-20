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

use super::Refs;
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
    XlsxArea, XlsxBook, XlsxCell, XlsxChange, XlsxValue, a1, mark_full_calc, parse_a1,
    project_xlsx, read_xlsx_cells,
};
use std::collections::{BTreeMap, BTreeSet};

const MAX_COLUMN: u32 = 16_384;
const MAX_ROW: u32 = 1_048_576;

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
            first: match (&line.x, *kind == ChartKind::Scatter) {
                (Some(x), true) => Some(First {
                    cells: x,
                    numeric: true,
                    shared: false,
                }),
                (None, false) if !wanted.category_cells.is_empty() => Some(First {
                    cells: &wanted.category_cells,
                    numeric: wanted.numeric_cats,
                    shared: true,
                }),
                _ => None,
            },
            values: &line.values,
        })
        .collect();
    let mut refs = vec![Refs::default(); wants.len()];
    // Held series first, at their own cells: the chart's categories are
    // the first such series' that draws them.
    let mut shared: Option<Line> = None;
    for ((want, seat), refs) in wants.iter().zip(seats).zip(&mut refs) {
        if let Some(ser) = seat.cells {
            let cats = plan.held(&held_refs(tree, ser)?, want, refs)?;
            if shared.is_none() && want.first.as_ref().is_some_and(|first| first.shared) {
                shared = cats;
            }
        }
    }
    // Then a held series' categories it had no cells for, and each new
    // series beside its template.
    for ((want, seat), refs) in wants.iter().zip(seats).zip(&mut refs) {
        match (seat.cells, seat.template) {
            (Some(_), _) => {
                if refs.first.is_none()
                    && let (Some(first), Some(line)) = (&want.first, &shared)
                    && first.shared
                {
                    plan.take(line, first.cells, first.numeric, line)?;
                    refs.first = Some(line.formula());
                }
            }
            (None, Some(template)) => {
                plan.added(&held_refs(tree, template)?, want, shared.as_ref(), refs)?;
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

/// A direct one-row or one-column range on one sheet, as a chart's `c:f`
/// names it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Line {
    sheet: String,
    first: (u32, u32),
    last: (u32, u32),
}

impl Line {
    /// `Sheet1!$B$2:$B$5`, `'My sheet'!B1`.
    fn parse(formula: &str) -> Option<Self> {
        let formula = formula.trim();
        if formula.contains('[') {
            return None;
        }
        let (sheet, area) = formula.rsplit_once('!')?;
        let sheet = match sheet.strip_prefix('\'') {
            Some(quoted) => quoted.strip_suffix('\'')?.replace("''", "'"),
            None => sheet.to_owned(),
        };
        let (from, to) = area.split_once(':').unwrap_or((area, area));
        let (from, to) = (parse_a1(from)?, parse_a1(to)?);
        let first = (from.0.min(to.0), from.1.min(to.1));
        let last = (from.0.max(to.0), from.1.max(to.1));
        (!sheet.is_empty() && (first.0 == last.0 || first.1 == last.1)).then_some(Self {
            sheet,
            first,
            last,
        })
    }

    /// The range's first cell alone.
    fn head(&self) -> Self {
        Self {
            sheet: self.sheet.clone(),
            first: self.first,
            last: self.first,
        }
    }

    /// Down a column (`Some(true)`) or along a row; `None` for one cell.
    fn down(&self) -> Option<bool> {
        (self.first != self.last).then_some(self.first.0 == self.last.0)
    }

    /// The cells in sequence order.
    fn keys(&self) -> impl Iterator<Item = Key> + '_ {
        (self.first.1..=self.last.1).flat_map(move |row| {
            (self.first.0..=self.last.0).map(move |col| (self.sheet.clone(), col, row))
        })
    }

    /// `count` cells from the same first cell, down a column or along a
    /// row: `None` for none, refused past the sheet's edge.
    fn fit(&self, count: usize, down: bool) -> Result<Option<Self>, RebuildReason> {
        let Some(more) = count.checked_sub(1) else {
            return Ok(None);
        };
        let more = u32::try_from(more).map_err(|_| RebuildReason::NoRoom)?;
        let (col, row) = self.first;
        let last = if down {
            row.checked_add(more).map(|row| (col, row))
        } else {
            col.checked_add(more).map(|col| (col, row))
        };
        match last {
            Some(last) if last.0 <= MAX_COLUMN && last.1 <= MAX_ROW => Ok(Some(Self {
                sheet: self.sheet.clone(),
                first: self.first,
                last,
            })),
            _ => Err(RebuildReason::NoRoom),
        }
    }

    /// The range `by` columns to the right (for a series down a column) or
    /// rows below (along a row); `None` past the sheet's edge.
    fn shifted(&self, by: u32, down: bool) -> Option<Self> {
        let step = |(col, row): (u32, u32)| {
            let at = if down {
                (col.checked_add(by)?, row)
            } else {
                (col, row.checked_add(by)?)
            };
            (at.0 <= MAX_COLUMN && at.1 <= MAX_ROW).then_some(at)
        };
        Some(Self {
            sheet: self.sheet.clone(),
            first: step(self.first)?,
            last: step(self.last)?,
        })
    }

    /// The reference as a chart writes it: `'Sheet1'!$B$2:$B$5`.
    fn formula(&self) -> String {
        let anchored = |(col, row): (u32, u32)| {
            let cell = a1(col, row);
            let split = cell
                .find(|c: char| c.is_ascii_digit())
                .unwrap_or(cell.len());
            format!("${}${}", &cell[..split], &cell[split..])
        };
        let sheet = format!("'{}'", self.sheet.replace('\'', "''"));
        if self.first == self.last {
            format!("{sheet}!{}", anchored(self.first))
        } else {
            format!("{sheet}!{}:{}", anchored(self.first), anchored(self.last))
        }
    }
}

/// A held sequence's reference: its range and its text as the chart holds
/// it.
#[derive(Debug, Clone)]
struct Held {
    line: Line,
    text: String,
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
}

/// A held series' references: its name, its categories or x values, its
/// values; `None` for a literal or absent slot.
#[derive(Debug, Default)]
struct HeldRefs {
    name: Option<Held>,
    first: Option<Held>,
    values: Option<Held>,
}

fn held_refs(tree: &XmlTree, ser: usize) -> Result<HeldRefs, RebuildReason> {
    let slot = |names: &[&str]| -> Result<Option<Held>, RebuildReason> {
        let Some(at) = names.iter().find_map(|name| xml::child(tree, ser, C, name)) else {
            return Ok(None);
        };
        let points = held::points(tree, at).ok_or(RebuildReason::Unreadable)?;
        points
            .formula
            .map(|text| {
                Line::parse(&text)
                    .map(|line| Held { line, text })
                    .ok_or(RebuildReason::Unreadable)
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

/// A series' categories (the chart's one list, `shared`) or x values.
struct First<'a> {
    cells: &'a [Cell],
    numeric: bool,
    shared: bool,
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
}

impl<'b> Plan<'b> {
    fn new(book: &'b XlsxBook, tree: &XmlTree) -> Result<Self, RebuildReason> {
        let mut named = BTreeSet::new();
        let mut down = None;
        for node in tree.nodes.iter().filter(|node| node.is(C, "f")) {
            let line = Line::parse(&node.text).ok_or(RebuildReason::Unreadable)?;
            down = down.or(line.down());
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
                };
                (sheet.name.as_str(), view)
            })
            .collect();
        Ok(Self {
            sheets,
            named,
            down: down.unwrap_or(true),
            planned: BTreeMap::new(),
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
    /// or x values. The categories it planned, if it drew them.
    fn held(
        &mut self,
        held: &HeldRefs,
        want: &Want<'_>,
        refs: &mut Refs,
    ) -> Result<Option<Line>, RebuildReason> {
        if let Some(name) = &held.name {
            let line = name.line.head();
            self.take(
                &line,
                &[Cell::Text(want.name.to_owned())],
                false,
                &name.line,
            )?;
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
        let down = self.down_of(&at.line, None);
        let Some(line) = self.grown(&at.line, first.cells.len(), down)? else {
            return Ok(None);
        };
        self.take(&line, first.cells, first.numeric, &at.line)?;
        refs.first = Some(at.to(&line));
        Ok(Some(line))
    }

    /// A new series' sequences: its categories the chart's (else its
    /// template's), its x values the template's where those cells already
    /// hold them, and its values, name and other x values shifted from the
    /// template's into the first free cells beside them.
    fn added(
        &mut self,
        template: &HeldRefs,
        want: &Want<'_>,
        shared: Option<&Line>,
        refs: &mut Refs,
    ) -> Result<(), RebuildReason> {
        let mut x = None;
        if let (Some(first), Some(at)) = (&want.first, &template.first) {
            let down = self.down_of(&at.line, None);
            let line = match shared.filter(|_| first.shared) {
                Some(line) => Some(line.clone()),
                None if first.shared => self.grown(&at.line, first.cells.len(), down)?,
                None => at.line.fit(first.cells.len(), down)?,
            };
            match line {
                Some(line) if first.shared || self.holds(&line, first.cells) => {
                    self.take(&line, first.cells, first.numeric, &at.line)?;
                    refs.first = Some(line.formula());
                }
                Some(line) => x = Some((line, at.line.clone(), first.cells)),
                None => {}
            }
        } else if let (Some(first), Some(line)) = (&want.first, shared)
            && first.shared
        {
            self.take(line, first.cells, first.numeric, line)?;
            refs.first = Some(line.formula());
        }
        let Some(values) = &template.values else {
            return Ok(());
        };
        let name = template.name.as_ref().map(|name| name.line.head());
        let down = self.down_of(&values.line, name.as_ref());
        let Some(line) = values.line.fit(want.values.len(), down)? else {
            return Ok(());
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
        Ok(())
    }

    /// The cell writes: each planned cell that does not already read as
    /// planned, in its own format (a new cell in its model's). A formula
    /// or read-only cell refuses.
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
                return Err(RebuildReason::ReadOnlyCell);
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
