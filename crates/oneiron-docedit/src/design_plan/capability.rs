//! Layout capability (ARCH-0077, "Layout selection"): each placeholder's
//! role, type and index, effective bounds and text style read through the
//! deck resolvers, the content it suits, and an estimated capacity. Estimates
//! choose candidates and never certify fit; emission still renders and
//! checks. Selection never reads a layout's name.
use super::Rect;
use super::brief::{Block, BlockContent, Brief, Carrier, Cell, Dataset};
use crate::deck::{MasterView, Placeholder, RetainedNode, ShapeView, Spacing, State, TextStyle};
use crate::fonts::{Face, FontBook};
use crate::native_patch::{TableLayout, grid};
use std::sync::Arc;

/// EMU per hundredth of a point.
const EMU_PER_CENTIPOINT: i64 = 127;
/// Schema-default `a:bodyPr` insets and `a:tcPr` cell margins, in EMU:
/// left, top, right, bottom.
const DEFAULT_INSETS: [i64; 4] = [91_440, 45_720, 91_440, 45_720];
/// The space between ordinary shapes in an arrangement, in EMU.
pub(super) const GUTTER: i64 = 182_880;
/// A chart's estimated floor: plot and axis labels, in lines of its text.
const CHART_LINES: i64 = 5;

/// What a block becomes on the slide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Carry {
    Title,
    Text,
    Table,
    Chart,
    /// A part-of-whole chart.
    Share,
    Picture,
}

/// The content types a placeholder or an ordinary area takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Suits {
    title: bool,
    text: bool,
    table: bool,
    chart: bool,
    picture: bool,
}

impl Suits {
    const NONE: Self = Self {
        title: false,
        text: false,
        table: false,
        chart: false,
        picture: false,
    };
    /// Ordinary shapes carry any content but a placeholder title.
    pub(super) const ORDINARY: Self = Self {
        title: false,
        text: true,
        table: true,
        chart: true,
        picture: true,
    };

    /// By `p:ph/@type`: `obj` takes any content, a body or subtitle takes
    /// text only, and the typed placeholders take their own kind. Footer
    /// placeholders take nothing.
    fn placeholder(kind: &str) -> Self {
        match kind {
            "title" | "ctrTitle" => Self {
                title: true,
                ..Self::NONE
            },
            "body" | "subTitle" => Self {
                text: true,
                ..Self::NONE
            },
            "obj" => Self::ORDINARY,
            "tbl" => Self {
                table: true,
                ..Self::NONE
            },
            "chart" => Self {
                chart: true,
                ..Self::NONE
            },
            "pic" | "clipArt" => Self {
                picture: true,
                ..Self::NONE
            },
            _ => Self::NONE,
        }
    }

    fn takes(self, carry: Carry) -> bool {
        match carry {
            Carry::Title => self.title,
            Carry::Text => self.text,
            Carry::Table => self.table,
            Carry::Chart | Carry::Share => self.chart,
            Carry::Picture => self.picture,
        }
    }
}

/// Resolved first-level text metrics, in EMU. With a face from the font
/// book, widths and the single line are the face's own; without one, or for
/// text the face cannot measure, the em rule stands in and the estimate
/// says it was not measured.
#[derive(Debug, Clone)]
pub(super) struct Metrics {
    size: i64,
    indent: i64,
    first_line: i64,
    insets: [i64; 4],
    face: Option<Arc<Face>>,
    line_spacing: Spacing,
    before: Spacing,
    after: Spacing,
}

/// The theme's latin typefaces: `+mj-lt` and `+mn-lt`.
#[derive(Debug, Clone, Copy)]
pub(super) struct ThemeFonts<'a> {
    pub(super) major: Option<&'a str>,
    pub(super) minor: Option<&'a str>,
}

impl Metrics {
    /// `None` when the size or a margin is unresolved: no estimate is made.
    fn new(
        style: &TextStyle,
        insets: [i64; 4],
        fonts: &FontBook,
        theme: ThemeFonts<'_>,
    ) -> Option<Self> {
        let size = i64::from(style.size.value?) * EMU_PER_CENTIPOINT;
        let indent = match style.indent.state {
            State::Unresolved(_) => return None,
            _ => style.indent.value.unwrap_or(0),
        };
        let typeface = match style.typeface.value.as_deref() {
            Some("+mj-lt") => theme.major,
            Some("+mn-lt") | None => theme.minor,
            Some(name) => Some(name),
        };
        let bold = style.bold.value.unwrap_or(false);
        Some(Self {
            size,
            indent,
            first_line: style.first_line.value.unwrap_or(0),
            insets,
            face: typeface.and_then(|name| fonts.face(name, bold, false)),
            line_spacing: style
                .line_spacing
                .value
                .unwrap_or(Spacing::Percent(100_000)),
            before: style.space_before.value.unwrap_or(Spacing::Points(0)),
            after: style.space_after.value.unwrap_or(Spacing::Points(0)),
        })
    }

    /// The face's family when it measures every one of `texts`.
    fn measured<T: AsRef<str>>(&self, texts: &[T]) -> Option<String> {
        let face = self.face.as_ref()?;
        texts
            .iter()
            .all(|text| face.advance(text.as_ref(), self.size).is_some())
            .then(|| face.family().to_owned())
    }

    /// One single-spaced line: the face's ascent, descent and gap, else 1.2
    /// times the size.
    fn single(&self) -> i64 {
        self.face
            .as_ref()
            .map_or(self.size * 6 / 5, |face| face.line(self.size))
    }

    fn spaced(&self, spacing: Spacing) -> i64 {
        match spacing {
            Spacing::Percent(share) => self.single() * share / 100_000,
            Spacing::Points(centipoints) => centipoints * EMU_PER_CENTIPOINT,
        }
    }

    fn line(&self) -> i64 {
        self.spaced(self.line_spacing).max(1)
    }

    /// The face's width, else the em rule: East Asian wide and fullwidth
    /// characters take a full em, others half.
    fn advance(&self, text: &str) -> i64 {
        self.face
            .as_ref()
            .and_then(|face| face.advance(text, self.size))
            .unwrap_or_else(|| {
                text.chars()
                    .map(|ch| if wide(ch) { self.size } else { self.size / 2 })
                    .sum()
            })
    }

    /// Lines of `text` wrapped greedily at spaces (and between wide
    /// characters) in `first` width, then `rest`; at least one. A word
    /// wider than the line breaks across lines.
    fn lines_in(&self, text: &str, first: i64, rest: i64) -> i64 {
        let space = self.advance(" ");
        let mut lines = 1;
        let mut used = 0;
        let mut width = first.max(1);
        for word in words(text) {
            let need = self.advance(word);
            let gap = if used == 0 { 0 } else { space };
            if used > 0 && used + gap + need > width {
                lines += 1;
                used = 0;
                width = rest.max(1);
            }
            let gap = if used == 0 { 0 } else { space };
            used += gap + need;
            while used > width {
                lines += 1;
                used -= width;
                width = rest.max(1);
            }
        }
        lines
    }

    /// Lines of `text` in `usable` width, at least one.
    fn lines(&self, text: &str, usable: i64) -> i64 {
        self.lines_in(text, usable, usable)
    }

    /// The height these paragraphs need in `width`, insets included: lines
    /// at the paragraph's line spacing, the space after each paragraph and
    /// before every one but the first.
    fn height(&self, paragraphs: &[String], width: i64) -> Option<i64> {
        let [left, top, right, bottom] = self.insets;
        let usable = width - left - right - self.indent;
        let first = usable - self.first_line;
        if usable <= 0 || first <= 0 {
            return None;
        }
        let mut height = top + bottom;
        for (index, paragraph) in paragraphs.iter().enumerate() {
            if index > 0 {
                height += self.spaced(self.before);
            }
            height += self.lines_in(paragraph, first, usable) * self.line();
            height += self.spaced(self.after);
        }
        Some(height)
    }
}

/// Break opportunities: runs of non-space text, with every wide character
/// a word of its own.
fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split_whitespace().flat_map(|word| {
        let mut pieces = Vec::new();
        let mut start = 0;
        for (at, ch) in word.char_indices() {
            if wide(ch) {
                if start < at {
                    pieces.push(&word[start..at]);
                }
                pieces.push(&word[at..at + ch.len_utf8()]);
                start = at + ch.len_utf8();
            }
        }
        if start < word.len() {
            pieces.push(&word[start..]);
        }
        pieces
    })
}

fn wide(ch: char) -> bool {
    matches!(u32::from(ch),
        0x1100..=0x115F
        | 0x2E80..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE4F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F300..=0x1F64F
        | 0x20000..=0x3FFFD)
}

/// One layout placeholder that can be filled by role.
#[derive(Debug, Clone)]
pub(super) struct Slot {
    pub(super) placeholder: Placeholder,
    pub(super) shape: RetainedNode,
    pub(super) bounds: Rect,
    suits: Suits,
    /// `None` when its text style is unresolved: it then takes no text.
    text: Option<Metrics>,
}

/// One layout's capability profile.
#[derive(Debug, Clone)]
pub(super) struct Profile {
    pub(super) layout: String,
    pub(super) titles: Vec<Slot>,
    /// Content placeholders in reading order.
    pub(super) content: Vec<Slot>,
    /// Where ordinary shapes go: the union of the content placeholders,
    /// else the master's body area.
    pub(super) region: Option<Rect>,
}

/// The profiles of one master's layouts, in `p:sldLayoutIdLst` order.
#[derive(Debug, Clone)]
pub(super) struct Template {
    pub(super) profiles: Vec<Profile>,
    /// New text in an ordinary shape, a table or a chart.
    ordinary: Option<Metrics>,
}

impl Template {
    pub(super) fn read(master: &MasterView, fonts: &FontBook) -> Self {
        let theme = ThemeFonts {
            major: master.major_font.as_deref(),
            minor: master.minor_font.as_deref(),
        };
        let master_body = master
            .shapes
            .iter()
            .filter(|shape| {
                shape
                    .placeholder
                    .as_ref()
                    .is_some_and(|ph| matches!(ph.kind.as_str(), "body" | "obj"))
            })
            .find_map(bounds);
        let profiles = master
            .layouts
            .iter()
            .map(|layout| {
                let mut titles = Vec::new();
                let mut content = Vec::new();
                for (shape, style) in layout.shapes.iter().zip(&layout.text) {
                    let (Some(placeholder), Some(bounds)) = (&shape.placeholder, bounds(shape))
                    else {
                        continue;
                    };
                    let suits = Suits::placeholder(&placeholder.kind);
                    if suits == Suits::NONE {
                        continue;
                    }
                    let slot = Slot {
                        placeholder: placeholder.clone(),
                        shape: shape.node.clone(),
                        bounds,
                        suits,
                        text: Metrics::new(style, insets(shape), fonts, theme),
                    };
                    if suits.title {
                        titles.push(slot);
                    } else {
                        content.push(slot);
                    }
                }
                content.sort_by_key(|slot| (slot.bounds.y, slot.bounds.x));
                let region = content
                    .iter()
                    .map(|slot| slot.bounds)
                    .reduce(Rect::union)
                    .or(master_body);
                Profile {
                    layout: layout.part.clone(),
                    titles,
                    content,
                    region,
                }
            })
            .collect();
        Self {
            profiles,
            ordinary: Metrics::new(&master.ordinary_text, DEFAULT_INSETS, fonts, theme),
        }
    }

    /// A placeholder as a room: its own text style, the ordinary style for
    /// tables and charts.
    pub(super) fn slot<'t>(&'t self, slot: &'t Slot) -> Room<'t> {
        Room {
            bounds: slot.bounds,
            suits: slot.suits,
            text: slot.text.as_ref(),
            ordinary: self.ordinary.as_ref(),
        }
    }

    /// An area for ordinary shapes.
    pub(super) fn area(&self, bounds: Rect) -> Room<'_> {
        Room {
            bounds,
            suits: Suits::ORDINARY,
            text: self.ordinary.as_ref(),
            ordinary: self.ordinary.as_ref(),
        }
    }
}

/// DrawingML's coordinate bound (ST_PositiveCoordinate); within it, the
/// rectangle arithmetic below cannot overflow.
const COORDINATE: i64 = 27_273_042_316_900;

/// Unrotated, ungrouped, with an effective offset and extent inside the
/// schema's coordinate range.
fn bounds(shape: &ShapeView) -> Option<Rect> {
    let geometry = &shape.geometry;
    if !shape.group_path.is_empty()
        || geometry.rotation.value.unwrap_or(0) != 0
        || geometry.flip_h.value.unwrap_or(false)
        || geometry.flip_v.value.unwrap_or(false)
    {
        return None;
    }
    let (x, y) = geometry.offset.value?;
    let (cx, cy) = geometry.extent.value?;
    let range = |value: i64| value.abs() <= COORDINATE;
    (cx > 0 && cy > 0 && range(x) && range(y) && range(cx) && range(cy)).then_some(Rect {
        x,
        y,
        cx,
        cy,
    })
}

fn insets(shape: &ShapeView) -> [i64; 4] {
    let mut out = DEFAULT_INSETS;
    if let Some(text) = &shape.text {
        for (slot, value) in out.iter_mut().zip(&text.body.insets) {
            if let Some(inset) = value.value {
                *slot = inset;
            }
        }
    }
    out
}

/// What a block asks of a room.
#[derive(Debug, Clone)]
pub(super) enum Need<'b> {
    Title(&'b str),
    /// A claim then each of its qualifications, one paragraph each.
    Text(Vec<String>),
    /// `dataset` is `None` only for a reference the brief did not resolve.
    Data {
        dataset: Option<&'b Dataset>,
        carriers: &'b [Carrier],
    },
    Picture,
}

impl<'b> Need<'b> {
    pub(super) fn of(brief: &'b Brief, block: &'b Block) -> Self {
        match &block.content {
            BlockContent::Title { text } => Self::Title(text),
            BlockContent::Claim {
                text,
                qualifications,
                ..
            } => Self::Text(
                std::iter::once(text)
                    .chain(qualifications)
                    .cloned()
                    .collect(),
            ),
            BlockContent::Data { dataset, carriers } => Self::Data {
                dataset: brief.dataset(dataset),
                carriers,
            },
            BlockContent::Asset { .. } => Self::Picture,
        }
    }

    /// Whether any room of this kind could take the block, size aside.
    pub(super) fn suited(&self, suits: Suits) -> bool {
        match self {
            Self::Title(_) => suits.title,
            Self::Text(_) => suits.text,
            Self::Data { carriers, .. } => {
                carriers.iter().any(|&carrier| suits.takes(carry(carrier)))
            }
            Self::Picture => suits.picture,
        }
    }
}

fn carry(carrier: Carrier) -> Carry {
    match carrier {
        Carrier::Chart => Carry::Chart,
        Carrier::Table => Carry::Table,
        Carrier::Share => Carry::Share,
    }
}

/// A placeholder or ordinary area a block may go into.
#[derive(Debug, Clone, Copy)]
pub(super) struct Room<'t> {
    pub(super) bounds: Rect,
    pub(super) suits: Suits,
    text: Option<&'t Metrics>,
    ordinary: Option<&'t Metrics>,
}

/// An estimate that `need` fits `room`: the carry it takes and the height it
/// needs. Data takes the first of its carriers that fits.
pub(super) fn fit(need: &Need<'_>, room: &Room<'_>) -> Option<(Carry, i64)> {
    let bounds = room.bounds;
    let within = |height: i64| (height <= bounds.cy).then_some(height);
    match need {
        Need::Title(text) if room.suits.title => {
            let height = room.text?.height(&[(*text).to_owned()], bounds.cx)?;
            within(height).map(|height| (Carry::Title, height))
        }
        Need::Text(paragraphs) if room.suits.text => {
            let height = room.text?.height(paragraphs, bounds.cx)?;
            within(height).map(|height| (Carry::Text, height))
        }
        Need::Data { dataset, carriers } => carriers.iter().find_map(|&carrier| {
            let carry = carry(carrier);
            if !room.suits.takes(carry) {
                return None;
            }
            let (dataset, metrics) = ((*dataset)?, room.ordinary?);
            let height = match carrier {
                Carrier::Table => table_height(dataset, metrics, bounds)?,
                Carrier::Chart => chart_height(dataset, metrics, bounds.cx)?,
                Carrier::Share => share_height(dataset, metrics, bounds.cx)?,
            };
            within(height).map(|height| (carry, height))
        }),
        Need::Picture if room.suits.picture => Some((Carry::Picture, 0)),
        _ => None,
    }
}

/// The face that measured `need` in `room` as `carry`, when one measured all
/// of its text; `None` means the em rule estimated it.
pub(super) fn measured(need: &Need<'_>, room: &Room<'_>, carry: Carry) -> Option<String> {
    match (need, carry) {
        (Need::Title(text), _) => room.text?.measured(&[*text]),
        (Need::Text(paragraphs), _) => room.text?.measured(paragraphs),
        (
            Need::Data {
                dataset: Some(dataset),
                ..
            },
            Carry::Table,
        ) => {
            // The table's displayed text, as creation writes it (FIX 8577).
            let layout = TableLayout::of(dataset, &dataset.merges).ok()?;
            let texts: Vec<&str> = layout.text.iter().flatten().map(String::as_str).collect();
            room.ordinary?.measured(&texts)
        }
        (
            Need::Data {
                dataset: Some(dataset),
                ..
            },
            Carry::Chart | Carry::Share,
        ) => {
            let texts: Vec<String> = dataset
                .columns
                .iter()
                .map(|column| column.name.clone())
                .chain(dataset.rows.iter().flatten().map(cell_text))
                .collect();
            room.ordinary?.measured(&texts)
        }
        _ => None,
    }
}

/// The height a native table needs in `bounds` (FIX 8577), measured on the
/// table creation writes there: the same displayed text, equal columns and
/// rows with the remainder last, each shown cell over its whole merged
/// rectangle inside the cell margins, and covered cells showing nothing. A
/// row needs its tallest one-row cell; a cell merged down needs its rows
/// together, any shortfall going to its last row. PowerPoint grows a row
/// past its share of the frame, so when one would grow the grown table's
/// height is returned and the room does not take it; otherwise the height
/// its content needs.
fn table_height(dataset: &Dataset, metrics: &Metrics, bounds: Rect) -> Option<i64> {
    let [left, top, right, bottom] = DEFAULT_INSETS;
    let layout = TableLayout::of(dataset, &dataset.merges).ok()?;
    let widths = grid(bounds.cx, layout.cols())?;
    let shares = grid(bounds.cy, layout.rows())?;
    let mut rows = vec![0_i64; shares.len()];
    let mut down = Vec::new();
    for (row, col, span_rows, span_cols, text) in layout.shown() {
        let width: i64 = widths[col..col + span_cols].iter().sum();
        let need =
            metrics.lines(text, (width - left - right).max(1)) * metrics.line() + top + bottom;
        if span_rows == 1 {
            rows[row] = rows[row].max(need);
        } else {
            down.push((row, span_rows, need));
        }
    }
    let settled = |mut heights: Vec<i64>| -> i64 {
        for &(row, span, need) in &down {
            let held: i64 = heights[row..row + span].iter().sum();
            if need > held {
                heights[row + span - 1] += need - held;
            }
        }
        heights.iter().sum()
    };
    let grown = settled(
        shares
            .iter()
            .zip(&rows)
            .map(|(share, need)| *share.max(need))
            .collect(),
    );
    if grown > bounds.cy {
        return Some(grown);
    }
    Some(settled(rows))
}

/// A floor, not a layout: each category needs a line of width, the plot a
/// few lines of height.
fn chart_height(dataset: &Dataset, metrics: &Metrics, width: i64) -> Option<i64> {
    let categories = i64::try_from(dataset.rows.len()).ok()?;
    (categories * metrics.line() <= width).then_some(CHART_LINES * metrics.line())
}

/// A pie needs a square of its plot floor beside a legend line per part.
fn share_height(dataset: &Dataset, metrics: &Metrics, width: i64) -> Option<i64> {
    let parts = i64::try_from(dataset.rows.len()).ok()?;
    let plot = CHART_LINES * metrics.line();
    (plot * 2 <= width).then_some(plot.max(parts * metrics.line()))
}

fn cell_text(cell: &Cell) -> String {
    match cell {
        Cell::Missing => String::new(),
        Cell::Number(number) => number.to_string(),
        Cell::Text(text) | Cell::Date(text) => text.clone(),
    }
}
