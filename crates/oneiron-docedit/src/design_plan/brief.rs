//! The brief: the kept, typed outline a design is compiled from (ARCH-0077,
//! "Create: an approved argument, then a design"). The schema is closed.
//! Design choices (coordinates, shape counts, font sizes, master or layout
//! names, decorative geometry, chart styling) have no field, and a key the
//! schema does not name is refused with its JSON Pointer path.
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// Why a brief cannot be compiled. Every path is a JSON Pointer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BriefError {
    #[error("the brief is not JSON")]
    Json,
    #[error("field not in the brief schema: {path}")]
    UnknownField { path: String },
    #[error("missing brief field: {path}")]
    Missing { path: String },
    #[error("brief value has the wrong type or is not allowed: {path}")]
    Invalid { path: String },
    #[error("empty brief value: {path}")]
    Empty { path: String },
    #[error("brief id used twice: {id}")]
    DuplicateId { id: String },
    #[error("brief names an unknown id: {path}")]
    UnknownReference { path: String },
    #[error("page has a second title: {path}")]
    SecondTitle { path: String },
    #[error("evidence quote does not match its hash: {path}")]
    QuoteHash { path: String },
    #[error("number column has no unit: {path}")]
    MissingUnit { path: String },
    #[error("only number columns carry a unit: {path}")]
    UnexpectedUnit { path: String },
    #[error("cell does not match its column: {path}")]
    Cell { path: String },
    #[error("missing cell in a dataset without a missing-value meaning: {path}")]
    MissingMeaning { path: String },
    #[error("carrier cannot express this dataset: {path}")]
    Carrier { path: String },
}

/// The outline fields of ARCH-0077's brief table.
#[derive(Debug, Clone, PartialEq)]
pub struct Brief {
    pub communication: Communication,
    /// The explicit language requirement (a language tag).
    pub language: String,
    /// Explicit accessibility requirements, carried to emission.
    pub accessibility: Vec<String>,
    /// Pages in argument order.
    pub pages: Vec<Page>,
    pub datasets: Vec<Dataset>,
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Communication {
    pub audience: String,
    pub outcome: String,
    pub main_message: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Page {
    pub id: String,
    /// What the page does in the argument; never read to choose a layout.
    pub job: String,
    pub division: Division,
    /// Blocks in argument order.
    pub blocks: Vec<Block>,
}

/// Whether a page may become several slides. Absent means fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Division {
    Fixed,
    Split,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub id: String,
    pub priority: Priority,
    pub content: BlockContent,
}

/// Absent means required: only content marked optional may be left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Required,
    Optional,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BlockContent {
    /// The page's headline; at most one per page.
    Title {
        text: String,
    },
    /// A claim with its evidence pins and the qualifications that must be
    /// shown with it.
    Claim {
        text: String,
        qualifications: Vec<String>,
        evidence: Vec<Pin>,
    },
    /// A dataset and the carriers that may express it, in preference order;
    /// alternatives stay open until design.
    Data {
        dataset: String,
        carriers: Vec<Carrier>,
    },
    Asset {
        asset: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    Chart,
    Table,
    /// Parts of one whole: a pie of one series.
    Share,
}

/// An evidence pin as the brief keeps it: document, version, cursor span and
/// the quote with its BLAKE3 hash. Cursors and versions are opaque here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// The cited CLAIM, when the engine maps the pin's cursors itself.
    pub claim: Option<String>,
    pub document: String,
    pub version: String,
    pub start: String,
    pub end: String,
    pub quote: String,
    pub quote_hash: [u8; 32],
    /// The cursors no longer map; the quote is kept.
    pub drift: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Dataset {
    pub id: String,
    pub columns: Vec<Column>,
    /// Rectangular: every row has one cell per column.
    pub rows: Vec<Vec<Cell>>,
    /// What a missing cell means; required when any cell is missing.
    pub missing: Option<String>,
    pub sources: Vec<String>,
    /// Merge rectangles over the table grid, header row 0 included. A
    /// merge covers data rows only; its continuation cells are `null`.
    pub merges: Vec<crate::native_patch::Merge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub name: String,
    pub kind: ColumnKind,
    /// Required on number columns, refused on the others.
    pub unit: Option<String>,
    /// How a number column shows its values; refused on the others.
    pub format: Option<NumberFormat>,
}

impl Column {
    /// A number as this column shows it.
    #[must_use]
    pub fn display(&self, value: f64) -> String {
        self.format.map_or_else(
            || crate::native_patch::number(value),
            |format| format.render(value),
        )
    }
}

/// A number column's display: fixed decimals, optional thousands grouping,
/// and percent, where the value is a fraction shown times one hundred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumberFormat {
    pub decimals: u8,
    pub grouping: bool,
    pub percent: bool,
}

impl NumberFormat {
    pub const MAX_DECIMALS: u8 = 10;

    /// The SpreadsheetML format code, such as `#,##0.00` or `0.0%`.
    #[must_use]
    pub fn code(&self) -> String {
        let whole = if self.grouping { "#,##0" } else { "0" };
        let fraction = if self.decimals > 0 {
            format!(".{}", "0".repeat(usize::from(self.decimals)))
        } else {
            String::new()
        };
        let percent = if self.percent { "%" } else { "" };
        format!("{whole}{fraction}{percent}")
    }

    /// The value as the code shows it.
    #[must_use]
    pub fn render(&self, value: f64) -> String {
        let shown = if self.percent { value * 100.0 } else { value };
        let text = format!("{shown:.*}", usize::from(self.decimals));
        let text = if self.grouping { group(&text) } else { text };
        if self.percent {
            format!("{text}%")
        } else {
            text
        }
    }
}

/// Thousands separators in the whole part of a formatted number.
fn group(text: &str) -> String {
    let (sign, rest) = text
        .strip_prefix('-')
        .map_or(("", text), |rest| ("-", rest));
    let (whole, fraction) = rest
        .split_once('.')
        .map_or((rest, None), |(w, f)| (w, Some(f)));
    let mut grouped = String::new();
    for (index, digit) in whole.chars().enumerate() {
        if index > 0 && (whole.len() - index) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    match fraction {
        Some(fraction) => format!("{sign}{grouped}.{fraction}"),
        None => format!("{sign}{grouped}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnKind {
    Number,
    Text,
    /// ISO 8601 calendar dates (`2026-01-31`).
    Date,
}

/// A missing cell is not zero.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Missing,
    Number(f64),
    Text(String),
    Date(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub id: String,
    pub kind: AssetKind,
    /// The intended factual content.
    pub content: String,
}

/// Factual diagrams and illustrations are kept apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetKind {
    Factual,
    Illustration,
}

impl Brief {
    /// Parse and check a brief: the closed schema, then content, references,
    /// units, cells and pins.
    pub fn parse(bytes: &[u8]) -> Result<Self, BriefError> {
        let value: Value = serde_json::from_slice(bytes).map_err(|_| BriefError::Json)?;
        let top = Fields::new(
            &value,
            "",
            &[
                "communication",
                "language",
                "accessibility",
                "pages",
                "datasets",
                "assets",
            ],
        )?;
        let communication = {
            let path = top.at("communication");
            let fields = Fields::new(
                top.get("communication")?,
                &path,
                &["audience", "outcome", "main_message"],
            )?;
            Communication {
                audience: fields.text("audience")?,
                outcome: fields.text("outcome")?,
                main_message: fields.text("main_message")?,
            }
        };
        let datasets = top
            .optional_list("datasets")?
            .into_iter()
            .map(|(path, value)| dataset(value, &path))
            .collect::<Result<Vec<_>, _>>()?;
        let assets = top
            .optional_list("assets")?
            .into_iter()
            .map(|(path, value)| asset(value, &path))
            .collect::<Result<Vec<_>, _>>()?;
        let pages = top
            .list("pages")?
            .into_iter()
            .map(|(path, value)| page(value, &path, &datasets, &assets))
            .collect::<Result<Vec<_>, _>>()?;
        let brief = Self {
            communication,
            language: top.text("language")?,
            accessibility: top
                .optional_list("accessibility")?
                .into_iter()
                .map(|(path, value)| text(value, &path))
                .collect::<Result<_, _>>()?,
            pages,
            datasets,
            assets,
        };
        brief.unique_ids()?;
        Ok(brief)
    }

    /// The page and block with this block id.
    pub fn block(&self, id: &str) -> Option<(&Page, &Block)> {
        self.pages.iter().find_map(|page| {
            page.blocks
                .iter()
                .find(|block| block.id == id)
                .map(|block| (page, block))
        })
    }

    pub fn dataset(&self, id: &str) -> Option<&Dataset> {
        self.datasets.iter().find(|dataset| dataset.id == id)
    }

    /// Pages, blocks, datasets and assets share one id space.
    fn unique_ids(&self) -> Result<(), BriefError> {
        let mut seen = BTreeSet::new();
        let ids = self.pages.iter().flat_map(|page| {
            std::iter::once(page.id.as_str())
                .chain(page.blocks.iter().map(|block| block.id.as_str()))
        });
        let ids = ids
            .chain(self.datasets.iter().map(|dataset| dataset.id.as_str()))
            .chain(self.assets.iter().map(|asset| asset.id.as_str()));
        for id in ids {
            if !seen.insert(id) {
                return Err(BriefError::DuplicateId { id: id.to_owned() });
            }
        }
        Ok(())
    }
}

/// One JSON object read against its closed key set.
struct Fields<'v> {
    path: String,
    map: &'v Map<String, Value>,
}

impl<'v> Fields<'v> {
    fn new(value: &'v Value, path: &str, allowed: &[&str]) -> Result<Self, BriefError> {
        let map = value.as_object().ok_or_else(|| invalid(path))?;
        if let Some(key) = map.keys().find(|key| !allowed.contains(&key.as_str())) {
            return Err(BriefError::UnknownField {
                path: pointer(path, key),
            });
        }
        Ok(Self {
            path: path.to_owned(),
            map,
        })
    }

    fn at(&self, key: &str) -> String {
        pointer(&self.path, key)
    }

    fn get(&self, key: &str) -> Result<&'v Value, BriefError> {
        self.map
            .get(key)
            .ok_or_else(|| BriefError::Missing { path: self.at(key) })
    }

    fn text(&self, key: &str) -> Result<String, BriefError> {
        text(self.get(key)?, &self.at(key))
    }

    fn word(&self, key: &str) -> Result<Option<&'v str>, BriefError> {
        self.map
            .get(key)
            .map(|value| value.as_str().ok_or_else(|| invalid(&self.at(key))))
            .transpose()
    }

    /// A required, non-empty array with each item's path.
    fn list(&self, key: &str) -> Result<Vec<(String, &'v Value)>, BriefError> {
        let path = self.at(key);
        let items = items(self.get(key)?, &path)?;
        if items.is_empty() {
            return Err(BriefError::Empty { path });
        }
        Ok(items)
    }

    fn optional_list(&self, key: &str) -> Result<Vec<(String, &'v Value)>, BriefError> {
        self.map
            .get(key)
            .map_or(Ok(Vec::new()), |value| items(value, &self.at(key)))
    }
}

fn items<'v>(value: &'v Value, path: &str) -> Result<Vec<(String, &'v Value)>, BriefError> {
    let array = value.as_array().ok_or_else(|| invalid(path))?;
    Ok(array
        .iter()
        .enumerate()
        .map(|(index, item)| (pointer(path, &index.to_string()), item))
        .collect())
}

fn text(value: &Value, path: &str) -> Result<String, BriefError> {
    let text = value.as_str().ok_or_else(|| invalid(path))?;
    if text.trim().is_empty() {
        return Err(BriefError::Empty {
            path: path.to_owned(),
        });
    }
    Ok(text.to_owned())
}

fn invalid(path: &str) -> BriefError {
    BriefError::Invalid {
        path: path.to_owned(),
    }
}

/// RFC 6901: `~` and `/` in a key are escaped.
fn pointer(path: &str, key: &str) -> String {
    format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"))
}

fn page(
    value: &Value,
    path: &str,
    datasets: &[Dataset],
    assets: &[Asset],
) -> Result<Page, BriefError> {
    let fields = Fields::new(value, path, &["id", "job", "division", "blocks"])?;
    let division = match fields.word("division")? {
        None | Some("fixed") => Division::Fixed,
        Some("split") => Division::Split,
        Some(_) => return Err(invalid(&fields.at("division"))),
    };
    let mut blocks = Vec::new();
    for (path, value) in fields.list("blocks")? {
        let block = block(value, &path, datasets, assets)?;
        let titled = |block: &Block| matches!(block.content, BlockContent::Title { .. });
        if titled(&block) && blocks.iter().any(titled) {
            return Err(BriefError::SecondTitle { path });
        }
        blocks.push(block);
    }
    Ok(Page {
        id: fields.text("id")?,
        job: fields.text("job")?,
        division,
        blocks,
    })
}

fn block(
    value: &Value,
    path: &str,
    datasets: &[Dataset],
    assets: &[Asset],
) -> Result<Block, BriefError> {
    if !value.is_object() {
        return Err(invalid(path));
    }
    let kind = value
        .get("kind")
        .ok_or_else(|| BriefError::Missing {
            path: pointer(path, "kind"),
        })?
        .as_str();
    let extra: &[&str] = match kind {
        Some("title") => &["text"],
        Some("claim") => &["text", "qualifications", "evidence"],
        Some("data") => &["dataset", "carriers"],
        Some("asset") => &["asset"],
        _ => return Err(invalid(&pointer(path, "kind"))),
    };
    let allowed: Vec<&str> = ["id", "kind", "priority"]
        .iter()
        .chain(extra)
        .copied()
        .collect();
    let fields = Fields::new(value, path, &allowed)?;
    let priority = match fields.word("priority")? {
        None | Some("required") => Priority::Required,
        Some("optional") => Priority::Optional,
        Some(_) => return Err(invalid(&fields.at("priority"))),
    };
    let content = match kind {
        Some("title") => BlockContent::Title {
            text: fields.text("text")?,
        },
        Some("claim") => BlockContent::Claim {
            text: fields.text("text")?,
            qualifications: fields
                .optional_list("qualifications")?
                .into_iter()
                .map(|(path, value)| text(value, &path))
                .collect::<Result<_, _>>()?,
            evidence: fields
                .list("evidence")?
                .into_iter()
                .map(|(path, value)| pin(value, &path))
                .collect::<Result<_, _>>()?,
        },
        Some("data") => {
            let id = fields.text("dataset")?;
            let dataset = datasets
                .iter()
                .find(|dataset| dataset.id == id)
                .ok_or_else(|| BriefError::UnknownReference {
                    path: fields.at("dataset"),
                })?;
            let mut carriers = Vec::new();
            for (path, value) in fields.list("carriers")? {
                let carrier = match value.as_str() {
                    Some("chart") => Carrier::Chart,
                    Some("table") => Carrier::Table,
                    Some("share") => Carrier::Share,
                    _ => return Err(invalid(&path)),
                };
                if carriers.contains(&carrier) {
                    return Err(invalid(&path));
                }
                if !expresses(carrier, dataset) {
                    return Err(BriefError::Carrier { path });
                }
                carriers.push(carrier);
            }
            BlockContent::Data {
                dataset: id,
                carriers,
            }
        }
        _ => {
            let id = fields.text("asset")?;
            if !assets.iter().any(|asset| asset.id == id) {
                return Err(BriefError::UnknownReference {
                    path: fields.at("asset"),
                });
            }
            BlockContent::Asset { asset: id }
        }
    };
    Ok(Block {
        id: fields.text("id")?,
        priority,
        content,
    })
}

/// A table expresses any dataset with rows; a classic chart needs a text or
/// date category column followed only by number series; a share needs a
/// text category and one number series of present, non-negative parts with
/// a positive whole.
fn expresses(carrier: Carrier, dataset: &Dataset) -> bool {
    if dataset.rows.is_empty() {
        return false;
    }
    match carrier {
        Carrier::Table => true,
        Carrier::Share => match dataset.columns.as_slice() {
            [category, part] => category.kind == ColumnKind::Text
                && part.kind == ColumnKind::Number
                && dataset.rows.iter().all(
                    |row| matches!(row.get(1), Some(Cell::Number(n)) if n.is_finite() && *n >= 0.0),
                )
                && dataset
                    .rows
                    .iter()
                    .filter_map(|row| match row.get(1) {
                        Some(Cell::Number(n)) => Some(*n),
                        _ => None,
                    })
                    .sum::<f64>()
                    > 0.0,
            _ => false,
        },
        Carrier::Chart => match dataset.columns.split_first() {
            Some((category, series)) => {
                category.kind != ColumnKind::Number
                    && !series.is_empty()
                    && series
                        .iter()
                        .all(|column| column.kind == ColumnKind::Number)
            }
            None => false,
        },
    }
}

fn pin(value: &Value, path: &str) -> Result<Pin, BriefError> {
    let fields = Fields::new(
        value,
        path,
        &[
            "claim",
            "document",
            "version",
            "start",
            "end",
            "quote",
            "quote_hash",
            "drift",
        ],
    )?;
    let quote = fields.text("quote")?;
    let hash_path = fields.at("quote_hash");
    let quote_hash = fields
        .get("quote_hash")?
        .as_str()
        .and_then(digest)
        .ok_or_else(|| invalid(&hash_path))?;
    if *blake3::hash(quote.as_bytes()).as_bytes() != quote_hash {
        return Err(BriefError::QuoteHash {
            path: path.to_owned(),
        });
    }
    let drift = match fields.map.get("drift") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| invalid(&fields.at("drift")))?,
    };
    Ok(Pin {
        claim: fields
            .map
            .get("claim")
            .map(|claim| text(claim, &fields.at("claim")))
            .transpose()?,
        document: fields.text("document")?,
        version: fields.text("version")?,
        start: fields.text("start")?,
        end: fields.text("end")?,
        quote,
        quote_hash,
        drift,
    })
}

/// 64 lowercase hex digits.
fn digest(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn asset(value: &Value, path: &str) -> Result<Asset, BriefError> {
    let fields = Fields::new(value, path, &["id", "kind", "content"])?;
    let kind = match fields.word("kind")? {
        Some("factual") => AssetKind::Factual,
        Some("illustration") => AssetKind::Illustration,
        Some(_) => return Err(invalid(&fields.at("kind"))),
        None => {
            return Err(BriefError::Missing {
                path: fields.at("kind"),
            });
        }
    };
    Ok(Asset {
        id: fields.text("id")?,
        kind,
        content: fields.text("content")?,
    })
}

fn dataset(value: &Value, path: &str) -> Result<Dataset, BriefError> {
    let fields = Fields::new(
        value,
        path,
        &["id", "columns", "rows", "missing", "sources", "merges"],
    )?;
    let mut columns = Vec::new();
    for (path, value) in fields.list("columns")? {
        let column = Fields::new(value, &path, &["name", "type", "unit", "format"])?;
        let kind = match column.word("type")? {
            Some("number") => ColumnKind::Number,
            Some("text") => ColumnKind::Text,
            Some("date") => ColumnKind::Date,
            Some(_) => return Err(invalid(&column.at("type"))),
            None => {
                return Err(BriefError::Missing {
                    path: column.at("type"),
                });
            }
        };
        let unit = column
            .map
            .get("unit")
            .map(|unit| text(unit, &column.at("unit")))
            .transpose()?;
        match (kind, &unit) {
            (ColumnKind::Number, None) => return Err(BriefError::MissingUnit { path }),
            (ColumnKind::Text | ColumnKind::Date, Some(_)) => {
                return Err(BriefError::UnexpectedUnit {
                    path: column.at("unit"),
                });
            }
            _ => {}
        }
        let format = match column.map.get("format") {
            None => None,
            Some(_) if kind != ColumnKind::Number => return Err(invalid(&column.at("format"))),
            Some(value) => {
                let path = column.at("format");
                let format = Fields::new(value, &path, &["decimals", "grouping", "percent"])?;
                let flag = |key: &str| -> Result<bool, BriefError> {
                    format.map.get(key).map_or(Ok(false), |value| {
                        value.as_bool().ok_or_else(|| invalid(&format.at(key)))
                    })
                };
                let decimals = match format.map.get("decimals") {
                    None => 0,
                    Some(value) => value
                        .as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .filter(|n| *n <= NumberFormat::MAX_DECIMALS)
                        .ok_or_else(|| invalid(&format.at("decimals")))?,
                };
                Some(NumberFormat {
                    decimals,
                    grouping: flag("grouping")?,
                    percent: flag("percent")?,
                })
            }
        };
        columns.push(Column {
            name: column.text("name")?,
            kind,
            unit,
            format,
        });
    }
    let missing = fields
        .map
        .get("missing")
        .map(|meaning| text(meaning, &fields.at("missing")))
        .transpose()?;
    let height = fields.optional_list("rows")?.len();
    let merges = merges(&fields, height, columns.len())?;
    let continuation = |row: usize, col: usize| {
        merges.iter().any(|merge| {
            (merge.row..merge.row + merge.rows).contains(&(row + 1))
                && (merge.col..merge.col + merge.cols).contains(&col)
                && (merge.row, merge.col) != (row + 1, col)
        })
    };
    let mut rows = Vec::new();
    for (index, (path, value)) in fields.optional_list("rows")?.into_iter().enumerate() {
        let cells = items(value, &path)?;
        if cells.len() != columns.len() {
            return Err(BriefError::Cell { path });
        }
        let row = cells
            .into_iter()
            .zip(&columns)
            .enumerate()
            .map(|(col, ((path, value), column))| {
                if continuation(index, col) {
                    return match value {
                        Value::Null => Ok(Cell::Missing),
                        _ => Err(BriefError::Cell { path }),
                    };
                }
                cell(value, column.kind, path, missing.is_some())
            })
            .collect::<Result<_, _>>()?;
        rows.push(row);
    }
    Ok(Dataset {
        id: fields.text("id")?,
        columns,
        rows,
        missing,
        sources: fields
            .list("sources")?
            .into_iter()
            .map(|(path, value)| text(value, &path))
            .collect::<Result<_, _>>()?,
        merges,
    })
}

/// Merge rectangles over data rows (`row` indexes `rows`), each at least two
/// cells, inside the grid and disjoint; returned on the table grid, where
/// the header is row 0.
fn merges(
    fields: &Fields<'_>,
    height: usize,
    width: usize,
) -> Result<Vec<crate::native_patch::Merge>, BriefError> {
    let mut out: Vec<crate::native_patch::Merge> = Vec::new();
    for (path, value) in fields.optional_list("merges")? {
        let merge = Fields::new(value, &path, &["row", "col", "rows", "cols"])?;
        let number = |key: &str| {
            merge
                .get(key)?
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| invalid(&merge.at(key)))
        };
        let (row, col, rows, cols) = (
            number("row")?,
            number("col")?,
            number("rows")?,
            number("cols")?,
        );
        let inside = rows >= 1
            && cols >= 1
            && rows.saturating_mul(cols) >= 2
            && row.checked_add(rows).is_some_and(|end| end <= height)
            && col.checked_add(cols).is_some_and(|end| end <= width);
        let next = crate::native_patch::Merge {
            row: row + 1,
            col,
            rows,
            cols,
        };
        let overlaps = out.iter().any(|held| {
            next.row < held.row + held.rows
                && held.row < next.row + next.rows
                && next.col < held.col + held.cols
                && held.col < next.col + next.cols
        });
        if !inside || overlaps {
            return Err(invalid(&path));
        }
        out.push(next);
    }
    Ok(out)
}

fn cell(value: &Value, kind: ColumnKind, path: String, meaning: bool) -> Result<Cell, BriefError> {
    let cell = match (kind, value) {
        (_, Value::Null) if meaning => Some(Cell::Missing),
        (_, Value::Null) => return Err(BriefError::MissingMeaning { path }),
        (ColumnKind::Number, Value::Number(number)) => number.as_f64().map(Cell::Number),
        (ColumnKind::Text, Value::String(text)) => Some(Cell::Text(text.clone())),
        (ColumnKind::Date, Value::String(date)) if calendar_date(date).is_some() => {
            Some(Cell::Date(date.clone()))
        }
        _ => None,
    };
    cell.ok_or(BriefError::Cell { path })
}

/// `YYYY-MM-DD` naming a real proleptic Gregorian day: its year, month and
/// day.
pub(crate) fn calendar_date(date: &str) -> Option<(u32, u32, u32)> {
    let bytes = date.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| {
        date.get(range)
            .filter(|digits| digits.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|digits| digits.parse::<u32>().ok())
    };
    let (Some(year), Some(month), Some(day)) = (number(0..4), number(5..7), number(8..10)) else {
        return None;
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    (1..=days).contains(&day).then_some((year, month, day))
}
