//! Office body records and side-table bindings.
//! Entry: `OfficeBodyHead`.
//! Definitions live here; office_body forwards their original names.

use super::*;

/// Each artifact's office facts: its format and the version it imported.
pub(super) const SOURCES: SideTable<EntityId, OfficeBodySource, Named> =
    SideTable::new(&side_table::OFFICE_BODY_HEAD);

/// Deck forks' office records (the run each belongs to), by artifact and
/// fork; the fork's document is its typed-body fork.
pub(super) const FORKS: SideTable<(EntityId, EntityId), OfficeBodyFork, Named> =
    SideTable::new(&side_table::OFFICE_BODY_FORK);

pub(super) const EXPORTS: SideTable<Vec<u8>, OfficeBodyExportRecord, Named> =
    SideTable::new(&side_table::OFFICE_BODY_EXPORT);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeBodyKind {
    Docx,
    Xlsx,
    Pptx,
}

impl OfficeBodyKind {
    /// The body's typed-body schema tag.
    pub(super) fn schema(self) -> &'static str {
        match self {
            Self::Docx => "office.docx.v1",
            Self::Xlsx => "office.xlsx.v1",
            Self::Pptx => "office.pptx.v1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct OfficeBodySource {
    pub(super) kind: OfficeBodyKind,
    pub(super) source_version: u64,
    pub(super) source_hash: [u8; 32],
}

/// One artifact's live body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyHead {
    pub artifact: EntityId,
    pub kind: OfficeBodyKind,
    /// The imported version every export projects onto.
    pub source_version: u64,
    pub source_hash: [u8; 32],
    /// The body as imported: every export's base.
    pub import_frontier: Vec<u8>,
    pub frontier: Vec<u8>,
    /// Commits on the body so far, merged forks' included.
    pub commits: u64,
}

/// One call's commit: the new frontier, the ids it minted in operation order
/// (paragraphs, deck nodes; none for a workbook), its receipt, and what the
/// operations adapted so the document stays one its application opens
/// (a workbook's sheet shown or added to keep one visible).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyEdit {
    pub frontier: Vec<u8>,
    pub minted: Vec<String>,
    pub receipt: TextCommitReceipt,
    pub effects: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ForkState {
    Open,
    Merged {
        by: BodyActor,
        at: u64,
        head: Vec<u8>,
    },
    Discarded {
        by: BodyActor,
        at: u64,
    },
}

/// Machine work on a body: opened at a live frontier, written only by its opener,
/// merged by someone else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyFork {
    pub id: EntityId,
    pub artifact: EntityId,
    pub opener: BodyActor,
    pub base: Vec<u8>,
    pub commits: u64,
    pub opened_at: u64,
    pub state: ForkState,
    /// The run the fork belongs to, whose approve-all scope covers it.
    #[serde(default)]
    pub run_root: Option<EntityId>,
}

pub struct OfficeBodyExportRequest<'a> {
    pub actor: WriteActor,
    /// The revision author a DOCX export shows; recorded for every export.
    /// `None` shows the exporting actor, whose DOCX bytes hold a token
    /// instead (FIX 4513).
    pub author: Option<&'a str>,
    pub run_ref: &'a str,
    /// The envelope the export version carries; `None` gives it the
    /// exporter's own.
    pub made_by: Option<&'a MadeBy>,
    /// The local time a workbook recalculates at.
    pub zone: &'a OfficeRecalcZone,
}

/// The local time a workbook export or preview recalculates TODAY() and
/// NOW() at, as the caller's device knows it: its offset east of UTC now,
/// and the IANA zone it read that from, kept as a label. The vault keeps no
/// owner zone; a caller that names none gets the default, UTC (FIX 790).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OfficeRecalcZone {
    pub utc_offset_minutes: i16,
    pub iana_timezone: Option<String>,
}

impl OfficeRecalcZone {
    /// The caller's zone, checked as an outbound schedule's is: a zone label
    /// comes with its offset, and an offset is within ±14 hours.
    pub fn from_caller(
        utc_offset_minutes: Option<i16>,
        iana_timezone: Option<String>,
    ) -> Result<Self> {
        if iana_timezone.is_some() && utc_offset_minutes.is_none() {
            return Err(invalid("iana_timezone requires utc_offset_minutes"));
        }
        let utc_offset_minutes = utc_offset_minutes.unwrap_or_default();
        if !(-840..=840).contains(&utc_offset_minutes) {
            return Err(invalid("utc_offset_minutes must be in -840..=840"));
        }
        if iana_timezone.as_deref().is_some_and(|label| {
            label.trim().is_empty() || label.chars().any(char::is_control) || label.len() > 255
        }) {
            return Err(invalid(
                "iana_timezone must be non-blank and contain no controls",
            ));
        }
        Ok(Self {
            utc_offset_minutes,
            iana_timezone,
        })
    }
}

/// An export version and the exact body it projects. The version keeps a
/// pointer to its body frontier, not a second body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyExportRecord {
    pub artifact: EntityId,
    pub version: u64,
    pub frontier: Vec<u8>,
    pub source_version: u64,
    pub actor: BodyActor,
    /// The author the export showed; empty once its actor was erased.
    pub author: String,
    /// The token a DOCX export with no author carries in its bytes in place
    /// of its actor; `None` for an author the caller gave and every other
    /// format (FIX 4513).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub at: u64,
    pub changes: u64,
    /// The engine that recalculated an XLSX export and the local time it
    /// read; `None` when the file recalculates on open, and for DOCX.
    pub recalc: Option<String>,
    /// What the projection adapted, as Excel would, so the file stays one
    /// its application opens: a pivot cache whose source went keeps its
    /// cached results, a picture whose cells were deleted collapses, a note
    /// goes with its cell. One line each; none for DOCX.
    pub effects: Vec<String>,
}

/// `version` is `None` when the body equals its import: a no-op keeps the
/// original package and lands nothing.
#[derive(Debug, Clone)]
pub struct OfficeBodyExport {
    pub frontier: Vec<u8>,
    pub version: Option<BlobArtifactVersion>,
    pub record: Option<OfficeBodyExportRecord>,
}

/// The workbook an XLSX export would land now, recalculated, read back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XlsxPreview {
    pub frontier: Vec<u8>,
    pub book: XlsxBook,
    /// The engine that recalculated it and the local time it read; `None`
    /// when it could not, and formula values are blank until the file is
    /// opened.
    pub recalc: Option<String>,
}

/// One `vault.artifacts.body.read` projection (OF-067, FIX 2939): the view,
/// with the keys the lifted texts it may show hold and their custody
/// records, read in the one snapshot the view was read in.
pub(super) struct OfficeBodyRead {
    pub(super) view: OfficeBodyView,
    pub(super) keys: LiftedKeys,
    pub(super) lifted: LiftedSources,
}
