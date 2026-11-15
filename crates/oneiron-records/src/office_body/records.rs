//! Moved from `crates/oneiron/src/office_body/records.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::office_body::*;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::typed_body::body_actor::BodyActor;
use oneiron_store::write_envelope::provenance::text_commit::TextCommitReceipt;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeBodyKind {
    Docx,
    Xlsx,
    Pptx,
}

impl OfficeBodyKind {
    /// The body's typed-body schema tag.
    pub fn schema(self) -> &'static str {
        match self {
            Self::Docx => "office.docx.v1",
            Self::Xlsx => "office.xlsx.v1",
            Self::Pptx => "office.pptx.v1",
        }
    }
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
    /// The run its opener named when it opened the fork: a label, never
    /// what a scope matches (FIX 3551).
    #[serde(default)]
    pub run_root: Option<EntityId>,
    /// The try the fork was opened from, which the host bound the opening
    /// surface to and the opening writer proved live (FIX 3551): the run
    /// whose approve-all scope covers it. `None` for an owner's or a direct
    /// opening, which belongs to no run.
    #[serde(default)]
    pub origin: Option<oneiron_store::attempt_id::AttemptId>,
}

/// Why an XLSX export or preview kept its cached values: the formula
/// engine's own stable reason and display words. These fields do not add a
/// vault frontier to the exported file. Mutually exclusive with `recalc`
/// on XLSX paths: success sets the
/// stamp and leaves this `None`, fallback sets this and leaves the stamp
/// `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeRecalcFailure {
    /// The engine's stable reason (`FormulaError::code()`), such as
    /// `engine-error` or `unsupported-workbook`.
    pub code: String,
    /// The engine's display string for this failure.
    pub detail: String,
}

/// A node's ids in a kept deck export whose Keep did not bind the deck
/// (FIX 12346). The held projection's bindings are authoritative for that
/// export even when the live deck was already bound elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldDeckId {
    pub node: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creation_id: Option<String>,
}

/// One consecutive actor group's author binding for a multi-revision DOCX
/// export. `None` is a missing or erased receipt, presented as `erased`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfficeBodyExportAuthor {
    pub actor: Option<EntityId>,
    pub token: String,
}

/// The workbook an XLSX export would land now, recalculated, read back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XlsxPreview {
    pub frontier: Vec<u8>,
    pub book: XlsxBook,
    /// The engine that recalculated it and the local time it read; `None`
    /// when it could not, and then `recalc_failure` names why while formula
    /// values stay the projected package's cached values until the file is
    /// opened.
    pub recalc: Option<String>,
    /// Why this preview kept its cached values instead; `None` when it
    /// recalculated. On fallback each computed cell of `book` carries
    /// `CachedAfterFailure`.
    pub recalc_failure: Option<OfficeRecalcFailure>,
}

/// Why two copies of one proposal's header do not merge.
#[cfg(feature = "sync")]
pub const OTHER_HEADER: &str = "the proposal's header differs";

/// Two copies of one actor field as one: the same actor, or no one when
/// either copy names no one, since an erase wins (FIX 3520). `None` when
/// they name two actors.
#[cfg(feature = "sync")]
pub fn met(ours: BodyActor, theirs: BodyActor) -> Option<BodyActor> {
    match (ours, theirs) {
        _ if ours == theirs => Some(ours),
        (BodyActor::Erased, _) | (_, BodyActor::Erased) => Some(BodyActor::Erased),
        _ => None,
    }
}

/// Two copies of one member's answer as one; `None` when they differ.
#[cfg(feature = "sync")]
pub fn merged_answer(ours: &MemberAnswer, theirs: &MemberAnswer) -> Option<MemberAnswer> {
    let by = match (&ours.by, &theirs.by) {
        (AnsweringAuthority::Word { person: a }, AnsweringAuthority::Word { person: b }) => {
            AnsweringAuthority::Word {
                person: met(*a, *b)?,
            }
        }
        (a, b) if a == b => a.clone(),
        _ => return None,
    };
    let caller = met(ours.caller, theirs.caller)?;
    let merged = MemberAnswer {
        by,
        caller,
        ..ours.clone()
    };
    let other = MemberAnswer {
        by: merged.by.clone(),
        caller,
        ..theirs.clone()
    };
    (other == merged).then_some(merged)
}

/// Two copies of one member as one: a decision beats waiting, and two
/// decisions stand only when they are the same one. `None` when they differ.
#[cfg(feature = "sync")]
pub fn merged_member(ours: &ProposalMember, theirs: &ProposalMember) -> Option<ProposalMember> {
    if ours.run_root != theirs.run_root || ours.origin != theirs.origin {
        return None;
    }
    let opener = met(ours.opener, theirs.opener)?;
    let mut member = match (ours.verdict, theirs.verdict) {
        (MemberVerdict::Waiting, _) => theirs.clone(),
        (_, MemberVerdict::Waiting) => ours.clone(),
        (a, b) if a != b => return None,
        _ => {
            let answer = match (&ours.answer, &theirs.answer) {
                (Some(a), Some(b)) => Some(merged_answer(a, b)?),
                (None, None) => None,
                _ => return None,
            };
            ProposalMember {
                answer,
                ..ours.clone()
            }
        }
    };
    member.opener = opener;
    Some(member)
}
