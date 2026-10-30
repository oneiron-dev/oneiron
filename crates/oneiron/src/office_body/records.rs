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
    /// The run its opener named when it opened the fork: a label, never
    /// what a scope matches (FIX 3551).
    #[serde(default)]
    pub run_root: Option<EntityId>,
    /// The try the fork was opened from, which the host bound the opening
    /// surface to and the opening writer proved live (FIX 3551): the run
    /// whose approve-all scope covers it. `None` for an owner's or a direct
    /// opening, which belongs to no run.
    #[serde(default)]
    pub origin: Option<crate::attempt_queue::AttemptId>,
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The zone its caller named for TODAY() and NOW(); `None` for a deck
    /// export (FIX 12183).
    pub recalc_zone: Option<OfficeRecalcZone>,
    /// What the projection adapted, as Excel would, so the file stays one
    /// its application opens: a pivot cache whose source went keeps its
    /// cached results, a picture whose cells were deleted collapses, a note
    /// goes with its cell. One line each; none for DOCX.
    pub effects: Vec<String>,
}

impl OfficeBodyExportRecord {
    /// The export's own recalculation clock: the time it exported at, in
    /// the zone its caller named. `None` for a deck export, which keeps
    /// no zone (FIX 12183).
    pub(super) fn recalc_clock(&self) -> Option<(u64, OfficeRecalcZone)> {
        self.recalc_zone.clone().map(|zone| (self.at, zone))
    }
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

/// Why two copies of one proposal's header do not merge.
#[cfg(feature = "sync")]
const OTHER_HEADER: &str = "the proposal's header differs";

/// Two copies of one actor field as one: the same actor, or no one when
/// either copy names no one, since an erase wins (FIX 3520). `None` when
/// they name two actors.
#[cfg(feature = "sync")]
fn met(ours: BodyActor, theirs: BodyActor) -> Option<BodyActor> {
    match (ours, theirs) {
        _ if ours == theirs => Some(ours),
        (BodyActor::Erased, _) | (_, BodyActor::Erased) => Some(BodyActor::Erased),
        _ => None,
    }
}

/// Two copies of one member's answer as one; `None` when they differ.
#[cfg(feature = "sync")]
fn merged_answer(ours: &MemberAnswer, theirs: &MemberAnswer) -> Option<MemberAnswer> {
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
fn merged_member(ours: &ProposalMember, theirs: &ProposalMember) -> Option<ProposalMember> {
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

/// `ours` and `theirs`, two copies of one proposal, as one (FIX 2691):
/// members union by fork, a member's decision beats its waiting, asks union
/// by ask group, and a settled proposal beats an open one. A merge that
/// leaves no member waiting closes the proposal at its last answer, so every
/// machine closes it alike (a call; canon is silent). `Err` names why the
/// copies diverge: another header, two decisions on one member, two
/// settlements, or a settlement beside a member that still waits.
#[cfg(feature = "sync")]
fn merged_proposal(
    ours: &OfficeBodyProposal,
    theirs: &OfficeBodyProposal,
) -> std::result::Result<OfficeBodyProposal, &'static str> {
    let opener = met(ours.header.opener, theirs.header.opener).ok_or(OTHER_HEADER)?;
    let header = ProposalHeader {
        opener: ours.header.opener,
        ..theirs.header.clone()
    };
    if header != ours.header {
        return Err(OTHER_HEADER);
    }
    let mut merged = ours.clone();
    merged.header.opener = opener;
    for member in &theirs.members {
        match merged
            .members
            .iter_mut()
            .find(|held| held.fork == member.fork)
        {
            Some(held) => {
                *held = merged_member(held, member).ok_or("two decisions on one member differ")?;
            }
            None => merged.members.push(member.clone()),
        }
    }
    for ask in &theirs.asks {
        if !merged.asks.iter().any(|held| held.ask == ask.ask) {
            merged.asks.push(ask.clone());
        }
    }
    merged.asks.sort_by_key(|ask| (ask.at, ask.ask));
    merged.ask_refused = match (&ours.ask_refused, &theirs.ask_refused) {
        (Some(a), Some(b)) if (b.at, &b.reason) > (a.at, &a.reason) => Some(b.clone()),
        (a, b) => a.clone().or_else(|| b.clone()),
    };
    // An ask raised since the refusal clears it, as it does here.
    if merged
        .ask_refused
        .as_ref()
        .is_some_and(|refused| merged.asks.iter().any(|ask| ask.at >= refused.at))
    {
        merged.ask_refused = None;
    }
    merged.settlement = match (&ours.settlement, &theirs.settlement) {
        (Some(a), Some(b)) if a != b => return Err("two settlements differ"),
        (a, b) => a.clone().or_else(|| b.clone()),
    };
    let waits = merged
        .members
        .iter()
        .any(|member| member.verdict == MemberVerdict::Waiting);
    if waits && merged.settlement.is_some() {
        return Err("a settled proposal holds a member that still waits");
    }
    if !waits {
        let at = merged
            .members
            .iter()
            .filter_map(|member| member.answer.as_ref().map(|answer| answer.at))
            .max()
            .unwrap_or(merged.header.opened_at);
        consent::close_if_done(&mut merged, at, None);
    }
    Ok(merged)
}

#[cfg(feature = "sync")]
impl OfficeBodyProposal {
    /// Whether this copy holds all of `other`, a copy of the same proposal:
    /// merging `other` into it changes nothing (FIX 2691).
    pub(crate) fn covers(&self, other: &Self) -> bool {
        merged_proposal(self, other).is_ok_and(|merged| merged == *self)
    }

    /// This copy as this vault holds a carried one: naming no one where this
    /// vault erased an actor, and without a waiting member such an actor
    /// opened, as the erase leaves a proposal here (FIX 3520). `None` when no
    /// member is left.
    pub(crate) fn carried_here(mut self, vault: &Vault, txn: &RoTxn<'_>) -> Result<Option<Self>> {
        let erased = |actor: &mut BodyActor| -> Result<bool> {
            let gone = match actor.id() {
                Some(id) => vault.carrier_actor_erased_in_txn(txn, &id)?,
                None => false,
            };
            if gone {
                *actor = BodyActor::Erased;
            }
            Ok(gone)
        };
        erased(&mut self.header.opener)?;
        let mut members = Vec::with_capacity(self.members.len());
        for mut member in self.members {
            if erased(&mut member.opener)? && member.verdict == MemberVerdict::Waiting {
                continue;
            }
            if let Some(answer) = &mut member.answer {
                erased(&mut answer.caller)?;
                if let AnsweringAuthority::Word { person } = &mut answer.by {
                    erased(person)?;
                }
            }
            members.push(member);
        }
        self.members = members;
        Ok((!self.members.is_empty()).then_some(self))
    }
}

#[cfg(feature = "sync")]
impl Vault {
    /// Each office proposal on `artifact`, read in `txn`: what a window
    /// carries beside the artifact (FIX 2691).
    pub(crate) fn office_proposals_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
    ) -> Result<Vec<OfficeBodyProposal>> {
        Ok(consent::PROPOSALS
            .scan_from(&self.store, txn, artifact.as_bytes())?
            .into_iter()
            .map(|(_, record)| record)
            .collect())
    }

    /// Merges `carried`, another machine's copy of a proposal, into this
    /// vault's in the caller's writer (FIX 2691), as [`merged_proposal`]
    /// merges two copies. It writes the proposal and the membership of each
    /// of its forks and nothing else: no holder is asked, no fork lands or
    /// goes, no grant is used. A copy whose artifact has not landed here
    /// waits; one whose artifact this vault deleted or erased is refused and
    /// never brings it back. A copy that diverges from this vault's, or that
    /// holds a fork another proposal here holds, conflicts, and the one held
    /// here stands.
    pub(crate) fn merge_carried_office_proposal_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        carried: &OfficeBodyProposal,
    ) -> Result<crate::entity_doc::DocumentMerge> {
        use crate::entity_doc::DocumentMerge;
        use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
        let artifact = carried.header.artifact;
        if crate::ports::removed_in_txn(&self.store, wtxn, &artifact)? {
            return Ok(DocumentMerge::Refused("its artifact is removed here"));
        }
        match live_entity_row_in_txn(&self.store, wtxn, &artifact)? {
            LiveEntityRow::Live { .. } => {}
            LiveEntityRow::Absent => return Ok(DocumentMerge::Waiting),
            LiveEntityRow::DeletedShell => {
                return Ok(DocumentMerge::Refused("its artifact is deleted here"));
            }
        }
        let Some(carried) = carried.clone().carried_here(self, wtxn)? else {
            return Ok(DocumentMerge::Held);
        };
        let key = (artifact, carried.header.proposal);
        let merged = match consent::PROPOSALS.get(&self.store, wtxn, &key)? {
            None => carried,
            Some(held) => match merged_proposal(&held, &carried) {
                Ok(merged) if merged == held => return Ok(DocumentMerge::Held),
                Ok(merged) => merged,
                Err(reason) => {
                    tracing::warn!(
                        artifact = %artifact.to_hex(),
                        proposal = %key.1.to_hex(),
                        reason,
                        "a carried office proposal diverges from the one held here"
                    );
                    return Ok(DocumentMerge::Conflict);
                }
            },
        };
        for member in &merged.members {
            let joined = consent::MEMBERSHIP.get(&self.store, wtxn, &(artifact, member.fork))?;
            if joined.is_some_and(|joined| joined != key.1) {
                tracing::warn!(
                    artifact = %artifact.to_hex(),
                    proposal = %key.1.to_hex(),
                    "a carried office proposal holds a fork another proposal here holds"
                );
                return Ok(DocumentMerge::Conflict);
            }
        }
        consent::PROPOSALS.put(&self.store, wtxn, &key, &merged)?;
        for member in &merged.members {
            consent::MEMBERSHIP.put(&self.store, wtxn, &(artifact, member.fork), &key.1)?;
        }
        Ok(DocumentMerge::Written)
    }

    /// The office facts a body's sync frame carries beside its frontiers
    /// (FIX 2458): its format and the package version it imported, so the
    /// machine that takes the body reads it as the office body it is. `None`
    /// for an entity with no office body.
    pub(crate) fn office_frame_record_in_txn(
        &self,
        txn: &RoTxn<'_>,
        artifact: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        SOURCES
            .get(&self.store, txn, artifact)?
            .map(|source| {
                rmp_serde::to_vec_named(&source).map_err(|_| invalid("office body source encode"))
            })
            .transpose()
    }

    /// Installs `record`, the office facts a carried body's frame brought,
    /// for `artifact`, whose body of `schema` was born here from that frame
    /// (FIX 2458). Facts this vault holds stand.
    pub(crate) fn adopt_office_frame_record_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        artifact: &EntityId,
        schema: &str,
        record: &[u8],
    ) -> Result<()> {
        if record.is_empty() || SOURCES.contains(&self.store, wtxn, artifact)? {
            return Ok(());
        }
        let source: OfficeBodySource =
            rmp_serde::from_slice(record).map_err(|_| invalid("office body frame source"))?;
        if source.kind.schema() != schema {
            return Err(invalid(
                "an office body frame's source names another format",
            ));
        }
        SOURCES.put(&self.store, wtxn, artifact, &source)
    }

    /// The office merge preflight a carried body's operations pass before
    /// they land on the head here (FIX 2458): the merged body still reads as
    /// its format, and, for a DOCX or XLSX body, the carried head's changes
    /// since the frontier both hold block nothing and meet no block or cell
    /// the head changed too, as a reviewed fork's must to land. A deck's
    /// operations merge as its tree allows. `false` opens a fork the owner
    /// resolves; a schema no office body has lands as merged.
    pub(crate) fn preflight_carried_office_body(
        &self,
        schema: &str,
        carried: &crate::typed_body::sync_frame::CarriedBody<'_>,
    ) -> Result<bool> {
        let kinds = [
            OfficeBodyKind::Docx,
            OfficeBodyKind::Xlsx,
            OfficeBodyKind::Pptx,
        ];
        let Some(kind) = kinds.into_iter().find(|kind| kind.schema() == schema) else {
            return Ok(true);
        };
        if validate(kind, carried.merged).is_err() {
            return Ok(false);
        }
        if kind == OfficeBodyKind::Pptx {
            return Ok(true);
        }
        let diff = three_way(
            kind,
            carried.live,
            carried.theirs,
            carried.base,
            carried.head,
        )?;
        Ok(!diff.blocking()
            && !diff
                .conflicts
                .iter()
                .any(|conflict| conflict.kind == ConflictKind::BothEdited))
    }
}
