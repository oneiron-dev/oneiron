//! Standing artifact questions (ARCH-0076, OF-506): a question whose adapter is
//! [`ARTIFACT_ADAPTER`] asks each of its artifacts on the head, once at first, then again
//! when the artifact or a folder item it reads has a newer head that has been quiet for the
//! vault's interval, and when its schedule falls due. Arrivals are found by polling heads
//! against the versions last asked, and live bodies against the frontiers last asked, so
//! an edit never exported arrives too (FIX 2115); no append path is touched. Each ask
//! holds its answers as a fresh proposal for Keep under a ref of its own. While that
//! proposal or a wake's re-ask of it waits, the artifact is not asked again: the edit
//! settle carry splits a held proposal and wakes its proposer. A Keep of one of them moves
//! the head the question follows. An arrival asks again only the units whose reads moved
//! since the versions the question answered (a row's read cells or its header, a
//! paragraph's text, a folder item's file); a schedule asks them all. The ask is the
//! question's principal's, on the question's dial and clock, through the host's decider;
//! an artifact or file the principal cannot read is not asked.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

mod history;
mod ask_selection;
mod live;
mod manual;
mod unit_receipts;

pub use self::history::artifact_ask_records;
pub(super) use self::history::artifact_event_record;
pub use self::manual::refresh_artifact_question_now;
pub use self::unit_receipts::ArtifactUnitReceipt;
pub(crate) use self::unit_receipts::artifact_unit_receipts;

use self::ask_selection::ask_selection;

use serde::{Deserialize, Serialize};

use super::refresh::{hold_failed, standing_asker};
use super::saved_reader::{SavedArtifactReads, saved_artifact_reads};
use super::{records::*, store::*};
use crate::blob_artifact::{ArtifactAskUnits, read_blob_artifact_head_in_txn};
use crate::edit_roundtrip::judgment_cells::named_sheet_cells;
use crate::edit_roundtrip::slides_review::SlideReviewLabels;
use crate::edit_roundtrip::{ArtifactAsk, CellRef, CellValue, FolderItem, RangeRef, UnitDecider};
use crate::edit_settle::PendingProposalView;
use crate::llm::decision::{DecisionBandPolicy, Reversibility};
use crate::office_body::LivePin;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, Error, ErrorKind, Result, Vault, WriteActor};

/// Key: id16(question) + id16(artifact).
pub(super) const ASKED: SideTable<(EntityId, EntityId), ArtifactAsked, Named> =
    SideTable::new(&side_table::TYPED_QUESTION_ARTIFACT_ASKED);

/// One ask's run clock, past which no unit call runs.
const ASK_DEADLINE: Duration = Duration::from_secs(300);

/// The last ask of one artifact for one question: the schedule's projection of the ask
/// log (FIX 2337).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct ArtifactAsked {
    question_version: u32,
    /// Each read artifact's head version when it was asked, the artifact first.
    pub(super) versions: Vec<(EntityId, u64)>,
    asked_at: u64,
    /// The proposal its answers wait under; none when no unit was answered.
    proposal_ref: Option<String>,
    /// The logged ask this stamp projects; none on a stamp written before asks were
    /// logged one by one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ask_id: Option<EntityId>,
    /// Each read artifact's live body when it was asked, those with one: an edit to it
    /// never exported moves no version, and arrives as a move of the body (FIX 2115).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    live: Vec<(EntityId, LivePin)>,
}

/// One question a pass could not ask, at the artifact it stopped on; it is held, then
/// asked again.
pub struct ArtifactRefreshFailure {
    pub question: EntityId,
    pub artifact: Option<EntityId>,
    pub error: Error,
}

/// The proposals one pass held for Keep, and the questions that failed.
#[derive(Default)]
pub struct ArtifactRefreshBatch {
    pub proposed: Vec<PendingProposalView>,
    pub failures: Vec<ArtifactRefreshFailure>,
}

/// A selection's units, resolved.
enum Selection<'a> {
    SheetRows {
        sheet: &'a str,
        rows: RangeRef,
        answer_col: u32,
        header_row: Option<u32>,
        max_count: Option<u64>,
    },
    Paragraphs {
        blocks: &'a [String],
        author: &'a str,
        labels: SlideReviewLabels,
    },
    FolderItems {
        sheet: &'a str,
        answer_col: u32,
        items: Vec<FolderItem>,
        max_count: Option<u64>,
    },
}

impl<'a> Selection<'a> {
    fn resolve(units: &'a ArtifactAskUnits) -> Result<Self> {
        Ok(match units {
            ArtifactAskUnits::SheetRows {
                sheet,
                rows,
                answer_column,
                header_row,
                max_count,
            } => Self::SheetRows {
                sheet,
                rows: RangeRef::parse(rows)?,
                answer_col: *answer_column,
                header_row: *header_row,
                max_count: *max_count,
            },
            ArtifactAskUnits::Paragraphs {
                blocks,
                author,
                labels,
            } => Self::Paragraphs {
                blocks,
                author,
                labels: labels.clone(),
            },
            ArtifactAskUnits::FolderItems {
                sheet,
                answer_column,
                items,
                max_count,
            } => Self::FolderItems {
                sheet,
                answer_col: *answer_column,
                items: items
                    .iter()
                    .map(|item| {
                        Ok(FolderItem {
                            artifact: EntityId::from_hex(&item.artifact_ref)?,
                            row: item.row,
                        })
                    })
                    .collect::<Result<_>>()?,
                max_count: *max_count,
            },
        })
    }

    /// The files it reads besides the artifact.
    fn files(&self) -> Vec<EntityId> {
        match self {
            Self::FolderItems { items, .. } => items.iter().map(|item| item.artifact).collect(),
            _ => Vec::new(),
        }
    }
}

/// The units of a selection whose reads moved, which an arrival asks again.
enum Changed {
    Rows(BTreeSet<u32>),
    Blocks(Vec<String>),
    Items(Vec<FolderItem>),
}

impl Changed {
    fn is_empty(&self) -> bool {
        match self {
            Self::Rows(rows) => rows.is_empty(),
            Self::Blocks(blocks) => blocks.is_empty(),
            Self::Items(items) => items.is_empty(),
        }
    }
}

/// Whether `units` names a selection a standing question can ask.
pub(super) fn validate_artifact_units(units: &ArtifactUnits) -> Result<()> {
    Selection::resolve(&units.selection).map(|_| ())
}

/// Asks every standing artifact question's due artifacts, each question as its principal
/// through the decider `decider_for` makes from its record and that actor, under `policy`.
/// A question that fails is held for the refresh hold, then asked again; the others still
/// run.
pub fn refresh_due_artifact_questions<D: UnitDecider>(
    vault: &Vault,
    now: u64,
    policy: &DecisionBandPolicy,
    decider_for: impl FnMut(&QuestionRecord, WriteActor) -> Result<D>,
) -> Result<ArtifactRefreshBatch> {
    refresh_due_artifact_questions_while(vault, now, policy, &mut || true, decider_for)
}

/// [`refresh_due_artifact_questions`] under a host's pause (FIX 7376): no next
/// question's decider is made and no next artifact is asked once `may_start` says no.
/// The ask in flight finishes with its proposal and stamp, and the pass returns what it
/// has; what it left unasked is neither failed nor held, and stays due.
pub fn refresh_due_artifact_questions_while<D: UnitDecider>(
    vault: &Vault,
    now: u64,
    policy: &DecisionBandPolicy,
    may_start: &mut impl FnMut() -> bool,
    mut decider_for: impl FnMut(&QuestionRecord, WriteActor) -> Result<D>,
) -> Result<ArtifactRefreshBatch> {
    let mut batch = ArtifactRefreshBatch::default();
    let quiet = {
        let txn = vault.store.env.read_txn()?;
        crate::gate::resolve_policy_manifest(&vault.store, &txn)?.artifact_answer_quiet_seconds()
    };
    'questions: for (question, version, record) in standing_artifact_questions(vault, now)? {
        if !may_start() {
            break;
        }
        let made = standing_asker(vault, &record)
            .and_then(|actor| Ok((actor, decider_for(&record, actor)?)));
        let (actor, decider) = match made {
            Ok(made) => made,
            Err(error) => {
                hold_failed(vault, question, now);
                batch.failures.push(ArtifactRefreshFailure {
                    question,
                    artifact: None,
                    error,
                });
                continue;
            }
        };
        let asking = Asking {
            vault,
            question,
            version,
            record: &record,
            actor,
            policy,
            decider: &decider,
            now,
            quiet,
        };
        for units in &record.definition.artifacts {
            if !may_start() {
                break 'questions;
            }
            match asking.ask_if_due(units) {
                Ok(Some(view)) => batch.proposed.push(view),
                Ok(None) => {}
                Err(error) => {
                    hold_failed(vault, question, now);
                    batch.failures.push(ArtifactRefreshFailure {
                        question,
                        artifact: Some(units.artifact),
                        error,
                    });
                    break;
                }
            }
        }
    }
    Ok(batch)
}

/// Every unpaused standing artifact question outside a failure's hold, at its head
/// version.
fn standing_artifact_questions(
    vault: &Vault,
    now: u64,
) -> Result<Vec<(EntityId, u32, QuestionRecord)>> {
    let txn = vault.store.env.read_txn()?;
    let mut records = Vec::new();
    for row in QUESTION_HEAD.iter_raw_from(&vault.store, &txn, &[])? {
        let (key, _) = row?;
        let Some(HeadKey(id)) = HeadKey::decode_key(&key) else {
            continue;
        };
        let Some(head) = QUESTION_HEAD.get(&vault.store, &txn, &HeadKey(id))? else {
            continue;
        };
        if head.paused || head.retry_at.is_some_and(|at| at > now) {
            continue;
        }
        let record = QUESTION_VERSION
            .get(
                &vault.store,
                &txn,
                &VersionKey {
                    id,
                    version: head.version,
                },
            )?
            .ok_or(Error::CorruptedIndex("question version"))?;
        if record.definition.adapter == ARTIFACT_ADAPTER
            && record.definition.activation == QuestionActivation::Standing
        {
            records.push((id, head.version, record));
        }
    }
    Ok(records)
}

/// One question's asks in one pass.
struct Asking<'a> {
    vault: &'a Vault,
    question: EntityId,
    version: u32,
    record: &'a QuestionRecord,
    /// The principal, who holds the proposals.
    actor: WriteActor,
    policy: &'a DecisionBandPolicy,
    decider: &'a dyn UnitDecider,
    now: u64,
    quiet: u64,
}

impl Asking<'_> {
    /// Asks `units` when it is due, and holds the answers as a proposal.
    fn ask_if_due(&self, units: &ArtifactUnits) -> Result<Option<PendingProposalView>> {
        let vault = self.vault;
        let artifact = units.artifact;
        let selection = Selection::resolve(&units.selection)?;
        let mut files = selection.files();
        let mut observed = Vec::with_capacity(files.len() + 1);
        let mut observed_live = Vec::new();
        let mut changed_at = 0;
        let stamp = {
            let txn = vault.store.env.read_txn()?;
            for id in std::iter::once(&artifact).chain(&files) {
                let head = read_blob_artifact_head_in_txn(&vault.store, &txn, id)?;
                if *id == artifact && head.is_none() {
                    return Ok(None);
                }
                changed_at = changed_at.max(head.as_ref().map_or(0, |head| head.created_at));
                observed.push((*id, head.map_or(0, |head| head.version)));
                // A live body's newest commit is a change too (FIX 2115).
                if let Some((pin, at)) = vault.office_body_pin_in_txn(&txn, id)? {
                    changed_at = changed_at.max(at);
                    observed_live.push((*id, pin));
                }
            }
            ASKED.get(&vault.store, &txn, &(self.question, artifact))?
        };
        let mut only = None;
        if let Some(stamp) = stamp.filter(|stamp| stamp.question_version == self.version) {
            let Some(baseline) = baseline(vault, artifact, &stamp)? else {
                return Ok(None);
            };
            let refresh = &self.record.definition.refresh;
            let arrived = refresh.on_arrival
                && (baseline != observed || stamp.live != observed_live)
                && self.now >= changed_at.saturating_add(self.quiet);
            let scheduled = refresh
                .every_seconds
                .is_some_and(|every| self.now >= stamp.asked_at.saturating_add(every));
            if !(arrived || scheduled) {
                return Ok(None);
            }
            if !scheduled {
                only = self.changed_units(artifact, &selection, &baseline, &observed, &stamp.live)?;
                // An edit to a live body never exported moves no version (FIX 2115).
                if let Some(only) = only.as_mut()
                    && let Some(live) =
                        self.live_changed_units(artifact, &selection, &stamp.live)?
                {
                    only.merge(live);
                }
                // Nothing it reads moved: the question follows the head unasked.
                if only.as_ref().is_some_and(Changed::is_empty) {
                    let stamp = ArtifactAsked {
                        versions: observed,
                        live: observed_live,
                        ..stamp
                    };
                    vault.with_write_txn(|wtxn| {
                        ASKED.put(&vault.store, wtxn, &(self.question, artifact), &stamp)
                    })?;
                    return Ok(None);
                }
            }
        }
        // Each read rechecks authority: the principal reads the artifact and its
        // files inside the lane the version was saved under (FIX 2116).
        let principal = self.record.principal;
        let ids: Vec<EntityId> = std::iter::once(artifact)
            .chain(files.iter().copied())
            .collect();
        let SavedArtifactReads { readable, sight } =
            saved_artifact_reads(vault, principal, &self.record.read_lane, &ids)?;
        if !readable.contains(&artifact) {
            return Ok(None);
        }
        files.retain(|file| readable.contains(file));
        let definition = &self.record.definition;
        // The recorded ceiling stands, as on a manual ask (FIX 9912).
        let dial = definition.dial;
        let budget = definition.deadline(vault)?;
        self.ask_recorded(artifact, observed, "standing", |reference| {
            let ask = ArtifactAsk {
                question: &definition.question,
                principal,
                dial,
                policy: self.policy,
                reversibility: Reversibility::ReversibleRead,
                decider: self.decider,
                evidence: &[],
                budget,
                deadline: Instant::now() + ASK_DEADLINE,
                run_ref: reference,
            };
            ask_selection(
                vault,
                artifact,
                &selection,
                &files,
                only.as_ref(),
                ask,
                sight,
            )
        })
    }

    /// The units of `selection` whose reads moved between the `baseline` versions the
    /// question answered and the `observed` heads: a row whose read cells (or header)
    /// changed, its answer cell aside; a paragraph whose text changed; a folder item whose
    /// file has a newer head. `None` when a version no longer reads, so all are asked.
    /// An export of the live edit the last ask already read asks nothing again: reads
    /// compare past the newest export since the baseline, as a held answer's split does
    /// (FIX 12049).
    fn changed_units(
        &self,
        artifact: EntityId,
        selection: &Selection<'_>,
        baseline: &[(EntityId, u64)],
        observed: &[(EntityId, u64)],
        pinned: &[(EntityId, LivePin)],
    ) -> Result<Option<Changed>> {
        let vault = self.vault;
        let version = |versions: &[(EntityId, u64)], id: EntityId| {
            versions
                .iter()
                .find(|(read, _)| *read == id)
                .map_or(0, |(_, version)| *version)
        };
        let pin = |id: EntityId| {
            pinned
                .iter()
                .find(|(read, _)| *read == id)
                .map(|(_, pin)| pin)
        };
        if let Selection::FolderItems { items, .. } = selection {
            let mut changed = Vec::new();
            for item in items {
                let (base, head) = (
                    version(baseline, item.artifact),
                    version(observed, item.artifact),
                );
                if base == head {
                    continue;
                }
                if let Some(pin) = pin(item.artifact)
                    && let Some(span) = vault.export_span(&item.artifact, Some(pin), base, head)?
                {
                    if vault.live_body_changed_until(
                        &item.artifact,
                        Some(pin),
                        Some(span.frontier.as_slice()),
                    )? {
                        changed.push(*item);
                        continue;
                    }
                    // The export holds what the last ask already read; versions after it
                    // still ask, as today.
                    if span.bytes.is_none() {
                        continue;
                    }
                }
                changed.push(*item);
            }
            return Ok(Some(Changed::Items(changed)));
        }
        let (then, now) = (version(baseline, artifact), version(observed, artifact));
        // The newest export since the baseline holds the body as it stood at its
        // frontier, compared with the pin the last ask read (FIX 12017).
        let artifact_pin = pin(artifact);
        let exported = vault.export_span(&artifact, artifact_pin, then, now)?;
        let (Some(then), Some(now)) = (
            vault.read_blob_artifact_version(&artifact, then)?,
            vault.read_blob_artifact_version(&artifact, now)?,
        ) else {
            return Ok(None);
        };
        Ok(match selection {
            Selection::SheetRows {
                sheet,
                rows,
                answer_col,
                header_row,
                ..
            } => {
                let cols: Vec<u32> = (rows.start.col..=rows.end.col)
                    .filter(|col| col != answer_col)
                    .collect();
                let wanted = |cell: &CellRef| {
                    cols.contains(&cell.col)
                        && ((rows.start.row..=rows.end.row).contains(&cell.row)
                            || Some(cell.row) == *header_row)
                };
                let (Ok(then), Ok(now)) = (
                    named_sheet_cells(&then, sheet, &wanted),
                    named_sheet_cells(&now, sheet, &wanted),
                ) else {
                    return Ok(None);
                };
                let exported_sheet = match (&exported, artifact_pin) {
                    (Some(span), Some(pin)) => vault.live_sheet_until(
                        &artifact,
                        Some(pin),
                        sheet,
                        Some((span.frontier.as_slice(), span.version)),
                    )?,
                    _ => None,
                };
                let export_cells = match exported.as_ref().and_then(|span| span.bytes.as_ref()) {
                    Some(bytes) => match named_sheet_cells(bytes, sheet, &wanted) {
                        Ok(cells) => Some(cells),
                        Err(_) => return Ok(None),
                    },
                    None => None,
                };
                let read_from = match &exported {
                    Some(span) if span.bytes.is_none() => &now,
                    Some(_) => export_cells.as_ref().unwrap_or(&then),
                    None => &then,
                };
                let moved = |row: u32| {
                    cols.iter().any(|col| {
                        let cell = CellRef { col: *col, row };
                        read_from.get(&cell).unwrap_or(&CellValue::Blank)
                            != now.get(&cell).unwrap_or(&CellValue::Blank)
                    })
                };
                let live_moved = |row: u32| {
                    exported_sheet.as_ref().is_some_and(|sheet| {
                        cols.iter().any(|col| sheet.differs(*col, row))
                    })
                };
                let header_moved = header_row.is_some_and(|row| moved(row) || live_moved(row))
                    || exported_sheet.as_ref().is_some_and(|sheet| sheet.whole().is_some());
                Some(Changed::Rows(
                    (rows.start.row..=rows.end.row)
                        .filter(|row| header_moved || moved(*row) || live_moved(*row))
                        .collect(),
                ))
            }
            Selection::Paragraphs { blocks, .. } => {
                let limits = {
                    let txn = vault.store.env.read_txn()?;
                    vault.docx_archive_limits_in_txn(&txn, Some(self.record.principal))?
                };
                // The DOCX reads run in the host's memory (FIX 10651); a resource
                // refusal is the engine's error, never a quiet re-ask of all (FIX 10587).
                let resources = crate::office_body::document_resources();
                let texts = |bytes: &[u8]| {
                    let read = match resources
                        .docx(|| oneiron_docedit::docx_body::read_docx_blocks(bytes, limits))
                    {
                        Ok(read) => read,
                        Err(error) => {
                            if let Some(refusal) = error.resource() {
                                return Err(crate::office_body::document_refused(refusal));
                            }
                            return Ok(None);
                        }
                    };
                    Ok(Some(
                        read.into_iter()
                            .map(|block| {
                                let text = *blake3::hash(block.text.as_bytes()).as_bytes();
                                (block.id, text)
                            })
                            .collect::<std::collections::BTreeMap<_, _>>(),
                    ))
                };
                let (Some(then), Some(now)) = (texts(&then)?, texts(&now)?) else {
                    return Ok(None);
                };
                let exported_units = match (&exported, artifact_pin) {
                    (Some(span), Some(pin)) => vault.live_paragraphs_until(
                        &artifact,
                        Some(pin),
                        Some(span.frontier.as_slice()),
                    )?,
                    _ => None,
                };
                let export_texts = match exported.as_ref().and_then(|span| span.bytes.as_ref()) {
                    Some(bytes) => match texts(bytes)? {
                        Some(texts) => Some(texts),
                        None => return Ok(None),
                    },
                    None => None,
                };
                let read_from = match &exported {
                    Some(span) if span.bytes.is_none() => &now,
                    Some(_) => export_texts.as_ref().unwrap_or(&then),
                    None => &then,
                };
                Some(Changed::Blocks(
                    blocks
                        .iter()
                        .filter(|block| {
                            read_from.get(*block) != now.get(*block)
                                || exported_units
                                    .as_ref()
                                    .is_some_and(|units| units.change(*block).is_some())
                        })
                        .cloned()
                        .collect(),
                ))
            }
            Selection::FolderItems { .. } => None,
        })
    }
}

/// The versions the question has already answered: those it last asked, with the
/// artifact's at the latest Keep of that ask's proposal or of a wake's re-ask of it.
/// `None` while one of them waits for Keep.
fn baseline(
    vault: &Vault,
    artifact: EntityId,
    stamp: &ArtifactAsked,
) -> Result<Option<Vec<(EntityId, u64)>>> {
    let mut versions = stamp.versions.clone();
    let mut refs: Vec<String> = stamp.proposal_ref.iter().cloned().collect();
    let mut seen = BTreeSet::new();
    while let Some(reference) = refs.pop() {
        if !seen.insert(reference.clone()) {
            continue;
        }
        if vault.pending_proposal(&artifact, &reference)?.is_some() {
            return Ok(None);
        }
        if let Some(kept) = vault
            .blob_artifact_settlement(&artifact, &reference)?
            .and_then(|settled| settled.version)
            && let Some(slot) = versions.iter_mut().find(|(id, _)| *id == artifact)
        {
            slot.1 = slot.1.max(kept);
        }
        refs.extend(vault.answer_reask_refs(&artifact, &reference)?);
    }
    Ok(Some(versions))
}

/// One ask a standing artifact question made of one artifact, read back by its principal
/// (`vault.questions.answers`): the head it asked and where its answers stand. Every
/// logged ask stays (FIX 2337); a later ask of the same artifact replaces only an ask
/// stamped before asks were logged, which names no `ask_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAskRecord {
    pub artifact: EntityId,
    /// The question version that asked.
    pub question_version: u32,
    /// The artifact's head version the ask read.
    pub artifact_version: u64,
    pub asked_at: u64,
    /// The proposal its answers were held under for Keep; none when no unit was answered.
    #[serde(default)]
    pub proposal_ref: Option<String>,
    pub standing: ArtifactAskStanding,
    /// The logged ask's own id; none on an ask stamped before asks were logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ask_id: Option<EntityId>,
    /// The kind of error that stopped a failed ask, which held nothing, by its stable
    /// wire name (FIX 9177); none when the ask completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed: Option<String>,
    /// For a wake's re-ask of withdrawn answers, the proposal they were withdrawn from
    /// (FIX 9174); none for the question's own ask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_proposal_ref: Option<String>,
    /// Whether this ask was logged with its ref details left out (FIX 9419): its refs
    /// did not pass the secret scan, so it names no proposal, and a completed one's
    /// standing is [`ArtifactAskStanding::DetailsOmitted`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub details_omitted: bool,
    /// Every unit the ask left without an answer, with its receipt (FIX 9913),
    /// whether or not it held a proposal; an answered unit's decision rides
    /// the proposal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<ArtifactUnitReceipt>,
}

/// Where one artifact ask's answers stand, by the same walk the next ask's baseline takes:
/// the ask's own proposal and every wake's re-ask of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ArtifactAskStanding {
    /// No unit was answered, so nothing was held.
    Unanswered,
    /// The proposal, or a wake's re-ask of it, waits for Keep.
    Waiting,
    /// Nothing waits, and a Keep of the proposal or of a re-ask moved the artifact to
    /// `version`.
    Kept { version: u64 },
    /// Nothing waits and no Keep moved the artifact: the answers were discarded, or an edit
    /// withdrew them.
    Closed,
    /// The ask failed and held nothing (FIX 9177): the record's `failed` names its error's
    /// kind. A completed ask that answered no unit is [`Self::Unanswered`].
    Failed,
    /// The ask was logged with its ref details left out (FIX 9419): it names no proposal,
    /// so where its answers stand is not read here.
    DetailsOmitted,
}
