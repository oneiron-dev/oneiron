//! Standing artifact questions (ARCH-0076, OF-506): a question whose adapter is
//! [`ARTIFACT_ADAPTER`] asks each of its artifacts on the head, once at first, then again
//! when the artifact or a folder item it reads has a newer head that has been quiet for the
//! vault's interval, and when its schedule falls due. Arrivals are found by polling heads
//! against the versions last asked, so no append path is touched. Each ask holds its answers
//! as a fresh proposal for Keep under a ref of its own. While that proposal or a wake's
//! re-ask of it waits, the artifact is not asked again: the edit settle carry splits a held
//! proposal and wakes its proposer. A Keep of one of them moves the head the question
//! follows. The ask is the question's principal's, on the question's dial and clock,
//! through the host's decider; an artifact or file the principal cannot read is not asked.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::refresh::{hold_failed, principal_actor, source_actor_key};
use super::{records::*, store::*};
use crate::blob_artifact::{ArtifactAskUnits, read_blob_artifact_head_in_txn};
use crate::edit_roundtrip::slides_review::SlideReviewLabels;
use crate::edit_roundtrip::{
    ArtifactAsk, ArtifactAskRun, FolderAsk, FolderItem, ParagraphAsk, RangeRef, SheetRowsAsk,
    UnitDecider,
};
use crate::edit_settle::PendingProposalView;
use crate::llm::decision::{DecisionBandPolicy, DecisionRung, Reversibility};
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::{EntityId, Error, Result, Vault, WriteActor};

/// Key: id16(question) + id16(artifact).
const ASKED: SideTable<(EntityId, EntityId), ArtifactAsked, Named> =
    SideTable::new(&side_table::TYPED_QUESTION_ARTIFACT_ASKED);

/// One ask's run clock, past which no unit call runs.
const ASK_DEADLINE: Duration = Duration::from_secs(300);

/// The last ask of one artifact for one question.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct ArtifactAsked {
    question_version: u32,
    /// Each read artifact's head version when it was asked, the artifact first.
    versions: Vec<(EntityId, u64)>,
    asked_at: u64,
    /// The proposal its answers wait under; none when no unit was answered.
    proposal_ref: Option<String>,
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
                labels: serde_json::from_value(labels.clone()).map_err(|_| {
                    Error::InvalidConfig("a paragraph question names its labels".into())
                })?,
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
    mut decider_for: impl FnMut(&QuestionRecord, WriteActor) -> Result<D>,
) -> Result<ArtifactRefreshBatch> {
    let mut batch = ArtifactRefreshBatch::default();
    let quiet = {
        let txn = vault.store.env.read_txn()?;
        crate::gate::resolve_policy_manifest(&vault.store, &txn)?.artifact_answer_quiet_seconds()
    };
    for (question, version, record) in standing_artifact_questions(vault, now)? {
        let made = principal_actor(vault, record.principal)
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
            }
            ASKED.get(&vault.store, &txn, &(self.question, artifact))?
        };
        if let Some(stamp) = stamp.filter(|stamp| stamp.question_version == self.version) {
            let Some(baseline) = baseline(vault, artifact, &stamp)? else {
                return Ok(None);
            };
            let refresh = &self.record.definition.refresh;
            let arrived = refresh.on_arrival
                && baseline != observed
                && self.now >= changed_at.saturating_add(self.quiet);
            let scheduled = refresh
                .every_seconds
                .is_some_and(|every| self.now >= stamp.asked_at.saturating_add(every));
            if !(arrived || scheduled) {
                return Ok(None);
            }
        }
        // Each read rechecks authority: the principal reads the artifact and its files.
        let principal = self.record.principal;
        let readable = {
            let txn = vault.store.env.read_txn()?;
            let key = source_actor_key(vault, &txn, principal, None)?
                .require_access_grants(Some(principal));
            let read = vault.scoped_read(key);
            let mut readable = BTreeSet::new();
            for id in std::iter::once(&artifact).chain(&files) {
                if read.entity_raw_live_in(&txn, id)?.is_some() {
                    readable.insert(*id);
                }
            }
            readable
        };
        if !readable.contains(&artifact) {
            return Ok(None);
        }
        files.retain(|file| readable.contains(file));
        let reference = format!(
            "standing:{}:{}:{}",
            &self.question.to_hex()[..16],
            self.version,
            self.now
        );
        let definition = &self.record.definition;
        let mut dial = definition.dial;
        dial.ceiling = dial.ceiling.min(DecisionRung::Big);
        let ask = ArtifactAsk {
            question: &definition.question,
            principal,
            dial,
            policy: self.policy,
            reversibility: Reversibility::ReversibleRead,
            decider: self.decider,
            evidence: &[],
            budget: definition.deadline(vault)?,
            deadline: Instant::now() + ASK_DEADLINE,
            run_ref: &reference,
        };
        let run = ask_selection(vault, artifact, &selection, &files, ask)?;
        let proposed = match &run.proposal {
            Some(proposal) => {
                Some(vault.retain_edit_proposal(&artifact, proposal, None, self.actor, self.now)?)
            }
            None => None,
        };
        let stamp = ArtifactAsked {
            question_version: self.version,
            versions: observed,
            asked_at: self.now,
            proposal_ref: proposed.as_ref().map(|_| reference),
        };
        vault.with_write_txn(|wtxn| {
            ASKED.put(&vault.store, wtxn, &(self.question, artifact), &stamp)
        })?;
        Ok(proposed)
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

/// The builder `selection` names, over the readable `files` of a folder ask.
fn ask_selection(
    vault: &Vault,
    artifact: EntityId,
    selection: &Selection<'_>,
    files: &[EntityId],
    ask: ArtifactAsk<'_>,
) -> Result<ArtifactAskRun> {
    match selection {
        Selection::SheetRows {
            sheet,
            rows,
            answer_col,
            header_row,
            max_count,
        } => vault.ask_blob_artifact_sheet_rows(
            &artifact,
            &SheetRowsAsk {
                ask,
                sheet,
                rows: *rows,
                answer_col: *answer_col,
                header_row: *header_row,
                max_count_override: *max_count,
                only_rows: None,
            },
        ),
        Selection::Paragraphs {
            blocks,
            author,
            labels,
        } => vault.ask_blob_artifact_paragraphs(
            &artifact,
            &ParagraphAsk {
                ask,
                blocks,
                author,
                labels,
            },
        ),
        Selection::FolderItems {
            sheet,
            answer_col,
            items,
            max_count,
        } => {
            let items: Vec<FolderItem> = items
                .iter()
                .filter(|item| files.contains(&item.artifact))
                .copied()
                .collect();
            if items.is_empty() {
                return Ok(ArtifactAskRun {
                    proposal: None,
                    abstained: Vec::new(),
                    refused: Vec::new(),
                });
            }
            vault.ask_folder_items_into_sheet(
                &artifact,
                &FolderAsk {
                    ask,
                    items: &items,
                    sheet,
                    answer_col: *answer_col,
                    max_count_override: *max_count,
                    sight: crate::secret_custody::SecretSight::Masked,
                },
            )
        }
    }
}
