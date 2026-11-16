//! `vault.critic.outcome` and `vault.critic.findings` (LEARN-CRITIC Q3 = B). The
//! vault owner, or an agent on its own live owner Grant that lists the verb, records
//! the anchored result of one critique of a persisted review, and reads that review
//! back with its standing outcomes and its critics' cells, scoped to the review.
//! An agent acts only on a review it wrote. No request carries a success flag:
//! the owner states a verdict, and an agent names a completed directed seal recheck
//! whose findings the engine reads (ruling LEARN-CRITIC-ANCHOR).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::outcomes::{
    OutcomeWriter, calibration_receipt, outcome_of, record_review_outcome_in_txn,
    standing_outcome_in_txn,
};
use super::persistence::review_actor_in_txn;
use super::{CriticReviewOutcome, ReviewResult, trusted_review_in_txn};
use crate::authority::{NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn};
use crate::critic::{CritiqueArtifact, CritiqueVerdict, ReliabilityOutcomeSource};
use crate::edge::EdgeActorClass;
use crate::learning::doors::LearningCellView;
use crate::learning::evidence::EvidenceRow;
use crate::learning::{LearningCell, TypeRef};
use crate::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, Memory, MemoryError,
    MemoryResult,
};
use crate::self_heal::audit::{SealCheckKind, SealedAttemptReceipt};
use crate::{EntityId, Vault};

const OUTCOME_VERB: &str = "vault.critic.outcome";
const FINDINGS_VERB: &str = "vault.critic.findings";
const NO_GRANT: &str = "no live Grant from a live owner names this agent and lists the verb";

#[doc(hidden)]
pub use oneiron_verb_wire::critic::review::doors::{
    CriticFindingsRequest, CriticOutcomeAnchor, CriticOutcomeSubmit,
};

#[doc(hidden)]
pub use oneiron_records::critic::review::doors::CriticOutcomeRecord;

/// One critique's standing outcome and the calibration evidence it gave.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticStandingOutcomeView {
    pub artifact_id: String,
    /// The standing `review.outcome` claim, 32-hex.
    pub outcome_ref: String,
    pub outcome: CriticOutcomeRecord,
    /// The receipt the critique's calibration evidence sits under.
    pub calibration_receipt: String,
    /// The evidence the critic's cell holds under that receipt: absent while
    /// the write gate holds the outcome. A fact the critique's kept dissent
    /// settled outranks the outcome and is the row shown then.
    pub evidence: Option<EvidenceRow>,
}

/// `vault.critic.outcome`'s answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticOutcomeView {
    pub verdict_ref: String,
    #[serde(flatten)]
    pub standing: CriticStandingOutcomeView,
    /// The Grant that admitted an agent caller, 32-hex; absent for the owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<String>,
}

/// One calibration cell of the review's critiques.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticCellView {
    /// The review's critiques this cell calibrates.
    pub artifact_ids: Vec<String>,
    /// The cell's estimate, the aggregate over every review and source the
    /// cell serves. Its provenance, head citations and attributed receipts
    /// list only this review's calibration receipts, a borrowed prior's too.
    pub cell: LearningCellView,
    /// Evidence rows of this cell from other reviews or sources: counted in the
    /// estimate, not shown.
    pub undisclosed_evidence: u64,
}

/// `vault.critic.findings`'s answer: the persisted review, its standing
/// outcomes and its critics' cells, scoped to the review.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticFindingsView {
    pub target_ref: String,
    pub session_ref: String,
    /// The review as stored: triage, critiques and decision receipts.
    pub review: CriticReviewOutcome,
    /// Each critique's standing outcome, in the review's critique order.
    pub outcomes: Vec<CriticStandingOutcomeView>,
    /// One entry per distinct calibration cell of the review's critiques.
    pub cells: Vec<CriticCellView>,
}

/// The review's critiques one calibration cell calibrates, and their receipts.
struct CellCritiques {
    cell: LearningCell,
    artifact_ids: Vec<String>,
    receipts: BTreeSet<String>,
}

/// The caller a door admitted, in its snapshot.
#[derive(Debug, Clone, Copy)]
enum Caller {
    /// The live vault owner.
    Owner,
    /// An agent and the live owner Grant that lists the verb.
    Agent { agent: EntityId, grant: EntityId },
}

/// Records the anchored outcome of one critique: the owner's verdict, or what a
/// completed directed seal recheck of the reviewed result settles. A critique
/// holds one standing outcome; a later one with another value supersedes it.
///
/// # Errors
///
/// FORBIDDEN for a caller that is neither the live owner nor an agent on a live
/// owner Grant listing the verb, or an agent stating an owner verdict;
/// NOT_FOUND for a review the caller may not act on, or no such critique;
/// INVALID_STATE for a recheck that settles nothing; BAD_REQUEST for a malformed
/// reference; storage errors.
pub fn critic_outcome(
    memory: &Memory<'_>,
    input: CriticOutcomeSubmit,
) -> MemoryResult<CriticOutcomeView> {
    let vault = memory.vault();
    let verdict = entity_ref(OUTCOME_VERB, "verdict_ref", &input.verdict_ref)?;
    let target = entity_ref(OUTCOME_VERB, "target_ref", &input.target_ref)?;
    let recheck = match &input.anchor {
        CriticOutcomeAnchor::OwnerVerdict { .. } => None,
        CriticOutcomeAnchor::SealRecheck { attempt_ref } => Some(attempt_id(attempt_ref)?),
    };
    let at = vault.now_recorded_at();
    let (view, dismissed) = vault.try_with_write_txn_grouped(|txn| {
        let caller = admit_in_txn(memory, txn, OUTCOME_VERB)?;
        let review = admitted_review_in_txn(vault, txn, caller, OUTCOME_VERB, &verdict, &target)?;
        let artifact = review
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == input.artifact_id && !artifact.out_of_scope)
            .cloned()
            .ok_or_else(|| not_found(OUTCOME_VERB, "the review holds no such critique"))?;
        let (source, accepted) = match (&input.anchor, recheck) {
            (CriticOutcomeAnchor::OwnerVerdict { accepted }, _) => {
                if !matches!(caller, Caller::Owner) {
                    return Err(refused(
                        OUTCOME_VERB,
                        "an owner verdict is the owner's own act; an agent names a completed seal recheck",
                    ));
                }
                (ReliabilityOutcomeSource::OwnerVerdict, *accepted)
            }
            (CriticOutcomeAnchor::SealRecheck { .. }, Some(attempt)) => {
                let accepted = recheck_settles_in_txn(vault, txn, attempt, &target, &artifact)?;
                refuse_reused_recheck_in_txn(vault, txn, &verdict, &artifact, attempt)?;
                (ReliabilityOutcomeSource::SealRecheck { attempt }, accepted)
            }
            (CriticOutcomeAnchor::SealRecheck { .. }, None) => {
                return Err(MemoryError::bad_request(format!(
                    "{OUTCOME_VERB}: a seal recheck names its sealed try"
                )));
            }
        };
        let (writer, grant) = match caller {
            Caller::Owner => (OutcomeWriter::Owner(memory.write_actor()), None),
            Caller::Agent { grant, .. } => (OutcomeWriter::Review, Some(grant.to_hex())),
        };
        record_review_outcome_in_txn(
            vault,
            txn,
            &verdict,
            writer,
            &artifact.artifact_id,
            source,
            accepted,
            at,
        )?;
        let session = review_session_in_txn(vault, txn, &verdict)?;
        let standing = standing_view_in_txn(vault, txn, &session, &verdict, &artifact)?
            .ok_or_else(|| {
                MemoryError::new(
                    MEMORY_CODE_INVALID_STATE,
                    format!("{OUTCOME_VERB}: the outcome does not stand after its write"),
                    &["Read the review's findings."],
                )
            })?;
        let view = CriticOutcomeView {
            verdict_ref: verdict.to_hex(),
            standing,
            grant_ref: grant,
        };
        Ok::<_, MemoryError>((view, (!accepted).then_some(review)))
    })?;
    // An overruled critique keeps its dissent, in writes of its own after the
    // outcome's commit, as the owner's outcome writer does.
    if let Some(review) = dismissed {
        super::preserve_review_dissent(vault, &review, &input.artifact_id, at)?;
    }
    Ok(view)
}

/// Reads one persisted review, each critique's standing outcome, and the cells
/// of its critics with provenance cut to this review's calibration receipts.
/// It writes nothing and runs no projector.
///
/// # Errors
///
/// FORBIDDEN for a caller that is neither the live owner nor an agent on a live
/// owner Grant listing the verb; NOT_FOUND for a review the caller may not
/// read; BAD_REQUEST for a malformed reference; storage errors.
pub fn critic_findings(
    memory: &Memory<'_>,
    input: &CriticFindingsRequest,
) -> MemoryResult<CriticFindingsView> {
    let vault = memory.vault();
    let verdict = entity_ref(FINDINGS_VERB, "verdict_ref", &input.verdict_ref)?;
    let target = entity_ref(FINDINGS_VERB, "target_ref", &input.target_ref)?;
    let (review, session, outcomes) = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        let caller = admit_in_txn(memory, &txn, FINDINGS_VERB)?;
        let review = admitted_review_in_txn(vault, &txn, caller, FINDINGS_VERB, &verdict, &target)?;
        let session = review_session_in_txn(vault, &txn, &verdict)?;
        let mut outcomes = Vec::new();
        for artifact in review
            .artifacts
            .iter()
            .filter(|artifact| !artifact.out_of_scope)
        {
            if let Some(standing) = standing_view_in_txn(vault, &txn, &session, &verdict, artifact)?
            {
                outcomes.push(standing);
            }
        }
        (review, session, outcomes)
    };
    // A cell is a statistic many reviews share, read after the review's own
    // snapshot: its type tree read opens a snapshot of its own.
    let mut cells: BTreeMap<[u8; 32], CellCritiques> = BTreeMap::new();
    for artifact in review
        .artifacts
        .iter()
        .filter(|artifact| !artifact.out_of_scope)
    {
        let entry = cells
            .entry(artifact.calibration.digest())
            .or_insert_with(|| CellCritiques {
                cell: artifact.calibration.clone(),
                artifact_ids: Vec::new(),
                receipts: BTreeSet::new(),
            });
        entry.artifact_ids.push(artifact.artifact_id.clone());
        entry
            .receipts
            .insert(calibration_receipt(&verdict, &artifact.artifact_id));
    }
    let mut views = Vec::with_capacity(cells.len());
    for critiques in cells.into_values() {
        let parents = type_parents(vault, &critiques.cell)?;
        let (cell, undisclosed_evidence) = crate::learning::doors::receipt_scoped_cell_view(
            vault,
            &critiques.cell,
            &parents,
            &critiques.receipts,
        )?;
        views.push(CriticCellView {
            artifact_ids: critiques.artifact_ids,
            cell,
            undisclosed_evidence,
        });
    }
    Ok(CriticFindingsView {
        target_ref: target.to_hex(),
        session_ref: session.to_hex(),
        review: CriticReviewOutcome::from(review),
        outcomes,
        cells: views,
    })
}

/// The caller, in `txn`: the live vault owner, or an agent on its own live owner
/// Grant listing `verb`. The caller's actor binding and any credential it
/// presented are checked first.
fn admit_in_txn(memory: &Memory<'_>, txn: &heed::RoTxn<'_>, verb: &str) -> MemoryResult<Caller> {
    let vault = memory.vault();
    crate::memory::verify_actor_binding_in_txn(vault, txn, memory.actor(), memory.actor_class())?;
    if let Some(slip) = memory.presented_credential()
        && !vault.capability_slip_is_live_in_txn(txn, slip)?
    {
        return Err(refused(verb, "the caller's credential is no longer live"));
    }
    if crate::memory::actor_is_vault_owner_in_txn(vault, txn, memory.actor(), memory.actor_class())?
    {
        if !crate::consent::person_is_live_in_txn(vault, txn, &memory.actor())? {
            return Err(refused(verb, "the vault owner is not a live person"));
        }
        return Ok(Caller::Owner);
    }
    if memory.actor_class() != EdgeActorClass::Agent {
        return Err(refused(
            verb,
            "the caller is neither the vault owner nor an agent",
        ));
    }
    match principal_standing_or_lapse_in_txn(
        vault,
        txn,
        memory.actor(),
        EdgeActorClass::Agent,
        verb,
    )? {
        Ok(standing) => Ok(Caller::Agent {
            agent: memory.actor(),
            grant: standing.grant.ok_or_else(|| refused(verb, NO_GRANT))?,
        }),
        Err(NoStanding::PactStandingLapsed) => Err(refused(verb, PACT_STANDING_LAPSED)),
        Err(NoStanding::NotStanding) => Err(refused(verb, NO_GRANT)),
    }
}

/// The trusted, persisted review `verdict` of `target`, when `caller` may act on
/// it: the owner on any review, an agent only on a review it wrote. Any other
/// review answers as a missing one.
fn admitted_review_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: Caller,
    verb: &str,
    verdict: &EntityId,
    target: &EntityId,
) -> MemoryResult<ReviewResult> {
    let missing = || {
        not_found(
            verb,
            "no review the caller may act on has this verdict and target",
        )
    };
    let review = trusted_review_in_txn(vault, txn, verdict, target)?.ok_or_else(missing)?;
    if let Caller::Agent { agent, .. } = caller
        && review_actor_in_txn(vault, txn, verdict)?.entity_ref() != agent
    {
        return Err(missing());
    }
    Ok(review)
}

/// The session bundle of the review `verdict`, which its outcomes are about.
fn review_session_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    verdict: &EntityId,
) -> MemoryResult<EntityId> {
    let body = vault
        .get_claim_in_txn(txn, verdict)?
        .ok_or(crate::Error::EntityNotFound)?;
    let session = body
        .session_tag
        .as_deref()
        .ok_or(crate::Error::InvalidClaimBody(
            "review has no session bundle",
        ))?;
    Ok(EntityId::from_hex(session)?)
}

/// The standing outcome of `artifact`, a critique of the review `verdict`, with
/// the calibration evidence its critic's cell holds for it; `None` when none
/// stands.
fn standing_view_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    session: &EntityId,
    verdict: &EntityId,
    artifact: &CritiqueArtifact,
) -> MemoryResult<Option<CriticStandingOutcomeView>> {
    let Some((id, body)) =
        standing_outcome_in_txn(vault, txn, session, verdict, &artifact.artifact_id)?
    else {
        return Ok(None);
    };
    let (source, accepted) = outcome_of(&body.value)?;
    let receipt = calibration_receipt(verdict, &artifact.artifact_id);
    let evidence = crate::learning::evidence::EVIDENCE.get(
        &vault.store,
        txn,
        &(artifact.calibration.digest(), receipt.clone()),
    )?;
    Ok(Some(CriticStandingOutcomeView {
        artifact_id: artifact.artifact_id.clone(),
        outcome_ref: id.to_hex(),
        outcome: outcome_record(source, accepted),
        calibration_receipt: receipt,
        evidence,
    }))
}

fn outcome_record(source: ReliabilityOutcomeSource, accepted: bool) -> CriticOutcomeRecord {
    let (label, attempt) = match source {
        ReliabilityOutcomeSource::HeldOutEval => ("held_out_eval", None),
        ReliabilityOutcomeSource::OwnerVerdict => ("owner_verdict", None),
        ReliabilityOutcomeSource::Beam => ("beam", None),
        ReliabilityOutcomeSource::CriticAgreement => ("critic_agreement", None),
        ReliabilityOutcomeSource::SealRecheck { attempt } => ("seal_recheck", Some(attempt)),
    };
    CriticOutcomeRecord {
        source: label.to_owned(),
        accepted,
        seal_attempt_ref: attempt
            .map(|attempt| crate::entity_id::bytes_to_hex_lower(attempt.as_bytes())),
    }
}

/// Whether the critique `artifact` of `target` held, as the completed directed
/// recheck of the sealed try `attempt` settles it (ruling LEARN-CRITIC-ANCHOR):
/// a flaw the check found on any objective means the target was flawed, so the
/// critique held unless it accepted the target; a clear check settles only when
/// it judged every objective the try's confession named, and then the critique
/// held only if it accepted the target. The check must have judged `target`
/// itself, with a judge model other than the executor's.
fn recheck_settles_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: crate::attempt_queue::AttemptId,
    target: &EntityId,
    artifact: &CritiqueArtifact,
) -> MemoryResult<bool> {
    let receipt = vault
        .sealed_attempt_receipt_in_txn(txn, attempt)?
        .ok_or_else(|| not_found(OUTCOME_VERB, "no sealed try has this attempt"))?;
    let target_hex = target.to_hex();
    let check = receipt
        .checks
        .iter()
        .find(|check| check.request.kind == SealCheckKind::ConfessionRecheck)
        .ok_or_else(|| settles_nothing("the sealed try has no directed recheck"))?;
    if receipt.result_ref != target_hex || check.request.result_ref != target_hex {
        return Err(settles_nothing(
            "the recheck judged another result than the reviewed target",
        ));
    }
    let outcome = check
        .outcome
        .as_ref()
        .ok_or_else(|| settles_nothing("the directed recheck is not complete"))?;
    if model_name(&outcome.judge_revision) == model_name(&receipt.executor) {
        return Err(settles_nothing(
            "the recheck's judge is the try's executor model",
        ));
    }
    let accepts = artifact.verdict == CritiqueVerdict::Accept;
    if outcome.findings.iter().any(|finding| finding.flaw_present) {
        return Ok(!accepts);
    }
    if !judged_every_confessed_objective(&receipt, &outcome.findings) {
        return Err(settles_nothing(
            "a clear recheck of part of the confession settles no critique",
        ));
    }
    Ok(accepts)
}

/// Whether `findings` judge each objective the sealed try's confession names,
/// and no other.
fn judged_every_confessed_objective(
    receipt: &SealedAttemptReceipt,
    findings: &[crate::self_heal::audit::ObjectiveFinding],
) -> bool {
    let confessed: BTreeSet<&str> = receipt
        .confession
        .objectives
        .iter()
        .map(|objective| objective.objective.as_str())
        .collect();
    let judged: BTreeSet<&str> = findings
        .iter()
        .map(|finding| finding.objective.as_str())
        .collect();
    !confessed.is_empty() && confessed == judged
}

/// A model revision's model, the part before its last `@`, as the seal's owner
/// completion compares a judge with an executor.
fn model_name(revision: &str) -> &str {
    revision
        .rsplit_once('@')
        .map_or(revision, |(model, _)| model)
}

/// Refuses a recheck of `attempt` that already settles a critique of another
/// review, or another critique, in the critic cell of `artifact`: one check
/// is one observation of a cell. The critique's own standing outcome may name
/// it again.
fn refuse_reused_recheck_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    verdict: &EntityId,
    artifact: &CritiqueArtifact,
    attempt: crate::attempt_queue::AttemptId,
) -> MemoryResult<()> {
    let cell = artifact.calibration.digest();
    for (other_verdict, other_artifact) in
        super::outcomes::standing_recheck_outcomes_in_txn(vault, txn, attempt)?
    {
        if other_verdict == *verdict && other_artifact == artifact.artifact_id {
            continue;
        }
        let other = super::persistence::persisted_artifact_in_txn(
            vault,
            txn,
            &other_verdict,
            &other_artifact,
        )?;
        if other.calibration.digest() == cell {
            return Err(settles_nothing(
                "this recheck already settles another critique in the critic's cell",
            ));
        }
    }
    Ok(())
}

/// The recorded type tree's ancestors of `cell`'s type, as the review read its
/// critics' cells: none for an untyped cell or a tree no longer kept.
fn type_parents(vault: &Vault, cell: &LearningCell) -> MemoryResult<Vec<TypeRef>> {
    let Some(stamp) = &cell.type_ref else {
        return Ok(Vec::new());
    };
    Ok(
        crate::task_type::type_tree_at(vault, cell.project, stamp.tree_version)?
            .map(|tree| tree.ancestors(stamp))
            .unwrap_or_default(),
    )
}

fn entity_ref(verb: &str, field: &str, reference: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(reference)
        .map_err(|_| MemoryError::bad_request(format!("{verb}: {field} is an entity id, 32 hex")))
}

fn attempt_id(reference: &str) -> MemoryResult<crate::attempt_queue::AttemptId> {
    crate::task_verb::decode_hex::<16>(reference)
        .and_then(|bytes| crate::attempt_queue::AttemptId::from_bytes(&bytes).ok())
        .ok_or_else(|| {
            MemoryError::bad_request(format!(
                "{OUTCOME_VERB}: attempt_ref is a sealed try's attempt id, 32 hex"
            ))
        })
}

/// A door's refusal of a caller it does not admit.
fn refused(verb: &str, why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{verb} takes the vault owner, or an agent on its own live owner Grant that lists it: {why}"
        ),
        &["Call as the owner, or have the owner grant this agent the verb by name."],
    )
}

fn not_found(verb: &str, why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_NOT_FOUND,
        format!("{verb}: {why}"),
        &["An agent acts only on a review it wrote; name its verdict, target and critique."],
    )
}

/// A seal recheck that settles no critique.
fn settles_nothing(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_INVALID_STATE,
        format!("{OUTCOME_VERB}: {why}"),
        &["Name the sealed try whose completed directed recheck judged the reviewed target."],
    )
}
