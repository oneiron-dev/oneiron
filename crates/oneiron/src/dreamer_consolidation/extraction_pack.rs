//! The bound Extraction verdict's checked pack rebuild: question keys and canonical
//! options rebuilt with the native builders, without wording or question ids.
//!
//! A bound extraction job sends one [`ExtractionPack`](crate::verbs::ExtractionPack) as its
//! verdict state. [`rebuild_checked_pack`] checks every candidate operand, derives every
//! candidate id with the native deterministic id, rebuilds the listed and prior sets in
//! native order, and rebuilds the read's question keys and canonical options with the same
//! plain builders native extraction calls. The bound handler then maps the pack's
//! `candidate:<index>` aliases and compares keys and options in order.
//!
//! The split is strict: key parts and Choice contracts come from shared preparation that
//! never reads wording, and only native applies the lent wording to build questions. This
//! module never calls `QuestionFamily::question`, never calls
//! `ConsolidationDecisions::shipped`, and never computes, compares or returns a question
//! id. Page byte measurement renders through the shared renderers with simulated label
//! numbers, never through question ids.
//!
//! Per read, the rebuild returns the native sets beside the questions: a correction read
//! and its final list the rebuilt listed claims with no priors, while a resolution read
//! and its finals list no listed claims with the rebuilt conflict heads. A final round
//! consumes the pack's earlier answers against the canonical options of the questions they
//! answer. Every refusal fails closed toward `BAD_REQUEST` in the bound handler, which
//! maps these errors by message.

mod finals;
mod reads;

pub(crate) use super::resources::{BoundBranchInput, BoundBranchRead, project_bound_branch};

use super::branch::BranchAxes;
use super::support::invalid_consolidation;
use crate::attempt_queue::AttemptId;
use crate::claim::ScopedRead;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::model_decision::AnswerContract;
use crate::verbs::{ExtractionPack, ExtractionRead, PackQuestion};

/// What the checked rebuild returns: the derived candidate ids, the rebuilt
/// listed and prior sets, and the rebuilt questions with canonical options.
#[derive(Debug, Clone)]
pub(crate) struct RebuiltExtractionPack {
    /// The native identifiers derived for the pack candidates, in pack order.
    pub(crate) candidate_ids: Vec<EntityId>,
    /// The rebuilt listed claims, in native first-seen order. Correction reads
    /// list them; resolution reads leave this empty.
    pub(crate) listed: Vec<EntityId>,
    /// The rebuilt prior heads, in native id order. Resolution reads list the
    /// conflict heads; correction reads leave this empty.
    pub(crate) priors: Vec<EntityId>,
    /// The rebuilt questions with canonical native options, in native order.
    pub(crate) questions: Vec<PackQuestion>,
}

/// Rebuilds `pack`'s question keys and canonical options with the native
/// builders over the `bound` projection: every operand checked, every
/// candidate id derived natively, the listed and prior sets rebuilt in native
/// order, and the read's part validated against the rebuilt paging. Earlier
/// answers are checked inside their questions' canonical options, and every
/// rebuilt Choice contract is validated without building any question.
///
/// # Errors
///
/// Any operand, set, part, round or earlier answer the native builders would
/// not produce: malformed references, an ungrammatical predicate, a null
/// proposal, missing evidence, a relationship outside the bound set, an
/// unknown or unlisted corrected claim, candidates spanning more than one
/// conflict or none at all, a part beside its rebuilt pages, a final round
/// that does not exist, or an earlier answer outside its canonical options.
/// The bound handler maps every error below to its request refusal.
pub(crate) fn rebuild_checked_pack(
    pack: &ExtractionPack,
    bound: &BoundBranchRead,
    attempt: AttemptId,
    axes: &BranchAxes,
    read: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
) -> Result<RebuiltExtractionPack> {
    let checked = reads::check_pack_candidates(pack, bound, attempt, axes)?;
    let (listed, priors, questions) = match pack.read {
        ExtractionRead::Correction => {
            if !pack.earlier.is_empty() {
                return Err(invalid_consolidation(
                    "extraction earlier answers name no read question",
                ));
            }
            let questions = reads::correction_plan_questions(&checked, pack.part)?;
            (checked.listed_ids(), Vec::new(), questions)
        }
        ExtractionRead::CorrectionFinal => {
            let questions = finals::correction_final_plan(&checked, &pack.earlier, pack.part)?;
            (checked.listed_ids(), Vec::new(), questions)
        }
        ExtractionRead::Resolution => {
            if !pack.earlier.is_empty() {
                return Err(invalid_consolidation(
                    "extraction earlier answers name no read question",
                ));
            }
            let built = reads::resolution_conflict(&checked.rows, bound, read, txn)?;
            let questions = reads::resolution_plan_questions(&built, pack.part)?;
            (Vec::new(), built.prior_ids(), questions)
        }
        ExtractionRead::ResolutionFinal => {
            let built = reads::resolution_conflict(&checked.rows, bound, read, txn)?;
            let question = finals::resolution_final_plan(&built, &pack.earlier, pack.part)?;
            (Vec::new(), built.prior_ids(), vec![question])
        }
        ExtractionRead::IdentityFinal => {
            let built = reads::resolution_conflict(&checked.rows, bound, read, txn)?;
            let questions = finals::identity_final_plan(&built, &pack.earlier, pack.part)?;
            (Vec::new(), built.prior_ids(), questions)
        }
    };
    for question in &questions {
        check_choice_contract(&question.options)?;
    }
    Ok(RebuiltExtractionPack {
        candidate_ids: checked.candidate_ids(),
        listed,
        priors,
        questions,
    })
}

/// Runs the ladder's contract check over one rebuilt Choice's `options`
/// without building any question or identifier.
fn check_choice_contract(options: &[String]) -> Result<()> {
    AnswerContract::Choice {
        options: options.to_vec(),
    }
    .validate()
    .map_err(|_| invalid_consolidation("a rebuilt pack contract breaks the choice contract"))
}

/// Maps one pack option to its native canonical text: a `candidate:<index>`
/// alias to the derived identifier of that pack operand, anything else
/// unchanged. A raw derived identifier must use its alias, and an index must
/// be canonical decimal inside the operands. The bound handler maps every
/// offered option through this function before it compares contracts, and the
/// rebuild maps every earlier answer the same way.
pub(crate) fn map_candidate_alias(option: &str, candidates: &[EntityId]) -> Result<String> {
    let Some(index) = option.strip_prefix("candidate:") else {
        if candidates.iter().any(|id| id.to_hex() == option) {
            return Err(invalid_consolidation(
                "a candidate option must use its candidate index alias",
            ));
        }
        return Ok(option.to_owned());
    };
    let position: usize = index.parse().map_err(|_| {
        invalid_consolidation("a candidate option must name a decimal candidate index")
    })?;
    if position.to_string() != index {
        return Err(invalid_consolidation(
            "a candidate option index must be canonical decimal",
        ));
    }
    candidates
        .get(position)
        .map(EntityId::to_hex)
        .ok_or_else(|| {
            invalid_consolidation("a candidate option index is outside the pack operands")
        })
}
