//! A consult ladder's Finish of a consent-required interruption, checked
//! against the case that interruption froze (FIX 9742), and the record every
//! Finish keeps of when it was claimed and recorded (FIX 9743).
//!
//! The first consent-requiring interruption freezes its case once, in the
//! engine's own row: the case ref (the ask its human verdict settles), the
//! interruption's kind and time, and its opener with the binding generation
//! and the credential lineage it held. A Finish of that interruption lands
//! on the case's settled ask when one was raised (`consent_ask`): a
//! governing decision with a counted human word from someone other than the
//! opener and outside the opener's credential lineage (FIX 10693). While
//! that ask stands unsettled the ladder stays where it is. A case whose ask
//! was never raised finishes as before and is recorded as unverified.
//! Nothing here reads a caller's kind or approval: the case, the ask, its
//! words and its settlement are the engine's rows.
//!
//! The case is an authority record, kept in a session that keeps no record
//! too, with its authority fields only and no conversation content (Engine
//! 10-26, ARCH-0052, FIX 10694).

use crate::Vault;
use crate::consult_ladder::{InterruptedState, LadderTerminalState, LadderTransitionError};
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::memory::MemoryResult;
use crate::task_authority::BindingGeneration;

use super::super::ask_record;
use super::super::ask_settlement::ask_settlement_in;
use super::super::ask_types::{
    TaskAskDecision, TaskAskEvidenceReason, TaskAskResult, TaskAskSettlementReason, TaskAskSource,
};
use super::super::highway_types::TaskLifecycleRecord;
use super::super::lifecycle_receipt;
use super::super::task_actor::TaskActor;

const CASE_CALL: &str = "consult_case";
const FINISH_CALL: &str = "consult_finish";
const FIELD_CASE_REF: &str = "case_ref";
const FIELD_KIND: &str = "interruption_kind";
const FIELD_INTERRUPTED_AT: &str = "interrupted_at";
const FIELD_OPENER_GENERATION: &str = "opener_generation";
const FIELD_OPENER_LINEAGE: &str = "opener_lineage";

/// A frozen case, as its Finish and its ask read it.
pub(super) struct FrozenCase {
    /// The ask group whose settlement verifies the case.
    pub(super) case_ref: EntityId,
    /// The actor whose interruption froze it.
    pub(super) opener: Option<EntityId>,
    /// The credential chains the opener's handle carried (FIX 10693).
    opener_lineage: Vec<[u8; 32]>,
}

/// `task_ref`'s frozen case, read in `txn`: `None` when none was frozen or
/// its case ref does not read.
pub(super) fn frozen_case_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> MemoryResult<Option<FrozenCase>> {
    let Some(case) = lifecycle_receipt::kept_in(vault, txn, &case_id(task_ref)?)? else {
        return Ok(None);
    };
    let Some(case_ref) = case
        .fields
        .get(FIELD_CASE_REF)
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    let opener = case
        .actor
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok());
    let opener_lineage = case
        .fields
        .get(FIELD_OPENER_LINEAGE)
        .map_or_else(Vec::new, |joined| {
            joined
                .split(',')
                .filter_map(super::super::brief::decode_hex::<32>)
                .collect()
        });
    Ok(Some(FrozenCase {
        case_ref,
        opener,
        opener_lineage,
    }))
}

/// A Finish of a consent-required interruption that its case's settled ask
/// verified. Only [`verify_finish_in`] builds one.
pub(super) struct VerifiedConsultFinish {
    /// The case, and the ask group whose settlement verified it.
    case_ref: EntityId,
    /// The class that ask was governed under, `key@version`, when it named one.
    class: Option<String>,
    /// When that ask settled.
    settled_at: u64,
}

/// What the consent a Finish needs came to.
pub(super) enum ConsultConsent {
    /// The case's ask settled it.
    Verified(VerifiedConsultFinish),
    /// No ask was raised for the case, or no case was frozen: the Finish
    /// lands as before and its record says the consent went unverified.
    Unverified,
}

/// The id the case of `task_ref`'s consent-requiring interruption is kept
/// under: one per consult, as only its first such interruption freezes one.
fn case_id(task_ref: EntityId) -> MemoryResult<String> {
    lifecycle_receipt::receipt_id(CASE_CALL, &[task_ref.as_bytes()])
}

/// Freezes the case of `task_ref`'s first consent-requiring interruption,
/// once, in `wtxn`, the transaction that records the interruption, with the
/// credential chains the opener's handle carried (`opener_lineage`, FIX
/// 10693). Kept in a savepoint of its own: a case that does not land is
/// logged and leaves the interruption's write as it is.
pub(super) fn freeze_case_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    task_ref: EntityId,
    interrupted: &InterruptedState,
    opener: (EntityId, &[[u8; 32]]),
    generation: Option<&BindingGeneration>,
) {
    let (opener, opener_lineage) = opener;
    let mut case = TaskLifecycleRecord {
        call: CASE_CALL.to_owned(),
        outcome: "consent_required".to_owned(),
        occurred_at: interrupted.interrupted_at,
        actor: TaskActor::Actor(opener),
        on_behalf_of: None,
        job_ref: None,
        trigger_ref: Some(task_ref.to_hex()),
        fields: std::collections::BTreeMap::new(),
    };
    case.fields
        .insert(FIELD_CASE_REF.to_owned(), interrupted.case_ref.to_hex());
    case.fields
        .insert(FIELD_KIND.to_owned(), interrupted.kind.as_str().to_owned());
    case.fields.insert(
        FIELD_INTERRUPTED_AT.to_owned(),
        interrupted.interrupted_at.to_string(),
    );
    if let Some(generation) = generation {
        case.fields.insert(
            FIELD_OPENER_GENERATION.to_owned(),
            generation
                .bindings()
                .iter()
                .map(|binding| bytes_to_hex_lower(binding))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if !opener_lineage.is_empty() {
        case.fields.insert(
            FIELD_OPENER_LINEAGE.to_owned(),
            opener_lineage
                .iter()
                .map(|slip| bytes_to_hex_lower(slip))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    let kept = case_id(task_ref).and_then(|id| {
        if lifecycle_receipt::kept_in(vault, &*wtxn, &id)?.is_some() {
            return Ok(());
        }
        stamp_in_savepoint(vault, wtxn, &case, id)
    });
    if kept.is_err() {
        tracing::warn!(
            task = %task_ref.to_hex(),
            "a consult interruption's consent case was not frozen; the interruption stands"
        );
    }
}

/// The consent a Finish of `task_ref`'s consent-required interruption
/// carries, read in `txn`, the Finish's own transaction. Its frozen case's
/// ask, when one was raised, must have settled a decision that governs this
/// consult with a counted human word from someone other than the case's
/// opener and outside its credential lineage; an ask still open, or one
/// that settled on none of that, leaves the ladder where it is.
pub(super) fn verify_finish_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
) -> MemoryResult<ConsultConsent> {
    let Some(case) = frozen_case_in(vault, txn, task_ref)? else {
        return Ok(ConsultConsent::Unverified);
    };
    let case_ref = case.case_ref;
    let Some(group) = ask_record::read_group(vault, txn, case_ref)? else {
        return Ok(ConsultConsent::Unverified);
    };
    let governs = group.class_tasks().any(|task| task == task_ref);
    match ask_settlement_in(vault, txn, case_ref)? {
        Some(result) if governs && settles_consent(vault, txn, &result, &case) => {
            Ok(ConsultConsent::Verified(VerifiedConsultFinish {
                case_ref,
                class: result
                    .settlement
                    .effective
                    .class
                    .as_ref()
                    .map(|class| format!("{}@{}", class.key, class.version)),
                settled_at: result.settlement.at,
            }))
        }
        _ => Err(super::ladder_refusal(
            LadderTransitionError::ConsentRequired,
        )),
    }
}

/// Whether `result` is a human verdict: settled by its words, not its
/// deadline or a stale cut, on a decision, with a counted human word from
/// someone other than `case`'s opener and outside its credential lineage.
fn settles_consent(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    result: &TaskAskResult,
    case: &FrozenCase,
) -> bool {
    matches!(
        result.settlement.reason,
        TaskAskSettlementReason::FirstWord | TaskAskSettlementReason::AllResponded
    ) && !matches!(
        result.decision,
        TaskAskDecision::Unknown | TaskAskDecision::Conflict
    ) && result.evidence.iter().any(|entry| {
        entry.reason == TaskAskEvidenceReason::Counted
            && entry.source == TaskAskSource::Human
            && Some(entry.answer.actor_ref) != case.opener
            && !from_opener_lineage(vault, txn, entry.answer.word_ref, &case.opener_lineage)
    })
}

/// Whether the word `word_ref` was admitted from `opener`'s credential
/// lineage or a fork of it (FIX 10693, DEC-0006): its owner proof's frozen
/// chains reach the opener's delegation roots. A common signing host is not
/// a common lineage. A word whose chains are unknown, or that do not read,
/// counts as the opener's: it verifies no consent.
fn from_opener_lineage(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    word_ref: EntityId,
    opener: &[[u8; 32]],
) -> bool {
    if opener.is_empty() {
        return false;
    }
    match ask_record::answer_lineage_in(vault, txn, word_ref) {
        Ok(Some(answer)) => vault
            .frozen_lineages_meet_in_txn(txn, &answer, opener)
            .unwrap_or(true),
        Ok(None) | Err(_) => true,
    }
}

/// Keeps the record of one Finish, in `wtxn`, the transaction it landed in:
/// the engine time it was recorded at, the time the caller claimed it
/// finished, whether the consult's deadline had passed and whether the
/// claimed time is later than the engine's, and what its consent came to.
/// Every claimed time is accepted as before; these only say what was true.
/// Kept in a savepoint of its own: a record that does not land is logged
/// and leaves the Finish as it is.
pub(super) fn record_finish_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    finish: FinishRecord<'_>,
) {
    let recorded_at = vault.store.clock.now_recorded_at();
    let mut record = TaskLifecycleRecord {
        call: FINISH_CALL.to_owned(),
        outcome: finish.terminal.disposition.as_str().to_owned(),
        occurred_at: recorded_at,
        actor: TaskActor::Actor(finish.actor),
        on_behalf_of: None,
        job_ref: None,
        trigger_ref: Some(finish.task_ref.to_hex()),
        fields: std::collections::BTreeMap::new(),
    };
    let fields = &mut record.fields;
    fields.insert("recorded_at".to_owned(), recorded_at.to_string());
    fields.insert(
        "finished_at".to_owned(),
        finish.terminal.finished_at.to_string(),
    );
    if finish
        .deadline_at
        .is_some_and(|deadline| deadline < recorded_at)
    {
        fields.insert("overdue".to_owned(), "true".to_owned());
    }
    if finish.terminal.finished_at > recorded_at {
        fields.insert("future_claimed".to_owned(), "true".to_owned());
    }
    match finish.consent {
        Some(ConsultConsent::Verified(verified)) => {
            fields.insert("consent".to_owned(), "verified".to_owned());
            fields.insert("consent_settlement".to_owned(), verified.case_ref.to_hex());
            fields.insert(
                "consent_settled_at".to_owned(),
                verified.settled_at.to_string(),
            );
            if let Some(class) = &verified.class {
                fields.insert("consent_class".to_owned(), class.clone());
            }
        }
        Some(ConsultConsent::Unverified) => {
            fields.insert("consent_unverified".to_owned(), "true".to_owned());
        }
        None => {}
    }
    let kept = lifecycle_receipt::receipt_id(FINISH_CALL, &[finish.task_ref.as_bytes()])
        .and_then(|id| stamp_in_savepoint(vault, wtxn, &record, id));
    if kept.is_err() {
        tracing::warn!(
            task = %finish.task_ref.to_hex(),
            "a consult Finish's record was not kept; the Finish stands"
        );
    }
}

/// One landed Finish, as its record names it.
pub(super) struct FinishRecord<'a> {
    pub(super) task_ref: EntityId,
    pub(super) actor: EntityId,
    pub(super) terminal: &'a LadderTerminalState,
    /// The consult's deadline, when it has one.
    pub(super) deadline_at: Option<u64>,
    /// What its consent came to, when its interruption required consent.
    pub(super) consent: Option<&'a ConsultConsent>,
}

/// Keeps `record` under `id` in a savepoint of `wtxn`: it lands whole, or
/// not at all and `wtxn` goes on as it was.
fn stamp_in_savepoint(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &TaskLifecycleRecord,
    id: String,
) -> MemoryResult<()> {
    let mut savepoint = vault
        .store
        .env
        .nested_write_txn(wtxn)
        .map_err(crate::Error::from)?;
    lifecycle_receipt::stamp_record_in(vault, &mut savepoint, record, id, None)?;
    savepoint.commit().map_err(crate::Error::from)?;
    Ok(())
}
