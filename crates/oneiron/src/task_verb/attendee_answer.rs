//! The owner-proof rule for an attendee ask's answer (OF-365, ILDF2 P4).
//!
//! An ask whose intent key is `disclosure.attendee_ask/<ask hex>` asks the
//! vault's owners "who is this?" about one speaker. Its first counted word
//! decides that speaker's identity, so a word counts only as the owner's own
//! act: a Human word from the actor a live owner proof names, given on a
//! direct surface at the ask's admission node, naming one of the options the
//! ask CLAIM froze. Every other word is refused before it is recorded, so an
//! unauthorized word can never occupy First and strand the owner's later
//! tap. A settlement without that proof may still close the ask on its
//! deadline or as stale, never on a definitive word. The settlement that
//! selects the owner's word resolves the speaker's identity in its own
//! transaction, from that word's option alone; a replay never resolves
//! again. Other asks are unchanged.

use super::ask_record::{self, AskGroup};
use super::ask_types::{
    TaskAskDecision, TaskAskEvidenceReason, TaskAskResult, TaskAskSettlementReason, TaskAskSource,
    TaskAskWord,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::ClaimLifecycleStatus;
use crate::consent::AuthenticatedOwner;
use crate::disclosure::{AttendeeIdentityChoice, PREDICATE_DISCLOSURE_ATTENDEE_ASK};
use crate::error::{Error, GateError, Result};
use crate::memory::Memory;
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::task_verb::ConsultPayloadRef;
use crate::{EntityId, Vault};

/// The ask CLAIM hex an attendee ask's intent key carries; `None` for every
/// other ask.
fn attendee_intent(group: &AskGroup) -> Option<&str> {
    group
        .requested
        .intent_key
        .strip_prefix(PREDICATE_DISCLOSURE_ATTENDEE_ASK)?
        .strip_prefix('/')
}

fn owner_not_authenticated(reason: &'static str) -> Error {
    Error::Gate(GateError::ConsentOwnerNotAuthenticated(reason))
}

/// The candidates the attendee ask CLAIM `ask_ref` froze, once the ask that
/// carries it checks out: its question names the CLAIM, and the CLAIM is a
/// live, typed attendee ask on the ask's own revision.
fn frozen_candidates_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group: &AskGroup,
    ask_ref: EntityId,
) -> Result<Vec<EntityId>> {
    let what = &group.effective.what;
    let claim_ref = ConsultPayloadRef::Claim(ask_ref);
    if what.reference != claim_ref && !what.context_refs.contains(&claim_ref) {
        return Err(ask_record::invalid());
    }
    let raw = vault
        .get_raw_in(txn, &ask_ref)?
        .ok_or_else(ask_record::invalid)?;
    if EntityMetadataHeader::parse(&raw).map(|header| header.entity_type) != Some(ENTITY_TYPE_CLAIM)
    {
        return Err(ask_record::invalid());
    }
    let body = crate::claim::decode_claim_body(
        raw.get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or_else(ask_record::invalid)?,
        true,
    )?;
    if body.predicate != PREDICATE_DISCLOSURE_ATTENDEE_ASK
        || body.lifecycle != ClaimLifecycleStatus::Active
    {
        return Err(ask_record::invalid());
    }
    // The strict typed decode of the frozen question, before any field of it
    // is read below.
    crate::disclosure::validate_disclosure_claim_structure(&body)?;
    let field = |key: &str| {
        body.value.as_map().and_then(|entries| {
            entries
                .iter()
                .find(|(name, _)| name.as_str() == Some(key))
                .map(|(_, value)| value)
        })
    };
    if field("revision").and_then(rmpv::Value::as_u64) != Some(what.revision) {
        return Err(ask_record::invalid());
    }
    let Some(rmpv::Value::Array(candidates)) = field("candidates") else {
        return Err(ask_record::invalid());
    };
    candidates
        .iter()
        .map(|candidate| match candidate {
            rmpv::Value::Binary(bytes) => EntityId::from_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| ask_record::invalid())?,
            )
            .map_err(|_| ask_record::invalid()),
            _ => Err(ask_record::invalid()),
        })
        .collect()
}

/// Refuses a word on an attendee ask unless it is the owner's own act; any
/// other ask passes untouched. Runs in shared word admission, before the
/// word is recorded, for `tasks_answer`, a consult answer and a redeemed
/// option link alike.
#[expect(
    clippy::too_many_arguments,
    reason = "one admission check over the word, its writer and the owner proof"
)]
pub(super) fn guard_word(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    group: &AskGroup,
    source: TaskAskSource,
    actor: EntityId,
    word: &TaskAskWord,
    owner: Option<&AuthenticatedOwner>,
) -> Result<()> {
    let Some(hex) = attendee_intent(group) else {
        return Ok(());
    };
    let ask_ref = EntityId::from_hex(hex).map_err(|_| ask_record::invalid())?;
    if ask_ref.to_hex() != hex {
        return Err(ask_record::invalid());
    }
    let candidates = frozen_candidates_in(vault, txn, group, ask_ref)?;
    // A definitive answer names one frozen option, in its canonical form.
    let choice = word
        .option
        .as_ref()
        .and_then(AttendeeIdentityChoice::from_option)
        .ok_or_else(ask_record::invalid)?;
    if word.confirmation.is_some()
        || choice.option().ok().as_ref() != word.option.as_ref()
        || matches!(choice, AttendeeIdentityChoice::Contact(contact) if !candidates.contains(&contact))
    {
        return Err(ask_record::invalid());
    }
    // Only the admission node settles the ask, so a word anywhere else
    // could never settle under the proof that admitted it.
    if !ask_record::owns_revision(vault, txn, id, group)? {
        return Err(owner_not_authenticated(
            "an attendee answer is given on the node that admitted the ask",
        ));
    }
    let Some(owner) = owner else {
        return Err(owner_not_authenticated(
            "an attendee answer needs the owner's own authenticated word",
        ));
    };
    if source != TaskAskSource::Human || owner.revalidate_in_txn(vault, txn)? != actor {
        return Err(owner_not_authenticated(
            "an attendee answer is the authenticated owner's own word",
        ));
    }
    Ok(())
}

/// Whether settlement may cut `group` for `reason` with `decision` under
/// `owner`. An attendee ask's first word decides an identity only under the
/// live proof of the owner who gave it; without that proof the ask stays
/// open, and only its deadline or staleness closes it, on the hold default.
pub(super) fn may_cut(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    group: &AskGroup,
    reason: TaskAskSettlementReason,
    decision: &TaskAskDecision,
    owner: Option<&AuthenticatedOwner>,
) -> Result<bool> {
    if matches!(
        reason,
        TaskAskSettlementReason::Deadline | TaskAskSettlementReason::Stale
    ) || attendee_intent(group).is_none()
    {
        return Ok(true);
    }
    let TaskAskDecision::First(answer) = decision else {
        return Ok(true);
    };
    match owner {
        Some(owner) => Ok(owner.revalidate_in_txn(vault, txn)? == answer.actor_ref),
        None => Ok(false),
    }
}

/// Resolves the speaker's identity from the word `result` selected, in the
/// settlement's own write transaction, before the settlement is stored.
///
/// It acts only on a definitive cut of an attendee ask: a counted Human word
/// selected First, coverage met, no fallback, a question still current, and
/// live owner proof naming that word's actor. The choice is that word's own
/// option, never a later caller's. An identity an owner door already
/// recorded for this speaker and revision stands: the decision slot keeps
/// its winner, and this settlement records its word without overwriting it.
pub(super) fn resolve_answer_in(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    group: &AskGroup,
    result: &TaskAskResult,
    owner: Option<&AuthenticatedOwner>,
) -> Result<()> {
    let Some(hex) = attendee_intent(group) else {
        return Ok(());
    };
    let (TaskAskDecision::First(answer), Some(owner)) = (&result.decision, owner) else {
        return Ok(());
    };
    if !result.coverage.met
        || result.fallback.is_some()
        || result.settlement.reason == TaskAskSettlementReason::Stale
        || owner.revalidate_in_txn(vault, txn)? != answer.actor_ref
    {
        return Ok(());
    }
    let selected = result
        .evidence
        .iter()
        .find(|entry| {
            entry.answer == *answer
                && entry.reason == TaskAskEvidenceReason::Counted
                && entry.source == TaskAskSource::Human
        })
        .ok_or_else(ask_record::invalid)?;
    let choice = selected
        .word
        .option
        .as_ref()
        .and_then(AttendeeIdentityChoice::from_option)
        .ok_or_else(ask_record::invalid)?;
    let ask_ref = EntityId::from_hex(hex).map_err(|_| ask_record::invalid())?;
    match vault.resolve_attendee_identity_in_txn(
        txn,
        owner,
        &ask_ref,
        group.effective.what.revision,
        choice,
    ) {
        Ok(_) | Err(Error::Gate(GateError::ConsentApproveOnceSpent(_))) => Ok(()),
        Err(error) => Err(error),
    }
}

impl Memory<'_> {
    /// The owner proof a word this surface writes carries: the proof the
    /// host bound for the owner's direct request, and only there. Generated
    /// code and a room turn answer for no one in person, so theirs is none.
    pub(super) fn answer_owner_proof(&self) -> Option<&AuthenticatedOwner> {
        if self.writes_generated() || self.room_turn().is_some() {
            return None;
        }
        self.owner_authorship()
    }
}
