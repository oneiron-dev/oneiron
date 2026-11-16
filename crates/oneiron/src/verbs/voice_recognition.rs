//! `vault.voices.recognition.withdraw` (VOICE-RECOGNITION-CONSENT-NO-DOOR):
//! a person withdraws voice-recognition consent. The withdrawal deletes the
//! subject's voiceprint, its sample and vector rows and its active pointer,
//! and keeps the consent record (ARCH-0061 promise-dura-13), in the one
//! write [`Vault::withdraw_voice_consent_as`] makes. The subject's render
//! bank stays under its own consent (`vault.voices.render_consent`). The
//! acting person
//! records it: on their own voice on their own live person proof, owner of
//! the vault or not, or on another subject's under the owner's authority
//! (a counterparty enrolled on logged consent holds no credential here).
//!
//! An agent logs a counterparty's spoken withdrawal on a call
//! (VOICE-WITHDRAW-AGENT-ON-CALL; lead: "the way out must never be harder
//! than the way in") under the same Grant that lets it log that person's
//! consent: one naming [`VOICE_RECOGNITION_CONSENT_VERB`], checked live in
//! the withdrawal's write. Each live owner is told in that write.
//!
//! There is no door that grants recognition consent or enrolls a print:
//! a hosted enrolment needs the written release first
//! (CLOUD-FLOOR-BIPA-VOICEPRINT). Until that door lands, a Grant naming the
//! consent verb confers only the withdrawal, which only narrows.
use crate::Vault;
use crate::authority::{NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::voice_identity::VoiceWithdrawalReceipt;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::voice_recognition::{
    VoiceRecognitionWithdrawReceipt, VoiceRecognitionWithdrawRequest,
};

/// The verb's public spelling.
const WITHDRAW_VERB: &str = "vault.voices.recognition.withdraw";

/// The verb an agent's Grant names to log a counterparty's spoken
/// voice-recognition consent on a call (ARCH-0061:102), and with it that
/// person's spoken withdrawal (VOICE-WITHDRAW-AGENT-GRANT = A): the way in
/// and the way out are one Grant. The consent-logging door, when it lands,
/// checks this same name (FIX row VOICE-RECOGNITION-CONSENT-LOG-DOOR).
pub const VOICE_RECOGNITION_CONSENT_VERB: &str = "vault.voices.recognition.consent";

/// `vault.voices.recognition.withdraw` on an embedded handle: an agent's
/// handle logs a counterparty's spoken withdrawal under its own Grant; any
/// other acts as the vault's embedded owner, who may withdraw for any
/// subject.
pub fn withdraw_voice_recognition_consent(
    memory: &Memory<'_>,
    input: VoiceRecognitionWithdrawRequest,
) -> MemoryResult<VoiceRecognitionWithdrawReceipt> {
    match memory.actor_class() {
        EdgeActorClass::Agent | EdgeActorClass::System => {
            withdraw_voice_recognition_consent_as_agent(memory, input)
        }
        EdgeActorClass::Human => {
            let owner = memory.embedded_owner(WITHDRAW_VERB)?;
            withdraw_voice_recognition_consent_as(memory.vault(), &owner, input)
        }
    }
}

/// `vault.voices.recognition.withdraw` under the acting person's proof,
/// which the withdrawal's write revalidates: a person's own for their own
/// voice, the owner's for another subject's.
pub fn withdraw_voice_recognition_consent_as(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    input: VoiceRecognitionWithdrawRequest,
) -> MemoryResult<VoiceRecognitionWithdrawReceipt> {
    let subject = subject_of(&input)?;
    let recorded_by = proof.actor_for_read(vault)?;
    let receipt = vault.withdraw_voice_consent_as(
        proof,
        subject,
        input.event_id,
        input.occurred_at,
        input.basis,
    )?;
    Ok(wire_receipt(&receipt, recorded_by))
}

/// `vault.voices.recognition.withdraw` for the agent `memory` acts as, on
/// its own credential: it logs the spoken withdrawal of the subject it
/// names, a counterparty on its call, never a vault owner's (the owner
/// withdraws their own voice on their own proof). The withdrawal's write
/// admits the agent first ([`agent_withdrawer_in_txn`]); the door's early
/// check ([`voice_recognition_withdrawal_admits_agent`]) runs the same
/// admission in a snapshot of its own.
pub fn withdraw_voice_recognition_consent_as_agent(
    memory: &Memory<'_>,
    input: VoiceRecognitionWithdrawRequest,
) -> MemoryResult<VoiceRecognitionWithdrawReceipt> {
    let subject = subject_of(&input)?.ok_or_else(|| {
        MemoryError::bad_request("an agent names the subject whose spoken withdrawal it logs")
    })?;
    let agent = memory.actor();
    let receipt = memory.vault().withdraw_voice_consent_logged_by_agent(
        agent,
        subject,
        input.event_id,
        input.occurred_at,
        input.basis,
        |txn| agent_withdrawer_in_txn(memory, txn, Some(subject)),
    )?;
    Ok(wire_receipt(&receipt, agent))
}

/// The agent withdrawal's admission alone, in a snapshot of its own: a door
/// asks it before the row's verb hooks fire, so no hook fires on a call the
/// withdrawal's write would refuse. The write admits the agent again.
pub fn voice_recognition_withdrawal_admits_agent(memory: &Memory<'_>) -> MemoryResult<()> {
    let txn = memory
        .vault()
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)?;
    agent_withdrawer_in_txn(memory, &txn, None).map(drop)
}

/// Whether the agent `memory` acts as may log a spoken withdrawal in `txn`:
/// its actor binding holds, its presented credential is still live, a live
/// Grant from a live owner names it and lists
/// [`VOICE_RECOGNITION_CONSENT_VERB`], and `subject`, when named, is no
/// live owner of the vault. Answers that Grant.
fn agent_withdrawer_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    subject: Option<EntityId>,
) -> MemoryResult<EntityId> {
    let vault = memory.vault();
    crate::memory::verify_actor_binding_in_txn(vault, txn, memory.actor(), memory.actor_class())?;
    if let Some(slip) = memory.presented_credential()
        && !vault.capability_slip_is_live_in_txn(txn, slip)?
    {
        return Err(agent_refused("the caller's credential is no longer live"));
    }
    let standing = match memory.actor_class() {
        EdgeActorClass::Agent | EdgeActorClass::System => principal_standing_or_lapse_in_txn(
            vault,
            txn,
            memory.actor(),
            memory.actor_class(),
            VOICE_RECOGNITION_CONSENT_VERB,
        )?,
        EdgeActorClass::Human => Err(NoStanding::NotStanding),
    };
    let grant = match standing.map(|standing| standing.grant) {
        Ok(Some(grant)) => grant,
        Err(NoStanding::PactStandingLapsed) => return Err(agent_refused(PACT_STANDING_LAPSED)),
        Ok(None) | Err(NoStanding::NotStanding) => {
            return Err(agent_refused(
                "no live Grant from a live owner names this agent and lists the consent verb",
            ));
        }
    };
    if let Some(subject) = subject
        && crate::policy_model::owners_in_txn(vault, txn)?.contains(&subject)
    {
        return Err(agent_refused(
            "a vault owner withdraws their own voice on their own proof",
        ));
    }
    Ok(grant)
}

/// The refusal of an agent the withdrawal does not admit.
fn agent_refused(why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{WITHDRAW_VERB} logs a counterparty's spoken withdrawal only for an agent whose own \
             Grant lists {VOICE_RECOGNITION_CONSENT_VERB}: {why}"
        ),
        &[
            "Have the owner grant this agent the consent verb by name, or let the person withdraw on their own proof.",
        ],
    )
}

/// The subject `input` names, if any.
fn subject_of(input: &VoiceRecognitionWithdrawRequest) -> MemoryResult<Option<EntityId>> {
    input
        .subject
        .as_deref()
        .map(EntityId::from_hex)
        .transpose()
        .map_err(|_| MemoryError::bad_request("subject is an entity id in lowercase hex"))
}

/// The wire receipt of `receipt`, recorded by `recorded_by`.
fn wire_receipt(
    receipt: &VoiceWithdrawalReceipt,
    recorded_by: EntityId,
) -> VoiceRecognitionWithdrawReceipt {
    VoiceRecognitionWithdrawReceipt {
        event_id: receipt.consent_event_ref.clone(),
        subject: receipt.subject_ref.to_hex(),
        recorded_by: recorded_by.to_hex(),
        replayed: receipt.replayed,
        already_absent: receipt.already_absent,
        deleted_print: receipt.deleted_print,
        deleted_sample_count: u64::try_from(receipt.deleted_sample_count).unwrap_or(u64::MAX),
        deleted_vector_count: u64::try_from(receipt.deleted_vector_count).unwrap_or(u64::MAX),
        deleted_active_pointer: receipt.deleted_active_pointer,
    }
}
