//! `vault.voices.recognition.withdraw` and `vault.voices.recognition.consent`
//! (VOICE-RECOGNITION-CONSENT-NO-DOOR, VOICE-CONSENT-LOG-WHO = A): a person withdraws
//! voice-recognition consent, and a person logs it. The withdrawal deletes the
//! subject's voiceprint, its sample and vector rows and its active pointer,
//! and keeps the consent record (ARCH-0061 promise-dura-13), in the one
//! write [`Vault::withdraw_voice_consent_as`] makes. The subject's render
//! bank stays under its own consent (`vault.voices.render_consent`). The
//! acting person records it: on their own voice on their own live person proof, owner of
//! the vault or not, or on another subject's under the owner's authority
//! (a counterparty enrolled on logged consent holds no credential here).
//!
//! An agent logs a counterparty's spoken word on a call, its consent or its
//! withdrawal (VOICE-WITHDRAW-AGENT-ON-CALL, VOICE-CONSENT-LOG-WHO = A;
//! oneiron-arch-0061 "the agent logs who/when/what"; lead: "the way out must never be harder
//! than the way in") under the same Grant that lets it log that person's
//! consent: one naming [`VOICE_RECOGNITION_CONSENT_VERB`], checked live in
//! each write; never for a live owner's voice or its own. Each live owner is
//! told in that write, on its first insertion; a replay tells no one again.
//! An agent here is an agent or system-class principal on its own credential.
//!
//! No door enrols a print: logging consent enrols nothing, and enrolment stays
//! engine-only, where its own law check answers the hosted written release
//! (CLOUD-FLOOR-BIPA-VOICEPRINT). A logged consent is dated by the vault's
//! clock at the latest, so it never outlives a later withdrawal.
use crate::Vault;
use crate::authority::{NoStanding, PACT_STANDING_LAPSED, principal_standing_or_lapse_in_txn};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};
use crate::voice_identity::{VoiceConsentReceipt, VoicePrintPurpose, VoiceWithdrawalReceipt};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::voice_recognition::{
    VoiceRecognitionConsentReceipt, VoiceRecognitionConsentRequest, VoiceRecognitionPurpose,
    VoiceRecognitionWithdrawReceipt, VoiceRecognitionWithdrawRequest,
};

/// The withdrawal verb's public spelling.
const WITHDRAW_VERB: &str = "vault.voices.recognition.withdraw";

/// The verb an agent's Grant names to log a counterparty's spoken
/// voice-recognition consent on a call (ARCH-0061:102), and with it that
/// person's spoken withdrawal (VOICE-WITHDRAW-AGENT-GRANT = A): the way in
/// and the way out are one Grant. The consent-log door checks this same name
/// (VOICE-CONSENT-LOG-WHO = A); logging consent enrols no print, and no door
/// enrols one.
pub const VOICE_RECOGNITION_CONSENT_VERB: &str = "vault.voices.recognition.consent";

/// `vault.voices.recognition.withdraw` on an embedded handle: an agent or
/// system handle logs a counterparty's spoken withdrawal under its own
/// Grant; a human handle acts as the vault's embedded owner, who may
/// withdraw for any subject (any other human handle is refused).
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
    let subject = subject_of(input.subject.as_deref())?;
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
/// admits the agent first ([`agent_recorder_in_txn`]); the door's early
/// check ([`voice_recognition_recorder_admits_agent`]) runs the same
/// admission in a snapshot of its own.
pub fn withdraw_voice_recognition_consent_as_agent(
    memory: &Memory<'_>,
    input: VoiceRecognitionWithdrawRequest,
) -> MemoryResult<VoiceRecognitionWithdrawReceipt> {
    let subject = subject_of(input.subject.as_deref())?.ok_or_else(|| {
        MemoryError::bad_request("an agent names the subject whose spoken withdrawal it logs")
    })?;
    let agent = memory.actor();
    let receipt = memory.vault().withdraw_voice_consent_logged_by_agent(
        agent,
        subject,
        input.event_id,
        input.occurred_at,
        input.basis,
        |txn| agent_recorder_in_txn(memory, txn, Some(subject), WITHDRAW_VERB),
    )?;
    Ok(wire_receipt(&receipt, agent))
}

/// `vault.voices.recognition.consent` on an embedded handle: an agent or
/// system handle logs a counterparty's spoken consent under its own Grant;
/// a human handle acts as the vault's embedded owner, who may log for any
/// subject (any other human handle is refused). Logging consent enrols
/// nothing.
pub fn record_voice_recognition_consent(
    memory: &Memory<'_>,
    input: VoiceRecognitionConsentRequest,
) -> MemoryResult<VoiceRecognitionConsentReceipt> {
    match memory.actor_class() {
        EdgeActorClass::Agent | EdgeActorClass::System => {
            record_voice_recognition_consent_as_agent(memory, input)
        }
        EdgeActorClass::Human => {
            let owner = memory.embedded_owner(VOICE_RECOGNITION_CONSENT_VERB)?;
            record_voice_recognition_consent_as(memory.vault(), &owner, input)
        }
    }
}

/// `vault.voices.recognition.consent` under the acting person's proof,
/// which the consent's write revalidates: a person's own for their own
/// voice, the owner's for another subject's. It enrols no print.
pub fn record_voice_recognition_consent_as(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    input: VoiceRecognitionConsentRequest,
) -> MemoryResult<VoiceRecognitionConsentReceipt> {
    let subject = subject_of(input.subject.as_deref())?;
    let purposes = purposes_of(&input)?;
    let recorded_by = proof.actor_for_read(vault)?;
    let receipt = vault.record_voice_consent_as(
        proof,
        subject,
        input.event_id,
        input.occurred_at,
        purposes,
        input.basis,
    )?;
    Ok(consent_wire_receipt(&receipt, recorded_by))
}

/// `vault.voices.recognition.consent` for the agent `memory` acts as, on
/// its own credential: it logs the spoken consent of the subject it
/// names, a counterparty on its call, never a live owner's voice (the owner
/// consents for their own voice on their own proof). The consent's write
/// admits the agent first ([`agent_recorder_in_txn`]); the door's early
/// check ([`voice_recognition_recorder_admits_agent`]) runs the same
/// admission in a snapshot of its own. It enrols no print.
pub fn record_voice_recognition_consent_as_agent(
    memory: &Memory<'_>,
    input: VoiceRecognitionConsentRequest,
) -> MemoryResult<VoiceRecognitionConsentReceipt> {
    let subject = subject_of(input.subject.as_deref())?.ok_or_else(|| {
        MemoryError::bad_request("an agent names the subject whose spoken consent it logs")
    })?;
    let purposes = purposes_of(&input)?;
    let agent = memory.actor();
    let receipt = memory.vault().record_voice_consent_logged_by_agent(
        agent,
        subject,
        input.event_id,
        input.occurred_at,
        purposes,
        input.basis,
        |txn| agent_recorder_in_txn(memory, txn, Some(subject), VOICE_RECOGNITION_CONSENT_VERB),
    )?;
    Ok(consent_wire_receipt(&receipt, agent))
}

/// The agent recorder's admission alone, in a snapshot of its own: a door
/// asks it before the row's verb hooks fire, so no hook fires for an agent
/// whose credential or Grant the write would refuse. The subject, the
/// purposes and the date are judged only in the write, which admits the
/// agent again. It serves both the
/// consent and the withdrawal verbs (`verb`, the row's own spelling, names
/// the refusal): the admission is the same Grant.
pub fn voice_recognition_recorder_admits_agent(
    memory: &Memory<'_>,
    verb: &str,
) -> MemoryResult<()> {
    let txn = memory
        .vault()
        .store
        .env
        .read_txn()
        .map_err(crate::Error::from)?;
    agent_recorder_in_txn(memory, &txn, None, verb).map(drop)
}

/// Whether the agent `memory` acts as may log a spoken word in `txn` under
/// `verb`: its actor binding holds, its presented credential is still live, a live
/// Grant from a live owner names it and lists
/// [`VOICE_RECOGNITION_CONSENT_VERB`], and `subject`, when named, is no
/// live owner of the vault. Answers that Grant.
fn agent_recorder_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    subject: Option<EntityId>,
    verb: &str,
) -> MemoryResult<EntityId> {
    let vault = memory.vault();
    crate::memory::verify_actor_binding_in_txn(vault, txn, memory.actor(), memory.actor_class())?;
    if let Some(slip) = memory.presented_credential()
        && !vault.capability_slip_is_live_in_txn(txn, slip)?
    {
        return Err(agent_refused(
            verb,
            "the caller's credential is no longer live",
        ));
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
        Err(NoStanding::PactStandingLapsed) => {
            return Err(agent_refused(verb, PACT_STANDING_LAPSED));
        }
        Ok(None) | Err(NoStanding::NotStanding) => {
            return Err(agent_refused(
                verb,
                "no live Grant from a live owner names this agent and lists the consent verb",
            ));
        }
    };
    if subject == Some(memory.actor()) {
        return Err(agent_refused(
            verb,
            "an agent logs a counterparty's word, never its own",
        ));
    }
    if let Some(subject) = subject
        && crate::policy_model::owners_in_txn(vault, txn)?.contains(&subject)
    {
        return Err(agent_refused(
            verb,
            "a vault owner consents and withdraws for their own voice on their own proof",
        ));
    }
    Ok(grant)
}

/// The refusal of an agent `verb` does not admit.
fn agent_refused(verb: &str, why: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!(
            "{verb} logs a counterparty's spoken word only for an agent whose own \
             Grant lists {VOICE_RECOGNITION_CONSENT_VERB}: {why}"
        ),
        &[
            "Have the owner grant this agent the consent verb by name, or let the person act on their own proof.",
        ],
    )
}

/// The subject a request names, if any.
fn subject_of(subject: Option<&str>) -> MemoryResult<Option<EntityId>> {
    subject
        .map(EntityId::from_hex)
        .transpose()
        .map_err(|_| MemoryError::bad_request("subject is an entity id in lowercase hex"))
}

/// The engine purposes a consent `input`'s wire purposes name: at least one,
/// in their pinned spelling's order, so a retry that lists them in another
/// order replays. A repeated purpose is left to the consent record's own
/// check.
fn purposes_of(input: &VoiceRecognitionConsentRequest) -> MemoryResult<Vec<VoicePrintPurpose>> {
    if input.purposes.is_empty() {
        return Err(MemoryError::bad_request(
            "name at least one recognition purpose",
        ));
    }
    let mut purposes: Vec<_> = input
        .purposes
        .iter()
        .map(|purpose| match purpose {
            VoiceRecognitionPurpose::MeetingAttribution => VoicePrintPurpose::MeetingAttribution,
            VoiceRecognitionPurpose::LiveInterlocutor => VoicePrintPurpose::LiveInterlocutor,
        })
        .collect();
    purposes.sort_by_key(VoicePrintPurpose::as_str);
    Ok(purposes)
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

/// The wire receipt of a consent `receipt`, recorded by `recorded_by`: the
/// purposes answered back as wire purposes.
fn consent_wire_receipt(
    receipt: &VoiceConsentReceipt,
    recorded_by: EntityId,
) -> VoiceRecognitionConsentReceipt {
    VoiceRecognitionConsentReceipt {
        event_id: receipt.consent_event_ref.clone(),
        subject: receipt.subject_ref.to_hex(),
        recorded_by: recorded_by.to_hex(),
        purposes: receipt
            .purposes
            .iter()
            .map(|purpose| match purpose {
                VoicePrintPurpose::MeetingAttribution => {
                    VoiceRecognitionPurpose::MeetingAttribution
                }
                VoicePrintPurpose::LiveInterlocutor => VoiceRecognitionPurpose::LiveInterlocutor,
            })
            .collect(),
        replayed: receipt.replayed,
    }
}
