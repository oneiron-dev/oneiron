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
//! There is no door that grants recognition consent or enrolls a print:
//! a hosted enrolment needs the written release first
//! (CLOUD-FLOOR-BIPA-VOICEPRINT).
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryError, MemoryResult};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::voice_recognition::{
    VoiceRecognitionWithdrawReceipt, VoiceRecognitionWithdrawRequest,
};

/// The verb's public spelling.
const WITHDRAW_VERB: &str = "vault.voices.recognition.withdraw";

/// `vault.voices.recognition.withdraw` on an embedded handle: as the
/// vault's embedded owner, who may withdraw for any subject.
pub fn withdraw_voice_recognition_consent(
    memory: &Memory<'_>,
    input: VoiceRecognitionWithdrawRequest,
) -> MemoryResult<VoiceRecognitionWithdrawReceipt> {
    let owner = memory.embedded_owner(WITHDRAW_VERB)?;
    withdraw_voice_recognition_consent_as(memory.vault(), &owner, input)
}

/// `vault.voices.recognition.withdraw` under the acting person's proof,
/// which the withdrawal's write revalidates: a person's own for their own
/// voice, the owner's for another subject's.
pub fn withdraw_voice_recognition_consent_as(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    input: VoiceRecognitionWithdrawRequest,
) -> MemoryResult<VoiceRecognitionWithdrawReceipt> {
    let subject = input
        .subject
        .as_deref()
        .map(EntityId::from_hex)
        .transpose()
        .map_err(|_| MemoryError::bad_request("subject is an entity id in lowercase hex"))?;
    let recorded_by = proof.actor_for_read(vault)?;
    let receipt = vault.withdraw_voice_consent_as(
        proof,
        subject,
        input.event_id,
        input.occurred_at,
        input.basis,
    )?;
    Ok(VoiceRecognitionWithdrawReceipt {
        event_id: receipt.consent_event_ref,
        subject: receipt.subject_ref.to_hex(),
        recorded_by: recorded_by.to_hex(),
        replayed: receipt.replayed,
        already_absent: receipt.already_absent,
        deleted_print: receipt.deleted_print,
        deleted_sample_count: u64::try_from(receipt.deleted_sample_count).unwrap_or(u64::MAX),
        deleted_vector_count: u64::try_from(receipt.deleted_vector_count).unwrap_or(u64::MAX),
        deleted_active_pointer: receipt.deleted_active_pointer,
    })
}
