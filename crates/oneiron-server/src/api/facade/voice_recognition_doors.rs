//! The voice-recognition consent doors (VOICE-RECOGNITION-CONSENT-NO-DOOR,
//! VOICE-CONSENT-LOG-WHO = A): `vault.voices.recognition.withdraw` and
//! `vault.voices.recognition.consent`. Each acts as the request's live person
//! on their own proof (`shared_act_doors::person`), owner of the vault or
//! not. The engine's write revalidates that proof: the person's own voice on
//! a live person's proof, another subject's only under the owner's authority.
//! The withdrawal deletes the subject's voiceprint, its samples and its active
//! pointer, and keeps the consent record (ARCH-0061 promise-dura-13); logging
//! consent enrols no print. `host_doors` re-exports them.
//!
//! Any other caller is an agent (agent or system class) on its own credential, which logs a
//! counterparty's spoken word on a call, its consent or its withdrawal
//! (VOICE-WITHDRAW-AGENT-ON-CALL, VOICE-CONSENT-LOG-WHO = A), under its own
//! Grant naming the consent-log verb (`VOICE_RECOGNITION_CONSENT_VERB`); the
//! engine checks that Grant in each write and tells each live owner there,
//! on its first insertion. It never logs a live member's consent, and a live
//! member whose withdrawal it logs is told too (VOICE-CONSENT-LOG-MEMBERS).
//!
//! Each lists its rows (`host_door_lists`): the subject and the recorder its
//! receipt names. The consent log and the print rows are side tables, which
//! hold no listed row.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{
    self, VoiceRecognitionConsentReceipt, VoiceRecognitionConsentRequest,
    VoiceRecognitionWithdrawReceipt, VoiceRecognitionWithdrawRequest,
};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::MaybeListed;
use super::shared_act_doors::{as_person_naming, person};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Whom the door acts for.
enum Recorder {
    /// The owner, or a live person on their own proof.
    Person(AuthenticatedOwner),
    /// An agent on its own credential, whose Grant the engine checks.
    Agent(EntityId, EdgeActorClass),
}

/// The request's recorder: a person's proof when [`person`] gives one,
/// else the agent the credential binds. A human caller [`person`] refuses
/// keeps that refusal.
fn recorder(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<Recorder> {
    super::owner_binding::host_preflight(server, auth)?;
    let refusal = match person(server, auth, verb) {
        Ok(proof) => return Ok(Recorder::Person(proof)),
        Err(refusal) => refusal,
    };
    match super::facade_actor(server, auth) {
        Ok((actor, class)) if class != EdgeActorClass::Human => Ok(Recorder::Agent(actor, class)),
        _ => Err(refusal),
    }
}

/// The row's early check (`recognition_recorder`): a person's proof, or
/// an agent the engine's recorder admits in a snapshot of its own, so no
/// hook fires on a call the write would refuse.
pub(super) fn recorder_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    match recorder(server, auth, verb)? {
        Recorder::Person(_) => Ok(()),
        Recorder::Agent(actor, class) => sdk::voice_recognition_recorder_admits_agent(
            &crate::api::credential_memory(&server.vault, Some(auth), actor, class)
                .at(auth.locality()),
            verb,
        ),
    }
}

/// The subject and the recorder two hex strings name, once each: `None` when
/// one does not read as an entity.
fn rows_of(subject: &str, recorded_by: &str) -> Option<Vec<EntityId>> {
    let subject = EntityId::from_hex(subject).ok()?;
    let recorded_by = EntityId::from_hex(recorded_by).ok()?;
    let mut rows = vec![subject];
    if recorded_by != subject {
        rows.push(recorded_by);
    }
    Some(rows)
}

/// The subject and the recorder a withdrawal receipt names.
fn receipt_rows(receipt: &VoiceRecognitionWithdrawReceipt) -> Option<Vec<EntityId>> {
    rows_of(&receipt.subject, &receipt.recorded_by)
}

/// The subject and the recorder a consent receipt names.
fn consent_receipt_rows(receipt: &VoiceRecognitionConsentReceipt) -> Option<Vec<EntityId>> {
    rows_of(&receipt.subject, &receipt.recorded_by)
}

/// `vault.voices.recognition.withdraw`: the person withdraws recognition
/// consent for their own voice, the vault owner for any subject's, or an
/// agent holding the consent-log Grant for a counterparty on its call. A
/// replay of a recorded withdrawal deletes nothing and says so.
pub(crate) async fn vault_voices_recognition_withdraw(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceRecognitionWithdrawRequest,
) -> MaybeListed<VoiceRecognitionWithdrawReceipt> {
    const VERB: &str = "vault.voices.recognition.withdraw";
    match recorder(server, auth, VERB) {
        Ok(Recorder::Agent(actor, class)) => {
            let auth = auth.clone();
            as_person_naming(
                server,
                VERB,
                Ok((actor, class)),
                move |server, (actor, class)| {
                    let memory =
                        crate::api::credential_memory(&server.vault, Some(&auth), actor, class)
                            .at(auth.locality());
                    sdk::withdraw_voice_recognition_consent_as_agent(&memory, input)
                },
                receipt_rows,
            )
            .await
        }
        Ok(Recorder::Person(proof)) => {
            as_person_naming(
                server,
                VERB,
                Ok(proof),
                move |server, proof| {
                    sdk::withdraw_voice_recognition_consent_as(server.vault(), &proof, input)
                },
                receipt_rows,
            )
            .await
        }
        Err(refusal) => (Err(refusal), Some(Vec::new())),
    }
}

/// `vault.voices.recognition.consent`: the person logs recognition consent
/// for their own voice, the vault owner for any subject's, or an agent holding
/// the consent-log Grant for a counterparty's spoken word on its call. A replay
/// of a recorded consent says so. It enrols no print.
pub(crate) async fn vault_voices_recognition_consent(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceRecognitionConsentRequest,
) -> MaybeListed<VoiceRecognitionConsentReceipt> {
    const VERB: &str = "vault.voices.recognition.consent";
    match recorder(server, auth, VERB) {
        Ok(Recorder::Agent(actor, class)) => {
            let auth = auth.clone();
            as_person_naming(
                server,
                VERB,
                Ok((actor, class)),
                move |server, (actor, class)| {
                    let memory =
                        crate::api::credential_memory(&server.vault, Some(&auth), actor, class)
                            .at(auth.locality());
                    sdk::record_voice_recognition_consent_as_agent(&memory, input)
                },
                consent_receipt_rows,
            )
            .await
        }
        Ok(Recorder::Person(proof)) => {
            as_person_naming(
                server,
                VERB,
                Ok(proof),
                move |server, proof| {
                    sdk::record_voice_recognition_consent_as(server.vault(), &proof, input)
                },
                consent_receipt_rows,
            )
            .await
        }
        Err(refusal) => (Err(refusal), Some(Vec::new())),
    }
}
