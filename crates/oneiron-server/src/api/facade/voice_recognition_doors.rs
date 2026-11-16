//! The voice-recognition consent door (VOICE-RECOGNITION-CONSENT-NO-DOOR):
//! `vault.voices.recognition.withdraw`. It acts as the request's live person
//! on their own proof (`shared_act_doors::person`), owner of the vault or
//! not. The engine's withdrawal write revalidates that proof: the person's
//! own voice on a live person's proof, another subject's only under the
//! owner's authority. The withdrawal deletes the subject's voiceprint, its
//! samples and its active pointer, and keeps the consent record
//! (ARCH-0061 promise-dura-13). `host_doors` re-exports it.
//!
//! Any other caller is an agent on its own credential, which logs a
//! counterparty's spoken withdrawal on a call (VOICE-WITHDRAW-AGENT-ON-CALL)
//! under its own Grant naming the consent-log verb
//! (`VOICE_RECOGNITION_CONSENT_VERB`); the engine checks that Grant in the
//! withdrawal's write and tells each live owner there.
//!
//! It lists its rows (`host_door_lists`): the subject and the recorder its
//! receipt names. The consent log and the print rows are side tables, which
//! hold no listed row.
use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{
    self, VoiceRecognitionWithdrawReceipt, VoiceRecognitionWithdrawRequest,
};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::support::MaybeListed;
use super::shared_act_doors::{as_person_naming, person};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Whom the door acts for.
enum Withdrawer {
    /// The owner, or a live person on their own proof.
    Person(AuthenticatedOwner),
    /// An agent on its own credential, whose Grant the engine checks.
    Agent(EntityId, EdgeActorClass),
}

/// The request's withdrawer: a person's proof when [`person`] gives one,
/// else the agent the credential binds. A human caller [`person`] refuses
/// keeps that refusal.
fn withdrawer(server: &SyncServer, auth: &CoreAuth, verb: &str) -> MemoryResult<Withdrawer> {
    super::owner_binding::host_preflight(server, auth)?;
    let refusal = match person(server, auth, verb) {
        Ok(proof) => return Ok(Withdrawer::Person(proof)),
        Err(refusal) => refusal,
    };
    match super::facade_actor(server, auth) {
        Ok((actor, class)) if class != EdgeActorClass::Human => Ok(Withdrawer::Agent(actor, class)),
        _ => Err(refusal),
    }
}

/// The row's early check (`recognition_withdrawer`): a person's proof, or
/// an agent the engine's withdrawal admits in a snapshot of its own, so no
/// hook fires on a call the write would refuse.
pub(super) fn withdrawer_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    match withdrawer(server, auth, verb)? {
        Withdrawer::Person(_) => Ok(()),
        Withdrawer::Agent(actor, class) => sdk::voice_recognition_withdrawal_admits_agent(
            &crate::api::credential_memory(&server.vault, Some(auth), actor, class)
                .at(auth.locality()),
        ),
    }
}

/// The subject and the recorder a receipt names, once each: `None` when
/// one does not read as an entity.
fn receipt_rows(receipt: &VoiceRecognitionWithdrawReceipt) -> Option<Vec<EntityId>> {
    let subject = EntityId::from_hex(&receipt.subject).ok()?;
    let recorded_by = EntityId::from_hex(&receipt.recorded_by).ok()?;
    let mut rows = vec![subject];
    if recorded_by != subject {
        rows.push(recorded_by);
    }
    Some(rows)
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
    match withdrawer(server, auth, VERB) {
        Ok(Withdrawer::Agent(actor, class)) => {
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
        Ok(Withdrawer::Person(proof)) => {
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
