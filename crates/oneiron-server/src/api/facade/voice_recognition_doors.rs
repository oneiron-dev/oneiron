//! The voice-recognition consent door (VOICE-RECOGNITION-CONSENT-NO-DOOR):
//! `vault.voices.recognition.withdraw`. It acts as the request's live person
//! on their own proof (`shared_act_doors::person`), owner of the vault or
//! not. The engine's withdrawal write revalidates that proof: the person's
//! own voice on a live person's proof, another subject's only under the
//! owner's authority. The withdrawal deletes the subject's voiceprint, its
//! samples and its active pointer, and keeps the consent record
//! (ARCH-0061 promise-dura-13). `host_doors` re-exports it.
//!
//! It lists its rows (`host_door_lists`): the subject and the recorder its
//! receipt names. The consent log and the print rows are side tables, which
//! hold no listed row.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::task_verb::sdk::{
    self, VoiceRecognitionWithdrawReceipt, VoiceRecognitionWithdrawRequest,
};

use super::host_doors::support::MaybeListed;
use super::shared_act_doors::{as_person_naming, person};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

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
/// consent for their own voice, or the vault owner for any subject's. A
/// replay of a recorded withdrawal deletes nothing and says so.
pub(crate) async fn vault_voices_recognition_withdraw(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceRecognitionWithdrawRequest,
) -> MaybeListed<VoiceRecognitionWithdrawReceipt> {
    const VERB: &str = "vault.voices.recognition.withdraw";
    as_person_naming(
        server,
        VERB,
        person(server, auth, VERB),
        move |server, proof| {
            sdk::withdraw_voice_recognition_consent_as(server.vault(), &proof, input)
        },
        receipt_rows,
    )
    .await
}
