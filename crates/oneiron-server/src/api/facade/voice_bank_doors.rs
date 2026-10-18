//! The owner's voice-bank host doors (DOOR-143, e2e VOICE-02):
//! `vault.voices.packs.put` and `vault.voices.inspect`, each under the proof
//! `/v1/owner` takes from the request, so the proven person is the voice's
//! subject and the bank refuses another person's voice. A target's locality
//! is always its host's clone wire's, never the caller's. `host_doors`
//! re-exports them.
//!
//! Each lists the voice's owner (`host_door_lists`), as `ai.speech` lists
//! the person a banked voice is: here the proven owner, whose own voice every
//! door acts on. The bank's packs, identities, targets and render consent are
//! side tables, which hold no listed row.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::MemoryError;
use oneiron::task_verb::sdk::{
    self, VoiceBankInspectRequest, VoiceBankInspection, VoiceBankPackPutRequest,
    VoiceBankPackReceipt,
};

use super::host_doors::{MaybeListed, owner_proof};
use super::shared_act_doors::as_person_naming;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The proven owner, whom a door's answer lists: `None` when the proof no
/// longer reads as this vault's.
fn proven(server: &SyncServer, owner: &AuthenticatedOwner) -> Option<EntityId> {
    owner.actor_for_read(server.vault()).ok()
}

/// `vault.voices.packs.put`: the owner banks one immutable pack of their own
/// voice. A captured pack cites their current render grant.
pub(crate) async fn vault_voices_packs_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceBankPackPutRequest,
) -> MaybeListed<VoiceBankPackReceipt> {
    const VERB: &str = "vault.voices.packs.put";
    let proof = owner_proof(auth, server, VERB);
    let person = proof.as_ref().ok().and_then(|owner| proven(server, owner));
    as_person_naming(
        server,
        VERB,
        proof,
        move |server, owner| sdk::put_voice_bank_pack_as(server.vault(), &owner, input),
        move |_| person.map(|person| vec![person]),
    )
    .await
}

/// `vault.voices.inspect`: the owner's own voice as the bank holds it, for
/// one configured hosted target at the locality its clone wire states:
/// identity, pack metadata without audio or transcripts, the current render
/// decision and the target's current clone. No provider call.
pub(crate) async fn vault_voices_inspect(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceBankInspectRequest,
) -> MaybeListed<VoiceBankInspection> {
    const VERB: &str = "vault.voices.inspect";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Some(Vec::new())),
    };
    let Some(cloner) = server
        .ai
        .model_runtime()
        .media()
        .voice_cloner(&input.target)
    else {
        return (
            Err(MemoryError::not_found(
                "no configured hosted speech provider by that name clones voices",
            )),
            Some(Vec::new()),
        );
    };
    let locality = cloner.locality();
    let person = proven(server, &owner);
    as_person_naming(
        server,
        VERB,
        Ok(owner),
        move |server, owner| sdk::inspect_voice_bank_as(server.vault(), &owner, &input, locality),
        move |_| person.map(|person| vec![person]),
    )
    .await
}
