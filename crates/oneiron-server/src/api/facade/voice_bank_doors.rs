//! The owner's voice-bank host doors (DOOR-143, e2e VOICE-02):
//! `vault.voices.packs.put`, `.render_consent`, `.targets.provision`,
//! `.targets.evict` and `.inspect`, each under the proof `/v1/owner` takes
//! from the request, so the proven person is the voice's subject and the
//! bank refuses another person's voice. Provisioning and the vendor
//! deletions run the flows `/v1/ai/voices` runs (api/ai/voices.rs): the same
//! paid clone run, the same refusal before any provider call when the render
//! consent does not reach the target, and the same best-effort deletion. A
//! target's locality is always its host's clone wire's, never the caller's.
//! `host_doors` re-exports them.
//!
//! Each lists the voice's owner (`host_door_lists`), as `ai.speech` lists
//! the person a banked voice is: here the proven owner, whose own voice every
//! door acts on. The bank's packs, identities, targets and render consent are
//! side tables, which hold no listed row.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{
    self, VoiceBankInspectRequest, VoiceBankInspection, VoiceBankPackPutRequest,
    VoiceBankPackReceipt, VoiceRenderConsentReceipt, VoiceRenderConsentRequest,
    VoiceTargetEvictReceipt, VoiceTargetEvictRequest, VoiceTargetProvisionRequest,
    VoiceTargetReceipt,
};

use super::host_doors::{MaybeListed, internal, owner_proof};
use super::shared_act_doors::as_person_naming;
use crate::api::ai::{VoiceBankRefusal, evict_answer, provision_clone, render_consent_answer};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The proven owner, whom a door's answer lists: `None` when the proof no
/// longer reads as this vault's.
fn proven(server: &SyncServer, owner: &AuthenticatedOwner) -> Option<EntityId> {
    owner.actor_for_read(server.vault()).ok()
}

/// `answer` beside the proven owner it is of; a refusal lists none.
fn naming_owner<T>(person: Option<EntityId>, answer: MemoryResult<T>) -> MaybeListed<T> {
    let rows = match &answer {
        Ok(_) => person.map(|person| vec![person]),
        Err(_) => Some(Vec::new()),
    };
    (answer, rows)
}

/// A provisioning refusal on the facade's wire: no configured clone target
/// is not found, a missing language a bad request, a failed vendor clone an
/// unavailable model, and a bank refusal as the engine maps it.
fn memory_refusal(refusal: VoiceBankRefusal) -> MemoryError {
    match refusal {
        VoiceBankRefusal::NoCloneTarget => MemoryError::not_found(
            "no configured hosted speech provider by that name clones voices",
        ),
        VoiceBankRefusal::LanguageRequired => MemoryError::bad_request_with(
            "this target clones only with the clip's language",
            &["Name the language the clips are spoken in."],
        ),
        VoiceBankRefusal::VendorCloneFailed(error) => MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            format!("the provider did not make the clone: {error}"),
            &["Provision again later, or provision another configured target."],
        ),
        VoiceBankRefusal::Bank(error) => error.into(),
    }
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

/// `vault.voices.render_consent`: the owner records their render decision
/// on their own voice. A withdrawal drops the voice's target clones, and
/// each is deleted at its vendor, best effort; the packs stay.
pub(crate) async fn vault_voices_render_consent(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceRenderConsentRequest,
) -> MaybeListed<VoiceRenderConsentReceipt> {
    const VERB: &str = "vault.voices.render_consent";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Some(Vec::new())),
    };
    let person = proven(server, &owner);
    let held = Arc::clone(server);
    let recorded = tokio::task::spawn_blocking(move || {
        sdk::record_own_render_consent(held.vault(), &owner, input)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    let answer = match recorded {
        Ok((consent, evicted)) => {
            let media = server.ai.model_runtime().media();
            Ok(render_consent_answer(media, &consent, &evicted).await)
        }
        Err(refusal) => Err(refusal),
    };
    naming_owner(person, answer)
}

/// `vault.voices.targets.provision`: the owner's own voice cloned at a
/// configured hosted target, or its current clone there. The render consent
/// must reach the target's locality before any provider call.
pub(crate) async fn vault_voices_targets_provision(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceTargetProvisionRequest,
) -> MaybeListed<VoiceTargetReceipt> {
    const VERB: &str = "vault.voices.targets.provision";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Some(Vec::new())),
    };
    let person = proven(server, &owner);
    let answer = provision_clone(
        server,
        Some(&owner),
        &input.voice_id,
        &input.target,
        input.include_generated,
        input.language.as_deref(),
    )
    .await
    .map_err(memory_refusal);
    naming_owner(person, answer)
}

/// `vault.voices.targets.evict`: the owner drops a target's clone of their
/// own voice, deleted at its vendor, best effort. The identity and its packs
/// stay.
pub(crate) async fn vault_voices_targets_evict(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceTargetEvictRequest,
) -> MaybeListed<VoiceTargetEvictReceipt> {
    const VERB: &str = "vault.voices.targets.evict";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(refusal) => return (Err(refusal), Some(Vec::new())),
    };
    let person = proven(server, &owner);
    let (voice_id, target) = (input.voice_id.clone(), input.target.clone());
    let held = Arc::clone(server);
    let evicted = tokio::task::spawn_blocking(move || {
        sdk::evict_own_voice_target(held.vault(), &owner, &input)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    let answer = match evicted {
        Ok(evicted) => {
            let media = server.ai.model_runtime().media();
            Ok(evict_answer(media, voice_id, target, evicted.as_ref()).await)
        }
        Err(refusal) => Err(refusal),
    };
    naming_owner(person, answer)
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
            Err(memory_refusal(VoiceBankRefusal::NoCloneTarget)),
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
