//! The voice-bank host doors (DOOR-143, e2e VOICE-02, FIX 4393, 4396):
//! `vault.voices.packs.put`, `.render_consent`, `.targets.provision`,
//! `.targets.evict`, `.inspect` and `.lineage`. Each acts as the request's
//! live person on their own proof (`shared_act_doors::person`), owner of the
//! vault or not, or else as the credential's own actor on its
//! credential-bound read key, whom the bank admits as a designed voice's
//! creator alone. The bank binds every act to the voice's subject or creator
//! and refuses another's voice. Provisioning and the vendor deletions run the
//! flows `/v1/ai/voices` runs (api/ai/voices.rs): the same paid clone run,
//! the same refusal before any provider call when the render consent does
//! not reach the target, and the same best-effort deletion. A target's
//! locality is always its host's clone wire's, never the caller's.
//! `host_doors` re-exports them.
//!
//! Each lists its rows (`host_door_lists`), as `ai.speech` lists the person
//! a banked voice is: here the actor, the voice's subject or creator, whose
//! own voice every door acts on; the lineage lists every subject and
//! recorder its events name. The bank's packs, identities, targets, render
//! consent and history are side tables, which hold no listed row.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError, MemoryResult,
};
use oneiron::task_verb::sdk::{
    self, VoiceBankInspectRequest, VoiceBankInspection, VoiceBankPackPutRequest,
    VoiceBankPackReceipt, VoiceRenderConsentReceipt, VoiceRenderConsentRequest,
    VoiceRenderEventView, VoiceRenderLineageRequest, VoiceTargetEvictReceipt,
    VoiceTargetEvictRequest, VoiceTargetProvisionRequest, VoiceTargetReceipt, VoiceTargetRender,
};
use oneiron::voice_identity::ref_bank::VoiceBankActor;

use super::clock_ingress;
use super::host_doors::support::{MaybeListed, internal};
use super::shared_act_doors::{as_person_naming, person};
use crate::api::ai::{
    CloneRequest, VoiceBankRefusal, clone_payer, evict_answer, provision_clone_funded,
    render_consent_answer,
};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// Whom a voice door acts as: the request's live person on their own proof,
/// owner or not; else the credential's own actor on the read key its
/// credential gives it, which the bank admits as a designed voice's creator
/// alone. A caller with neither is refused.
fn voice_bank_actor(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<VoiceBankActor> {
    if let Ok(proof) = person(server, auth, verb) {
        return Ok(VoiceBankActor::Person(proof));
    }
    let refused = || {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{verb} is a live person's own act, or a designed voice's creator's"),
            &[
                "Present your own verified human credential for your own voice.",
                "Present the creating actor's own credential for a designed voice.",
            ],
        )
    };
    let (actor, class) = super::owner_binding::facade_caller_or(server, auth, refused)?;
    let memory =
        crate::api::credential_memory(server.vault(), Some(auth), actor, class).at(auth.locality());
    VoiceBankActor::creator(&memory)
}

/// The authority check the voice rows' doors run first (`door_admits`): a
/// live person's proof, or a credential-bound creator. The bank decides
/// which voice either acts on.
pub(super) fn voice_bank_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    voice_bank_actor(server, auth, verb).map(drop)
}

/// The actor a door's answer lists: `None` when it no longer reads as this
/// vault's.
fn acting(server: &SyncServer, actor: &VoiceBankActor) -> Option<EntityId> {
    actor.entity_for_read(server.vault()).ok()
}

/// `answer` beside the actor it is of; a refusal lists none.
fn naming_actor<T>(actor: Option<EntityId>, answer: MemoryResult<T>) -> MaybeListed<T> {
    let rows = match &answer {
        Ok(_) => actor.map(|actor| vec![actor]),
        Err(_) => Some(Vec::new()),
    };
    (answer, rows)
}

/// Every subject and recorder a voice's render history names, once each:
/// `None` when one does not read as an entity.
fn lineage_rows(events: &[VoiceRenderEventView]) -> Option<Vec<EntityId>> {
    let mut rows = Vec::new();
    for event in events {
        for entity in [&event.decision.subject, &event.decision.recorded_by] {
            let entity = EntityId::from_hex(entity).ok()?;
            if !rows.contains(&entity) {
                rows.push(entity);
            }
        }
    }
    Some(rows)
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

/// `vault.voices.packs.put`: the actor banks one immutable pack of their own
/// voice. A captured pack cites the subject's current render grant.
pub(crate) async fn vault_voices_packs_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceBankPackPutRequest,
) -> MaybeListed<VoiceBankPackReceipt> {
    const VERB: &str = "vault.voices.packs.put";
    let actor = voice_bank_actor(server, auth, VERB);
    let named = actor.as_ref().ok().and_then(|actor| acting(server, actor));
    as_person_naming(
        server,
        VERB,
        actor,
        move |server, actor| sdk::put_voice_bank_pack_as(server.vault(), &actor, input),
        move |_| named.map(|named| vec![named]),
    )
    .await
}

/// `vault.voices.render_consent`: the actor records their render decision
/// on their own voice. A withdrawal drops the voice's target clones, and
/// each is deleted at its vendor, best effort; the packs stay. A replay of
/// a recorded decision answers its original receipt and deletes nothing.
pub(crate) async fn vault_voices_render_consent(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceRenderConsentRequest,
) -> MaybeListed<VoiceRenderConsentReceipt> {
    const VERB: &str = "vault.voices.render_consent";
    let actor = match voice_bank_actor(server, auth, VERB) {
        Ok(actor) => actor,
        Err(refusal) => return (Err(refusal), Some(Vec::new())),
    };
    let named = acting(server, &actor);
    let held = Arc::clone(server);
    let recorded = clock_ingress::run_blocking(move || {
        sdk::record_voice_render_decision_as(held.vault(), &actor, input)
    })
    .await
    .unwrap_or_else(|_| Err(internal(VERB)));
    let answer = match recorded {
        Ok(recorded) => {
            let media = server.ai.model_runtime().media();
            Ok(render_consent_answer(media, &recorded).await)
        }
        Err(refusal) => Err(refusal),
    };
    naming_actor(named, answer)
}

/// `vault.voices.targets.provision`: the actor's own voice cloned at a
/// configured hosted target, or its current clone there. The render consent
/// must reach the target's locality before any provider call. The clone's
/// vendor calls bill the calling live run's scope funding, when one funds
/// them, and run on the vault's run otherwise (FIX 10630).
pub(crate) async fn vault_voices_targets_provision(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceTargetProvisionRequest,
) -> MaybeListed<VoiceTargetReceipt> {
    const VERB: &str = "vault.voices.targets.provision";
    let actor = match voice_bank_actor(server, auth, VERB) {
        Ok(actor) => actor,
        Err(refusal) => return (Err(refusal), Some(Vec::new())),
    };
    let named = acting(server, &actor);
    let answer = provision_clone_funded(
        server,
        Some(&actor),
        clone_payer(),
        CloneRequest {
            voice_id: &input.voice_id,
            target: &input.target,
            include_generated: input.include_generated,
            language: input.language.as_deref(),
        },
    )
    .await
    .map_err(memory_refusal);
    naming_actor(named, answer)
}

/// `vault.voices.targets.evict`: the actor drops a target's clone of their
/// own voice, deleted at its vendor, best effort. The identity and its packs
/// stay.
pub(crate) async fn vault_voices_targets_evict(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceTargetEvictRequest,
) -> MaybeListed<VoiceTargetEvictReceipt> {
    const VERB: &str = "vault.voices.targets.evict";
    let actor = match voice_bank_actor(server, auth, VERB) {
        Ok(actor) => actor,
        Err(refusal) => return (Err(refusal), Some(Vec::new())),
    };
    let named = acting(server, &actor);
    let (voice_id, target) = (input.voice_id.clone(), input.target.clone());
    let held = Arc::clone(server);
    let evicted = clock_ingress::run_blocking(move || {
        sdk::evict_own_voice_target(held.vault(), &actor, &input)
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
    naming_actor(named, answer)
}

/// `vault.voices.inspect`: the actor's own voice as the bank holds it, for
/// one target as this host renders it (FIX 4394): identity, pack metadata
/// without audio or transcripts, the current render decision, and a hosted
/// target's current clone at the locality its clone wire states, or a
/// reference target's fence at the locality its provider states. A target
/// this host does not render reads the same metadata and says so. No
/// provider call.
pub(crate) async fn vault_voices_inspect(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceBankInspectRequest,
) -> MaybeListed<VoiceBankInspection> {
    const VERB: &str = "vault.voices.inspect";
    let actor = match voice_bank_actor(server, auth, VERB) {
        Ok(actor) => actor,
        Err(refusal) => return (Err(refusal), Some(Vec::new())),
    };
    let render = target_render(server, &input.target);
    let named = acting(server, &actor);
    as_person_naming(
        server,
        VERB,
        Ok(actor),
        move |server, actor| sdk::inspect_voice_bank_as(server.vault(), &actor, &input, render),
        move |_| named.map(|named| vec![named]),
    )
    .await
}

/// How this host renders `target`: a hosted clone wire's, a reference
/// target's seated provider's, or neither.
fn target_render(server: &SyncServer, target: &str) -> VoiceTargetRender {
    let media = server.ai.model_runtime().media();
    if let Some(cloner) = media.voice_cloner(target) {
        return VoiceTargetRender::HostedClone {
            locality: cloner.locality(),
        };
    }
    media
        .reference_target_locality(target)
        .map_or(VoiceTargetRender::Unconfigured, |locality| {
            VoiceTargetRender::Reference { locality }
        })
}

/// `vault.voices.lineage`: the actor's own voice's render history (FIX
/// 4396), every decision recorded for it in order, with the target pointers
/// each dropped. Metadata only, with no provider call; empty for a voice the
/// bank holds nothing of. Beside it, every subject and recorder its events
/// name.
pub(crate) async fn vault_voices_lineage(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: VoiceRenderLineageRequest,
) -> MaybeListed<Vec<VoiceRenderEventView>> {
    const VERB: &str = "vault.voices.lineage";
    as_person_naming(
        server,
        VERB,
        voice_bank_actor(server, auth, VERB),
        move |server, actor| sdk::read_voice_render_lineage_as(server.vault(), &actor, &input),
        |events| lineage_rows(events),
    )
    .await
}
