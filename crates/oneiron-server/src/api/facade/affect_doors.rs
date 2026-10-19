//! Retrieval-prior setup and VAD consolidation on the caller's own owner proof.
use std::sync::Arc;

use oneiron::EntityId;
use oneiron::memory::MemoryResult;
use oneiron::memory::affect::{AffectClaimConsolidateRequest, AffectClaimConsolidation};
use oneiron::policy_manifest_doors::{
    self, RetrievalWeightsConfigureRequest, RetrievalWeightsReceipt, RetrievalWeightsView,
};
use oneiron::task_verb::sdk::EmptyRequest;

use super::FacadeApiError;
use super::host_doors::{Listed, credential_listing, off_runtime_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn vault_retrieval_weights_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<RetrievalWeightsView> {
    const VERB: &str = "vault.retrieval.weights.get";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let (answer, mut rows) = off_runtime_listing(VERB, move |_| {
        policy_manifest_doors::retrieval_weights_as_owner(server.vault(), &owner)
            .map_err(Into::into)
    })
    .await;
    if let Ok(view) = &answer {
        rows.extend(EntityId::from_hex(&view.manifest_ref).ok());
    }
    (answer, rows)
}

pub(crate) async fn vault_retrieval_weights_configure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: RetrievalWeightsConfigureRequest,
) -> Listed<RetrievalWeightsReceipt> {
    const VERB: &str = "vault.retrieval.weights.configure";
    let owner = match owner_proof(auth, server, VERB) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let server = Arc::clone(server);
    let (answer, mut rows) = off_runtime_listing(VERB, move |_| {
        policy_manifest_doors::configure_retrieval_weights_as_owner(server.vault(), &owner, input)
            .map_err(Into::into)
    })
    .await;
    if let Ok(receipt) = &answer {
        rows.extend(EntityId::from_hex(&receipt.configuration.manifest_ref).ok());
    }
    (answer, rows)
}

pub(crate) async fn vault_affect_claims_consolidate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: AffectClaimConsolidateRequest,
) -> Listed<AffectClaimConsolidation> {
    const VERB: &str = "vault.affect.claims.consolidate";
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, VERB)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return refused(error),
    };
    let (answer, mut rows) = credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.affect_claim_consolidate_as_owner(&owner, &input)
    })
    .await;
    if let Ok(consolidated) = &answer {
        rows.extend(
            std::iter::once(consolidated.claim_ref.as_str())
                .chain(
                    consolidated
                        .evidence_turns
                        .iter()
                        .map(|row| row.turn_ref.as_str()),
                )
                .chain(consolidated.active_state_ref.as_deref())
                .chain(consolidated.created_state_ref.as_deref())
                .chain(
                    consolidated
                        .superseded_state_refs
                        .iter()
                        .map(String::as_str),
                )
                .filter_map(|reference| EntityId::from_hex(reference).ok()),
        );
    }
    (answer, rows)
}

use oneiron::dreamer_runner::maintenance::action_mode::ActionModePolicy;
use oneiron::memory::coping_doors::{
    CopingAggregate, CopingAggregateRequest, CopingOutcomeReceipt, CopingOutcomeRecordRequest,
    CopingOutcomeUpdateRequest,
};
use oneiron::memory::wellness_doors::{
    WellnessPersonRequest, WellnessPolicyConfigureRequest, WellnessProjection,
};

pub(crate) async fn vault_affect_coping_record(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CopingOutcomeRecordRequest,
) -> Listed<CopingOutcomeReceipt> {
    const VERB: &str = "vault.affect.coping.record";
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, VERB)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.coping_outcome_record_as_owner(&owner, &input)
    })
    .await
}

pub(crate) async fn vault_affect_coping_update(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CopingOutcomeUpdateRequest,
) -> Listed<CopingOutcomeReceipt> {
    const VERB: &str = "vault.affect.coping.update";
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, VERB)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.coping_outcome_update_as_owner(&owner, &input)
    })
    .await
}

pub(crate) async fn vault_affect_coping_aggregate(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: CopingAggregateRequest,
) -> Listed<CopingAggregate> {
    const VERB: &str = "vault.affect.coping.aggregate";
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, VERB)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.coping_aggregate_as_owner(&owner, &input)
    })
    .await
}

pub(crate) async fn vault_affect_wellness_policy_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> Listed<Option<ActionModePolicy>> {
    const VERB: &str = "vault.affect.wellness.policy.get";
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, VERB)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.wellness_policy_as_owner(&owner)
    })
    .await
}

pub(crate) async fn vault_affect_wellness_policy_configure(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WellnessPolicyConfigureRequest,
) -> Listed<Option<ActionModePolicy>> {
    const VERB: &str = "vault.affect.wellness.policy.configure";
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, VERB)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.wellness_policy_configure_as_owner(&owner, &input)
    })
    .await
}

pub(crate) async fn vault_affect_wellness_derive(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WellnessPersonRequest,
) -> Listed<WellnessProjection> {
    const VERB: &str = "vault.affect.wellness.derive";
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, VERB)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.wellness_derive_as_owner(&owner, &input)
    })
    .await
}

pub(crate) async fn vault_affect_wellness_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WellnessPersonRequest,
) -> Listed<WellnessProjection> {
    const VERB: &str = "vault.affect.wellness.get";
    let admitted = || -> MemoryResult<_> {
        let owner = owner_proof(auth, server, VERB)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return refused(error),
    };
    credential_listing(server, auth, caller, VERB, move |_, _, memory| {
        memory.wellness_get_as_owner(&owner, &input)
    })
    .await
}
