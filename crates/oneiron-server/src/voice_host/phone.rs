//! A phone answer's actual receiving-agent read and prepared-output fence.

use std::sync::{Arc, Mutex};

use oneiron::claim::{ScopedRead, ScopedReadActorKey};
use oneiron::federation::Scope;
use oneiron::interlocutor::InterlocutorSet;
use oneiron::voice_cascade::GenerationEpoch;
use oneiron::{EntityId, Vault};

use super::HostError;
use crate::auth::{CoreAuth, CoreScope};

/// Created only from the receiving agent's actual authenticated credential.
/// The bridge's credential and caller metadata never enter this type.
pub struct PhoneCallRead {
    vault: Arc<Vault>,
    auth: CoreAuth,
    key: ScopedReadActorKey,
    agent: EntityId,
    definition: oneiron::agent_def::AgentDefinition,
    prepared: Mutex<Option<PreparedPhoneOutput>>,
}

/// Consent and sources of the voice core's current generation. The voice
/// core still owns its epoch, cancellation and playout state.
#[derive(Clone, PartialEq)]
struct PreparedPhoneOutput {
    generation: GenerationEpoch,
    scope: Scope,
    sources: Vec<EntityId>,
    interlocutors: InterlocutorSet,
}

impl PhoneCallRead {
    pub(super) fn new(
        vault: Arc<Vault>,
        auth: &CoreAuth,
        identity: EntityId,
        arrival_ref: &str,
    ) -> Result<Arc<Self>, HostError> {
        for scope in [CoreScope::Read, CoreScope::Write] {
            auth.require(scope).map_err(|_| HostError::InvalidRequest)?;
        }
        let proof = auth.verified_slip().ok_or(HostError::InvalidRequest)?;
        let key = vault
            .phone_line_answer_read_key(proof, identity, arrival_ref)?
            .for_destination(&auth.destination());
        let agent = EntityId::from_hex(key.actor_ref())?;
        if auth.principal_entity() != Some(agent) {
            return Err(HostError::InvalidRequest);
        }
        // Freeze instructions, models and the read scope from one admitted body.
        let (key, definition) = vault.scoped_read(key).phone_line_agent_read()?;
        // The native factory proved this principal is the line's live
        // AGENT_DEF, not a class inferred from provider or caller text.
        let read = Arc::new(Self {
            vault,
            auth: auth.clone(),
            key,
            agent,
            definition,
            prepared: Mutex::new(None),
        });
        Ok(read)
    }

    pub(super) fn admitted_for(
        &self,
        vault: &Vault,
        auth: &CoreAuth,
    ) -> Result<EntityId, HostError> {
        if !self.auth.same_authority(auth) {
            return Err(HostError::InvalidRequest);
        }
        self.admitted_media_agent(vault)
    }

    pub(crate) fn admitted_media_agent(&self, vault: &Vault) -> Result<EntityId, HostError> {
        if !std::ptr::eq(vault, self.vault.as_ref()) {
            return Err(HostError::InvalidRequest);
        }
        self.current_scope()?;
        Ok(self.agent)
    }

    pub(super) fn agent(&self) -> EntityId {
        self.agent
    }

    pub(super) fn read(&self) -> ScopedRead<'_> {
        self.vault.scoped_read(self.key.clone())
    }

    pub(super) fn definition(&self) -> &oneiron::agent_def::AgentDefinition {
        &self.definition
    }

    pub(super) fn models(&self) -> &[oneiron::agent_def::AgentModel] {
        &self.definition.models
    }

    pub(crate) fn media_models(&self) -> Arc<[oneiron::agent_def::AgentModel]> {
        Arc::from(self.models())
    }

    pub(super) fn memory(&self) -> Result<oneiron::memory::Memory<'_>, HostError> {
        Ok(crate::api::credential_memory(
            &self.vault,
            Some(&self.auth),
            self.agent,
            oneiron::EdgeActorClass::Agent,
        )
        .within_phone_line_read(&self.key)?)
    }

    /// Capture before context/history assembly, not after a model has already
    /// heard it. A changed scope requires fresh context, not re-stamping it.
    pub(super) fn current_scope(&self) -> Result<Scope, HostError> {
        self.read()
            .phone_line_scope()?
            .ok_or(HostError::InvalidRequest)
    }

    /// The scope was captured before the input was assembled. Never stamp
    /// context prepared under an earlier scope with the current one instead.
    pub(super) fn prepare_generation(
        &self,
        generation: GenerationEpoch,
        scope: Scope,
        sources: Vec<EntityId>,
        interlocutors: InterlocutorSet,
    ) -> Result<(), HostError> {
        if !self.output_is_current(&scope, &sources, &interlocutors)? {
            return Err(HostError::Stale);
        }
        let next = PreparedPhoneOutput {
            generation,
            scope,
            sources,
            interlocutors,
        };
        let mut prepared = self.prepared.lock().map_err(|_| HostError::Stopped)?;
        if let Some(prior) = prepared.as_ref()
            && prior.generation >= generation
        {
            return if prior == &next {
                Ok(())
            } else {
                Err(HostError::Stale)
            };
        }
        *prepared = Some(next);
        Ok(())
    }

    /// Called again by the existing weak playout fence at every dequeue,
    /// including a saved HTTP journal page. No prepared input means no audio.
    pub(super) fn accepts_output(&self, generation: GenerationEpoch) -> bool {
        self.accepts_output_with_sources(generation, &[])
    }

    /// A notice is made from its turn and the additional row it names.
    /// Its body must pass before either history or the control stream hears it.
    pub(super) fn accepts_notice(
        &self,
        generation: GenerationEpoch,
        notice: &oneiron::store::GateSystemNoticeRecord,
    ) -> bool {
        self.accepts_output_with_sources(generation, &super::speech::notice_rows(notice))
    }

    /// Saved bodies also carry rows a turn found but did not say, or the
    /// policy row a notice names. Check their union in the same snapshot.
    pub(super) fn accepts_output_with_sources(
        &self,
        generation: GenerationEpoch,
        sources: &[EntityId],
    ) -> bool {
        let Some(mut prepared) = self.prepared_output(generation) else {
            return false;
        };
        prepared.sources.extend_from_slice(sources);
        self.output_is_current(&prepared.scope, &prepared.sources, &prepared.interlocutors)
            .unwrap_or(false)
    }

    fn prepared_output(&self, generation: GenerationEpoch) -> Option<PreparedPhoneOutput> {
        self.prepared
            .lock()
            .ok()?
            .as_ref()
            .filter(|prepared| prepared.generation == generation)
            .cloned()
    }

    /// Consent, source admission and the native disclosure closure share
    /// one snapshot, including Tier-A marks and withdrawn source rows.
    pub(super) fn output_is_current(
        &self,
        prepared_scope: &Scope,
        sources: &[EntityId],
        interlocutors: &InterlocutorSet,
    ) -> Result<bool, HostError> {
        Ok(self
            .read()
            .phone_line_output_scope(sources, interlocutors)?
            .as_ref()
            == Some(prepared_scope))
    }
}

/// Ends only when the original credential or line no longer admits this call.
/// A scope-value change instead rebuilds context at the next turn.
pub(super) async fn revoked(phone: &PhoneCallRead) {
    let mut every = tokio::time::interval(super::boot::LIVENESS_EVERY);
    loop {
        every.tick().await;
        if phone.current_scope().is_err() {
            return;
        }
    }
}
