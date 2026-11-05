//! A phone answer's actual receiving-agent read and prepared-output fence.

use std::sync::{Arc, Mutex};

use oneiron::claim::{ScopedRead, ScopedReadActorKey};
use oneiron::federation::Scope;
use oneiron::voice_cascade::GenerationEpoch;
use oneiron::{EntityId, Vault};

use super::HostError;
use crate::auth::{CoreAuth, CoreScope};

/// Created only from the receiving agent's actual authenticated credential.
/// The bridge's credential and caller metadata never enter this type.
pub(crate) struct PhoneCallRead {
    vault: Arc<Vault>,
    key: ScopedReadActorKey,
    agent: EntityId,
    prepared: Mutex<Option<PreparedPhoneOutput>>,
}

/// Consent and sources of the voice core's current generation. The voice
/// core still owns its epoch, cancellation and playout state.
#[derive(Clone, PartialEq, Eq)]
struct PreparedPhoneOutput {
    generation: GenerationEpoch,
    scope: Scope,
    sources: Vec<EntityId>,
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
        // The native factory proved this principal is the line's live
        // AGENT_DEF, not a class inferred from provider or caller text.
        let read = Arc::new(Self {
            vault,
            key,
            agent,
            prepared: Mutex::new(None),
        });
        read.current_scope()?;
        Ok(read)
    }

    pub(super) fn agent(&self) -> EntityId {
        self.agent
    }

    pub(super) fn read(&self) -> ScopedRead<'_> {
        self.vault.scoped_read(self.key.clone())
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
    ) -> Result<(), HostError> {
        if !self.output_is_current(&scope, &sources)? {
            return Err(HostError::Stale);
        }
        let next = PreparedPhoneOutput {
            generation,
            scope,
            sources,
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
        let prepared = match self.prepared.lock() {
            Ok(prepared) => prepared.clone(),
            Err(_) => return false,
        };
        let Some(prepared) = prepared.filter(|prepared| prepared.generation == generation) else {
            return false;
        };
        self.output_is_current(&prepared.scope, &prepared.sources)
            .unwrap_or(false)
    }

    /// Source rows and consent share one native snapshot; source bodies are
    /// not loaded merely to check an audio packet's continued standing.
    pub(super) fn output_is_current(
        &self,
        prepared_scope: &Scope,
        sources: &[EntityId],
    ) -> Result<bool, HostError> {
        Ok(self.read().phone_line_output_scope(sources)?.as_ref() == Some(prepared_scope))
    }
}
