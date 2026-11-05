//! Per-call admission for host-served extraction encoders.
use std::sync::Arc;

use super::{ModelId, ModelLocality, defaults, locality_within_extraction_bound, manifest};
use crate::error::{Error, Result};
use crate::memory::extraction::{EncoderInput, ExtractionWork};
use crate::{Vault, embed::EmbedderLocality};

/// The actual input and backend of one extraction send. Never serialized or logged.
pub struct TaggerCall<'a> {
    pub input: &'a EncoderInput,
    pub work: ExtractionWork,
    pub model: &'a ModelId,
    pub locality: ModelLocality,
}

/// Host permission for the actual extraction input, not an editable route preference.
pub trait TaggerEgressPredicate: Send + Sync {
    fn permits(&self, call: &TaggerCall<'_>) -> bool;
}

impl<F> TaggerEgressPredicate for F
where
    F: Fn(&TaggerCall<'_>) -> bool + Send + Sync,
{
    fn permits(&self, call: &TaggerCall<'_>) -> bool {
        self(call)
    }
}

/// The invocation's vault and host opt-in, retained with a queued call.
/// It grants no source-read authority; callers keep their existing read checks.
#[derive(Clone)]
pub struct TaggerCallContext {
    vault: Arc<Vault>,
    predicate: Arc<dyn TaggerEgressPredicate>,
}

impl TaggerCallContext {
    pub fn new(vault: Arc<Vault>, predicate: Arc<dyn TaggerEgressPredicate>) -> Self {
        Self { vault, predicate }
    }

    /// Admit immediately before each send, including a transport's codec retry.
    pub fn authorize(
        &self,
        input: &EncoderInput,
        work: ExtractionWork,
        model: &ModelId,
        locality: EmbedderLocality,
    ) -> Result<()> {
        let locality = match locality {
            EmbedderLocality::OnDevice => return Ok(()),
            EmbedderLocality::OwnerServer => ModelLocality::OwnServer,
            EmbedderLocality::ThirdParty => ModelLocality::ThirdParty,
        };
        self.vault.authorize_tagger_call(
            &TaggerCall {
                input,
                work,
                model,
                locality,
            },
            self.predicate.as_ref(),
        )
    }
}

impl Vault {
    /// Validate the current extraction route and bound before invoking host code.
    pub fn authorize_tagger_call(
        &self,
        call: &TaggerCall<'_>,
        predicate: &dyn TaggerEgressPredicate,
    ) -> Result<()> {
        if call.locality == ModelLocality::OnDevice {
            return Ok(());
        }
        let invalid = |reason: &str| Error::InvalidConfig(reason.to_owned());
        let txn = self.store.env.read_txn()?;
        let defaults = defaults::read_effective_defaults(&self.store, &txn)?;
        if let Some(manifest) = manifest::read_manifest(&self.store, &txn)? {
            let routes = manifest::read_routes(&self.store, &txn)?;
            let route =
                manifest::effective_route(&manifest, &routes, manifest::ModelSlot::Oneironer)?;
            let selected = manifest.extraction_encoder(route)?;
            if route != call.locality || selected.revision() != call.model.revision() {
                return Err(invalid(
                    "tagger backend differs from the selected revision and route",
                ));
            }
        }
        let within = locality_within_extraction_bound(
            call.locality,
            defaults.table().extraction_max_locality,
        );
        drop(txn); // A host predicate may itself read this vault.
        if !within || !predicate.permits(call) {
            return Err(invalid(
                "nonlocal extraction needs host egress authorization",
            ));
        }
        Ok(())
    }
}
