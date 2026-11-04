//! Host-bound inference identity and extraction context.

use oneiron_model::llm::{CallPurpose, ExtractionEgressPredicate, ModelId, ModelLocality};

/// Host-provided evidence of the transport behind a selected model. Registered
/// means the live catalog row must exist. Advertised means the injected host
/// attests its own backend's identity and locality; a catalog row, if present,
/// must agree. Neither form can relabel an existing local/remote model.
#[derive(Debug, Clone)]
pub enum HostInferenceBinding {
    Registered,
    Advertised {
        model: ModelId,
        locality: ModelLocality,
        /// Host-attested only (FIX 10592): true means the constructing host
        /// verified every rung that may serve this route is Payer::Local +
        /// OwnServer + KeyCustody::Keyless from its host-bound ladder, via
        /// OfferLadder::all_keyless_own_server. False is paid, today's
        /// behavior exactly. Read beside selected_locality, never from caller JSON.
        keyless: bool,
    },
}

/// The actual backend and nonlocal extraction authority are host inputs, never
/// fields supplied by an LLM request or by the editable policy table.
pub struct HostInferenceContext<'a> {
    pub binding: HostInferenceBinding,
    pub extraction_egress: Option<&'a dyn ExtractionEgressPredicate>,
}
impl HostInferenceContext<'_> {
    pub fn selected_locality(&self) -> Option<ModelLocality> {
        match &self.binding {
            HostInferenceBinding::Registered => None,
            HostInferenceBinding::Advertised { locality, .. } => Some(*locality),
        }
    }
    /// Mirrors selected_locality: None-binding (Registered) is false.
    pub fn selected_keyless(&self) -> bool {
        matches!(
            &self.binding,
            HostInferenceBinding::Advertised { keyless: true, .. }
        )
    }
}

/// The purpose whose defaults row and gates admit and route a call. An
/// agent's free time sends its own records out as an extraction does, so
/// both autonomy labels are admitted and routed as extraction (FIX 4453).
pub fn admitted_as(purpose: &CallPurpose) -> &CallPurpose {
    match purpose {
        CallPurpose::AutonomyForHuman | CallPurpose::AutonomyOwnTime => &CallPurpose::Extraction,
        purpose => purpose,
    }
}
