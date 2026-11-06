//! Host-bound inference identity and extraction context.

use oneiron_model::llm::{CallPurpose, ExtractionEgressPredicate, ModelId, ModelLocality};

/// Host-provided evidence of the transport behind a selected model. Registered
/// means the live catalog row must exist. Advertised means the injected host
/// attests its own backend's identity and locality; a catalog row, if present,
/// must agree. SupervisedNativeLocal means the host attests that every route a
/// call of `model` may take is the native channel of a managed worker it
/// supervises on this machine, authenticated against that child before any
/// input is sent, or the call is not sent (I2-LOCAL): on device, though no
/// Local wire runs it in this process. None of the forms can relabel an
/// existing local/remote model. Built by trusted host code only: it is never
/// serialized, so no request, config or policy table can spell it.
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
    /// The host's on-device native transport for exactly `model`: the
    /// server's OfferLadder::native_local ladder. Its offers keep the payer,
    /// key custody and rates of the provider offers they stand beside, so
    /// the run admission charges each call as that offer's: free work stays
    /// free and paid work stays paid (FIX 14889). This binding names where
    /// the call runs, never who pays.
    SupervisedNativeLocal {
        model: ModelId,
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
            HostInferenceBinding::SupervisedNativeLocal { .. } => Some(ModelLocality::OnDevice),
        }
    }
    /// Mirrors selected_locality: None-binding (Registered) is false, and so
    /// is a supervised native one: keyless names own-server work only, and
    /// whether an on-device call is free its offer's payer and key custody
    /// decide in the run admission (FIX 14889).
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
