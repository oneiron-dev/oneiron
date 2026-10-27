//! The route a Big-rung call takes (FIX 9525). It is resolved against the
//! vault's live model policy each time, never read off the seat's configured
//! locality, and its posture is judged on the offers its send may reach, an
//! owner's fallback included. A rung bound to keep unit text on the host
//! sends only to the offers of that route that keep it there, in their order;
//! a route with none such leaves the host, so a posture that keeps the text
//! local empties the rung, as it always has.
//! Entry: `BigModel::resolve_decision_route`.
use std::sync::Arc;

use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::{LlmRequest, ModelId, ModelLocality};

use super::{Answerer, BigModel, failed};
use crate::models::OfferLadder;

/// Where a Big-rung call may send its unit text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum DecisionSendConstraint {
    /// Wherever the offers of its route send it.
    #[default]
    Any,
    /// Only to an offer that keeps it on the host: the question's posture
    /// keeps its unit text there.
    OnHost,
}

impl DecisionSendConstraint {
    /// `ladder` as a call under this constraint goes down it; `None` when no
    /// offer of it may take the call.
    fn bound(self, ladder: Arc<OfferLadder>) -> Option<Arc<OfferLadder>> {
        match self {
            Self::Any => Some(ladder),
            Self::OnHost => ladder.kept_on_host(),
        }
    }
}

/// The model a call names, where that model runs, and the ladder its send
/// goes down under the rung's constraint.
pub(super) struct ResolvedDecisionRoute {
    pub(super) model: ModelId,
    pub(super) locality: ModelLocality,
    pub(super) ladder: Arc<OfferLadder>,
}

/// The refusal of a call whose route has no offer its constraint lets it go
/// to.
fn kept_on_host() -> oneiron::Error {
    failed("refused: the question's posture keeps its text on the host")
}

impl BigModel {
    /// This rung for a question whose posture keeps unit text on the host:
    /// framed, worded and metered as this rung is, its calls sent only to
    /// the offers that keep the text there.
    pub(crate) fn kept_on_host(&self) -> Self {
        Self {
            models: Arc::clone(&self.models),
            vault: Arc::clone(&self.vault),
            answerer: self.answerer.clone(),
            wording: self.wording.clone(),
            reply: self.reply,
            meter: self.meter.clone(),
            runtime: self.runtime.clone(),
            pin: self.pin.clone(),
            trial_usage: self.trial_usage.clone(),
            send: DecisionSendConstraint::OnHost,
        }
    }

    /// The route a call takes now: the seat's under the vault's live model
    /// policy, or the one model as the router serves it, its ladder bound to
    /// this rung's constraint.
    pub(super) fn resolve_decision_route(&self) -> oneiron::Result<ResolvedDecisionRoute> {
        let (model, locality, ladder) = match &self.answerer {
            Answerer::Seat(role) => {
                let seat = self
                    .models
                    .seat(*role)
                    .ok_or_else(|| failed("the seat is gone"))?;
                let route = self
                    .models
                    .route_role(&self.vault, *role, seat)
                    .map_err(|refusal| failed(format!("refused: {refusal}")))?;
                (route.model, route.locality, route.ladder)
            }
            Answerer::Model(model) => {
                let (locality, ladder) = self
                    .models
                    .router()
                    .and_then(|router| router.served(model))
                    .ok_or_else(|| failed("the model is gone"))?;
                (model.clone(), locality, ladder)
            }
        };
        let ladder = self.send.bound(ladder).ok_or_else(kept_on_host)?;
        Ok(ResolvedDecisionRoute {
            model,
            locality,
            ladder,
        })
    }

    /// `request` admitted, and the ladder its send goes down: the seat's
    /// route under the vault's live model policy, or the one model under the
    /// policy a raw call naming it meets, bound to this rung's constraint.
    /// The route is admitted afresh, so a manifest that changed since the
    /// call was planned is the one its send is judged on.
    pub(super) fn admit_decision_route(
        &self,
        request: LlmRequest,
    ) -> oneiron::Result<(Arc<OfferLadder>, LlmRequest)> {
        let (ladder, request) = match &self.answerer {
            Answerer::Seat(role) => {
                let admitted = self
                    .models
                    .admit_role(&self.vault, *role, request)
                    .map_err(|refusal| failed(format!("refused: {refusal}")))?;
                (admitted.ladder, admitted.request)
            }
            Answerer::Model(model) => {
                let (locality, ladder) = self
                    .models
                    .router()
                    .and_then(|router| router.served(model))
                    .ok_or_else(|| failed("the model is gone"))?;
                let authorized = self
                    .vault
                    .authorize_raw_inference(
                        request,
                        &HostInferenceContext {
                            binding: HostInferenceBinding::Advertised {
                                model: model.clone(),
                                locality,
                            },
                            extraction_egress: None,
                        },
                    )
                    .map_err(|error| failed(format!("refused: {error}")))?;
                (ladder, authorized.into_request())
            }
        };
        let ladder = self.send.bound(ladder).ok_or_else(kept_on_host)?;
        Ok((ladder, request))
    }

    /// Whether a call's text may leave the host on the route it takes: an
    /// offer its send may reach is a third party's, a seat's owner fallback
    /// included; one model alone answers or nothing does, so no fallback
    /// is reached from it. A route that resolves to no offer the call may go
    /// to proves nothing, so it leaves.
    pub(super) fn route_leaves_host(&self) -> bool {
        let Ok(route) = self.resolve_decision_route() else {
            return true;
        };
        let reach = match self.answerer {
            Answerer::Seat(_) => route.ladder.prompt_locality_bound(),
            Answerer::Model(_) => route.locality,
        };
        reach == ModelLocality::ThirdParty
    }
}
