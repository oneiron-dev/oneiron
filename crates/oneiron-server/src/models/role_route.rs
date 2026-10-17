//! A role-bound call's model under the vault's live model manifest.
//!
//! Chat turns, workflow steps and the Dreamer's extraction are calls of a
//! model role, so they are admitted through that role (ARCH-0036). When the
//! vault has a manifest, its binding for the role at the effective route (the
//! pin, narrowed by any resident route) names the model, and this server must
//! serve exactly that model at exactly that route. A model it does not serve there is refused
//! before any call leaves: a vault's route may narrow, never silently widen.
//! Without a manifest the role's seat is the binding: the owner's `[models]`
//! ladder, pinned the way a routed seat is.
use std::sync::Arc;

use oneiron::llm::manifest::ModelRole;
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::{LlmRequest, ModelId, ModelLocality, ModelTierRef, Vault};

use super::{ModelRuntime, OfferLadder, Seat};
use crate::config::models::role_key;

/// Why a role-bound call was refused before it left.
#[derive(Debug)]
pub enum RoleRefusal {
    /// No `[models]` rung serves the role.
    NoSeat,
    /// The vault's route names a model this server does not serve there.
    RouteNotServed {
        model: ModelId,
        route: ModelLocality,
    },
    /// The engine's inference admission refused the call.
    Refused(Box<oneiron::Error>),
}

impl RoleRefusal {
    fn refused(error: oneiron::Error) -> Self {
        Self::Refused(Box::new(error))
    }
}

impl std::fmt::Display for RoleRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSeat => write!(f, "no [models] rung serves this role"),
            Self::RouteNotServed { model, route } => write!(
                f,
                "the vault's model route names {model} at {}; this server does not serve it there",
                serde_json::to_value(route)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_else(|| format!("{route:?}"))
            ),
            Self::Refused(error) => write!(f, "{error}"),
        }
    }
}

/// An admitted request and the ladder that serves it, under a run.
pub struct RoleCall {
    pub request: LlmRequest,
    pub ladder: Arc<OfferLadder>,
}

/// Where a call of a role runs: the model, its route, and the ladder that
/// serves it there: every rung of a seat's, or the one model a manifest pins.
pub struct RoleRoute {
    pub model: ModelId,
    pub locality: ModelLocality,
    pub ladder: Arc<OfferLadder>,
    /// No manifest binds the role, so the seat is the binding.
    seat_bound: bool,
}

impl ModelRuntime {
    /// Resolves `role` against the vault's live manifest and route; without
    /// a manifest, `seat` is the binding (the Dreamer's seat for its
    /// teacher). The model is the one the engine's admission will select, so
    /// the backend attests exactly that model.
    pub fn route_role(
        &self,
        vault: &Vault,
        role: ModelRole,
        seat: &Seat,
    ) -> Result<RoleRoute, RoleRefusal> {
        let Some(manifest) = vault.model_manifest().map_err(RoleRefusal::refused)? else {
            // A role whose work never leaves the device takes another role's
            // seat only when that seat stays on it too.
            if self.stays_on_device.contains(&role)
                && seat.role != role
                && seat.locality == ModelLocality::ThirdParty
            {
                return Err(RoleRefusal::NoSeat);
            }
            return Ok(RoleRoute {
                model: seat.model.clone(),
                locality: seat.locality,
                ladder: Arc::clone(&seat.ladder),
                seat_bound: true,
            });
        };
        let binding = manifest.binding(role).map_err(RoleRefusal::refused)?;
        let config =
            |reason: &str| RoleRefusal::refused(oneiron::Error::InvalidConfig(reason.into()));
        let route = vault
            .model_route(binding.slot)
            .map_err(RoleRefusal::refused)?
            .ok_or_else(|| config("model manifest changed during admission"))?;
        // The pin at the slot's widest route, else the narrower route's own
        // model: the manifest's binding rule.
        let model = if manifest.routes.get(&binding.slot) == Some(&route) {
            binding.model.clone()
        } else {
            binding
                .route_models
                .get(&route)
                .cloned()
                .ok_or_else(|| config("resident route has no model binding"))?
        };
        // A role whose work never leaves the device is served nowhere off
        // it, whatever a manifest pins.
        let stays = self.stays_on_device.contains(&role) && route == ModelLocality::ThirdParty;
        match self
            .router
            .as_ref()
            .and_then(|router| router.served(&model))
        {
            Some((served, ladder)) if served == route && !stays => {
                // A manifest-bound model on this role's own ladder (else the
                // calling seat's) answers as that rung, with its prompt and
                // receipt; the bare provider model has neither. A pinned
                // seat id is that seat's whole ladder.
                let rung = self
                    .seat(role)
                    .into_iter()
                    .chain([seat])
                    .find_map(|seat| seat.rung(&model));
                // Only a reranker rung speaks the rerank protocol: the bare
                // model may be the provider's chat route.
                if role == ModelRole::Reranker && rung.is_none() {
                    return Err(RoleRefusal::RouteNotServed { model, route });
                }
                Ok(RoleRoute {
                    ladder: rung.unwrap_or(ladder),
                    model,
                    locality: served,
                    seat_bound: false,
                })
            }
            _ => Err(RoleRefusal::RouteNotServed { model, route }),
        }
    }

    /// Admits `request` as a call of `role` against the vault's live policy.
    pub fn admit_role(
        &self,
        vault: &Vault,
        role: ModelRole,
        mut request: LlmRequest,
    ) -> Result<RoleCall, RoleRefusal> {
        let seat = self.seat(role).ok_or(RoleRefusal::NoSeat)?;
        let route = self.route_role(vault, role, seat)?;
        let key = ModelTierRef(role_key(role));
        if route.seat_bound {
            // The seat is this call's binding, as a routed seat's is: a
            // purpose default only places a call nothing binds.
            request.envelope.tier.per_seat = Some(key.clone());
        }
        // Every call of a role names its seat on its usage event, manifest or
        // not. Under a manifest that names no override: its tier still binds.
        request.envelope.tier.seat = Some(key);
        request.model = route.model.clone();
        request.envelope.locality = route.locality;
        let request = vault
            .authorize_model_role(
                role,
                request,
                &HostInferenceContext {
                    binding: HostInferenceBinding::Advertised {
                        model: route.model,
                        locality: route.locality,
                    },
                    extraction_egress: None,
                },
            )
            .map_err(RoleRefusal::refused)?
            .into_request();
        Ok(RoleCall {
            request,
            ladder: route.ladder,
        })
    }

    /// Admits `request`, whose model a durable seat bound (its envelope's
    /// `seat_effort` set), as a call of `role` that keeps that model: its
    /// own one-model ladder, under the policy a raw call naming it meets,
    /// never swapped for the role's route. The role's live route still
    /// clamps it: a seat served elsewhere, or wider than that route, is
    /// refused.
    pub fn admit_seat_bound(
        &self,
        vault: &Vault,
        role: ModelRole,
        request: LlmRequest,
    ) -> Result<RoleCall, RoleRefusal> {
        let seat = self.seat(role).ok_or(RoleRefusal::NoSeat)?;
        let route = self.route_role(vault, role, seat)?.locality;
        let model = request.model.clone();
        let refused = || RoleRefusal::RouteNotServed {
            model: model.clone(),
            route,
        };
        let (served, ladder) = self
            .router
            .as_ref()
            .and_then(|router| router.served(&model))
            .ok_or_else(refused)?;
        if served != request.envelope.locality || served > route {
            return Err(refused());
        }
        let request = vault
            .authorize_raw_inference(
                request,
                &HostInferenceContext {
                    binding: HostInferenceBinding::Advertised {
                        model: model.clone(),
                        locality: served,
                    },
                    extraction_egress: None,
                },
            )
            .map_err(RoleRefusal::refused)?
            .into_request();
        Ok(RoleCall { request, ladder })
    }
}
