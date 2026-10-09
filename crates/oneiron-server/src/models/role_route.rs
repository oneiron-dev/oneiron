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
use oneiron::{LlmBackend, LlmRequest, ModelId, ModelLocality, ModelTierRef, Vault};

use super::{ModelRuntime, Seat};
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

/// An admitted request and the backend that serves it.
pub struct RoleCall {
    pub request: LlmRequest,
    pub backend: Arc<dyn LlmBackend>,
}

/// Where a call of a role runs: the model, its route, and the backend that
/// serves it there.
pub struct RoleRoute {
    pub model: ModelId,
    pub locality: ModelLocality,
    pub backend: Arc<dyn LlmBackend>,
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
            return Ok(RoleRoute {
                model: seat.model.clone(),
                locality: seat.locality,
                backend: Arc::clone(&seat.backend),
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
        match self
            .router
            .as_ref()
            .and_then(|router| router.served(&model))
        {
            Some((served, backend)) if served == route => Ok(RoleRoute {
                // A manifest-bound model on this role's own ladder (else the
                // calling seat's) answers as that rung, with its prompt and
                // receipt; the bare provider behind it has neither.
                backend: self
                    .seat(role)
                    .into_iter()
                    .chain([seat])
                    .find_map(|seat| seat.rung(&model))
                    .unwrap_or(backend),
                model,
                locality: served,
                seat_bound: false,
            }),
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
        if route.seat_bound {
            // The seat is this call's binding, as a routed seat's is: a
            // purpose default only places a call nothing binds.
            request.envelope.tier.per_seat = Some(ModelTierRef(role_key(role)));
        }
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
            backend: route.backend,
        })
    }
}
