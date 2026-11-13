//! A role-bound call's model under the vault's live model manifest.
//!
//! Chat turns, workflow steps and the Dreamer's extraction are calls of a
//! model role, so they are admitted through that role (ARCH-0036). When the
//! vault has a manifest, its binding for the role at the effective route (the
//! pin, narrowed by any resident route) names the model, and this server must
//! serve exactly that model at exactly that route. A model it does not serve there is refused
//! before any call leaves: a vault's route may narrow, never silently widen.
//! Without a manifest the vault's active model pack names the role's model
//! when one of its variants runs on this server's offers (FIX 5366), else
//! the role's seat is the binding: the owner's `[models]` ladder, pinned the
//! way a routed seat is. A manifest that leaves the
//! optional browser planner unbound leaves it unseated, as no rung does.
//! An exact replay keeps its captured model and route, and finds the rung
//! that answered it on the role's route or on the model's raw route (FIX
//! 18546, [`ModelRuntime::admit_replay`]).
use std::sync::Arc;

use oneiron::llm::HostInferenceContext;
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::model_pack::ModelPackRoleChoice;
use oneiron::settings::model_pack::ModelPackAccess;
use oneiron::{LlmRequest, ModelId, ModelLocality, ModelTierRef, Vault};

use super::ladder::ReplayLadder;
use super::{ModelRuntime, OfferLadder, Seat};
use crate::config::models::{role_key, unbound_row_is_no_seat};

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
    /// An exact replay of a call that ran wider than the role's route, which
    /// only an owner's standing quota fallback (`use_fallback`) for the
    /// route's offers sends a call to: no such fallback the role may take
    /// names its model there now. The owner has turned it off or named
    /// another since, the role's route has narrowed, or the role's work now
    /// stays on the device (`leave_device = "never"`) and the call ran at a
    /// third party (FIX-LIST REPLAY-REFUSED-FOR-WIDER-FALLBACK-RUNG).
    FallbackNoLongerAllowed {
        model: ModelId,
        /// Where the replayed call ran.
        locality: ModelLocality,
        /// The role's route now.
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
                locality_name(*route)
            ),
            Self::FallbackNoLongerAllowed {
                model,
                locality,
                route,
            } => write!(
                f,
                "fallback no longer allowed: the replayed call ran on {model} at {}, wider than \
                 this role's route ({}), and no owner's fallback this role may take names it \
                 there now",
                locality_name(*locality),
                locality_name(*route)
            ),
            Self::Refused(error) => write!(f, "{error}"),
        }
    }
}

/// A route's wire name (`own_server`, `third_party`, ...).
fn locality_name(locality: ModelLocality) -> String {
    serde_json::to_value(locality)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{locality:?}"))
}

/// The widest route a model pack pick on `access` may run at (FIX 5366): a
/// local-GPU pick runs on this device or the owner's own model server, never
/// at a third party; any other access, wherever its offers serve it.
fn model_pack_ceiling(access: &ModelPackAccess) -> ModelLocality {
    if *access == ModelPackAccess::LocalGpu {
        ModelLocality::OwnServer
    } else {
        ModelLocality::ThirdParty
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
    /// No manifest binds the role, so the seat, or the vault's model pack,
    /// is the binding.
    seat_bound: bool,
}

/// An admitted exact replay (FIX 18546): the captured request, on its
/// captured model at its captured route, and the routes that may hold the
/// rung that answered it.
pub(crate) struct ReplayAdmission {
    pub(crate) request: LlmRequest,
    pub(crate) routes: ReplayRoutes,
}

/// The two routes on which an exact replay looks for the rung that answered
/// it (FIX 18546). `None` is a route that does not serve the captured model
/// at the captured route.
pub(crate) struct ReplayRoutes {
    /// The captured role's route: the role's rung for the captured model,
    /// alone, with the route prompt it has in the config now.
    role_route: Option<Arc<OfferLadder>>,
    /// The captured model's raw route: the ladder a raw call that names the
    /// model meets. Its one rung has no route prompt.
    raw_route: Option<Arc<OfferLadder>>,
}

impl ReplayRoutes {
    /// The route whose one picked rung answered a call of `model` at
    /// `locality`, and that rung (FIX 18546). The role's route goes first,
    /// then the raw route. A rung whose route prompt digest is
    /// `prompt_digest` comes before a rung with another digest. If no exact
    /// rung has that digest, this is the first exact rung, and the caller's
    /// digest check refuses it. `None` when no route has an exact rung.
    pub(crate) fn exact_rung(
        &self,
        model: &ModelId,
        locality: ModelLocality,
        prompt_digest: [u8; 32],
    ) -> Option<(&Arc<OfferLadder>, ReplayLadder<'_>)> {
        let mut exact = [&self.role_route, &self.raw_route]
            .into_iter()
            .flatten()
            .filter_map(|ladder| Some((ladder, ladder.for_replay_binding(model, locality)?)));
        let first = exact.next()?;
        if first.1.exact_prompt_digest() == prompt_digest {
            return Some(first);
        }
        Some(
            exact
                .find(|(_, replay)| replay.exact_prompt_digest() == prompt_digest)
                .unwrap_or(first),
        )
    }
}

impl ModelRuntime {
    /// Resolves `role` against the vault's live manifest and route; without
    /// a manifest, the vault's model pack's pick when one runs here
    /// ([`Self::model_pack_route`]), else `seat` is the binding (the
    /// Dreamer's seat for its teacher). The model is the one the engine's
    /// admission will select, so the backend attests exactly that model.
    pub fn route_role(
        &self,
        vault: &Vault,
        role: ModelRole,
        seat: &Seat,
    ) -> Result<RoleRoute, RoleRefusal> {
        self.route_role_with_pack(vault, role, seat, true)
    }

    /// [`Self::route_role`] without the vault's model pack: the manifest's
    /// route, else the configured seat's. It is the clamp an agent's
    /// seat-bound call meets, so a pack never narrows a per-agent pick
    /// (FIX 5367: per-agent settings always win).
    pub fn configured_route_role(
        &self,
        vault: &Vault,
        role: ModelRole,
        seat: &Seat,
    ) -> Result<RoleRoute, RoleRefusal> {
        self.route_role_with_pack(vault, role, seat, false)
    }

    fn route_role_with_pack(
        &self,
        vault: &Vault,
        role: ModelRole,
        seat: &Seat,
        follow_pack: bool,
    ) -> Result<RoleRoute, RoleRefusal> {
        let Some(manifest) = vault.model_manifest().map_err(RoleRefusal::refused)? else {
            if follow_pack && let Some(route) = self.model_pack_route(vault, role, seat)? {
                return Ok(route);
            }
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
        // A manifest with no row for the browser planner leaves it
        // unseated, as no rung does, so its call takes the chat role (CUA
        // E5). Any other role's missing row is refused below.
        if unbound_row_is_no_seat(role) && !manifest.roles.contains_key(&role) {
            return Err(RoleRefusal::NoSeat);
        }
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
        // An on-device route takes the model's on-device view, the native
        // channels of the workers this server supervises alone (I2-LOCAL);
        // any other route, its default one.
        match self
            .router
            .as_ref()
            .and_then(|router| router.served_at(&model, route))
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
                    .find_map(|seat| seat.rung_at(&model, served));
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

    /// The vault's active model pack's route for `role`, read when no
    /// manifest binds it (FIX 5366, 5367): the first variant the pack lists
    /// for the role whose model this server's offers serve on the variant's
    /// access, at the route that serves it, which binds the call as a seat
    /// does. An engine call (CALLS, FIX 5366): `None`, and the seat binds as
    /// before, when no pack is installed, no variant runs here, or the role's
    /// work stays on the device and the pick would leave it; a reranker's
    /// pick also needs a reranker rung, as a manifest's does. A local-GPU
    /// pick runs only on the model's on-device view: served at any other
    /// route, which may leave the device, it is no pick.
    fn model_pack_route(
        &self,
        vault: &Vault,
        role: ModelRole,
        seat: &Seat,
    ) -> Result<Option<RoleRoute>, RoleRefusal> {
        let Some(choice) = vault
            .model_pack_role_choice(role, &self.offer_access())
            .map_err(RoleRefusal::refused)?
        else {
            return Ok(None);
        };
        let Some((served, ladder)) = self.model_pack_served(&choice) else {
            return Ok(None);
        };
        let model = choice.model().clone();
        let widest = model_pack_ceiling(&choice.variant.access);
        if self.stays_on_device.contains(&role) && served == ModelLocality::ThirdParty {
            return Ok(None);
        }
        let rung = self
            .seat(role)
            .into_iter()
            .chain([seat])
            .find_map(|seat| seat.rung_at(&model, served));
        if role == ModelRole::Reranker && rung.is_none() {
            return Ok(None);
        }
        let ladder = rung.unwrap_or(ladder);
        // A local-GPU pick keeps its call local through every owner's
        // fallback too: its call-local ladder carries an own-server ceiling,
        // and a stricter ceiling the ladder has stays (review #6390).
        let ladder = if choice.variant.access == ModelPackAccess::LocalGpu {
            Arc::new(ladder.with_locality_ceiling(widest))
        } else {
            ladder
        };
        Ok(Some(RoleRoute {
            ladder,
            model,
            locality: served,
            seat_bound: true,
        }))
    }

    /// Where this server serves `choice`, a model pack's pick (FIX 5366),
    /// and the ladder that serves it there: at its access's route, never
    /// wider than that access allows (`model_pack_ceiling`). With no
    /// on-device view, `served_at` falls back to the model's default route,
    /// which may be remote, so a local-GPU pick served there is no pick.
    /// `None` when no route here serves it so. A role's pick and the
    /// compaction model's (FIX 20042) are served by this one rule.
    pub(crate) fn model_pack_served(
        &self,
        choice: &ModelPackRoleChoice,
    ) -> Option<(ModelLocality, Arc<OfferLadder>)> {
        let route = if choice.variant.access == ModelPackAccess::LocalGpu {
            ModelLocality::OnDevice
        } else {
            ModelLocality::ThirdParty
        };
        let widest = model_pack_ceiling(&choice.variant.access);
        self.raw_router
            .served_at(choice.model(), route)
            .filter(|(served, _)| *served <= widest)
    }

    /// Admits `request` as a call of `role` against the vault's live policy.
    pub fn admit_role(
        &self,
        vault: &Vault,
        role: ModelRole,
        request: LlmRequest,
    ) -> Result<RoleCall, RoleRefusal> {
        self.admit_role_receipted(vault, role, request)
            .map(|(call, _)| call)
    }

    /// The same admission, beside the catalog entry that exact snapshot read.
    pub(crate) fn admit_role_receipted(
        &self,
        vault: &Vault,
        role: ModelRole,
        mut request: LlmRequest,
    ) -> Result<(RoleCall, Option<String>), RoleRefusal> {
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
                    binding: route
                        .ladder
                        .host_binding(route.model, route.locality, false),
                    extraction_egress: None,
                },
            )
            .map_err(RoleRefusal::refused)?;
        let catalog_revision = request.binding().catalog_revision().map(str::to_owned);
        Ok((
            RoleCall {
                request: request.into_request(),
                ladder: route.ladder,
            },
            catalog_revision,
        ))
    }

    /// Admits `request`, whose model a durable seat bound (its envelope's
    /// `seat_effort` set), as a call of `role` that keeps that model: its
    /// own one-model ladder, under the policy a raw call naming it meets,
    /// never swapped for the role's route. The role's configured route
    /// ([`Self::configured_route_role`], never the model pack's) still
    /// clamps it: a seat served elsewhere, or wider than that route, is
    /// refused.
    pub fn admit_seat_bound(
        &self,
        vault: &Vault,
        role: ModelRole,
        request: LlmRequest,
    ) -> Result<RoleCall, RoleRefusal> {
        let seat = self.seat(role).ok_or(RoleRefusal::NoSeat)?;
        let route = self.configured_route_role(vault, role, seat)?.locality;
        let model = request.model.clone();
        let refused = || RoleRefusal::RouteNotServed {
            model: model.clone(),
            route,
        };
        let (served, ladder) = self
            .router
            .as_ref()
            .and_then(|router| router.served_at(&model, request.envelope.locality))
            .ok_or_else(refused)?;
        if served != request.envelope.locality || served > route {
            return Err(refused());
        }
        let request = vault
            .authorize_raw_inference(
                request,
                &HostInferenceContext {
                    binding: ladder.host_binding(model.clone(), served, false),
                    extraction_egress: None,
                },
            )
            .map_err(RoleRefusal::refused)?
            .into_request();
        Ok(RoleCall { request, ladder })
    }

    /// The free local chat model a run held at its spend cap may continue on
    /// (ARCH-0026 depletion ladder: continue on local): the first rung of
    /// `role`'s seat, in ladder order, that this server serves on the device,
    /// else on the owner's own server, as free work and within the role's
    /// configured route (`free_local_route`). `None` when no rung is served
    /// so. A configured, served model, not a live probe of its capacity.
    #[must_use]
    pub fn free_local_model(&self, vault: &Vault, role: ModelRole) -> Option<ModelId> {
        let seat = self.seat(role)?;
        let route = self.configured_route_role(vault, role, seat).ok()?.locality;
        let router = self.router.as_ref()?;
        seat.rung_models()
            .into_iter()
            .map(|(model, _)| model)
            .find(|model| free_local_route(router, model, route).is_some())
    }

    /// Admits `request` as a call of `role` on `model` alone, on its free
    /// local route (`free_local_route`), read now: the route the owner chose
    /// to continue a held run on. The role's configured route still clamps
    /// it, under the policy a raw call naming the model meets, as
    /// [`Self::admit_seat_bound`] does. A model no longer served there as
    /// free work is refused.
    pub fn admit_free_local(
        &self,
        vault: &Vault,
        role: ModelRole,
        mut request: LlmRequest,
        model: &ModelId,
    ) -> Result<RoleCall, RoleRefusal> {
        let seat = self.seat(role).ok_or(RoleRefusal::NoSeat)?;
        let route = self.configured_route_role(vault, role, seat)?.locality;
        let (served, ladder) = self
            .router
            .as_ref()
            .and_then(|router| free_local_route(router, model, route))
            .ok_or_else(|| RoleRefusal::RouteNotServed {
                model: model.clone(),
                route,
            })?;
        request.model = model.clone();
        request.envelope.locality = served;
        // The call still names its role's seat on its usage event.
        request.envelope.tier.seat = Some(ModelTierRef(role_key(role)));
        let request = vault
            .authorize_raw_inference(
                request,
                &HostInferenceContext {
                    binding: ladder.host_binding(model.clone(), served, false),
                    extraction_egress: None,
                },
            )
            .map_err(RoleRefusal::refused)?
            .into_request();
        Ok(RoleCall { request, ladder })
    }

    /// Admits `request`, an exact replay of a call that `role`'s admission
    /// sent, on its captured model at its captured route (FIX 18546). The
    /// role's pick never replaces the model. The role's live route clamps
    /// it as in [`Self::admit_seat_bound`], under the policy that a raw call
    /// naming the model meets. A call that ran wider than that route went
    /// out on an owner's standing quota fallback for one of the route's
    /// offers; its replay is admitted while that fallback, read now, still
    /// names its model there, and refused as
    /// [`RoleRefusal::FallbackNoLongerAllowed`] once it does not, or once
    /// the call ran at a third party and the role's work stays on the device
    /// (FIX-LIST REPLAY-REFUSED-FOR-WIDER-FALLBACK-RUNG). The admission keeps
    /// both routes that can hold the rung that answered: the role's own
    /// route, whose rung has its configured prompt, and the model's raw
    /// route, whose rung has none. A model that neither route serves at the
    /// captured route is refused.
    pub(crate) fn admit_replay(
        &self,
        vault: &Vault,
        role: ModelRole,
        request: LlmRequest,
    ) -> Result<ReplayAdmission, RoleRefusal> {
        let seat = self.seat(role).ok_or(RoleRefusal::NoSeat)?;
        let route = self.route_role(vault, role, seat)?;
        let model = request.model.clone();
        let locality = request.envelope.locality;
        let refused = || RoleRefusal::RouteNotServed {
            model: model.clone(),
            route: route.locality,
        };
        // Only an owner's standing fallback (`use_fallback`) for one of the
        // route's offers sends a call of the role wider than the route. The
        // replay keeps to that choice as it stands now, read here, so it
        // widens nothing; a choice the owner has since turned off or
        // narrowed refuses it for its own reason (Engine ruling 13 Nov). A
        // role whose work never leaves the device takes no third party's
        // fallback, read from the role itself: a manifest's pin off the
        // role's seat routes on the model's bare ladder, whose scope does not
        // carry the role's rule (review of #7309).
        let kept_on_device =
            self.stays_on_device.contains(&role) && locality == ModelLocality::ThirdParty;
        if locality > route.locality
            && (kept_on_device || !route.ladder.owner_fallback_serves(&model, locality))
        {
            return Err(RoleRefusal::FallbackNoLongerAllowed {
                model: model.clone(),
                locality,
                route: route.locality,
            });
        }
        // The role's route serves the model on the role's rung for it: any
        // rung of the seat, or the one model a manifest pins.
        let on_role_route = route.seat_bound || route.model == model;
        let role_route = seat.rung_at(&model, locality).filter(|ladder| {
            on_role_route && ladder.for_replay_binding(&model, locality).is_some()
        });
        let raw_route = self
            .router
            .as_ref()
            .and_then(|router| router.served_at(&model, locality))
            .and_then(|(served, ladder)| (served == locality).then_some(ladder));
        let Some(served) = role_route.as_ref().or(raw_route.as_ref()) else {
            return Err(refused());
        };
        let binding = served.host_binding(model.clone(), locality, false);
        let request = vault
            .authorize_raw_inference(
                request,
                &HostInferenceContext {
                    binding,
                    extraction_egress: None,
                },
            )
            .map_err(RoleRefusal::refused)?
            .into_request();
        Ok(ReplayAdmission {
            request,
            routes: ReplayRoutes {
                role_route,
                raw_route,
            },
        })
    }
}

/// Where `router` serves `model` as free work: on the device, else on the
/// owner's own server, at exactly that locality and no wider than `route`,
/// every rung of its ladder free by the run admission's rule
/// ([`OfferLadder::all_free_work`]: a paid on-device worker or a keyed own
/// server is not free). The ladder comes back with its owner's fallbacks held
/// at that locality. `None` when it is served so nowhere.
fn free_local_route(
    router: &super::ModelRouter,
    model: &ModelId,
    route: ModelLocality,
) -> Option<(ModelLocality, Arc<OfferLadder>)> {
    [ModelLocality::OnDevice, ModelLocality::OwnServer]
        .into_iter()
        .find_map(|locality| {
            let (served, ladder) = router.served_at(model, locality)?;
            (served == locality && served <= route && ladder.all_free_work())
                .then(|| (served, Arc::new(ladder.with_locality_ceiling(served))))
        })
}
