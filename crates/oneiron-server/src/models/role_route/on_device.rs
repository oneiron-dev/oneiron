//! A role's call that must not leave this device (I2-LOCAL, L9-15): the
//! route that keeps it there, whether a call carrying rows whose worlds
//! order the role's offers runs there, and the route such a call takes off
//! the device.
use oneiron::authority::WorldModelRoutes;
use oneiron::llm::manifest::ModelRole;
use oneiron::settings::model_pack::ModelPackAccess;
use oneiron::{LlmRequest, ModelLocality, Vault};

use super::{RoleCall, RoleRefusal, RoleRoute};
use crate::models::{ModelRuntime, Seat};

impl ModelRuntime {
    /// Where a call of `role` runs when it must not leave this device
    /// (I2-LOCAL, L9-15): [`Self::route_role`]'s route when it is on device
    /// and every call its ladder sends goes to a managed worker this server
    /// supervises, over that child's checked channel alone
    /// ([`OfferLadder::native_local`]: a manifest's or a model pack's
    /// on-device pin of a model a supervised worker serves natively, by its
    /// own id); when the seat itself binds the call, the seat's on-device
    /// view, when that view holds exactly the seat's rungs, each at its
    /// configured position ([`OfferLadder::same_rungs_as`]). A view that
    /// drops a rung of the seat would drop a fallback the seat's call takes,
    /// and one that holds a rung the seat left out (a rung the role's
    /// `leave_device` refuses) would take a fallback the seat's call never
    /// takes, so neither is a route here. `None` when a call of `role` could
    /// leave the device.
    ///
    /// [`OfferLadder::native_local`]: crate::models::OfferLadder::native_local
    /// [`OfferLadder::same_rungs_as`]: crate::models::OfferLadder::same_rungs_as
    pub(crate) fn on_device_route_role(
        &self,
        vault: &Vault,
        role: ModelRole,
        seat: &Seat,
    ) -> Result<Option<RoleRoute>, RoleRefusal> {
        let route = self.route_role(vault, role, seat)?;
        if route.locality == ModelLocality::OnDevice && route.ladder.native_local() {
            return Ok(Some(route));
        }
        if !route.seat_bound || route.model != seat.model {
            return Ok(None);
        }
        let Some(view) = seat
            .on_device
            .as_ref()
            .filter(|view| view.native_local() && view.same_rungs_as(&seat.ladder))
        else {
            return Ok(None);
        };
        Ok(Some(RoleRoute {
            model: route.model,
            locality: ModelLocality::OnDevice,
            ladder: self.ladder_for_role(role, view),
            seat_bound: true,
        }))
    }

    /// Whether a call of `role` that carries rows whose worlds order its
    /// offers by `routes` runs on this device (I2-LOCAL, L9-15): the route
    /// that keeps it there ([`Self::on_device_route_role`]) keeps a rung
    /// `routes` admits, and each rung the call's route off the device
    /// ([`Self::route_role_for_world_routes`]) takes under `routes`, so the
    /// on-device call never fails for a fallback that route would reach.
    /// [`WorldModelRoutes::Inherit`] leaves every rung. A route that cannot
    /// be read is no such route.
    #[must_use]
    pub(crate) fn role_routes_on_device(
        &self,
        vault: &Vault,
        role: ModelRole,
        routes: &WorldModelRoutes,
    ) -> bool {
        let Some(seat) = self.seat(role) else {
            return false;
        };
        let Ok(Some(on_device)) = self.on_device_route_role(vault, role, seat) else {
            return false;
        };
        let kept = on_device.ladder.for_world_routes(routes);
        kept.has_rungs()
            && self
                .route_role_for_world_routes(vault, role, seat, routes)
                .is_ok_and(|off| kept.holds_rungs_of(&off.ladder.for_world_routes(routes)))
    }

    /// [`Self::admit_role`] on the route a call of `role` takes when it must
    /// not leave this device ([`Self::on_device_route_role`]): refused before
    /// it is sent when a call of `role` could leave the device now.
    pub(crate) fn admit_role_on_device(
        &self,
        vault: &Vault,
        role: ModelRole,
        request: LlmRequest,
    ) -> Result<RoleCall, RoleRefusal> {
        let seat = self.seat(role).ok_or(RoleRefusal::NoSeat)?;
        let route = self
            .on_device_route_role(vault, role, seat)?
            .ok_or_else(|| RoleRefusal::RouteNotServed {
                model: seat.model.clone(),
                route: ModelLocality::OnDevice,
            })?;
        self.admit_on_route(vault, role, request, route)
            .map(|(call, _)| call)
    }

    /// [`Self::admit_role`] for a call of `role` off this device that
    /// carries rows whose worlds order its offers by `routes`, on
    /// [`Self::route_role_for_world_routes`]'s route.
    pub(crate) fn admit_role_for_world_routes(
        &self,
        vault: &Vault,
        role: ModelRole,
        request: LlmRequest,
        routes: &WorldModelRoutes,
    ) -> Result<RoleCall, RoleRefusal> {
        let seat = self.seat(role).ok_or(RoleRefusal::NoSeat)?;
        let route = self.route_role_for_world_routes(vault, role, seat, routes)?;
        self.admit_on_route(vault, role, request, route)
            .map(|(call, _)| call)
    }

    /// [`Self::route_role`] for a call of `role` off this device that
    /// carries rows whose worlds order its offers by `routes`: that route,
    /// unless it is a local-GPU model pack's pick on its model's on-device
    /// view and `routes` leaves no rung of it; then the pick's own-server
    /// route ([`Self::model_pack_own_server_route`]) when `routes` leaves a
    /// rung of that. A manifest's pin stays exact.
    fn route_role_for_world_routes(
        &self,
        vault: &Vault,
        role: ModelRole,
        seat: &Seat,
        routes: &WorldModelRoutes,
    ) -> Result<RoleRoute, RoleRefusal> {
        let route = self.route_role(vault, role, seat)?;
        if route.locality != ModelLocality::OnDevice
            || route.ladder.for_world_routes(routes).has_rungs()
        {
            return Ok(route);
        }
        Ok(self
            .model_pack_own_server_route(vault, role, seat)?
            .filter(|pick| pick.ladder.for_world_routes(routes).has_rungs())
            .unwrap_or(route))
    }

    /// The vault's local-GPU model pack's pick for `role` at its model's
    /// configured route, when the pick runs on the model's on-device view
    /// ([`Self::model_pack_served`]): the route that pick took before a
    /// `listen = "unix"` worker's reranker model had an on-device view by
    /// its own id (L9-15), within the pick's own-server ceiling. `None` with
    /// a manifest, which outranks the pack, and when no such pick runs here.
    fn model_pack_own_server_route(
        &self,
        vault: &Vault,
        role: ModelRole,
        seat: &Seat,
    ) -> Result<Option<RoleRoute>, RoleRefusal> {
        if vault
            .model_manifest()
            .map_err(RoleRefusal::refused)?
            .is_some()
        {
            return Ok(None);
        }
        let Some(choice) = vault
            .model_pack_role_choice(role, &self.offer_access())
            .map_err(RoleRefusal::refused)?
        else {
            return Ok(None);
        };
        let on_device = self
            .model_pack_served(&choice)
            .is_some_and(|(served, _)| served == ModelLocality::OnDevice);
        if choice.variant.access != ModelPackAccess::LocalGpu || !on_device {
            return Ok(None);
        }
        Ok(self
            .raw_router
            .served(choice.model())
            .filter(|(served, _)| *served <= ModelLocality::OwnServer)
            .and_then(|served| self.model_pack_pick_route(role, seat, &choice, served)))
    }
}
