//! Registration of the named official seats as Dreamer providers (OF-137).
//!
//! The official seat adapters ([`super::official_seats`]) know each vendor's
//! terms: which binary, which login the person runs, where that login may
//! run. The Dreamer runner seats ([`super::RunnerSeatPolicy`]) name
//! [`DreamerProviderAdapter`]s. This module is the bridge: an official seat
//! the owner holds registers under its adapter's name, so a seat policy can
//! order "claude-code", "chatgpt-signin" or "grok-api-key" next to the plain
//! CLI runners and quota exhaustion routes across all of them the same way.
//!
//! Nothing here can hold a vendor login either. A registered provider keeps
//! the seat's labels and custody handles (`OfficialSeatSpec`) and shapes the
//! adapter's connector per run; the login stays inside the official CLI or
//! the person's local token store, exactly as on the seat seam.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::llm::ModelId;

use super::connector::ByoaConnectorSpec;
use super::error::{ByoaError, ByoaResult, ERR_SEAT_SPEC, invalid};
use super::official_seats::{
    OfficialSeatAdapter, OfficialSeatInput, OfficialSeatRegistry, OfficialSeatRoute,
    OfficialSeatSpec,
};
use super::provider::{DreamerProviderAdapter, DreamerProviderInput, ProviderAdapterRegistry};

/// One official seat to register as a Dreamer provider: the seat the owner
/// holds, plus the endpoint bindings a CLI seat ignores.
#[derive(Debug, Clone)]
pub struct OfficialDreamerSeat {
    pub spec: OfficialSeatSpec,
    /// Slug bindings for endpoint-shaped seats (Agent SDK, Sign in with
    /// ChatGPT, API keys). CLI seats (Claude Code, Codex) ignore it.
    pub model_slug_map: BTreeMap<String, ModelId>,
    /// Overrides the adapter's default endpoint base URL.
    pub base_url: Option<String>,
}

/// An official seat adapter behind the Dreamer provider seam. The connector
/// it shapes is the adapter's own — the same argv or endpoint the seat
/// dispatch door judges — so placement and custody rules are the seat's,
/// not a second copy of them.
pub struct OfficialSeatDreamerProvider {
    adapter: Arc<dyn OfficialSeatAdapter>,
    seat: OfficialSeatSpec,
    model_slug_map: BTreeMap<String, ModelId>,
    base_url: Option<String>,
}

impl OfficialSeatDreamerProvider {
    /// The vendor route this provider runs.
    #[must_use]
    pub fn route(&self) -> OfficialSeatRoute {
        self.adapter.route()
    }

    /// The seat the owner holds. Labels and custody handles only.
    #[must_use]
    pub const fn seat(&self) -> &OfficialSeatSpec {
        &self.seat
    }
}

impl DreamerProviderAdapter for OfficialSeatDreamerProvider {
    fn name(&self) -> &'static str {
        self.adapter.name()
    }

    fn connector(&self, input: DreamerProviderInput) -> ByoaResult<ByoaConnectorSpec> {
        self.adapter.connector(
            &self.seat,
            OfficialSeatInput {
                task: input.task,
                checkout_id: Some(input.checkout_id),
                egress_profile_ref: input.egress_profile_ref,
                credential_handles: input.credential_handles,
                model_slug_map: self.model_slug_map.clone(),
                base_url: self.base_url.clone(),
            },
        )
    }
}

/// Whether a route's connector is an endpoint and so binds model slugs.
const fn binds_slugs(route: OfficialSeatRoute) -> bool {
    matches!(
        route,
        OfficialSeatRoute::ClaudeAgentSdkSubscription
            | OfficialSeatRoute::SignInWithChatGpt
            | OfficialSeatRoute::VendorApiKey
    )
}

/// Registers each seat's official adapter as a Dreamer provider under the
/// adapter's name ("claude-code", "codex", "claude-agent-sdk",
/// "chatgpt-signin", "grok-api-key").
///
/// Names collide with the plain CLI runners on purpose — an official
/// "claude-code" seat IS the claude-code runner, with the seat's login and
/// placement attached — so register into a registry that does not already
/// hold the plain runner of the same name, or take the duplicate refusal.
///
/// # Errors
///
/// Refuses a route with no adapter in `official` (a Grok subscription has
/// none, by design), an endpoint seat that binds no model slug, an invalid
/// seat spec, and a name the registry already holds.
pub fn register_official_dreamer_providers(
    registry: &mut ProviderAdapterRegistry,
    official: &OfficialSeatRegistry,
    seats: impl IntoIterator<Item = OfficialDreamerSeat>,
) -> ByoaResult<()> {
    for seat in seats {
        super::official_seats::validate_official_seat(&seat.spec)?;
        if binds_slugs(seat.spec.route) && seat.model_slug_map.is_empty() {
            return Err(invalid(ERR_SEAT_SPEC));
        }
        let adapter = official
            .adapter_for_route(seat.spec.route)
            .ok_or_else(|| {
                ByoaError::UnknownSeatAdapter(seat.spec.route.as_str().to_owned())
            })?;
        registry.register(Arc::new(OfficialSeatDreamerProvider {
            adapter,
            seat: seat.spec,
            model_slug_map: seat.model_slug_map,
            base_url: seat.base_url,
        }))?;
    }
    Ok(())
}
