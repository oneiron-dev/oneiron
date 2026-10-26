//! The owner-facing half of an official seat (OF-375): the settings the
//! owner writes, the sign-in surface built from them, the seat catalog a
//! settings page renders, and the Sign in with ChatGPT authorize request.

use oneiron::HostingPrivacyPosture;
use oneiron::code_sandbox::SandboxCredentialHandle;
use oneiron::dispatch_byoa::{
    DrySeatDecision, DrySeatFallback, OfficialSeatRoute, OfficialSeatSpec, SeatPlacementApproval,
    SeatPlanWindow, SiwcAuthorizeRequest, check_seat_placement, decide_dry_seat,
    pkce_s256_challenge, seat_login_plan, validate_official_seat,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The owner's settings for one official seat. Every field is a label, a
/// choice, or a custody handle; there is no field a vendor token could go in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SeatSettings {
    /// Route label, one of `OfficialSeatRoute::ALL` spellings.
    pub route: String,
    /// Opaque label for the person's account (never the credential).
    pub account_ref: String,
    #[serde(default)]
    pub machine_ref: Option<String>,
    /// Where the vendor's own login store lives on that machine.
    #[serde(default)]
    pub login_store_ref: Option<String>,
    /// Custody handle for endpoint-shaped seats, by name.
    #[serde(default)]
    pub credential_handle: Option<String>,
    /// The vendor binary is the unmodified build as published.
    #[serde(default = "default_true")]
    pub unmodified_binary: bool,
    #[serde(default)]
    pub anthropic_agent_sdk_approved: bool,
    #[serde(default)]
    pub openai_hosted_plan_approved: bool,
    /// `park` (default), `continue_on_local`, or `overdraft`.
    #[serde(default = "default_dry_fallback")]
    pub dry_fallback: String,
    /// The owner's spend cap when `dry_fallback` is `overdraft`.
    #[serde(default)]
    pub overdraft_cap_units: u64,
    #[serde(default)]
    pub plan_percent_used: Option<u8>,
    #[serde(default)]
    pub plan_resets_at: Option<u64>,
}

fn default_true() -> bool {
    true
}

fn default_dry_fallback() -> String {
    "park".to_owned()
}

impl SeatSettings {
    /// Folds the settings into the engine seat spec the dispatcher judges.
    ///
    /// # Errors
    ///
    /// Returns a message naming the unknown route/fallback label or the
    /// malformed custody handle.
    pub fn spec(&self) -> Result<OfficialSeatSpec, String> {
        let route = OfficialSeatRoute::from_label(self.route.trim())
            .ok_or_else(|| format!("unknown official seat route: {:?}", self.route))?;
        let credential_ref = self
            .credential_handle
            .as_deref()
            .map(str::trim)
            .filter(|handle| !handle.is_empty())
            .map(|handle| {
                SandboxCredentialHandle::new(handle.to_owned()).map_err(|error| error.to_string())
            })
            .transpose()?;
        let dry_fallback = match self.dry_fallback.trim().to_ascii_lowercase().as_str() {
            "park" | "park_until_reset" | "suspend" => DrySeatFallback::ParkUntilReset,
            "continue_on_local" | "local" => DrySeatFallback::ContinueOnLocal,
            "overdraft" | "spend" | "spend_overdraft" => DrySeatFallback::SpendOverdraft {
                cap_units: self.overdraft_cap_units,
            },
            other => return Err(format!("unknown dry-seat fallback: {other:?}")),
        };
        let plan_window = match (self.plan_percent_used, self.plan_resets_at) {
            (Some(percent_used), Some(resets_at)) => Some(SeatPlanWindow {
                percent_used,
                resets_at,
            }),
            _ => None,
        };
        Ok(OfficialSeatSpec {
            route,
            account_ref: self.account_ref.clone(),
            machine_ref: self.machine_ref.clone(),
            login_store_ref: self.login_store_ref.clone(),
            credential_ref,
            unmodified_binary: self.unmodified_binary,
            approvals: SeatPlacementApproval {
                anthropic_agent_sdk: self.anthropic_agent_sdk_approved,
                openai_hosted_plan: self.openai_hosted_plan_approved,
            },
            dry_fallback,
            plan_window,
        })
    }
}

/// Everything a sign-in surface needs to show, and nothing it must not: the
/// placement verdict, what the person runs, and what a dry seat would do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SeatLoginSurface {
    pub route: String,
    pub vendor: Option<String>,
    pub placement_ok: bool,
    pub placement_error: Option<String>,
    /// Argv the person runs themselves (the vendor's own login).
    pub login_argv: Vec<String>,
    /// Browser URL the person opens, for Sign in with ChatGPT.
    pub authorize_url: Option<String>,
    /// Always false; named so the surface states the posture.
    pub control_plane_holds_token: bool,
    /// `run`, `park`, `continue_on_local`, or `spend_overdraft`.
    pub dry_decision: String,
    pub park_until: Option<u64>,
    pub note: String,
}

/// Builds the sign-in surface for one seat on a runtime of hosting
/// `posture`: where the seat would actually run, whichever inference it
/// uses. A hosted runtime is Hosted with bring-your-own or local inference
/// too (FIX 9533); the provider-terms table judges the login there.
///
/// # Errors
///
/// Returns a message when the settings do not fold into a valid seat, or a
/// Sign in with ChatGPT surface is asked for without its authorize request.
pub fn seat_login_surface(
    posture: HostingPrivacyPosture,
    settings: &SeatSettings,
    now: u64,
    siwc: Option<&SiwcAuthorizeRequest>,
) -> Result<SeatLoginSurface, String> {
    let spec = settings.spec()?;
    validate_official_seat(&spec).map_err(|error| error.to_string())?;
    let placement =
        check_seat_placement(spec.route, posture, spec.approvals, spec.unmodified_binary);
    let plan = seat_login_plan(&spec, siwc).map_err(|error| error.to_string())?;
    let decision = decide_dry_seat(spec.plan_window.as_ref(), spec.dry_fallback, now);
    let (dry_decision, park_until) = match decision {
        DrySeatDecision::Run => ("run", None),
        DrySeatDecision::Park { until } => ("park", Some(until)),
        DrySeatDecision::ContinueOnLocal => ("continue_on_local", None),
        DrySeatDecision::Spend { .. } => ("spend_overdraft", None),
    };
    Ok(SeatLoginSurface {
        route: spec.route.as_str().to_owned(),
        vendor: plan.vendor.map(|vendor| vendor.as_str().to_owned()),
        placement_ok: placement.is_ok(),
        placement_error: placement.err().map(|error| error.to_string()),
        login_argv: plan.argv,
        authorize_url: plan.authorize_url,
        control_plane_holds_token: plan.control_plane_holds_token,
        dry_decision: dry_decision.to_owned(),
        park_until,
        note: plan.note.to_owned(),
    })
}

/// One row of the seat catalog a settings surface renders.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SeatRouteRow {
    pub route: String,
    pub vendor: Option<String>,
    pub user_login: bool,
    pub login_argv: Vec<String>,
    /// Placement on the person's own runtime, unmodified binary, no approvals.
    pub own_runtime_ok: bool,
    pub own_runtime_error: Option<String>,
    /// Placement on an Oneiron-hosted runtime, same assumptions.
    pub hosted_ok: bool,
    pub hosted_error: Option<String>,
}

/// Every seat route with its placement on both runtime classes, judged with
/// no vendor approvals granted: approvals only ever widen this table.
#[must_use]
pub fn seat_route_catalog() -> Vec<SeatRouteRow> {
    let approvals = SeatPlacementApproval::default();
    OfficialSeatRoute::ALL
        .into_iter()
        .map(|route| {
            let own =
                check_seat_placement(route, HostingPrivacyPosture::SelfHostLocal, approvals, true);
            let hosted =
                check_seat_placement(route, HostingPrivacyPosture::Hosted, approvals, true);
            SeatRouteRow {
                route: route.as_str().to_owned(),
                vendor: route.vendor().map(|vendor| vendor.as_str().to_owned()),
                user_login: route.is_user_login(),
                login_argv: route.login_argv(),
                own_runtime_ok: own.is_ok(),
                own_runtime_error: own.err().map(|error| error.to_string()),
                hosted_ok: hosted.is_ok(),
                hosted_error: hosted.err().map(|error| error.to_string()),
            }
        })
        .collect()
}

/// Builds a Sign in with ChatGPT authorize request from a PKCE verifier the
/// person's runtime generated and keeps. Only the S256 challenge leaves.
///
/// # Errors
///
/// Returns a message when the verifier is outside the RFC 7636 shape.
pub fn siwc_authorize_request(
    client_id: String,
    redirect_uri: String,
    verifier: &str,
    state: String,
    scope: Option<String>,
) -> Result<SiwcAuthorizeRequest, String> {
    Ok(SiwcAuthorizeRequest {
        client_id,
        redirect_uri,
        code_challenge: pkce_s256_challenge(verifier).map_err(|error| error.to_string())?,
        state,
        scope,
    })
}
