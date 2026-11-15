//! `PUT /v1/llm/defaults` through the setting door of `models.purpose_defaults` (FIX 8211;
//! DESIGN 15-setting-primitive, stage 2). The caller's own proof goes to `Vault::set_setting`,
//! which judges it in its write: the owner's table lands; a person who holds the vault's policy
//! power over the inference defaults moves them both ways, and over a table the owner set asks;
//! anyone else's change asks through a check-in, and the defaults stay as they are. The
//! credential's grade alone never replaces them. Once a holder approves the ask, the asker's same
//! change with that check-in applies once (`vault.settings.set` with `check_in_ref`).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use oneiron::consent::AuthenticatedOwner;
use oneiron::llm::{PurposeDefaultTable, purpose_defaults_change};
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};

use super::refusal;
use crate::{auth::CoreAuth, server::SyncServer};

/// The reason a change through this route gives.
const ROUTE: &str = "PUT /v1/llm/defaults";

/// Sets `table`, already validated, for the caller of `auth`: the owner on his proof; another
/// person on their own verified slip; any other principal as the agent it is. An applied change
/// answers `200` with the active table; a change that asks answers `202` with the check-in it
/// waits on, and the defaults stay as they are.
pub(super) fn submit(
    server: &SyncServer,
    auth: &CoreAuth,
    table: &PurposeDefaultTable,
) -> Response {
    let vault = &server.vault;
    let request = match purpose_defaults_change(table) {
        Ok(request) => SetSetting {
            why: Some(ROUTE.to_owned()),
            ..request
        },
        Err(_) => return refusal(StatusCode::BAD_REQUEST, "invalid_defaults"),
    };
    let owner = match crate::api::facade::owner_authorship(auth, server) {
        Ok(owner) => owner,
        Err(refused) => return refused.into_response(),
    };
    let person = if owner.is_none() {
        person(server, auth)
    } else {
        None
    };
    let caller = match (&owner, &person) {
        (Some(owner), _) => SettingCaller::Owner(owner),
        (None, Some(person)) => SettingCaller::Person(person),
        (None, None) => match auth.principal_entity() {
            Some(principal) => SettingCaller::Agent(principal),
            None => return refusal(StatusCode::FORBIDDEN, "owner_required"),
        },
    };
    match vault.set_setting(caller, request) {
        Ok(SetSettingOutcome::Applied { .. }) => match vault.purpose_default_table() {
            Ok(active) => Json(active).into_response(),
            Err(_) => refusal(StatusCode::INTERNAL_SERVER_ERROR, "defaults_unavailable"),
        },
        Ok(SetSettingOutcome::Pending { check_in }) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "pending": check_in })),
        )
            .into_response(),
        Err(error) => setting_refusal(error),
    }
}

/// The setting door's refusal as its wire code. The table was validated before the door, so an
/// `InvalidConfig` there is the door's power rule: a change the caller may neither make nor ask.
fn setting_refusal(error: oneiron::Error) -> Response {
    match error {
        oneiron::Error::Gate(_) => refusal(StatusCode::FORBIDDEN, "owner_required"),
        oneiron::Error::InvalidConfig(_) | oneiron::Error::Refused(_) => {
            refusal(StatusCode::FORBIDDEN, "policy_holder_required")
        }
        _ => refusal(StatusCode::INTERNAL_SERVER_ERROR, "defaults_unavailable"),
    }
}

/// A person's own proof on their own verified slip, bound to that slip so
/// the writing transaction checks it again. A slip that names no actor class
/// is judged by its holder: a stored live PERSON authenticates as one.
/// `None` for a slip of another class, an invitee's, or a holder that is no
/// stored person.
fn person(server: &SyncServer, auth: &CoreAuth) -> Option<AuthenticatedOwner> {
    let slip = auth
        .verified_slip()
        .filter(|_| matches!(auth.actor_class(), None | Some("human")))?;
    let principal = auth.principal_ref()?;
    let actor = oneiron::EntityId::from_hex(principal).ok()?;
    if slip.claims().holder_ref != actor.to_hex() || slip.claims().invitation_ref.is_some() {
        return None;
    }
    let person = server
        .vault
        .authenticate_owner(
            actor,
            principal,
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .ok()?;
    server
        .vault
        .bind_request_credential(person, slip.clone())
        .ok()
}
