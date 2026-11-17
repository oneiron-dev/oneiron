//! Doors for `tests/recovery_box_deposit_answer.rs`: the roots routes'
//! confirm and run work and the CLI confirm, without the HTTP guards
//! (OwnerDevice, kit_target).

use std::collections::BTreeSet;
use std::path::Path;

use oneiron::authority::ActAuthority;
use oneiron::consent::AuthenticatedOwner;
use oneiron::recovery::KitPiece;

use crate::api::{ConfirmDoor, RunRootRequest, confirm_answer, run_answer};

/// The roots confirm door's answer for `body`, without its guards.
pub fn confirm_answer_json(
    vault: &oneiron::Vault,
    authority: &ActAuthority,
    body: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let body = serde_json::from_value::<ConfirmDoor>(body)?;
    let answer =
        confirm_answer(vault, authority, body).map_err(|error| anyhow::anyhow!("{error:?}"))?;
    Ok(serde_json::to_value(answer)?)
}

/// The roots run door's answer for `body`, without its guards.
pub fn run_answer_json(
    vault: &oneiron::Vault,
    authority: &ActAuthority,
    body: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let body = serde_json::from_value::<RunRootRequest>(body)?;
    let enrolment = body
        .enrolment()
        .map_err(|error| anyhow::anyhow!("enrolment: {}", error.message()))?;
    let answer = run_answer(vault, authority, body, enrolment)
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    Ok(serde_json::to_value(answer)?)
}

/// The CLI confirm's answer for `pieces`, with no passphrase and no carry,
/// writing the box deposit only to `box_deposit_out`.
pub fn cli_confirm_json(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    pieces: &[&KitPiece],
    box_deposit_out: Option<&Path>,
) -> anyhow::Result<serde_json::Value> {
    let confirmed = crate::commands::confirm_on(
        vault,
        owner,
        pieces,
        None,
        &BTreeSet::new(),
        box_deposit_out,
    )?;
    Ok(serde_json::to_value(confirmed)?)
}
