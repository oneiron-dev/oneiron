//! The root ceremonies made directly on this install while its server runs
//! (FIX 4955): where the owner is signed in on the install whose root
//! changes, `request_root_change` answers that this install is the target,
//! and these doors make the change here, as the stopped vault's commands do,
//! with the same engine doors and every check in them.
//!
//! - `POST /roots/anchor`: the bound root's kit marks a machine mine
//!   (`Vault::anchor_machine`): this install's own enrolment request, or a new
//!   machine's with the code it shows.
//! - `POST /roots/restore`: the kit restores the world keys wrapped to its
//!   root here (`Vault::restore_world_kit`).
//! - `POST /roots/issue` and `POST /roots/confirm`: a new kit, its pieces to
//!   this caller only, then its confirm by two pieces read back (or one and
//!   the passphrase), which makes its root live here
//!   (`Vault::issue_world_kit`, `Vault::confirm_world_kit`).
//!
//! Each is a kit call under the recipient rule of its parent: it names its
//! `target`, this install, before any kit is read, and a hosted install takes
//! none. A kit this install cannot verify takes `fingerprint` or
//! `confirm_root`, as the commands' flags. The answer is the target's report
//! and its words, as a root request's run answers them. A pin and the roots
//! this install sees carry no kit (`root_routes`).

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::EntityId;
use oneiron::authority::RecoveryRootId;
use oneiron::recovery::{KitIssue, PassphraseCost, PieceHome};
use oneiron::world_keys::{KitConfirmation, RootWorkDone};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::super::machine_routes::parse_revision;
use super::super::{OwnerReply, OwnerRoute, OwnerTable, blocking, owner};
use super::{
    Kit, OwnerDevice, RootWorkAnswer, issue_homes, kit_target, passphrase_of, request_code,
    vault_id,
};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::pairing::MachineEnrolment;
use crate::auth::CoreAuth;
use crate::owner::{OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "post",
                path: "/roots/anchor",
                summary: "The named target's own call: the bound root's kit marks the enrolment's machine mine here, with the 26-symbol code a new machine shows; fingerprint or confirm_root vouches for a kit this install cannot verify.",
                row: None,
            },
            post(anchor),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/roots/restore",
                summary: "The named target's own call: the kit restores the world keys wrapped to its root on this install; fingerprint or confirm_root vouches for a kit this install cannot verify.",
                row: None,
            },
            post(restore),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/roots/issue",
                summary: "The named target's own call: issues a world kit over three homes, its pieces in this answer alone; nothing is published until confirm.",
                row: None,
            },
            post(issue),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/roots/confirm",
                summary: "The named target's own call: two pieces of the pending kit (or one and the passphrase) confirm it, and its root goes live here, carrying the machines named.",
                row: None,
            },
            post(confirm),
        ),
    ]
}

/// What vouches for a kit this install cannot verify: `fingerprint`, read on
/// one of the owner's machines that pins its root, or `confirm_root`, his
/// go-ahead bound to the root a refusal showed him. Each 64 hex; a
/// fingerprint is read first.
fn confirmation(
    fingerprint: Option<&str>,
    confirm_root: Option<&str>,
) -> OwnerResult<Option<KitConfirmation>> {
    if let Some(text) = fingerprint {
        let root = RecoveryRootId(parse_revision("fingerprint", text)?);
        return Ok(Some(KitConfirmation::Fingerprint(root)));
    }
    confirm_root
        .map(|text| parse_revision("confirm_root", text).map(RecoveryRootId))
        .transpose()
        .map(|root| root.map(KitConfirmation::Owner))
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct AnchorDoor {
    /// The install this call's kit is for, 32 hex: this one.
    target: String,
    /// The bound root's kit: its pieces as recovery codes, and the
    /// passphrase where one point is the passphrase.
    pieces: Vec<String>,
    #[serde(default)]
    passphrase: Option<String>,
    /// The machine's enrolment request, as `POST /v1/pairing/redeem` takes it.
    enrolment: Box<MachineEnrolment>,
    /// The code that machine shows when it is not this one, its 26 base32
    /// symbols.
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    confirm_root: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RestoreDoor {
    target: String,
    pieces: Vec<String>,
    #[serde(default)]
    passphrase: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    confirm_root: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct IssueDoor {
    target: String,
    /// One home per piece, in point order.
    homes: [PieceHome; 3],
    /// With a `passphrase` home.
    #[serde(default)]
    passphrase: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ConfirmDoor {
    target: String,
    pieces: Vec<String>,
    #[serde(default)]
    passphrase: Option<String>,
    /// On a reissue: other machines of the owner's under the old pin to
    /// mark his under the new root, 32 hex each.
    #[serde(default)]
    carry: Vec<String>,
}

/// `POST /v1/owner/roots/anchor`: marks the enrolment's machine mine under
/// the kit's root. This install's own request pins that root here and
/// re-wraps its keys; a new machine's request needs its code, and the root
/// must be this install's pin, which stays.
async fn anchor(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    _: OwnerDevice,
    payload: OwnerJsonBody<AnchorDoor>,
) -> OwnerReply<RootWorkAnswer> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
    kit_target(&server, &body.target)?;
    let request = body.enrolment.request()?;
    let answer = blocking(move || -> OwnerResult<RootWorkAnswer> {
        let vault = server.vault();
        let confirm = confirmation(body.fingerprint.as_deref(), body.confirm_root.as_deref())?;
        let code = body.code.as_deref().map(request_code).transpose()?;
        let seed = Kit::parse(body.pieces, body.passphrase)?.seed(vault)?;
        let anchored = vault.anchor_machine(&owner, &seed, &request, code, confirm)?;
        Ok(RootWorkAnswer::of(
            vault,
            RootWorkDone::Anchored(Box::new(anchored)),
        ))
    })
    .await?;
    Ok(Json(answer))
}

/// How long a kit restore waits on its best-effort authority catch-up
/// (FIX 11406) before it goes on without it.
const KIT_RESTORE_CATCH_UP: std::time::Duration = std::time::Duration::from_secs(10);

/// `POST /v1/owner/roots/restore`: opens the world keys wrapped to the kit's
/// root on this install. No world's setting changes; a kit this vault still
/// lists as pending is refused, for `confirm`.
async fn restore(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    _: OwnerDevice,
    payload: OwnerJsonBody<RestoreDoor>,
) -> OwnerReply<RootWorkAnswer> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
    kit_target(&server, &body.target)?;
    // FIX 11406: a best-effort authority catch-up, so the seed gate sees a
    // kit root peers already carry. No machine, no live connection, an error
    // or a stall past KIT_RESTORE_CATCH_UP leaves the restore as before.
    let vault = Arc::clone(&server.vault);
    let me = blocking(move || Ok(vault.local_machine()?.map(|machine| machine.id)))
        .await
        .ok()
        .flatten();
    if let Some(me) = me
        && let Some(connection) = crate::residence_machines::connection(&me)
    {
        match tokio::time::timeout(KIT_RESTORE_CATCH_UP, connection.catch_up_authority()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                tracing::debug!(error = %format!("{error:#}"), "kit restore authority catch-up skipped");
            }
            Err(_) => tracing::debug!("kit restore authority catch-up timed out"),
        }
    }
    let answer = blocking(move || -> OwnerResult<RootWorkAnswer> {
        let vault = server.vault();
        let confirm = confirmation(body.fingerprint.as_deref(), body.confirm_root.as_deref())?;
        let kit = Kit::parse(body.pieces, body.passphrase)?;
        let pieces = kit.pieces();
        let restored =
            vault.restore_world_kit(&owner, &pieces, kit.passphrase.as_ref(), confirm)?;
        Ok(RootWorkAnswer::of(
            vault,
            RootWorkDone::KitRestored(Box::new(restored)),
        ))
    })
    .await?;
    Ok(Json(answer))
}

/// `POST /v1/owner/roots/issue`: a new world kit over the homes, its pieces
/// in this answer alone. Nothing is published until `confirm`.
async fn issue(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    _: OwnerDevice,
    payload: OwnerJsonBody<IssueDoor>,
) -> OwnerReply<RootWorkAnswer> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
    kit_target(&server, &body.target)?;
    let answer = blocking(move || -> OwnerResult<RootWorkAnswer> {
        let vault = server.vault();
        issue_homes(&body.homes)?;
        let passphrase = Zeroizing::new(body.passphrase);
        let passphrase = passphrase.as_deref().map(passphrase_of).transpose()?;
        let issued = vault.issue_world_kit(
            &owner,
            &KitIssue {
                vault_id: vault_id(vault)?,
                homes: body.homes,
                passphrase: passphrase.as_ref(),
                cost: PassphraseCost::DEFAULT,
                only_machine: false,
            },
        )?;
        Ok(RootWorkAnswer::of(
            vault,
            RootWorkDone::KitIssued(Box::new(issued)),
        ))
    })
    .await?;
    Ok(Json(answer))
}

/// `POST /v1/owner/roots/confirm`: confirms the pending kit its pieces
/// rebuild; its root goes live here and the vault key gets its `world-kit`
/// escrow wrap.
async fn confirm(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    _: OwnerDevice,
    payload: OwnerJsonBody<ConfirmDoor>,
) -> OwnerReply<RootWorkAnswer> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
    kit_target(&server, &body.target)?;
    let answer = blocking(move || -> OwnerResult<RootWorkAnswer> {
        let vault = server.vault();
        let carry = body
            .carry
            .iter()
            .map(|machine| entity_id("carry", machine))
            .collect::<OwnerResult<BTreeSet<EntityId>>>()?;
        let kit = Kit::parse(body.pieces, body.passphrase)?;
        let pieces = kit.pieces();
        let confirmed =
            vault.confirm_world_kit(&owner, &pieces, kit.passphrase.as_ref(), &carry)?;
        Ok(RootWorkAnswer::of(
            vault,
            RootWorkDone::KitConfirmed {
                kit: Box::new(confirmed),
                mirror_pending: false,
            },
        ))
    })
    .await?;
    Ok(Json(answer))
}

/// The OpenAPI schema of `POST /v1/owner/roots/anchor`'s body (FIX 11611):
/// [`AnchorDoor`].
pub(crate) fn anchor_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<AnchorDoor>()
}

/// The OpenAPI schema of `POST /v1/owner/roots/restore`'s body (FIX 11611):
/// [`RestoreDoor`].
pub(crate) fn restore_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RestoreDoor>()
}

/// The OpenAPI schema of `POST /v1/owner/roots/issue`'s body (FIX 11611):
/// [`IssueDoor`].
pub(crate) fn issue_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<IssueDoor>()
}

/// The OpenAPI schema of `POST /v1/owner/roots/confirm`'s body (FIX 11611):
/// [`ConfirmDoor`].
pub(crate) fn confirm_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ConfirmDoor>()
}
