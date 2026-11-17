//! `POST /v1/owner/recovery-box/cancel`: an owner device's Cancel of the
//! release pending at the recovery box during its wait
//! (WAYBACK-BOX-WAIT-ENGINE-HOLD-ONE-WAIT = A; any owner of the vault may
//! cancel, WAYBACK-COOWNER-CANCEL-OTHER-OWNERS-RECOVERY = B).
//!
//! The owner's device signs the Cancel with its own live owner key
//! (`Vault::sign_recovery_box_cancel_as`) and sends the proof here. The
//! route passes `owner()` first, so a hosted operator's root acts as nobody
//! and an agent never reaches the act. The engine then checks the proof on
//! this node's fold (`Vault::cancel_box_recovery_as`): its person is the
//! owner this request proves, its key is that owner's own live owner key and
//! never the root's authority kind, its signature verifies for this vault,
//! and it was signed within five minutes of this node's clock. Only then
//! does the Cancel go to the box through the supervisor relay, naming who
//! cancelled. Sign-in alone cannot cancel. Nothing is written on this node.
//! A self-hosted vault has no box, so a proof it admits answers
//! `cancelled: false`.
//!
//! The wire form is the owner-key enrolment routes': a person as 32 hex, a
//! key as 64 lower-case hex, a signature as 128 lower-case hex.

use std::cell::Cell;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::post;
use oneiron::authority::{ActAuthority, RecoveryBoxCancelProof};
use oneiron::error::RecordError;
use oneiron::world_keys::{NoRecoveryBox, RecoveryBoxCanceller, RecoveryBoxHold};
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface_admitted, parse_revision};
use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::error::{ApiError, ApiErrorDetails};
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

/// The state of the conflict a Cancel answers when it did not reach the box
/// or the box's answer was lost.
const BOX_UNREACHABLE_STATE: &str = "recovery_box_unreachable";

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/recovery-box/cancel",
            summary: "An owner device's signed cancel of the release pending at the recovery box during its wait: the node checks the proof on its own fold, then asks the box. Answers cancelled true, or false when no release was pending.",
            row: None,
            shape: Some(
                RestShape::json(cancel_body_schema, cancel_reply_schema).refusing(&[
                    (
                        "400",
                        "A field is not in its wire form (person 32 hex, key 64 lower-case hex, signature 128 lower-case hex), or the body names another field.",
                    ),
                    (
                        "409",
                        "`refused`: the proof is not this owner's own live owner key's, does not verify for this vault, or was signed more than five minutes from this node's clock; nothing reached the box. `recovery_box_unreachable`: the cancel did not reach the box or its answer was lost; send it again.",
                    ),
                ]),
            ),
        },
        post(cancel),
    )]
}

/// An owner device's signed Cancel, as `Vault::sign_recovery_box_cancel_as`
/// made it.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct CancelRequest {
    /// The owner who cancels, as 32 hex: the owner this request proves.
    person: String,
    /// The owner key that signed, as 64 lower-case hex.
    key: String,
    /// When the device signed, in unix seconds on its clock.
    issued_at: u64,
    /// The recovery-started act's receipt this Cancel stops, when the
    /// device read it: the box then voids only that release. Absent or
    /// null: none, as the device signed it.
    #[serde(default)]
    release_receipt: Option<u64>,
    /// The key's Ed25519 signature over the Cancel's transcript, as 128
    /// lower-case hex.
    signature: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct CancelReply {
    /// `true` when the box voided a pending release; `false` when none was
    /// pending, or this vault has no box.
    cancelled: bool,
}

/// The OpenAPI schema of `POST /v1/owner/recovery-box/cancel`'s body:
/// [`CancelRequest`].
fn cancel_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<CancelRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/recovery-box/cancel`'s answer:
/// [`CancelReply`].
fn cancel_reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<CancelReply>()
}

/// A signature as the client sent it: 128 lower-case hex.
fn parse_signature(value: &str) -> OwnerResult<Vec<u8>> {
    oneiron_hex::decode::<64>(value)
        .map(Vec::from)
        .ok_or_else(|| {
            OwnerError::Invalid(
                "signature must be 128 lower-case hex: the owner key's signature over the cancel"
                    .to_owned(),
            )
        })
}

/// The engine's typed refusal of a proof as the owner's, with its words:
/// nothing reached the box. Anything else stays the engine's.
fn refusal(error: oneiron::Error) -> OwnerError {
    match &error {
        oneiron::Error::Record(RecordError::AuthorityRefused(_)) => {
            OwnerError::Refused(error.to_string())
        }
        _ => OwnerError::Engine(Box::new(error)),
    }
}

/// What the route answers when the Cancel went to the box and failed there:
/// it did not reach the box, or the box's answer was lost, so whether it
/// cancelled is unknown. The same Cancel can go again: a box that already
/// voided the release answers that none is pending.
fn box_unreachable() -> ApiError {
    ApiError::new(
        "the cancel did not reach the recovery box, or its answer was lost; whether it cancelled is unknown",
        ApiErrorDetails::InvalidState {
            state: Some(BOX_UNREACHABLE_STATE.to_owned()),
        },
        [
            "Send the cancel again within five minutes of signing it, or sign a new one; a box that already cancelled answers cancelled false.",
        ],
    )
}

/// The box seam a Cancel goes through: the vault's hold, remembering
/// whether the Cancel went to the box and failed there, which the engine's
/// error alone does not tell from a store failure.
struct CancelThroughBox<'a> {
    hold: &'a dyn RecoveryBoxHold,
    failed: Cell<bool>,
}

impl RecoveryBoxHold for CancelThroughBox<'_> {
    fn hold_kit_only(&self, kit_only: bool) -> oneiron::Result<()> {
        self.hold.hold_kit_only(kit_only)
    }

    fn report_recovery_wait(&self, wait: Duration) -> oneiron::Result<()> {
        self.hold.report_recovery_wait(wait)
    }

    fn cancel_pending_box_release(
        &self,
        cancelled_by: &RecoveryBoxCanceller,
        release_receipt: Option<u64>,
    ) -> oneiron::Result<bool> {
        let answer = self
            .hold
            .cancel_pending_box_release(cancelled_by, release_receipt);
        self.failed.set(answer.is_err());
        answer
    }
}

/// What one Cancel came to.
enum CancelOutcome {
    /// The box answered: whether it voided a pending release.
    Answered(bool),
    /// The Cancel went to the box and failed there.
    BoxUnreachable,
}

/// `POST /v1/owner/recovery-box/cancel`: checks the owner device's signed
/// Cancel on this node's fold, then asks the box to void the release
/// pending there.
async fn cancel(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<CancelRequest>,
) -> OwnerReply<CancelReply> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let body = payload.read(&server).await?;
    let outcome = blocking(move || -> OwnerResult<CancelOutcome> {
        let proof = RecoveryBoxCancelProof {
            person: entity_id("person", &body.person)?,
            key: parse_revision("key", &body.key)?,
            issued_at: body.issued_at,
            release_receipt: body.release_receipt,
            signature: parse_signature(&body.signature)?,
        };
        // A hosted vault's box answers through the supervisor relay; a
        // self-hosted vault has no box.
        let hold: &dyn RecoveryBoxHold = match server.recovery_box_hold() {
            Some(hold) => hold,
            None => &NoRecoveryBox,
        };
        let seam = CancelThroughBox {
            hold,
            failed: Cell::new(false),
        };
        let authority = ActAuthority::Owner(owner, surface);
        match server
            .vault()
            .cancel_box_recovery_as(&authority, &proof, &seam)
        {
            Ok(cancelled) => Ok(CancelOutcome::Answered(cancelled)),
            Err(error) if seam.failed.get() => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "an owner's recovery box cancel did not reach the box, or its answer was lost"
                );
                Ok(CancelOutcome::BoxUnreachable)
            }
            Err(error) => Err(refusal(error)),
        }
    })
    .await?;
    match outcome {
        CancelOutcome::Answered(cancelled) => Ok(Json(CancelReply { cancelled })),
        CancelOutcome::BoxUnreachable => Err(box_unreachable().into()),
    }
}
