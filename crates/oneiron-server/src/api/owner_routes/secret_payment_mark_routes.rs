//! `/v1/owner/secrets/payment-mark`: the owner says whether one credential is
//! a payment credential (L8-60; CROSS-ARCH-0019 `#fence-unproven`, RULING
//! L8-60-PAYMENT-MARKER = A). On a host whose runner fence is unproven, both
//! value doors withhold a payment credential unless the self-hoster lifted
//! that with `--release-payment-credentials-unfenced`; every other credential
//! stays at its rung. Until the owner answers, the credential's label hint
//! pre-fills the mark (a key a scan found as a Stripe key pays); `null`
//! clears his answer back to the hint. The engine checks the owner's proof
//! again in its transaction and keeps the act in a Gate record. An owner
//! act: no agent grant reaches it.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::secret_custody::SecretPaymentMarkSet;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/secrets/payment-mark",
            summary: "The owner says whether one credential is a payment credential (L8-60): `payment` true or false, or null to fall back to its label hint. On a host whose runner fence is unproven, a payment credential is withheld at both value doors (`payment_credential_withheld`) unless the self-hoster lifted that; every other credential stays at its rung.",
            row: None,
            shape: Some(
                RestShape::json(payment_mark_body_schema, payment_mark_reply_schema)
                    .refusing(&[("404", "No custody record has this id.")]),
            ),
        },
        post(set_payment_mark),
    )]
}

/// The owner's payment mark on one credential.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PaymentMarkBody {
    /// The custody record's id, 32 hex, as `GET /v1/owner/secrets/custody`
    /// names it.
    secret_id: String,
    /// `true`: a payment credential; `false`: not one; `null`: the owner's
    /// answer is cleared and the label hint answers.
    payment: Option<bool>,
}

/// Where the credential's payment mark stands after the act.
#[derive(Serialize, schemars::JsonSchema)]
struct PaymentMarkReply {
    /// The owner's stored answer; `null` once cleared.
    marked: Option<bool>,
    /// What the credential's label hint says: a scanned Stripe key pays.
    suggested: bool,
    /// Whether the value doors treat it as a payment credential now: the
    /// owner's answer, else the hint.
    payment: bool,
    /// The act's Gate receipt.
    receipt: String,
}

impl From<SecretPaymentMarkSet> for PaymentMarkReply {
    fn from(set: SecretPaymentMarkSet) -> Self {
        Self {
            marked: set.marked,
            suggested: set.suggested,
            payment: set.payment,
            receipt: set.receipt,
        }
    }
}

/// The OpenAPI schema of `POST /v1/owner/secrets/payment-mark`'s body:
/// [`PaymentMarkBody`].
fn payment_mark_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PaymentMarkBody>()
}

/// The OpenAPI schema of `POST /v1/owner/secrets/payment-mark`'s answer:
/// [`PaymentMarkReply`].
fn payment_mark_reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PaymentMarkReply>()
}

/// `POST /v1/owner/secrets/payment-mark`: the owner's payment mark on one
/// credential, and where it stands.
async fn set_payment_mark(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PaymentMarkBody>,
) -> OwnerReply<PaymentMarkReply> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
    let set = blocking(move || -> OwnerResult<SecretPaymentMarkSet> {
        let secret = entity_id("secret_id", &body.secret_id)?;
        Ok(server
            .vault()
            .set_secret_payment_mark(&owner, &secret, body.payment)?)
    })
    .await?;
    Ok(Json(set.into()))
}
