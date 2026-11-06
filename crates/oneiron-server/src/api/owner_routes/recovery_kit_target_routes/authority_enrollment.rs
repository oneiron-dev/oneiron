//! The owner's explicit pre-loss recovery-key enrollment on the kit's target install.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::post;
use oneiron::authority::ActAuthority;
use oneiron::error::RecordError;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::super::machine_routes::act_surface_admitted;
use super::super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner, owner_error};
use super::{Kit, OwnerDevice, kit_target};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::vault_key::hex;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/recovery-kit/enroll-authority",
            summary: "Before loss: explicitly enroll the recovery kit's distinct authority key on its named target install, with the live owner's act. Issuance and enrollment are separate; the committed receipt does not activate or publish the world kit.",
            row: None,
            shape: Some(RestShape::json(request_schema, receipt_schema)),
        },
        post(enroll),
    )]
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct EnrollRequest {
    target: String,
    /// The holding machine; the target install when omitted.
    #[serde(default)]
    machine: Option<String>,
    pieces: Vec<String>,
    #[serde(default)]
    passphrase: Option<String>,
}

impl Drop for EnrollRequest {
    fn drop(&mut self) {
        self.pieces.zeroize();
        self.passphrase.zeroize();
    }
}

#[derive(Serialize, schemars::JsonSchema)]
struct Receipt {
    entry: String,
    machine: String,
    public_key: String,
}

async fn enroll(
    auth: CoreAuth,
    headers: HeaderMap,
    extensions: Extensions,
    State(server): State<Arc<SyncServer>>,
    _: OwnerDevice,
    payload: OwnerJsonBody<EnrollRequest>,
) -> OwnerReply<Receipt> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let mut body = payload.read(&server).await?;
    kit_target(&server, &body.target)?;
    let named = body
        .machine
        .as_deref()
        .map(|machine| entity_id("machine", machine))
        .transpose()
        .map_err(owner_error)?;
    let machine = crate::owner::recovery_kit::authority_holding_machine(server.vault(), named)
        .map_err(OwnerError::from)
        .map_err(owner_error)?
        .ok_or_else(|| OwnerError::Refused("this install has no machine in the vault".to_owned()))
        .map_err(owner_error)?;
    let receipt = blocking(move || -> OwnerResult<Receipt> {
        let issuer = server.host_issuer().ok_or_else(|| {
            OwnerError::Refused(
                "this host holds no root signing key to authorize an owner key enrollment"
                    .to_owned(),
            )
        })?;
        let kit = Kit::parse(std::mem::take(&mut body.pieces), body.passphrase.take())?;
        let seed = kit.seed(server.vault())?;
        let authority = ActAuthority::Owner(owner, surface);
        let receipt = server
            .vault()
            .enrol_recovery_authority_key_as_host(&authority, machine, &seed, issuer)
            .map_err(refusal)?;
        Ok(Receipt {
            entry: hex(&receipt.entry),
            machine: receipt.machine.to_hex(),
            public_key: hex(&receipt.public_key),
        })
    })
    .await?;
    Ok(Json(receipt))
}

fn refusal(error: oneiron::Error) -> OwnerError {
    match &error {
        oneiron::Error::Record(RecordError::InvalidAuthorityLogBody(_)) => {
            OwnerError::Invalid(error.to_string())
        }
        oneiron::Error::Record(RecordError::AuthorityRefused(_)) => {
            OwnerError::Refused(error.to_string())
        }
        _ => OwnerError::Engine(Box::new(error)),
    }
}

fn request_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<EnrollRequest>()
}

fn receipt_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<Receipt>()
}
