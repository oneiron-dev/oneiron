//! Lost-owner recovery: the enrolled kit key authenticates; the device is only a target.

use std::io::BufReader;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::post;
use oneiron::authority::AuthorityVaultId;
use oneiron::error::RecordError;
use oneiron::recovery::KitSecretKind;
use serde::Deserialize;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::super::blocking;
use super::{Kit, OwnerDevice};
use crate::api::transfer::{self, BodyReader};
use crate::error::{ApiError, EnvelopedApiError};
use crate::owner::recovery_kit::authority_recovery::{DeviceAuthorityInput, RecoveryReceipt};
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

/// Bounds each queued read, not the body's length, as the existing transient readers do.
const BODY_PIECE: usize = 64 * 1024;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/v1/recovery/owner-authority", post(recover))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoverRequest {
    /// The actual authority vault id, not a mirror or data-key identity.
    target: String,
    new_device: DeviceAuthorityInput,
    kit: KitInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KitInput {
    pieces: Vec<KitText>,
    #[serde(default)]
    passphrase: Option<KitText>,
}

/// Each decoded field owns its wipe even if the surrounding JSON never finishes.
struct KitText(Zeroizing<String>);

impl<'de> Deserialize<'de> for KitText {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|text| Self(Zeroizing::new(text)))
    }
}

impl KitText {
    fn into_string(mut self) -> String {
        std::mem::take(&mut *self.0)
    }
}

async fn recover(
    _: OwnerDevice,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<RecoveryReceipt>, EnvelopedApiError> {
    if !crate::api::has_json_content_type(&headers) {
        return Err(ApiError::bad_request("invalid JSON request body", None).into());
    }
    let input = read_input(body).await?;
    let receipt = blocking(move || -> OwnerResult<RecoveryReceipt> {
        let target = authority_vault_id(&input.target)?;
        let actual = server.vault().authority_fold()?.vault_id;
        if actual != Some(target) {
            return Err(OwnerError::Invalid(
                "target must match this vault's actual authority vault id".to_owned(),
            ));
        }
        let new_device = input.new_device.into_native()?;
        let kit = Kit::parse(
            input
                .kit
                .pieces
                .into_iter()
                .map(KitText::into_string)
                .collect(),
            input.kit.passphrase.map(KitText::into_string),
        )?;
        let secret = server
            .vault()
            .restore_kit_here(
                target,
                KitSecretKind::RecoveryRoot,
                &kit.pieces(),
                kit.passphrase.as_ref(),
            )
            .map_err(|error| OwnerError::Invalid(format!("the kit does not open: {error}")))?;
        let entry = server
            .vault()
            .recover_owner_authority_from_kit(secret, new_device)
            .map_err(refusal)?;
        RecoveryReceipt::committed(&entry)
    })
    .await?;
    Ok(Json(receipt))
}

fn authority_vault_id(text: &str) -> OwnerResult<AuthorityVaultId> {
    let malformed = || OwnerError::Invalid("target must be a 64-hex authority vault id".to_owned());
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(malformed());
    }
    let mut id = [0; 32];
    for (at, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * at..2 * at + 2], 16).map_err(|_| malformed())?;
    }
    Ok(id)
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

/// The existing transient-reader pattern: no disk spool, body-length cap or new timer.
async fn read_input(body: Body) -> Result<RecoverRequest, ApiError> {
    let (sender, receiver) = mpsc::channel(2);
    let mut worker =
        transfer::spawn_worker(move || -> Result<RecoverRequest, serde_json::Error> {
            let mut json =
                serde_json::Deserializer::from_reader(BufReader::new(BodyReader::new(receiver)));
            let input = RecoverRequest::deserialize(&mut json)?;
            json.end()?;
            Ok(input)
        });
    let early = tokio::select! {
        biased;
        joined = &mut worker => Some(joined),
        () = transfer::feed_body_untimed(body, sender, BODY_PIECE) => None,
    };
    let joined = match early {
        Some(joined) => joined,
        None => worker.await,
    };
    match joined {
        Ok(Ok(input)) => Ok(input),
        Ok(Err(error)) if !error.is_io() => {
            Err(ApiError::bad_request("invalid JSON request body", None))
        }
        Ok(Err(_)) | Err(_) => Err(ApiError::bad_request(
            "the request body did not arrive whole",
            None,
        )),
    }
}
