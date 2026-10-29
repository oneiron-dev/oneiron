//! The client's own seal for `vault.secrets.custody.submit` (FIX 11441):
//! the input sealed to the holder on the caller's own side, under the
//! binding `vault.secrets.custody.get` answered, by the door's own seal, so
//! no plaintext goes to the server just to be sealed. No vault is opened and
//! no call is made.

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use oneiron::MemoryError;
use oneiron::authority::CustodyChange;
use oneiron::task_verb::sdk::{SecretCustodyViewReply, seal_custody_submit as engine_seal};

use super::boundary::{boundary_error, facade_error};
use super::js_json::js_json;

/// Seals a custody register or rotate on the caller's own side, as the Rust
/// [`engine_seal`] does: `view` is what `vault.secrets.custody.get`
/// answered, `change` is `register` or `rotate`, `holder` the candidate the
/// input is sealed to (the view's own install when null), `recipients` the
/// candidates permitted to hold the bytes (the holder alone when empty) and
/// `body` a register's whole record or a rotate's new value. Answers the
/// `vault.secrets.custody.submit` input that carries it.
#[napi]
pub fn seal_custody_submit(
    view: serde_json::Value,
    change: String,
    holder: Option<String>,
    recipients: Vec<String>,
    body: Buffer,
) -> napi::Result<serde_json::Value> {
    let view: SecretCustodyViewReply = serde_json::from_value(js_json(view)).map_err(|error| {
        facade_error(MemoryError::bad_request(format!(
            "the custody view is not the documented shape: {error}"
        )))
    })?;
    let change = CustodyChange::from_name(&change)
        .filter(|change| matches!(change, CustodyChange::Register | CustodyChange::Rotate))
        .ok_or_else(|| {
            facade_error(MemoryError::bad_request("change must be register or rotate"))
        })?;
    let sealed =
        engine_seal(&view, change, holder.as_deref(), &recipients, None, body.as_ref())
            .map_err(facade_error)?;
    serde_json::to_value(sealed)
        .map_err(|error| boundary_error(format!("could not serialize the sealed input: {error}")))
}
