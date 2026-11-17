//! `POST /sign/fields`: the owner's field editor saves its fields to a
//! signing document still in draft (ARCH-0064 SGN-07; RULING
//! ESIGN-EDITOR-SAVES-DRAFT = A, Engine 15 Nov 13:48). The editor shell
//! mints its caller a draft-fields token beside its computation token
//! (`editor_auth`); only this door admits it, from the request head and
//! before the body is read. The body is the verb's input, read up to the
//! API's request floor (`limits.request_body_bytes`), the bound the facade
//! reads the same verb's body under. The token is then admitted again, its
//! caller's credential re-consulted, and `vault.esign.fields.place` runs
//! through the facade's verb dispatch as that caller: the verb's Grant, lane
//! and project admission, its hooks and its answer's release are the
//! verb's own, and so is every refusal past the token's.
use super::editor_auth::EditorFieldsToken;
use super::*;

/// The one verb this door runs.
const PLACE_FIELDS_VERB: &str = "vault.esign.fields.place";

/// `POST /sign/fields`. A body past the request floor is refused as the
/// facade refuses it; a body that is not JSON is `signing_body_malformed`.
/// The verb's answer is the draft as `vault.esign.fields.place` answers it.
pub(super) async fn place_fields(
    State(server): State<Arc<SyncServer>>,
    token: EditorFieldsToken,
    body: Body,
) -> Response {
    let floor = server.config.limits.request_body_bytes;
    let bytes = match super::ingress::floored_body(body, floor).await {
        Ok(bytes) => bytes,
        Err(refusal) => return refusal,
    };
    let caller = match token.caller(&server) {
        Ok(caller) => caller,
        Err(refusal) => return refusal,
    };
    let Ok(input) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return super::ingress::malformed();
    };
    let call = crate::api::FacadeCall::bound(&caller, None, None, None);
    match crate::api::facade_call_verb(&server, &call, PLACE_FIELDS_VERB, Ok(input)).await {
        Ok(output) => {
            crate::api::facade_released_reply(&server, &caller, PLACE_FIELDS_VERB, output)
        }
        Err(refused) => refused.into_response(),
    }
}
