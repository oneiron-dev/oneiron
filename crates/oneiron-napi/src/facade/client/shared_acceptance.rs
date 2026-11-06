//! Original-value HTTPS shared invitation acceptance (L14 S58): remote-only.
//!
//! [`NativeSharedAcceptance`] holds the ORIGINAL opaque
//! [`oneiron_remote::HttpsSharedInvitationAcceptance`] from a connected
//! [`oneiron_remote::OneironClient`]'s `accept_shared_invitation_https` or
//! `retry_shared_invitation_https` call, as its `Arc`, never a decoded
//! receipt or token. A receipt record cannot construct this value or supply
//! its provenance. The complete successful reply stays available on it even
//! after member-client creation fails, as the native value keeps it.
//!
//! Unconditional: these are remote-only APIs over `oneiron-remote`, so no
//! `engine` feature is needed. Engine bootstrap and retain live beside the
//! engine (`super::shared_env`, `cfg(engine)`).
//!
//! Inputs follow the existing `NativeClient::retry` template: `js_json`
//! then a typed `serde_json::from_value` decode, with a `BAD_REQUEST`
//! refusal on another shape. No new unsafe-integer input: the acceptance
//! request's `vault_id` is a decimal string on the native wire (a `u64`
//! past 2^53 does not survive a JS number), and `js_json` refuses an
//! unsafe whole number rather than narrowing it lossily.
//!
//! Request and reply outputs are JSON STRINGS from the original serde
//! serialization, never `serde_json::Value`: a large integer does not
//! survive a JS number on the way out either, and `js_json` rewrites
//! inputs only, never returned bodies.

use std::sync::Arc;

use napi_derive::napi;

use super::super::boundary::{boundary_error, facade_error};
use super::super::js_json::js_json;
use super::NativeClient;

/// A successful acceptance on the connected HTTPS home, kept as the native
/// value. Receipt records cannot construct this object or supply its
/// provenance.
#[napi]
pub struct NativeSharedAcceptance {
    inner: Arc<oneiron_remote::HttpsSharedInvitationAcceptance>,
}

impl NativeSharedAcceptance {
    /// The native acceptance, retained as its original value.
    fn from_accepted(accepted: oneiron_remote::HttpsSharedInvitationAcceptance) -> Self {
        Self {
            inner: Arc::new(accepted),
        }
    }

    /// The original acceptance for the engine's bootstrap call: the SAME
    /// `Arc` the native `BlockingEngine::bootstrap_shared_env` takes.
    pub(super) fn inner(&self) -> &Arc<oneiron_remote::HttpsSharedInvitationAcceptance> {
        &self.inner
    }
}

/// The `vault.members.accept_with_credential` input from JavaScript, as the
/// native request reads it: `vault_id` as a decimal string, `invitation`,
/// and the required credential `expires_at`.
fn accept_request(
    value: serde_json::Value,
) -> napi::Result<oneiron::verbs::SharedInvitationAcceptWithCredentialRequest> {
    let value = js_json(value);
    serde_json::from_value(value).map_err(|error| {
        facade_error(oneiron::MemoryError::new(
            oneiron::memory::MEMORY_CODE_BAD_REQUEST,
            format!("the shared acceptance request is not the documented shape: {error}"),
            &["Send {vault_id, invitation, expires_at}; vault_id is a decimal string."],
        ))
    })
}

#[napi]
impl NativeClient {
    /// Accepts the invitee's invitation through this connected handle with
    /// its own holder key, keeping the successful call's original HTTPS
    /// value. Only a connected HTTPS home accepts; any other handle or
    /// admission refusal raises the native `MemoryError`. Keep the returned
    /// object for bootstrap: a decoded receipt is no substitute.
    #[napi]
    pub fn accept_shared_invitation_https(
        &self,
        request: serde_json::Value,
    ) -> napi::Result<NativeSharedAcceptance> {
        let request = accept_request(request)?;
        let accepted = self
            .inner
            .accept_shared_invitation_https(request)
            .map_err(facade_error)?;
        Ok(NativeSharedAcceptance::from_accepted(accepted))
    }

    /// Retries a pending HTTPS acceptance under its original invocation: the
    /// same request with the refusal's pending payload, not a decoded generic
    /// retry reply. `pending` is the `PENDING_ASK` refusal as its serialized
    /// `MemoryError`; its invocation is reused, never fabricated. Only the
    /// native HTTPS call produces the returned object.
    #[napi]
    pub fn retry_shared_invitation_https(
        &self,
        pending: serde_json::Value,
        request: serde_json::Value,
    ) -> napi::Result<NativeSharedAcceptance> {
        let pending = js_json(pending);
        let pending: oneiron::MemoryError = serde_json::from_value(pending).map_err(|error| {
            facade_error(oneiron::MemoryError::new(
                oneiron::memory::MEMORY_CODE_BAD_REQUEST,
                format!("pending is not a serialized refusal: {error}"),
                &["Pass the PENDING_ASK error the call raised, with its hook."],
            ))
        })?;
        let request = accept_request(request)?;
        let accepted = self
            .inner
            .retry_shared_invitation_https(&pending, request)
            .map_err(facade_error)?;
        Ok(NativeSharedAcceptance::from_accepted(accepted))
    }

    /// Retries a pending HTTPS acceptance under its original invocation from
    /// the refusal's JSON text: the same request with the same invocation
    /// reuse, without a JavaScript value pass. `pending_json` is the
    /// `PENDING_ASK` refusal as its original serialized `MemoryError` text,
    /// so full integers parse in Rust. Only the native HTTPS call produces
    /// the returned object.
    #[napi]
    pub fn retry_shared_invitation_https_json(
        &self,
        pending_json: String,
        request: serde_json::Value,
    ) -> napi::Result<NativeSharedAcceptance> {
        let pending: oneiron::MemoryError =
            serde_json::from_str::<oneiron::MemoryError>(&pending_json).map_err(|error| {
                facade_error(oneiron::MemoryError::new(
                    oneiron::memory::MEMORY_CODE_BAD_REQUEST,
                    format!("pending is not a serialized refusal: {error}"),
                    &["Pass the PENDING_ASK error the call raised, with its hook."],
                ))
            })?;
        let request = accept_request(request)?;
        let accepted = self
            .inner
            .retry_shared_invitation_https(&pending, request)
            .map_err(facade_error)?;
        Ok(NativeSharedAcceptance::from_accepted(accepted))
    }
}

#[napi]
impl NativeSharedAcceptance {
    /// The normalized HTTPS home the acceptance selected.
    #[napi]
    pub fn home_url(&self) -> String {
        self.inner.home_url().to_owned()
    }

    /// The exact facade URL the original acceptance used.
    #[napi]
    pub fn acceptance_url(&self) -> String {
        self.inner.acceptance_url().to_owned()
    }

    /// The original acceptance request as JSON text; reading it creates no
    /// new acceptance. A string, so the decimal `vault_id` survives intact.
    #[napi]
    pub fn request_json(&self) -> napi::Result<String> {
        serde_json::to_string(self.inner.request()).map_err(|error| {
            boundary_error(format!("could not encode the acceptance request: {error}"))
        })
    }

    /// The complete original receipt and member credential as JSON text,
    /// available even after member-client creation or native bootstrap
    /// fails. A string, so no integer survives lossily as a JS number.
    #[napi]
    pub fn reply_json(&self) -> napi::Result<String> {
        serde_json::to_string(self.inner.reply()).map_err(|error| {
            boundary_error(format!("could not encode the acceptance reply: {error}"))
        })
    }

    /// A remote member handle on the acceptance's HTTPS home and original
    /// HTTP wire, under its returned member credential. Each request still
    /// passes the home's ordinary admission checks. The acceptance itself is
    /// retained: a malformed returned credential raises here while the
    /// complete reply stays available on this object.
    #[napi]
    pub fn member_client(&self) -> napi::Result<NativeClient> {
        let inner = self.inner.member_client().map_err(facade_error)?;
        Ok(NativeClient { inner, keep: None })
    }
}
