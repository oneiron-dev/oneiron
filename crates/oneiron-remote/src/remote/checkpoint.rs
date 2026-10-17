//! A pinned authority checkpoint's image and attestations (OF-469), over the
//! server route `GET /v1/core/authority/checkpoints/{id}`.
//!
//! A transport helper, not a verb: the route sits outside the facade nest. A
//! device pairs with [`OneironClient::pair_pinned`], keeps the pin it returns
//! apart from the credential, connects, and fetches the image the pin names
//! with [`OneironClient::pinned_authority_checkpoint`], which checks the image
//! and attestations against the pin before handing them back. The caller then
//! adopts them into its own vault (`Vault::adopt_authority_checkpoint`). An
//! embedded handle refuses: its vault is the one that would adopt.

use oneiron::authority::{
    AUTHORITY_CHECKPOINT_V2_MAX_BYTES, AuthorityCheckpointBundle, AuthorityCheckpointPin,
    VerifiedAuthorityCheckpoint,
};

use super::*;
use crate::{Backend, OneironClient};

/// Path prefix the kept checkpoint images hang off.
const CHECKPOINTS_PREFIX: &str = "v1/core/authority/checkpoints";

/// A bundle's success-body ceiling: the largest image as base64 (four bytes
/// per three), with room for its attestations.
const MAX_BUNDLE_RESPONSE_BYTES: usize = AUTHORITY_CHECKPOINT_V2_MAX_BYTES / 3 * 4 + (16 << 20);

fn hex_id(id: &[u8; 32]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl RemoteClient {
    /// `GET /v1/core/authority/checkpoints/{id}` under this handle's
    /// credential, on the export agent's long timeout.
    fn authority_checkpoint_bundle(
        &self,
        id: &[u8; 32],
    ) -> Result<AuthorityCheckpointBundle, MemoryError> {
        let url = self
            .base_url
            .join(&format!("{CHECKPOINTS_PREFIX}/{}", hex_id(id)))
            .map_err(|error| {
                transport_error(format!("could not build the checkpoint URL: {error}"))
            })?;
        let response = self
            .export_agent
            .get(url)
            .headers(self.credential_headers()?)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .send()
            .map_err(|error| transport_error(describe_send_failure(&error)))?;
        let status = response.status();
        if !status.is_success() {
            return Err(read_error_envelope(response, status));
        }
        let bytes =
            read_capped(response, MAX_BUNDLE_RESPONSE_BYTES).map_err(|failure| match failure {
                ReadFailure::TooLarge => transport_error(format!(
                    "the server's checkpoint exceeded the {MAX_BUNDLE_RESPONSE_BYTES}-byte read ceiling"
                )),
                ReadFailure::Io(message) => {
                    transport_error(format!("the server's checkpoint was truncated: {message}"))
                }
            })?;
        serde_json::from_slice(&bytes).map_err(|error| {
            transport_error(format!(
                "the server answered {status} for a checkpoint with a body this call could not decode: {error}"
            ))
        })
    }
}

/// An embedded handle's answer: the checkpoint comes from the server a
/// pairing named.
fn embedded_refusal() -> MemoryError {
    bad_request(
        "an authority checkpoint is fetched from the server that paired this device",
        &["Connect to that server with the credential pair_pinned returned."],
    )
}

impl OneironClient {
    /// The authority checkpoint image the server keeps at `id` and the
    /// attestations it stores for it, unverified. An id the server keeps no
    /// image at refuses `NOT_FOUND`; an embedded handle refuses
    /// `BAD_REQUEST`.
    pub fn authority_checkpoint_bundle(
        &self,
        id: &[u8; 32],
    ) -> Result<AuthorityCheckpointBundle, MemoryError> {
        match &self.backend {
            Backend::Remote(remote) => remote.authority_checkpoint_bundle(id),
            Backend::Embedded(_) => Err(embedded_refusal()),
        }
    }

    /// The image `pin` names (the pin [`Self::pair_pinned`] returned) and the
    /// attestations made with the pin's own key bindings, checked against the
    /// pin: the image's id, genesis and policy, and the pinned quorum of
    /// dual-signed attestations. A server whose checkpoint does not verify
    /// refuses. The caller adopts what this returns.
    pub fn pinned_authority_checkpoint(
        &self,
        pin: &AuthorityCheckpointPin,
    ) -> Result<AuthorityCheckpointBundle, MemoryError> {
        let mut bundle = self.authority_checkpoint_bundle(&pin.checkpoint)?;
        bundle.attestations.retain(|attestation| {
            pin.binding(&attestation.binding.root) == Some(&attestation.binding)
        });
        VerifiedAuthorityCheckpoint::verify(pin, &bundle.image, &bundle.attestations).map_err(
            |_| {
                transport_error(
                    "the server's checkpoint does not verify against the pairing pin; pair again with a link from the owner",
                )
            },
        )?;
        Ok(bundle)
    }
}
