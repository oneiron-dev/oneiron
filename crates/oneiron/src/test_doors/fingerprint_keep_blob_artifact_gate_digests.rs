//! K-proof door for blob-artifact and Gate digests that existing rows, keys and
//! bindings hold. Compiled only under `oneiron_test_support`; never part of the
//! engine API.
#![cfg(oneiron_test_support)]

use crate::blob_artifact::esign::{EsignOutboundVerb, EsignQrCapability};
use crate::genui::GrantMintIntent;
use crate::store::verb_invocation::InvocationId;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Result, Vault, gate};

/// The retry key a no-key e-sign call of `verb` derives from `invocation`.
#[must_use]
pub fn esign_no_key_call_key(
    verb: EsignOutboundVerb,
    document: EntityId,
    actor: EntityId,
    on_behalf_of: Option<&str>,
    invocation: InvocationId,
) -> String {
    verb.no_key_call_key_for_test(document, actor, on_behalf_of, invocation)
}

/// The SHA-256 a read of a sealed PDF compares with its seal's.
#[must_use]
pub fn sealed_pdf_sha256(bytes: &[u8]) -> [u8; 32] {
    Vault::esign_sealed_pdf_sha256_for_test(bytes)
}

/// The digest that keys a QR capability's token row.
#[must_use]
pub fn esign_qr_capability_digest(token: &EsignQrCapability) -> [u8; 32] {
    token.digest_for_test()
}

/// The id of `recipient`'s signature image `canonical` on `document`.
///
/// # Errors
/// The digest names a reserved id.
pub fn esign_signature_image_id(
    document: EntityId,
    recipient: &str,
    canonical: &[u8],
) -> Result<EntityId> {
    Vault::esign_signature_image_id_for_test(document, recipient, canonical)
}

/// The binding a standing outbound grant `intent` mints.
///
/// # Errors
/// `intent`'s scope is not a standing outbound one.
pub fn standing_outbound_grant_binding(intent: &GrantMintIntent) -> Result<[u8; 32]> {
    gate::standing_outbound_grant_binding_for_test(intent)
}

/// The binding of the MESSAGE write `actor` presents with `body`.
#[must_use]
pub fn witness_message_binding(actor: WriteActor, body: &[u8]) -> [u8; 32] {
    gate::witness_message_binding_for_test(actor, body)
}
