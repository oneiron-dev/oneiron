//! A delegated reader's credential on an embedded handle (FIX 647): the
//! verified slip the server's HTTP door binds to its handle
//! (`Memory::with_read_proof`), verified here against the handle's own vault,
//! so every read the handle runs reads under that slip's key, as a served
//! request's does.
//!
//! The credential is the one `pair` returns: the slip and its connection key.
//! The key signs one fresh holder proof here, and the vault checks it through
//! the read-only door the server checks a request's proof through
//! (`Vault::verify_logged_capability_slip_request`). The key is used for that
//! call only and never kept.

use ed25519_dalek::Signer;
use oneiron::authority::{CapabilitySlip, VerifiedSlip, holder_proof_challenge};
use oneiron::memory::MemoryError;
use oneiron::{EntityId, Vault};

use crate::error::bad_request;

/// Verifies the paired credential `key` a delegated reader presented against
/// `vault`, for a handle on it to read under ([`crate::OneironClient::with_read_credential`]).
///
/// # Errors
///
/// `BAD_REQUEST` for a key that is not a paired credential, and the engine's
/// refusal for a slip this vault does not verify now. A one-shot slip binds
/// no handle: a handle reads under it more than once, as a served request
/// may.
pub fn verify_read_credential(vault: &Vault, key: &str) -> Result<VerifiedSlip, MemoryError> {
    let not_paired = || {
        bad_request(
            "a read credential is a paired credential",
            &["Pass the delegated reader's credential exactly as pair returned it."],
        )
    };
    let (bearer, holder) = crate::remote::parse_credential(key)?;
    let holder = holder.ok_or_else(not_paired)?;
    let slip = CapabilitySlip::from_token(&bearer).map_err(|_| not_paired())?;
    let timestamp = crate::unix_seconds_now();
    let nonce = EntityId::now().to_hex();
    let transcript = slip
        .binding_transcript(&holder_proof_challenge(timestamp, &nonce))
        .map_err(MemoryError::from)?;
    let signature = holder.sign(&transcript).to_bytes();
    let verified = vault
        .verify_logged_capability_slip_request(&slip, timestamp, &signature, nonce.as_bytes())
        .map_err(MemoryError::from)?;
    if verified.claims().single_use {
        return Err(bad_request(
            "a one-shot slip cannot bind a handle's reads",
            &["Present a slip minted for repeated use."],
        ));
    }
    Ok(verified)
}
