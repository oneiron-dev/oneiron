//! A surface's own seal of a custody input (WILL L04 row 04, FIX 4993): the
//! bytes a register or rotate the owner's surface sealed carries to
//! `POST /v1/owner/secrets/custody` or `vault.secrets.custody.submit`, so
//! no console hands this install the plaintext just to authorize.
//!
//! It is the door's own seal, not a second one: the binding the custody
//! view gave the surface goes into [`InputBinding`] field for field, and
//! [`InputBinding::seal`] writes one envelope, or the frame of numbered
//! envelopes for a body past one envelope's bound (`super::envelopes`).
//! Nothing here reads a vault, so a client seals on its own side.

use oneiron_crypto::HybridPublicKey;

use super::{InputBinding, refused};
use crate::authority::{CustodyChange, CustodyRecipientPermit};
use crate::entity_id::EntityId;
use crate::error::Result;

/// What a surface binds a custody input to: the vault, secret id,
/// generation and custody revision its custody view read, the change it
/// asks, the holder it seals to and every permit it gives, ascending by
/// machine, exactly as the request it sends states them.
#[derive(Debug, Clone, Copy)]
pub struct CustodyInputBinding<'a> {
    pub vault_id: [u8; 32],
    pub secret_id: EntityId,
    pub change: CustodyChange,
    /// The generation the change approves.
    pub generation: u32,
    /// The custody revision the surface read.
    pub seen: [u8; 32],
    pub holder: EntityId,
    pub permits: &'a [CustodyRecipientPermit],
}

/// Seals `body` to the holder's encryption key, its public bytes as the
/// custody view lists them (`holder_key`), under `binding`: a register's
/// record body (`encode_secret_custody_body`) or a rotate's new value. No
/// length refuses it but the envelope codec's own bounds (FIX 5521).
///
/// # Errors
/// A key that does not import as the holder's encryption key; a body past
/// the frame's codec bounds; a seal that fails.
pub fn seal_custody_input(
    binding: &CustodyInputBinding<'_>,
    holder_key: &[u8],
    body: &[u8],
) -> Result<Vec<u8>> {
    let key = HybridPublicKey::from_bytes(holder_key)
        .map_err(|_| refused("the holder's encryption key does not import"))?;
    InputBinding {
        vault_id: binding.vault_id,
        id: binding.secret_id,
        change: binding.change,
        generation: binding.generation,
        seen: binding.seen,
        holder: binding.holder,
        permits: binding.permits,
    }
    .seal(&key, body)
}
