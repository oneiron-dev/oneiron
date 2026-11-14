//! Doors for `tests/own_device_counterparty_replay.rs` (fix list row 15412,
//! review #7537 P1): the own-device replay door's verdict on one MESSAGE
//! body, as a row an own machine wrote and its proven push brought
//! (`gate::validate_own_device_witness_message_body`), and a canonical
//! MESSAGE body in one author bucket. Thin wrappers over production code
//! only. Compiled only under `--cfg oneiron_test_support` (`test_doors`);
//! hidden, never API.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::gate::{WitnessMessageEnvelope, validate_own_device_witness_message_body};
use crate::vault::Vault;

/// The own-device replay door's verdict on `body`, a MESSAGE row `machine`
/// wrote, whose window names no `AuthoredBy` edge, read in one snapshot of
/// `vault`.
///
/// # Errors
///
/// The door's refusal, or the store's.
#[doc(hidden)]
pub fn own_machine_message_replay(vault: &Vault, machine: EntityId, body: &[u8]) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    validate_own_device_witness_message_body(&vault.store, &txn, machine, None, body)
}

/// A canonical, visible MESSAGE body of type `dialogue` in author bucket
/// `author` (`user`, `companion`, `system` or `counterparty`).
///
/// # Errors
///
/// The encoder's, for a bucket or content it refuses.
#[doc(hidden)]
pub fn message_body(author: &str, content: &str) -> Result<Vec<u8>> {
    WitnessMessageEnvelope {
        author,
        message_type: "dialogue",
        content,
        parts: None,
        metadata: None,
        is_visible: true,
        order: 0,
    }
    .encode_body()
}
