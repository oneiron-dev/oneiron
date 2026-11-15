//! Doors for `tests/guest_turn_counterparty.rs` (fix list row 15412, slice
//! 3b): admit one peer TURN row through the federated admission an import
//! runs (Imported grading), and answer the body that would land. A thin
//! wrapper over the production admission only. Compiled only under
//! `--cfg oneiron_test_support` with the `sync` feature; hidden, never API.

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_TURN;
use crate::vault::Vault;

/// The body a peer's TURN row `body`, sent at `at`, lands with in `vault`
/// after federated admission.
///
/// # Errors
///
/// The admission's refusal, or the vault's.
#[doc(hidden)]
pub fn admitted_peer_turn_body(vault: &Vault, body: &[u8], at: u64) -> Result<Vec<u8>> {
    let mut blob = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    blob.push(ENTITY_TYPE_TURN);
    blob.extend_from_slice(&at.to_be_bytes());
    blob.extend_from_slice(&at.to_be_bytes());
    blob.extend_from_slice(&at.to_be_bytes());
    blob.extend_from_slice(&0_u64.to_be_bytes());
    blob.extend_from_slice(body);
    let txn = vault.store.env.read_txn()?;
    let policy = crate::gate::resolve_policy_manifest(&vault.store, &txn)?;
    let admitted = crate::sync::selector::admit_federated_entity_blob(
        vault,
        &policy,
        &txn,
        &EntityId::now().to_hex(),
        Some(&blob),
    )?;
    Ok(admitted[ENTITY_METADATA_HEADER_LEN..].to_vec())
}
