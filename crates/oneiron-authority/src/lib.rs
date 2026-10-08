//! Authority vocabulary of the oneiron engine: the AUTHORITY_LOG wire layer, the federation
//! scope codecs and the credential-door bounds they share. Depends only on
//! `oneiron-contracts`. `oneiron` re-exports every public item at its old
//! `oneiron::<module>` path; applications depend on `oneiron`, not on this crate.

pub mod authority;
pub mod credential_door;
pub mod federation;

// Contracts vocabulary the moved code names through `crate::` paths, as it did in `oneiron`.
use oneiron_contracts::{EntityId, entity_id, error, registry};
