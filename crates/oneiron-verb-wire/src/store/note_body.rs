//! Moved from `crates/oneiron/src/store/note_body.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::note_kind as kinds;
use oneiron_store::receipt_identity::ERASED_CALL_IDENTITY;
use serde::Deserialize;
use serde::Serialize;

/// The stored spelling's prefix for [`NoteActor::Imported`]: `imported:`
/// and the source id in hex.
pub const IMPORTED_ACTOR_PREFIX: &str = "imported:";
