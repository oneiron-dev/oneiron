//! Moved from `crates/oneiron/src/note/documents.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use loro::ExportMode;
use loro::Frontiers;
use loro::LoroDoc;
use loro::UpdateOptions;
use loro::cursor::Cursor;
use loro::cursor::Side;
use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::side_table::codec::RawValue;
use oneiron_store::side_table::key::HexId;
use oneiron_store::write_envelope::provenance::ActorStamp;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

pub fn invalid(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidNoteBody(reason))
}
