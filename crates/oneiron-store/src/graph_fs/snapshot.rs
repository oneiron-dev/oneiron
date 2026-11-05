//! Historical file resolution over retained codebase snapshots. The manifest
//! selects bytes; the caller's live scoped read still admits both the artifact
//! and each blob before a path, name, length or body is returned.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::code_snapshot::ids::codebase_asset_entity_id as snapshot_asset_entity_id;
use crate::write_envelope::claim_body::lexical_query_hint::ScopedRead;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

use crate::graph_fs::paging::SealedPosition;

impl SealedPosition for String {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        String::from_utf8(bytes.to_vec()).ok()
    }
}
