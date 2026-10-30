//! The AUTHORITY_LOG rows one part of a federated import copies, which its
//! door reads beside each one it judges (FIX 2535, 2989): where this vault's
//! fold needs history the import's rows supply together, each is judged on
//! the fold with all of them in, as a local append's batch is.

use std::cell::OnceCell;
use std::collections::BTreeMap;

use loro::LoroMap;

use crate::authority::{
    AuthorityEntryHash, AuthorityLogEntry, authority_entry_hash, decode_authority_log_entry_body,
    validate_authority_log_entry_body_bytes,
};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::Result;
use crate::sync::ingest::is_authority_row;
use crate::sync::loro_support::map_for_each_value_bytes;

/// The authority blobs of one part, gathered before the copy reads the map
/// (a read of the map inside its own walk would wait on itself), decoded the
/// first time a door asks for them.
pub(in crate::sync) struct AuthorityBeside {
    blobs: Vec<Vec<u8>>,
    rows: OnceCell<BTreeMap<AuthorityEntryHash, AuthorityLogEntry>>,
}

impl AuthorityBeside {
    /// The AUTHORITY_LOG blobs of `entities` under the keys `copies` selects.
    pub(in crate::sync) fn gather(entities: &LoroMap, copies: impl Fn(&str) -> bool) -> Self {
        let mut blobs = Vec::new();
        map_for_each_value_bytes(entities, |key, value| {
            if let Some(blob) = value
                && is_authority_row(blob)
                && copies(key)
            {
                blobs.push(blob.to_vec());
            }
        });
        Self {
            blobs,
            rows: OnceCell::new(),
        }
    }

    /// The gathered rows, decoded, by hash. A blob that is no canonical
    /// authority row is left out: its own door refuses it.
    pub(in crate::sync) fn rows(&self) -> Result<BTreeMap<AuthorityEntryHash, AuthorityLogEntry>> {
        Ok(self
            .rows
            .get_or_init(|| {
                let mut rows = BTreeMap::new();
                for blob in &self.blobs {
                    let Some(body) = blob.get(ENTITY_METADATA_HEADER_LEN..) else {
                        continue;
                    };
                    if validate_authority_log_entry_body_bytes(body).is_err() {
                        continue;
                    }
                    if let Ok(entry) = decode_authority_log_entry_body(body)
                        && let Ok(hash) = authority_entry_hash(&entry)
                    {
                        rows.insert(hash, entry);
                    }
                }
                rows
            })
            .clone())
    }
}
