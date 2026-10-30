//! The AUTHORITY_LOG rows one part of a federated import copies, which its
//! door reads beside each one it judges (FIX 2535, 2989): where this vault's
//! fold needs history the import's rows supply together, each is judged on
//! the fold with all of them in, as a local append's batch is.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

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
/// first time a door asks for them. A clone shares the blobs and that one
/// decode.
#[derive(Clone)]
pub(in crate::sync) struct AuthorityBeside(Arc<Gathered>);

struct Gathered {
    blobs: Vec<Vec<u8>>,
    rows: OnceLock<BTreeMap<AuthorityEntryHash, AuthorityLogEntry>>,
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
        Self::of_blobs(blobs)
    }

    /// The AUTHORITY_LOG blobs among `rows`, for a caller with no carrier
    /// document, which gathers them from the rows it holds (FIX 11959).
    pub(in crate::sync) fn of_rows<'b>(rows: impl IntoIterator<Item = &'b [u8]>) -> Self {
        Self::of_blobs(
            rows.into_iter()
                .filter(|blob| is_authority_row(blob))
                .map(<[u8]>::to_vec)
                .collect(),
        )
    }

    fn of_blobs(blobs: Vec<Vec<u8>>) -> Self {
        Self(Arc::new(Gathered {
            blobs,
            rows: OnceLock::new(),
        }))
    }

    /// The gathered rows, decoded, by hash. A blob that is no canonical
    /// authority row is left out: its own door refuses it.
    pub(in crate::sync) fn rows(&self) -> Result<BTreeMap<AuthorityEntryHash, AuthorityLogEntry>> {
        Ok(self
            .0
            .rows
            .get_or_init(|| {
                let mut rows = BTreeMap::new();
                for blob in &self.0.blobs {
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
