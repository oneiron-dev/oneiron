//! The live world key pad rows of a side restore's source (KS-5, FIX 5686
//! part 2): a live row keeps its own pad beside its reference, so where the
//! custody the copy forks lacks a pad an image row names by bare reference,
//! or cannot read it, the row lands with the pad its source's live row
//! keeps, never the historical image's, once the restore's plan finds it not
//! retired there (`pad_custody`). A source whose rows do not read gives
//! none, warned: the restore goes on as it would without them.

use std::collections::BTreeMap;

use heed::types::Bytes;
use zeroize::Zeroizing;

use super::{CheckpointImage, SideRestoreSource, Source, codec_error};
use crate::{Result, Vault};

/// For each bare reference an image carries whose pad its source's live row
/// keeps, by row key: the image's row with that pad as its carrier.
#[derive(Default)]
pub(super) struct SidePads(BTreeMap<Vec<u8>, Zeroizing<Vec<u8>>>);

impl SidePads {
    /// The carrier row `row_key` lands as when custody cannot give its pad.
    pub(super) fn carrier(&self, row_key: &[u8]) -> Option<&Zeroizing<Vec<u8>>> {
        self.0.get(row_key)
    }
}

impl SideRestoreSource<'_> {
    /// This source's live pad rows for the bare references `image` carries
    /// ([`SidePads`]), read now.
    pub(super) fn live_pads(&self, image: &CheckpointImage) -> SidePads {
        let Some(rows) = image.databases.get("entities") else {
            return SidePads::default();
        };
        let wanted: Vec<&(Vec<u8>, Vec<u8>)> = rows
            .iter()
            .filter(|(_, raw)| {
                crate::world_keys::image_pad_row_of(raw).is_some_and(|row| !row.held)
            })
            .collect();
        if wanted.is_empty() {
            return SidePads::default();
        }
        let keys: Vec<&[u8]> = wanted.iter().map(|row| row.0.as_slice()).collect();
        let live = match &self.0 {
            Source::Open(vault) => open_rows(vault, &keys),
            Source::Disk { dir, page_seal, .. } => {
                crate::world_keys::read_sealed(dir, page_seal.as_ref(), || {
                    crate::store::read_existing_entity_rows(dir, &keys)
                })
            }
        };
        let live: BTreeMap<Vec<u8>, Vec<u8>> = match live {
            Ok(live) => live.into_iter().collect(),
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    "a side restore's source pad rows did not read; custody alone gives its pads"
                );
                return SidePads::default();
            }
        };
        SidePads(
            wanted
                .into_iter()
                .filter_map(|(key, raw)| {
                    let carrier = crate::world_keys::live_pad_carrier(raw, live.get(key)?)?;
                    Some((key.clone(), carrier))
                })
                .collect(),
        )
    }
}

/// The `entities` rows at `keys` of `vault`, open in this process.
fn open_rows(vault: &Vault, keys: &[&[u8]]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let txn = vault.store.env.read_txn()?;
    let entities = vault
        .store
        .env
        .open_database::<Bytes, Bytes>(&txn, Some("entities"))?
        .ok_or_else(codec_error)?;
    let mut rows = Vec::new();
    for &key in keys {
        if let Some(raw) = entities.get(&txn, key)? {
            rows.push((key.to_vec(), raw.to_vec()));
        }
    }
    Ok(rows)
}
