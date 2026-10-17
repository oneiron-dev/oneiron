//! The seed's store: each revision is one immutable ASSET row in the
//! replicated ledger, the same carrier a staged pack source rides, so the
//! seed syncs as authoritative and restores as content. The newest revision
//! is the seed; no mutable pointer exists to drift.
use super::{ShapeRow, ShapeSeed, invalid};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, TimeRange, Vault};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

const FORMAT: &str = "oneiron.vault_shape.seed.v1";
const ID_DOMAIN: &[u8] = b"oneiron.vault-shape.seed.asset.v1\0";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    revision: u64,
    parent: Option<String>,
    author: String,
    written_at: u64,
    rows: Vec<ShapeRow>,
}

/// One stored seed revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StoredShapeSeed {
    /// The revision's ASSET row id, hex.
    pub id: String,
    /// 1 for the first seed, one more for each revision after it.
    pub revision: u64,
    /// The revision this one replaced.
    pub parent: Option<String>,
    /// The actor that wrote this revision, hex.
    pub author: String,
    pub written_at: u64,
    pub seed: ShapeSeed,
}

/// The digest a seed's rows hash to, independent of who stored them when.
pub(super) fn seed_digest(seed: &ShapeSeed) -> Result<[u8; 32]> {
    let bytes =
        rmp_serde::to_vec_named(&seed.rows).map_err(|_| invalid("seed encoding failed"))?;
    Ok(*blake3::Hasher::new()
        .update(b"oneiron.vault_shape.seed_digest.v1\0")
        .update(&bytes)
        .finalize()
        .as_bytes())
}

fn decode(id: EntityId, body: &[u8]) -> Result<Option<StoredShapeSeed>> {
    #[derive(Deserialize)]
    struct Marker {
        format: String,
    }
    match rmp_serde::from_slice::<Marker>(body) {
        Ok(marker) if marker.format == FORMAT => {}
        _ => return Ok(None),
    }
    let envelope: Envelope =
        rmp_serde::from_slice(body).map_err(|_| invalid("invalid stored seed envelope"))?;
    Ok(Some(StoredShapeSeed {
        id: id.to_hex(),
        revision: envelope.revision,
        parent: envelope.parent,
        author: envelope.author,
        written_at: envelope.written_at,
        seed: ShapeSeed {
            rows: envelope.rows,
        },
    }))
}

impl Vault {
    /// The newest stored seed revision, or none before the first.
    ///
    /// # Errors
    ///
    /// A read failure, or a seed row that no longer decodes.
    pub fn shape_seed(&self) -> Result<Option<StoredShapeSeed>> {
        let txn = self.store.env.read_txn()?;
        self.shape_seed_in_txn(&txn)
    }

    pub(crate) fn shape_seed_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<Option<StoredShapeSeed>> {
        let mut newest: Option<StoredShapeSeed> = None;
        for id in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_ASSET, None)?
        {
            let id = id?;
            let LiveEntityRow::Live { body, .. } = live_entity_row_in_txn(&self.store, txn, &id)?
            else {
                continue;
            };
            let Some(stored) = decode(id, &body)? else {
                continue;
            };
            // Two revisions written apart at the same number order by id,
            // so every replica names the same seed.
            if newest
                .as_ref()
                .is_none_or(|have| (stored.revision, &stored.id) > (have.revision, &have.id))
            {
                newest = Some(stored);
            }
        }
        Ok(newest)
    }

    /// Stores `seed` as the next revision, written by `author`. The seed is
    /// intent and grants nothing: storing one changes no live structure. The
    /// same rows as the newest revision store nothing and return it.
    ///
    /// # Errors
    ///
    /// An invalid seed, or a write failure.
    pub fn put_shape_seed(
        &self,
        author: EntityId,
        seed: &ShapeSeed,
        now: u64,
    ) -> Result<StoredShapeSeed> {
        seed.validate()?;
        self.with_write_txn_grouped(|txn| {
            let head = self.shape_seed_in_txn(txn)?;
            if let Some(head) = head.as_ref()
                && head.seed == *seed
            {
                return Ok(head.clone());
            }
            let envelope = Envelope {
                format: FORMAT.to_owned(),
                revision: head.as_ref().map_or(1, |head| head.revision + 1),
                parent: head.map(|head| head.id),
                author: author.to_hex(),
                written_at: now,
                rows: seed.rows.clone(),
            };
            let bytes = rmp_serde::to_vec_named(&envelope)
                .map_err(|_| invalid("seed encoding failed"))?;
            let digest = blake3::Hasher::new()
                .update(ID_DOMAIN)
                .update(&bytes)
                .finalize();
            let mut raw = [0_u8; 16];
            raw.copy_from_slice(&digest.as_bytes()[..16]);
            let id = EntityId::from_bytes(raw).map_err(|_| invalid("seed id width"))?;
            self.batch_in()
                .put(
                    &id,
                    ENTITY_TYPE_ASSET,
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &bytes,
                )
                .apply(txn)?;
            Ok(StoredShapeSeed {
                id: id.to_hex(),
                revision: envelope.revision,
                parent: envelope.parent,
                author: envelope.author,
                written_at: now,
                seed: seed.clone(),
            })
        })
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes_to_hex_lower(bytes)
}
