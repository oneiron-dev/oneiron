//! Who owns a body and whether it is whole. One descriptor shape serves every
//! family that keeps bytes for a record: code-mode results (inline in LMDB or
//! one content-addressed file beside `data.mdb`), artifact versions and office
//! bodies. The descriptor is metadata only; bytes stay where their family keeps
//! them.
//!
//! Canon: a result is published complete only after its whole body is durable,
//! and a crash before that leaves it explicitly incomplete, never an empty
//! success (storage ABI, result body store; EIRI-ARCH-0002). Erase starts at
//! the owning record and removes its references; shared bytes outlive one
//! owner while another holds them (ARCH-0005a, ERASE-SHARED = B). A digest is
//! never an owner and never a read permit.

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};
use crate::store::ManifestDbs;
pub(crate) mod checkpoint;

/// Where a body's bytes live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyLocation {
    /// Under the owning family's LMDB rows; erased with the owner's rows.
    Inline,
    /// One per-vault file named by the digest; reclaimed only once no
    /// descriptor holds the digest.
    File,
}

/// A body's identity: its BLAKE3 digest, length and location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyRef {
    #[serde(with = "hex32")]
    pub blake3: [u8; 32],
    pub bytes: u64,
    pub location: BodyLocation,
}

/// Whether a body is whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyState {
    /// The producer has not finished, or stopped before the whole body was
    /// durable. `retained` is a durable partial a reader may see, labelled
    /// partial; `None` is a body with nothing safe to show.
    Incomplete { retained: Option<BodyRef> },
    /// The whole body is durable and its digest is final.
    Complete { body: BodyRef },
}

impl BodyState {
    /// The bytes this state holds, if any.
    #[must_use]
    pub const fn held(&self) -> Option<&BodyRef> {
        match self {
            Self::Incomplete { retained } => retained.as_ref(),
            Self::Complete { body } => Some(body),
        }
    }

    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }
}

/// One body occurrence and the record that owns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedBody {
    /// The content-owning record (an entity, or a run's replay record): erase
    /// starts here.
    pub owner: EntityId,
    /// This body or version occurrence. Two occurrences of the same bytes may
    /// have different owners, births and grants.
    pub occurrence: EntityId,
    pub state: BodyState,
    /// What a MESSAGE that holds a run's result keeps of where the body came
    /// from (FIX 365), so a read reopens it after the run's replay is gone.
    /// `None` on every other holder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<RetainedResultProvenance>,
}

/// A result hold's source: the producer run, its occurrence of the body and
/// its path there, and the rows the run's answers were served from (`None`
/// when the run kept no set, which is unknown, never public). It is no grant:
/// a reader is admitted again under the taint the body has now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedResultProvenance {
    pub run_id: EntityId,
    pub occurrence: EntityId,
    pub path: String,
    pub served_rows: Option<Vec<EntityId>>,
}

/// Body descriptors by owner. Key: id16 (owner) + id16 (occurrence).
const BODY: SideTable<(EntityId, EntityId), OwnedBody, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY);

/// Who holds a digest. Key: bytes32 (BLAKE3) + id16 (occurrence); value: the owner.
const BODY_DIGEST: SideTable<([u8; 32], EntityId), EntityId, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY_DIGEST);

/// File digests no descriptor holds any longer, for the file collector.
/// Key: bytes32 (BLAKE3); value: recorded-at of the release.
const BODY_RELEASED: SideTable<[u8; 32], u64, Named> =
    SideTable::new(&side_table::PROVENANCE_BODY_RELEASED);

/// Publishes `body`'s descriptor in the caller's transaction. An occurrence
/// may go from absent or incomplete to incomplete or complete; a complete
/// body is final, so the same descriptor again is a no-op and a different one
/// is refused. A publisher makes the bytes durable first, then publishes the
/// complete descriptor in the transaction that binds the result.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when the occurrence is already complete with
/// another descriptor; storage errors as they occur.
// The result body store (OF-597) and artifact versions call it.
#[allow(dead_code)]
pub(crate) fn publish_body_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    body: &OwnedBody,
) -> Result<()> {
    let key = (body.owner, body.occurrence);
    if let Some(prior) = BODY.get(store, txn, &key)? {
        if prior == *body {
            return Ok(());
        }
        if prior.state.is_complete() {
            return Err(Error::InvariantViolation(
                "a complete body's descriptor is final",
            ));
        }
        if let Some(held) = prior.state.held() {
            BODY_DIGEST.delete(store, txn, &(held.blake3, body.occurrence))?;
            release_if_unheld(store, txn, held)?;
        }
    }
    BODY.put(store, txn, &key, body)?;
    if let Some(held) = body.state.held() {
        BODY_DIGEST.put(store, txn, &(held.blake3, body.occurrence), &body.owner)?;
        BODY_RELEASED.delete(store, txn, &held.blake3)?;
    }
    Ok(())
}

/// One occurrence's descriptor.
// The result body store (OF-597) and artifact versions call it.
#[allow(dead_code)]
pub(crate) fn owned_body_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    owner: &EntityId,
    occurrence: &EntityId,
) -> Result<Option<OwnedBody>> {
    BODY.get(store, txn, &(*owner, *occurrence))
}

/// Every body `owner` holds, in occurrence order.
pub(crate) fn owned_bodies_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    owner: &EntityId,
) -> Result<Vec<OwnedBody>> {
    Ok(BODY
        .scan_from(store, txn, owner.as_bytes())?
        .into_iter()
        .map(|(_, body)| body)
        .collect())
}

/// The file a raw `vault_meta` row holds when it is a descriptor whose held
/// body (a complete one, or an incomplete one's retained part) is a file: its
/// digest and length. A checkpoint reads its rows raw, so this is how it
/// finds every file a descriptor holds, a legal hold's superseded ASSET file
/// included (FIX 5348).
///
/// # Errors
///
/// A descriptor row that does not decode.
pub(crate) fn file_body_of_row(key: &[u8], value: &[u8]) -> Result<Option<([u8; 32], u64)>> {
    if !key.starts_with(BODY.decl().prefix) {
        return Ok(None);
    }
    Ok(BODY
        .decode_value(value)?
        .state
        .held()
        .filter(|held| held.location == BodyLocation::File)
        .map(|held| (held.blake3, held.bytes)))
}

/// Among raw `vault_meta` rows, every descriptor holding `digest` turned
/// explicitly incomplete with nothing safe to show, and `digest`'s holder
/// and release rows dropped: a restore's prune of a body whose instance an
/// erase retired (KS-2A). Never an unreadable complete body. Rows stay in
/// order.
///
/// # Errors
///
/// A descriptor row that does not decode.
pub(crate) fn prune_digest_in_rows(
    rows: &mut Vec<(Vec<u8>, Vec<u8>)>,
    digest: &[u8; 32],
) -> Result<()> {
    let mut holders = BODY_DIGEST.decl().prefix.to_vec();
    holders.extend_from_slice(digest);
    let released = BODY_RELEASED.key_bytes(digest);
    rows.retain(|(key, _)| !key.starts_with(&holders) && *key != released);
    for (key, value) in rows.iter_mut() {
        if !key.starts_with(BODY.decl().prefix) {
            continue;
        }
        let mut body = BODY.decode_value(value)?;
        if body.state.held().is_some_and(|held| held.blake3 == *digest) {
            body.state = BodyState::Incomplete { retained: None };
            *value = BODY.encode_value(&body)?;
        }
    }
    Ok(())
}

/// Whether any descriptor still holds `blake3`.
pub(crate) fn digest_is_held_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    blake3: &[u8; 32],
) -> Result<bool> {
    Ok(!BODY_DIGEST.scan_keys(store, txn, blake3)?.is_empty())
}

/// Drops every body `owner` holds and queues each file digest no other
/// descriptor holds for the collector. Returns how many descriptors left.
pub(crate) fn release_owner_bodies_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    owner: &EntityId,
) -> Result<usize> {
    let bodies = owned_bodies_in_txn(store, txn, owner)?;
    for body in &bodies {
        BODY.delete(store, txn, &(body.owner, body.occurrence))?;
        if let Some(held) = body.state.held() {
            BODY_DIGEST.delete(store, txn, &(held.blake3, body.occurrence))?;
            release_if_unheld(store, txn, held)?;
        }
    }
    Ok(bodies.len())
}

/// Drops `owner`'s one `occurrence` and queues its file digest for the
/// collector when no other descriptor holds it. `false` when the owner holds
/// no such occurrence.
pub(crate) fn release_body_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    owner: &EntityId,
    occurrence: &EntityId,
) -> Result<bool> {
    let key = (*owner, *occurrence);
    let Some(body) = BODY.get(store, txn, &key)? else {
        return Ok(false);
    };
    BODY.delete(store, txn, &key)?;
    if let Some(held) = body.state.held() {
        BODY_DIGEST.delete(store, txn, &(held.blake3, *occurrence))?;
        release_if_unheld(store, txn, held)?;
    }
    Ok(true)
}

/// Up to `limit` released file digests, oldest key first. The collector
/// unlinks a file only once its reader pins allow and [`take_released_in_txn`]
/// confirms no descriptor took the digest back.
// The result body store (OF-597) and artifact versions call it.
#[allow(dead_code)]
pub(crate) fn released_bodies_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    limit: usize,
) -> Result<Vec<[u8; 32]>> {
    BODY_RELEASED
        .iter_from(store, txn, &[])?
        .take(limit)
        .map(|row| row.map(|(digest, _)| digest))
        .collect()
}

/// Takes `blake3` off the release queue. `true` when the file may go: the
/// digest was queued and no descriptor holds it.
// The result body store (OF-597) and artifact versions call it.
#[allow(dead_code)]
pub(crate) fn take_released_in_txn(
    store: &impl ManifestDbs,
    txn: &mut RwTxn<'_>,
    blake3: &[u8; 32],
) -> Result<bool> {
    let queued = BODY_RELEASED.delete(store, txn, blake3)?;
    Ok(queued && !digest_is_held_in_txn(store, txn, blake3)?)
}

/// A digest whose last holder just went: a file queues for the collector,
/// and an erase of an earlier holder that waited on this release retires
/// its instance now (KS-2A); a delete or a collection keeps the key.
fn release_if_unheld(store: &impl ManifestDbs, txn: &mut RwTxn<'_>, held: &BodyRef) -> Result<()> {
    if digest_is_held_in_txn(store, txn, &held.blake3)? {
        return Ok(());
    }
    #[cfg(unix)]
    crate::store::release_body_in_txn(store, txn, &held.blake3)?;
    if held.location == BodyLocation::File {
        let at = crate::ports::recorded_at_in_txn(store, txn)?;
        BODY_RELEASED.put(store, txn, &held.blake3, &at)?;
    }
    Ok(())
}

impl crate::Vault {
    /// Every body `owner` holds, with its completion state.
    ///
    /// # Errors
    ///
    /// Storage errors, or a stored descriptor that does not decode.
    pub fn owned_bodies(&self, owner: &EntityId) -> Result<Vec<OwnedBody>> {
        let rtxn = self.store.env.read_txn()?;
        owned_bodies_in_txn(&self.store, &rtxn, owner)
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        bytes: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(blake3::Hash::from_bytes(*bytes).to_hex().as_str())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        blake3::Hash::from_hex(value)
            .map(|hash| *hash.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
