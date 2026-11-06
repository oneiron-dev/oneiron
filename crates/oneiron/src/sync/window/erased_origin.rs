//! The origin CLAIM revisions a pinned window's history check refuses (FIX 21141), and the erased
//! form each refused live carrier takes before the window is persisted.

use std::collections::{BTreeMap, BTreeSet};

use loro::{CommitOptions, LoroDoc};

use super::super::loro_support::{map_get_bytes, map_insert_bytes};
use super::bridge::BRIDGE_ORIGIN;
use crate::Vault;
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{ClaimBody, encode_claim_body};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::origin::actor_erase::{
    OriginClaimKind, canonical_origin_claim_in_txn, erases_more, held_claim_in_txn,
    origin_claim_row, settle_in_txn,
};

/// The origin CLAIM revisions of one pinned window: the ones that never ship, live or in history,
/// and the erased form each refused live carrier takes before the window persists.
#[derive(Debug, Default)]
pub(super) struct ErasedOrigin {
    /// By entities-map key, the BLAKE3 of each refused revision's exact bytes.
    refused: BTreeMap<String, BTreeSet<[u8; 32]>>,
    /// By entities-map key, a refused live carrier's exact bytes and the erased form it takes.
    rewrites: BTreeMap<String, (Vec<u8>, Vec<u8>)>,
}

/// One origin CLAIM revision under an entities-map key.
struct Revision<'a> {
    digest: [u8; 32],
    blob: &'a [u8],
    kind: OriginClaimKind,
    body: ClaimBody,
}

impl ErasedOrigin {
    /// Reads them off `live`, the window's current origin CLAIM carriers, and `retained`, every
    /// revision its history or shallow root holds, each by entities-map key. A revision never
    /// ships when the scrub's settlement would rewrite it (it names an actor this vault erased, or
    /// the row this vault holds is its erased form), or when another revision under the same key,
    /// live or retained, is its erased form: the same claim with more of whom it names erased and
    /// nothing else changed (`erases_more`, as the reverse replacement pin reads it). An ordinary
    /// edit after the erased form leaves the original refused, since the erased form stays in the
    /// history beside it. A refused live carrier takes the form [`erased_live_form`] settles.
    ///
    /// # Errors
    ///
    /// Storage errors, or an erased form that does not encode.
    pub(super) fn read(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        live: &BTreeMap<String, Vec<u8>>,
        retained: &[(String, Vec<u8>)],
    ) -> Result<Self> {
        let mut by_key: BTreeMap<&str, BTreeMap<[u8; 32], &[u8]>> = BTreeMap::new();
        for (key, blob) in live
            .iter()
            .chain(retained.iter().map(|(key, blob)| (key, blob)))
        {
            by_key
                .entry(key.as_str())
                .or_default()
                .insert(*blake3::hash(blob).as_bytes(), blob.as_slice());
        }
        let mut erased = Self::default();
        for (key, blobs) in by_key {
            let Ok(id) = EntityId::from_hex(key) else {
                continue;
            };
            let revisions: Vec<Revision<'_>> = blobs
                .into_iter()
                .filter_map(|(digest, blob)| {
                    origin_claim_row(blob).map(|(kind, body)| Revision {
                        digest,
                        blob,
                        kind,
                        body,
                    })
                })
                .collect();
            for revision in &revisions {
                let erased_beside = revisions.iter().any(|other| {
                    other.digest != revision.digest
                        && other.kind == revision.kind
                        && erases_more(revision.kind, &id, &revision.body, &other.body)
                });
                if erased_beside
                    || canonical_origin_claim_in_txn(vault, txn, &id, revision.blob)?.is_some()
                {
                    erased
                        .refused
                        .entry(key.to_owned())
                        .or_default()
                        .insert(revision.digest);
                }
            }
            if let Some(current) = live.get(key)
                && erased.refuses(key, current)
                && let Some(form) = erased_live_form(vault, txn, &id, current, &revisions)?
            {
                erased
                    .rewrites
                    .insert(key.to_owned(), (current.clone(), form));
            }
        }
        Ok(erased)
    }

    /// Whether the exact bytes `blob` under entities-map key `key` are a refused revision.
    pub(super) fn refuses(&self, key: &str, blob: &[u8]) -> bool {
        self.refused
            .get(key)
            .is_some_and(|revisions| revisions.contains(blake3::hash(blob).as_bytes()))
    }

    /// Rewrites, under the same key in pinned window `doc`, each refused live carrier that is
    /// still current to its erased form, so neither a root the persist keeps nor the strict cut
    /// at its newest operation holds the refused bytes. The window is pinned already, so the
    /// history that still holds them never ships unchecked. Whether anything changed.
    ///
    /// # Errors
    ///
    /// A rewrite that cannot be written.
    pub(super) fn rewrite_live(&self, doc: &LoroDoc) -> Result<bool> {
        let entities = doc.get_map("entities");
        let due: Vec<(&String, &Vec<u8>)> = self
            .rewrites
            .iter()
            .filter(|(key, (refused, _))| {
                map_get_bytes(&entities, key).as_deref() == Some(refused.as_slice())
            })
            .map(|(key, (_, form))| (key, form))
            .collect();
        if due.is_empty() {
            return Ok(false);
        }
        // Pending operations commit as they were; only the rewrite is the bridge's own.
        doc.commit();
        for (key, form) in due {
            map_insert_bytes(&entities, key, form)?;
        }
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
        Ok(true)
    }
}

/// The form live carrier `current` of origin claim `id` takes: settled as the scrub settles a
/// carrier, against the row this vault holds and against each revision of `revisions`, until no
/// meeting erases more, so it names no one this vault erased or any of those revisions holds
/// erased. Each meeting only erases more, so a pass that changes nothing ends it. Its header
/// stays. `None` when it settles as it is.
fn erased_live_form(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    current: &[u8],
    revisions: &[Revision<'_>],
) -> Result<Option<Vec<u8>>> {
    let Some((kind, mut now)) = origin_claim_row(current) else {
        return Ok(None);
    };
    let held = held_claim_in_txn(vault, txn, kind, id)?;
    let beside: Vec<Option<&ClaimBody>> = std::iter::once(None)
        .chain(held.iter().map(Some))
        .chain(
            revisions
                .iter()
                .filter(|revision| revision.kind == kind)
                .map(|revision| Some(&revision.body)),
        )
        .collect();
    for _ in 0..beside.len() {
        let mut changed = false;
        for other in &beside {
            if let Some(settled) = settle_in_txn(vault, txn, kind, id, *other, &now)?.carried {
                now = settled;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut blob = current
        .get(..ENTITY_METADATA_HEADER_LEN)
        .ok_or(Error::CorruptedIndex("origin claim header"))?
        .to_vec();
    blob.extend_from_slice(&encode_claim_body(&now)?);
    Ok((blob != current).then_some(blob))
}
