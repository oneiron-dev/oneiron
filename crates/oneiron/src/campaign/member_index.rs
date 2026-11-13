//! The `campaign.member` claims by the CAMPAIGN their value is scoped to and
//! by the SAVED_QUERY that derived them (ARCH-0044 H202, census L3-28C). A
//! membership page used to read every CLAIM in the vault to find the heads
//! of one campaign or one query; these derived indexes name, per campaign and
//! per query, the `campaign.member` claims of any lifecycle.
//!
//! They are a prefilter only: the page re-reads every claim they nominate in
//! its own snapshot and runs its own match, admission and order on it, so a
//! page reads as it did when it scanned. Any doubt (flag unset, a read error,
//! a stored member value that does not decode, a hit the CLAIM type index
//! does not hold) answers `None`, and the page scans every CLAIM as before.
//! The claim projection's put chokepoint
//! (`store::claim_projection::maintain_claim_projection_index`) moves a
//! claim's rows here on every claim body write, and its removal
//! (`remove_claim_projection_index`) drops them, so these rows are as complete
//! as the predicate posting list they are rebuilt from. A row a path left
//! behind re-reads as no claim, or as another campaign's, and is skipped.

use std::collections::BTreeSet;

use crate::campaign::claims::{PREDICATE_CAMPAIGN_MEMBER, decode_campaign_member_value};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead};
use crate::registry::ENTITY_TYPE_CLAIM;
use crate::side_table::{self, Raw, RawValue, SideTable};
use crate::store::Store;
use crate::write_envelope::claim_body::ClaimBody;
use crate::{EntityId, Vault};

/// Keys are `(campaign, claim)`; the value is an empty marker.
const CAMPAIGN_INDEX: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::CAMPAIGN_MEMBER_CAMPAIGN_INDEX);

/// Keys are `(source query, claim)`; the value is an empty marker.
const QUERY_INDEX: SideTable<(EntityId, EntityId), (), Raw> =
    SideTable::new(&side_table::CAMPAIGN_MEMBER_QUERY_INDEX);

/// A `campaign.member` claim whose stored value does not decode.
const UNDECODABLE: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::CAMPAIGN_MEMBER_UNDECODABLE);

/// The rows one claim holds, so a rewrite or a removal moves them.
const REVERSE: SideTable<EntityId, IndexedMember, Raw> =
    SideTable::new(&side_table::CAMPAIGN_MEMBER_INDEX_REVERSE);

/// `Some(1)` once a whole rebuild of the indexes has committed.
const INDEX_STATE: SideTable<(), u64, Raw> =
    SideTable::new(&side_table::CAMPAIGN_MEMBER_INDEX_STATE);

const INDEX_VERSION: u64 = 1;

/// The index rows one `campaign.member` claim holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexedMember {
    /// The value decoded: the campaign it is scoped to, and the query that
    /// derived it (none for a manual enrollment).
    Decoded {
        campaign: EntityId,
        source_query: Option<EntityId>,
    },
    /// The value did not decode. While any such claim is stored the pages
    /// scan, and the scan reports it as it does today.
    Undecodable,
}

const TAG_UNDECODABLE: u8 = 0;
const TAG_MANUAL: u8 = 1;
const TAG_DERIVED: u8 = 2;

impl RawValue for IndexedMember {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        let mut raw = Vec::with_capacity(33);
        match self {
            Self::Undecodable => raw.push(TAG_UNDECODABLE),
            Self::Decoded {
                campaign,
                source_query,
            } => {
                raw.push(if source_query.is_some() {
                    TAG_DERIVED
                } else {
                    TAG_MANUAL
                });
                raw.extend_from_slice(campaign.as_bytes());
                if let Some(query) = source_query {
                    raw.extend_from_slice(query.as_bytes());
                }
            }
        }
        Ok(raw)
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        let id = |raw: &[u8]| {
            <[u8; 16]>::try_from(raw)
                .ok()
                .and_then(|raw| EntityId::from_bytes(raw).ok())
        };
        let decoded = match bytes.split_first() {
            Some((&TAG_UNDECODABLE, [])) => Some(Self::Undecodable),
            Some((&TAG_MANUAL, campaign)) => id(campaign).map(|campaign| Self::Decoded {
                campaign,
                source_query: None,
            }),
            Some((&TAG_DERIVED, ids)) if ids.len() == 32 => {
                let (campaign, query) = ids.split_at(16);
                id(campaign)
                    .zip(id(query))
                    .map(|(campaign, query)| Self::Decoded {
                        campaign,
                        source_query: Some(query),
                    })
            }
            _ => None,
        };
        decoded.ok_or_else(|| Error::CorruptedIndex("campaign member index reverse row").into())
    }
}

fn index_complete_in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> bool {
    matches!(INDEX_STATE.get(store, txn, &()), Ok(Some(INDEX_VERSION)))
}

/// The rows a claim holding `body` is indexed under: only a
/// `campaign.member` claim has any.
fn indexed_member(body: &ClaimBody) -> Option<IndexedMember> {
    if body.predicate != PREDICATE_CAMPAIGN_MEMBER {
        return None;
    }
    Some(match decode_campaign_member_value(&body.value) {
        Ok(value) => IndexedMember::Decoded {
            campaign: value.campaign,
            source_query: value.derivation.map(|derivation| derivation.source_query),
        },
        Err(_) => IndexedMember::Undecodable,
    })
}

fn put_member_rows(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    member: IndexedMember,
) -> Result<()> {
    match member {
        IndexedMember::Decoded {
            campaign,
            source_query,
        } => {
            CAMPAIGN_INDEX.put(store, txn, &(campaign, id), &())?;
            if let Some(query) = source_query {
                QUERY_INDEX.put(store, txn, &(query, id), &())?;
            }
        }
        IndexedMember::Undecodable => UNDECODABLE.put(store, txn, &id, &())?,
    }
    REVERSE.put(store, txn, &id, &member)
}

/// Drops claim `id`'s rows, in the writing transaction. The claim
/// projection's removal runs it, so every path that drops a claim's
/// projection rows (a rewrite, an erase, a deindex) drops these too.
///
/// # Errors
///
/// The index reads' and deletes' own store errors.
pub(crate) fn deindex_campaign_member_claim_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    let Some(member) = REVERSE.get(store, txn, &id)? else {
        return Ok(());
    };
    match member {
        IndexedMember::Decoded {
            campaign,
            source_query,
        } => {
            CAMPAIGN_INDEX.delete(store, txn, &(campaign, id))?;
            if let Some(query) = source_query {
                QUERY_INDEX.delete(store, txn, &(query, id))?;
            }
        }
        IndexedMember::Undecodable => {
            UNDECODABLE.delete(store, txn, &id)?;
        }
    }
    REVERSE.delete(store, txn, &id)?;
    Ok(())
}

/// Indexes claim `id` under the body about to be stored, in the writing
/// transaction, after the claim projection's removal dropped its old rows.
///
/// # Errors
///
/// The index writes' own store errors.
pub(crate) fn index_campaign_member_claim_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    body: &ClaimBody,
) -> Result<()> {
    match indexed_member(body) {
        Some(member) => put_member_rows(store, txn, id, member),
        None => Ok(()),
    }
}

impl Vault {
    /// Rebuilds the member indexes from the `campaign.member` predicate
    /// posting list when they are missing or stale, in one write
    /// transaction (a crash leaves nothing or everything). Runs at writable
    /// open and after a checkpoint restore (`force`); complete indexes are
    /// left alone.
    ///
    /// # Errors
    ///
    /// At open (`force` false) none: a failed rebuild of these Derived
    /// indexes never refuses the open; the flag stays unset and the pages
    /// keep the scan. The restore rebuild (`force`) propagates its store
    /// errors like its sibling backfills.
    pub(crate) fn backfill_campaign_member_index(&self, force: bool) -> Result<()> {
        match self.rebuild_campaign_member_index(force) {
            Err(error) if !force => {
                tracing::warn!(
                    %error,
                    "campaign member index rebuild failed; membership pages keep the scan"
                );
                Ok(())
            }
            other => other,
        }
    }

    fn rebuild_campaign_member_index(&self, force: bool) -> Result<()> {
        let mut wtxn = self.store.env.write_txn()?;
        if !force && index_complete_in_txn(&self.store, &wtxn) {
            return Ok(());
        }
        let ids = crate::claim::claim_ids_for_predicate_in_txn(
            &self.store,
            &wtxn,
            PREDICATE_CAMPAIGN_MEMBER,
        )?;
        let mut members = Vec::new();
        for id in ids {
            // A body that does not decode fails the scan's own read too: the
            // pages keep the scan while it is stored.
            let member = match self.get_claim_in_txn(&wtxn, &id) {
                Ok(Some(body)) => indexed_member(&body),
                Ok(None) => None,
                Err(_) => Some(IndexedMember::Undecodable),
            };
            if let Some(member) = member {
                members.push((id, member));
            }
        }
        for table in [&CAMPAIGN_INDEX, &QUERY_INDEX] {
            table.delete_from(&self.store, &mut wtxn, &[])?;
        }
        UNDECODABLE.delete_from(&self.store, &mut wtxn, &[])?;
        REVERSE.delete_from(&self.store, &mut wtxn, &[])?;
        for (id, member) in members {
            put_member_rows(&self.store, &mut wtxn, id, member)?;
        }
        INDEX_STATE.put(&self.store, &mut wtxn, &(), &INDEX_VERSION)?;
        wtxn.commit()?;
        Ok(())
    }
}

/// The claim ids under `owner` in `table`, when the indexes are complete
/// and no stored member value fails to decode.
fn indexed_ids_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    table: &SideTable<(EntityId, EntityId), (), Raw>,
    owner: EntityId,
) -> Option<Vec<EntityId>> {
    if !index_complete_in_txn(store, txn) {
        return None;
    }
    if UNDECODABLE
        .iter_from(store, txn, &[])
        .ok()?
        .next()
        .is_some()
    {
        return None;
    }
    let keys = table.scan_keys(store, txn, owner.as_bytes()).ok()?;
    let mut ids = Vec::with_capacity(keys.len());
    for (indexed_owner, id) in keys {
        if indexed_owner != owner {
            return None;
        }
        ids.push(id);
    }
    Some(ids)
}

/// `candidates` re-read in `txn`: a claim no longer stored, or no longer a
/// `campaign.member` claim, is dropped; one the CLAIM type index does not
/// hold is doubt, never a nomination the scan would not make.
fn checked_candidates_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    candidates: BTreeSet<EntityId>,
) -> Option<Vec<EntityId>> {
    let mut checked = Vec::with_capacity(candidates.len());
    for id in candidates {
        let Some(body) = vault.get_claim_in_txn(txn, &id).ok()? else {
            continue;
        };
        if body.predicate != PREDICATE_CAMPAIGN_MEMBER {
            continue;
        }
        if !EntityStoreRead::port_entity_type_indexed(&vault.store, txn, ENTITY_TYPE_CLAIM, &id)
            .ok()?
        {
            return None;
        }
        checked.push(id);
    }
    Some(checked)
}

/// The claims a campaign's membership page nominates, in id order: every
/// `campaign.member` claim scoped to `campaign`, whatever its lifecycle.
/// `None` means any doubt at all: the page scans every CLAIM.
pub(crate) fn indexed_campaign_member_claims(
    vault: &Vault,
    campaign: EntityId,
) -> Option<Vec<EntityId>> {
    let txn = vault.store.env.read_txn().ok()?;
    let ids = indexed_ids_in_txn(&vault.store, &txn, &CAMPAIGN_INDEX, campaign)?;
    checked_candidates_in_txn(vault, &txn, ids.into_iter().collect())
}

/// The claims a saved query's membership page nominates, in id order: every
/// `campaign.member` claim `query` derived, and every `campaign.member` claim
/// that replaced one of them, directly or through earlier `campaign.member`
/// replacements. That is the inverse of the page's own lineage walk
/// (`lineage_names_query_in_txn`, FIX 9664), which follows `Supersedes`
/// edges out of a head; this follows them in. `None` means any doubt at
/// all: the page scans every CLAIM.
pub(crate) fn indexed_saved_query_member_claims(
    vault: &Vault,
    query: EntityId,
) -> Option<Vec<EntityId>> {
    let txn = vault.store.env.read_txn().ok()?;
    let derived = indexed_ids_in_txn(&vault.store, &txn, &QUERY_INDEX, query)?;
    let mut found: BTreeSet<EntityId> = derived.iter().copied().collect();
    let mut next = derived;
    while let Some(older) = next.pop() {
        let edges = vault
            .store
            .port_edges(
                &txn,
                &older,
                EdgeDirection::In,
                Some(EdgeKind::Supersedes),
                None,
            )
            .ok()?;
        for edge in edges {
            // An in-edge row is keyed by its own side first: its peer is the
            // claim that replaced `older`.
            let newer = edge.ok()?.target;
            if found.contains(&newer) {
                continue;
            }
            let Some(body) = vault.get_claim_in_txn(&txn, &newer).ok()? else {
                continue;
            };
            if body.predicate != PREDICATE_CAMPAIGN_MEMBER {
                continue;
            }
            found.insert(newer);
            next.push(newer);
        }
    }
    checked_candidates_in_txn(vault, &txn, found)
}

/// Doors for `tests/campaign_member_index.rs`.
#[cfg(oneiron_test_support)]
impl Vault {
    /// Drops the indexes and their completeness flag, as a vault older than
    /// the indexes holds them, so the pages scan until the next open
    /// rebuilds them.
    pub(crate) fn drop_campaign_member_index_for_test(&self) -> Result<()> {
        self.with_write_txn(|wtxn| {
            for table in [&CAMPAIGN_INDEX, &QUERY_INDEX] {
                table.delete_from(&self.store, wtxn, &[])?;
            }
            UNDECODABLE.delete_from(&self.store, wtxn, &[])?;
            REVERSE.delete_from(&self.store, wtxn, &[])?;
            INDEX_STATE.delete(&self.store, wtxn, &())?;
            Ok(())
        })
    }

    /// Whether the indexes are complete.
    pub(crate) fn campaign_member_index_complete_for_test(&self) -> Result<bool> {
        let rtxn = self.store.env.read_txn()?;
        Ok(index_complete_in_txn(&self.store, &rtxn))
    }
}
