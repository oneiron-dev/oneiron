//! Node-local party shortcut vs synced PERSON truth plus twin reconciliation.

use std::collections::BTreeMap;
use std::io::Cursor;

use rmpv::Value;
use sha2::{Digest, Sha256};

use super::claims::{
    COMM_SCHEMA_VERSION, CommError, CommResult, KEY_PARTY_KEY, KEY_SCHEMA_VERSION,
};
use super::records::{
    decode_entity_id, encode_value, required_string, validate_key_string, value_map,
};
use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::claim::ClaimSource;
use crate::entity_id::EntityId;
use crate::identity_topology::{
    EntityLifecycleState, IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite,
    IdentityTopologyOp, MergeOp, SurvivorshipPlan,
};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::entity_id_from_type_index_key;

const PARTY_INDEX_PREFIX: &[u8] = b"comm.party.v1:";

/// Stable machine rationale recorded on the MS-01 ledger event when the
/// projector reconciles offline-minted twins of one `party_key`.
pub(super) const PARTY_KEY_TWIN_RATIONALE: &str = "comm.party_key_offline_twin";

/// What synced truth says about one party, and whether the node-local shortcut
/// agrees with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartyLookup {
    /// The shortcut names the canonical row; nothing to repair.
    Fresh(EntityId),
    /// Synced truth names this row, but the shortcut disagrees.
    Repairable(EntityId),
    /// No active comm-owned PERSON carries this `party_key`.
    Absent,
}

fn resolve_or_create_party(vault: &Vault, party: &str) -> CommResult<EntityId> {
    vault.try_with_write_txn(|wtxn| resolve_or_create_party_in_txn(vault, wtxn, party))
}

/// Reads the `party_key` of `id` if — and only if — it is an ACTIVE comm-owned
/// PERSON row. `None` covers every way an id can fail to be synced truth for a
/// party: absent, non-PERSON, undecodable or unrelated body, or a merge shell
/// (whose type stays PERSON while its identity has moved to the survivor).
///
/// Single validator for both the cache check and the synced scan, so the
/// shortcut can never disagree with the truth it is a shortcut for.
pub(super) fn active_comm_party_key_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: EntityId,
) -> CommResult<Option<String>> {
    let Some(raw) = vault.store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_PERSON {
        return Ok(None);
    }
    if vault.entity_lifecycle_state_in_txn(rtxn, &id)? != EntityLifecycleState::Active {
        return Ok(None);
    }
    let mut cursor = Cursor::new(&raw[ENTITY_METADATA_HEADER_LEN..]);
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(None);
    };
    let Ok(entries) = value_map(&value) else {
        return Ok(None);
    };
    Ok(required_string(entries, KEY_PARTY_KEY)
        .ok()
        .map(str::to_owned))
}

/// Every active comm-owned PERSON row, grouped by its exact `party_key`, ids
/// ascending. This is the synced truth the node-local index caches.
fn active_comm_persons_by_party_key_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
) -> CommResult<BTreeMap<String, Vec<EntityId>>> {
    let mut groups: BTreeMap<String, Vec<EntityId>> = BTreeMap::new();
    for entry in vault
        .store
        .type_index
        .prefix_iter(rtxn, &[ENTITY_TYPE_PERSON])?
    {
        let (key, _) = entry?;
        let id = entity_id_from_type_index_key(&key)?;
        if let Some(party_key) = active_comm_party_key_in_txn(vault, rtxn, id)? {
            groups.entry(party_key).or_default().push(id);
        }
    }
    for ids in groups.values_mut() {
        ids.sort_unstable();
    }
    Ok(groups)
}

/// Resolves one party against synced truth, read-only.
///
/// `PARTY_INDEX_PREFIX` is node-local cache state; the synced truth is the
/// PERSON body's `party_key`. A cache miss therefore means "look again", not
/// "absent" — treating it as absence is what mints a twin for a party that
/// already synced in. On a stale or missing hit this scans the type-4 rows and,
/// when several active rows share the key, picks the lexicographically smallest
/// id so every node converges on the same one.
fn lookup_party_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party_key: &str,
) -> CommResult<PartyLookup> {
    if let Some(raw) = vault
        .store
        .vault_meta
        .get(rtxn, &party_index_key(party_key))?
    {
        let id = decode_entity_id(&raw)?;
        if active_comm_party_key_in_txn(vault, rtxn, id)?.as_deref() == Some(party_key) {
            return Ok(PartyLookup::Fresh(id));
        }
    }
    Ok(active_comm_persons_by_party_key_in_txn(vault, rtxn)?
        .remove(party_key)
        .and_then(|ids| ids.into_iter().next())
        .map_or(PartyLookup::Absent, PartyLookup::Repairable))
}

/// Points the node-local shortcut at `id`.
fn put_party_index_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party_key: &str,
    id: EntityId,
) -> CommResult<()> {
    vault
        .store
        .vault_meta
        .put(wtxn, &party_index_key(party_key), id.as_bytes())?;
    Ok(())
}

/// Transaction-composable party resolution: repairs the shortcut from synced
/// truth on a miss and never mints.
fn resolve_party_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party_key: &str,
) -> CommResult<Option<EntityId>> {
    match lookup_party_in_txn(vault, &*wtxn, party_key)? {
        PartyLookup::Fresh(id) => Ok(Some(id)),
        PartyLookup::Repairable(id) => {
            put_party_index_in_txn(vault, wtxn, party_key, id)?;
            Ok(Some(id))
        }
        PartyLookup::Absent => Ok(None),
    }
}

/// Resolves (or mints) the PERSON party for `party` inside an existing write
/// transaction, so a caller can make party creation atomic with the write that
/// references it (e.g. recording an event). Doing the resolve in a separate
/// prior transaction lets a concurrent party deletion land in between, leaving
/// the event bound to a missing PERSON.
pub(super) fn resolve_or_create_party_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party: &str,
) -> CommResult<EntityId> {
    validate_key_string(party).map_err(|_| CommError::InvalidRecord)?;
    if let Some(id) = resolve_party_in_txn(vault, wtxn, party)? {
        return Ok(id);
    }
    let id = mint_comm_person_in_txn(vault, wtxn, party)?;
    put_party_index_in_txn(vault, wtxn, party, id)?;
    Ok(id)
}

/// Mints one comm-owned PERSON row carrying `party_key`. The caller decides
/// whether the node-local shortcut should name it.
pub(super) fn mint_comm_person_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    party: &str,
) -> CommResult<EntityId> {
    let id = EntityId::now();
    let body = encode_value(&Value::Map(vec![
        (
            Value::from(KEY_SCHEMA_VERSION),
            Value::from(COMM_SCHEMA_VERSION),
        ),
        (Value::from(KEY_PARTY_KEY), Value::from(party)),
    ]))?;
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id,
            entity_type: ENTITY_TYPE_PERSON,
            occurred: TimeRange { start: 0, end: 0 },
            learned_at: crate::unix_seconds_now(),
            data: body,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        true,
    )?;
    Ok(id)
}

/// Read-side party lookup. Answers from synced truth, and repairs the node-local
/// shortcut when it disagrees — a read-side miss must not report a party that
/// exists as absent (which would let the next write mint a twin for it). Only a
/// repair takes a write transaction; the fresh and absent cases stay read-only.
pub(super) fn resolve_party(vault: &Vault, party: &str) -> CommResult<Option<EntityId>> {
    validate_key_string(party).map_err(|_| CommError::InvalidRecord)?;
    let lookup = {
        let rtxn = vault.store.env.read_txn()?;
        lookup_party_in_txn(vault, &rtxn, party)?
    };
    match lookup {
        PartyLookup::Fresh(id) => Ok(Some(id)),
        PartyLookup::Repairable(id) => {
            vault.try_with_write_txn(|wtxn| put_party_index_in_txn(vault, wtxn, party, id))?;
            Ok(Some(id))
        }
        PartyLookup::Absent => Ok(None),
    }
}

/// Transaction-composable READ-ONLY party resolution: the same synced-truth
/// answer [`resolve_party`] gives, without the shortcut repair (a repair needs
/// a write, and this composes into transactions that must not take one, or
/// already hold one).
pub(crate) fn resolve_party_ref_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    party: &str,
) -> CommResult<Option<EntityId>> {
    validate_key_string(party).map_err(|_| CommError::InvalidRecord)?;
    Ok(match lookup_party_in_txn(vault, rtxn, party)? {
        PartyLookup::Fresh(id) | PartyLookup::Repairable(id) => Some(id),
        PartyLookup::Absent => None,
    })
}

/// Party resolution for a reader that holds a `Store` and no `Vault` — the
/// external-effect gate door.
///
/// It answers from the node-local shortcut and then RE-VALIDATES the hit
/// against synced truth (the row must still be a PERSON carrying exactly this
/// `party_key`), so a stale shortcut resolves to NOTHING rather than to the
/// wrong person. Deliberately the same interim shape CA's `comm.do_not_contact`
/// leg uses at the same hydration point, and deliberately fail-closed for this
/// caller: an unresolvable party means no override was found, which HOLDS the
/// send rather than releasing it.
pub(crate) fn resolve_party_ref_from_store_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party: &str,
) -> CommResult<Option<EntityId>> {
    let party_key = party.trim();
    if party_key.is_empty() {
        return Ok(None);
    }
    let Some(raw_id) = store.vault_meta.get(txn, &party_index_key(party_key))? else {
        return Ok(None);
    };
    let id = decode_entity_id(&raw_id)?;
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_PERSON {
        return Ok(None);
    }
    let mut cursor = Cursor::new(&raw[ENTITY_METADATA_HEADER_LEN..]);
    let Ok(value) = rmpv::decode::read_value(&mut cursor) else {
        return Ok(None);
    };
    let Ok(entries) = value_map(&value) else {
        return Ok(None);
    };
    Ok((required_string(entries, KEY_PARTY_KEY).ok() == Some(party_key)).then_some(id))
}

pub(super) fn party_index_key(party: &str) -> Vec<u8> {
    let digest = Sha256::digest(party.as_bytes());
    let mut key = Vec::with_capacity(PARTY_INDEX_PREFIX.len() + digest.len());
    key.extend_from_slice(PARTY_INDEX_PREFIX);
    key.extend_from_slice(&digest);
    key
}

/// Converges offline-minted twins of one `party_key` onto a single canonical
/// party, returning how many twins were merged away.
///
/// Identity created while synced truth was unreachable reconciles by MERGE, not
/// by prevention: two devices that each minted a party row for one key are both
/// right about the party and simply disagree about its id. Each group's lowest
/// id survives (a total order every node computes identically) and the rest go
/// through the ARCH-0055 MS-01 door as read-through merges — that door owns the
/// shell edges, the maintenance-band ledger, and undo. No claim subject is
/// rewritten and no `merged_into` edge is authored here.
///
/// Different `party_key` values are never merged. Deciding that two keys name
/// one human is cross-channel identity judgment and belongs to the Dreamer tier.
pub(super) fn reconcile_comm_party_twins(vault: &Vault, now: u64) -> CommResult<usize> {
    let twin_groups: Vec<(String, Vec<EntityId>)> = {
        let rtxn = vault.store.env.read_txn()?;
        active_comm_persons_by_party_key_in_txn(vault, &rtxn)?
            .into_iter()
            .filter(|(_, ids)| ids.len() > 1)
            .collect()
    };
    let mut merged = 0;
    for (party_key, twins) in twin_groups {
        // The door takes its own write transaction, so it runs outside the
        // PERSON scan's read transaction.
        let (survivor, sources) = twins.split_first().ok_or(CommError::InvalidRecord)?;
        let outcome = vault.apply_identity_topology_op(
            &IdentityTopologyOp::Merge(MergeOp {
                sources: sources.to_vec(),
                survivor: *survivor,
                evidence: IdentityOpEvidence {
                    refs: twins.clone(),
                    rationale: PARTY_KEY_TWIN_RATIONALE.to_owned(),
                },
                survivorship_plan: SurvivorshipPlan::ReadThrough,
            }),
            &IdentityOpWrite::auto(ClaimSource::Inferred),
            now,
        )?;
        if matches!(outcome, IdentityOpOutcome::Applied { .. }) {
            merged += sources.len();
        }
        vault.try_with_write_txn(|wtxn| {
            put_party_index_in_txn(vault, wtxn, &party_key, *survivor)
        })?;
    }
    Ok(merged)
}

/// Resolves or creates the PERSON entity used as a comm claim subject.
pub fn resolve_or_create_comm_party(vault: &Vault, party: &str) -> CommResult<EntityId> {
    resolve_or_create_party(vault, party)
}
