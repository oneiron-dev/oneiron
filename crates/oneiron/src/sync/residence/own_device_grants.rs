//! The own-device grants a linked machine's live slips stand on, served
//! beside its authority catch-up (FIX 23747, Engine RULING
//! OPENED-DEVICE-GRANT-CATCHUP = A). Pairing a device to a live owner
//! provisions the owner's own-device FEDERATION_GRANT, an ordinary entity
//! row, and names it in the paired slip's `grant_ref` (FIX 3134); every slip
//! door admits that slip only while the row stands on the machine that
//! verifies it. The authority log carries the slip's mint but not the row,
//! and window sync carries the row only inside the window it lives in, which
//! an opened machine does not hold, so such a machine refused every slip its
//! owner paired. Canon keeps necessary authority material on every opened
//! device (ARCH-0023b: "necessary authority cannot be omitted").
//!
//! The home serves each such row apart from any content, to a proven linked
//! machine only, as it serves the authority tail: for each grant a live slip
//! of its own fold names as a person's, the stored row while it stands, and
//! for each grant the machine asks about, its withdrawal as a hard tombstone
//! once withdrawn. The machine asks about the grants its own fold's live
//! slips name and the own-device grants it holds live, admits each row
//! through the entity-ingest ladder, as window sync would land it, and
//! replays each withdrawal through the one tombstone primitive, so a
//! withdrawn grant refuses there too and cannot come back. Nothing is rebuilt
//! from a mint's claims, and a member's or a guest's grant is never served
//! here.
//!
//! A row lands from any home, proven or not (Engine RULING
//! SYNC-HOME-UNANSWERED = B, 14 Nov: never gate the owner on his own vault):
//! it confers nothing beyond the live signed slip of the machine's own fold
//! that binds it, whose scope is the slip's own. A withdrawal replays only
//! from a home that proved itself a machine of the vault: it carries no
//! signature, its replay withdraws the grant for good, and every later
//! pairing of the owner names the same grant. A revoke the owner signs
//! still reaches the machine at once, through its authority log.

use std::collections::{BTreeMap, BTreeSet};

use super::authority_tail::require_owner_machine;
use crate::authority::{ACTOR_CLASS_HUMAN, PeerMachine, grant_known_withdrawn_in_txn};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::deletion::{TombstoneReason, TombstoneValueV2};
use crate::error::Result;
use crate::federation::{decode_federation_grant_body, is_own_device_grant};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_FEDERATION_GRANT;
use crate::sync::ingest::{EntityStep, IngestCtx, ingest_rows_in_savepoint};
use crate::sync::loro_support::TombstoneIndex;
use crate::sync::types::WindowKey;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

/// The most grants one ask names and one answer carries.
pub const OWN_DEVICE_GRANTS_PAGE_MAX: usize = 64;

/// One own-device grant as the home holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnDeviceGrantState {
    /// The stored row, its metadata header and body, while the grant stands.
    Live(Vec<u8>),
    /// The hard tombstone value of the grant's withdrawal.
    Withdrawn(Vec<u8>),
}

/// What one admission did with each grant the home served.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OwnDeviceGrantAdmission {
    /// The grants whose rows stand here now: landed, or held already.
    pub landed: BTreeSet<EntityId>,
    /// The grants whose withdrawal stands here now: replayed, or held
    /// already.
    pub withdrawn: BTreeSet<EntityId>,
    /// The grants refused: not asked for, not a person's own-device grant
    /// for a holder whose live slip names it, refused by the ladder, or a
    /// withdrawal served by a home that proved no machine of this vault.
    pub refused: BTreeSet<EntityId>,
}

/// The own-device grants this machine asks its home about: each grant a
/// live slip of its fold names as a person's ([`named_own_device_grants_in_txn`]),
/// with the holders whose slip names it, and each own-device grant it holds
/// live, with its member, so a withdrawal reaches a grant whose slips no
/// longer stand too.
///
/// # Errors
///
/// An authority history this vault cannot fold; storage errors.
pub fn own_device_grant_refs(vault: &Vault) -> Result<BTreeMap<EntityId, BTreeSet<String>>> {
    let txn = vault.store.env.read_txn()?;
    let mut asked = named_own_device_grants_in_txn(vault, &txn)?;
    for id in EntityStoreRead::port_entity_ids_by_type(
        &vault.store,
        &txn,
        ENTITY_TYPE_FEDERATION_GRANT,
        None,
    )? {
        let id = id?;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        } = live_entity_row_in_txn(&vault.store, &txn, &id)?
        else {
            continue;
        };
        let Ok(grant) = decode_federation_grant_body(&body) else {
            continue;
        };
        if is_own_device_grant(&grant) {
            asked
                .entry(id)
                .or_default()
                .insert(grant.member_ref.to_hex());
        }
    }
    Ok(asked)
}

/// Each grant a live slip of this vault's fold names, with the holders
/// (PERSON hex) whose live slip names it. Only a slip a pairing could have
/// bound to an own-device grant counts: a person's (no actor class, or
/// human), with no parent, share or delegation.
fn named_own_device_grants_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<BTreeMap<EntityId, BTreeSet<String>>> {
    let fold = vault.authority_view_readonly_in_txn(txn)?;
    let mut named: BTreeMap<EntityId, BTreeSet<String>> = BTreeMap::new();
    for (slip_id, mint) in &fold.slips.mints {
        let claims = &mint.action.claims;
        let Some(grant_ref) = claims.grant_ref.as_deref() else {
            continue;
        };
        if claims.parent_id.is_some()
            || claims.share_ref.is_some()
            || claims.delegation.is_some()
            || claims
                .actor_class
                .as_deref()
                .is_some_and(|class| class != ACTOR_CLASS_HUMAN)
            || !fold.slip_is_live(slip_id)
        {
            continue;
        }
        let Ok(grant) = EntityId::from_hex(grant_ref) else {
            continue;
        };
        named
            .entry(grant)
            .or_default()
            .insert(claims.holder_ref.clone());
    }
    Ok(named)
}

/// The state of each grant in `asked` that this home serves a linked
/// machine whose proof stands here ([`own_device_grant_states`]). Refused
/// for any other peer, as the authority tail is.
///
/// # Errors
///
/// A refused peer; storage errors.
pub fn own_device_grants_for(
    vault: &Vault,
    peer: PeerMachine,
    asked: &BTreeSet<EntityId>,
) -> Result<Vec<(EntityId, OwnDeviceGrantState)>> {
    require_owner_machine(vault, peer)?;
    own_device_grant_states(vault, asked)
}

/// The state of each grant in `asked`, at most
/// [`OWN_DEVICE_GRANTS_PAGE_MAX`]: a hard tombstone once it is withdrawn
/// here, or its stored row while it stands as the own-device grant of a
/// holder whose live slip here names it ([`named_own_device_grants_in_txn`]).
/// Another kind of row, a member's or a guest's grant, a grant that does not
/// decode, a live grant no live slip names and a grant never held here are
/// left out. The caller has already admitted the machine.
///
/// # Errors
///
/// An authority history this vault cannot fold; storage errors.
pub fn own_device_grant_states(
    vault: &Vault,
    asked: &BTreeSet<EntityId>,
) -> Result<Vec<(EntityId, OwnDeviceGrantState)>> {
    let txn = vault.store.env.read_txn()?;
    let named = named_own_device_grants_in_txn(vault, &txn)?;
    let mut served = Vec::new();
    for id in asked.iter().take(OWN_DEVICE_GRANTS_PAGE_MAX) {
        if EntityStoreRead::port_entity_record(&vault.store, &txn, id)?
            .is_some_and(|row| row.entity_type != ENTITY_TYPE_FEDERATION_GRANT)
        {
            continue;
        }
        let withdrawn = || -> Result<OwnDeviceGrantState> {
            Ok(OwnDeviceGrantState::Withdrawn(
                TombstoneValueV2 {
                    reason: TombstoneReason::UserHardDelete,
                    deleted_at: vault.instant_in_txn(&txn)?.secs(),
                    request_id: *id.as_bytes(),
                }
                .encode()
                .to_vec(),
            ))
        };
        if grant_known_withdrawn_in_txn(&vault.store, &txn, *id)
            || vault.local_hard_delete_marker_exists_in_txn(&txn, id)?
        {
            served.push((*id, withdrawn()?));
            continue;
        }
        match live_entity_row_in_txn(&vault.store, &txn, id)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_FEDERATION_GRANT,
                body,
            } => {
                let Ok(grant) = decode_federation_grant_body(&body) else {
                    continue;
                };
                if is_own_device_grant(&grant)
                    && named
                        .get(id)
                        .is_some_and(|holders| holders.contains(&grant.member_ref.to_hex()))
                    && let Some(raw) = vault.store.port_entity_raw(&txn, id)?
                {
                    served.push((*id, OwnDeviceGrantState::Live(raw.to_vec())));
                }
            }
            LiveEntityRow::DeletedShell => served.push((*id, withdrawn()?)),
            LiveEntityRow::Live { .. } | LiveEntityRow::Absent => {}
        }
    }
    Ok(served)
}

/// Admits what the home served for the grants this machine asked about
/// (`asked`, [`own_device_grant_refs`] read here): each live row of a
/// person's own-device grant whose holder's live slip names it lands through
/// the entity-ingest ladder in its base window, as window sync lands it, and
/// each withdrawal replays through the one tombstone primitive. A grant not
/// asked for, a row of another kind or holder, and a tombstone over a row of
/// another kind are refused, and nothing is written for them.
///
/// The rows and tombstones carry no signature of their own. A row confers
/// nothing beyond the live signed slip of this machine's own fold that binds
/// it, so it lands whichever home served it: a home that has not proved
/// itself yet never keeps the owner from his device (Engine RULING
/// SYNC-HOME-UNANSWERED = B). A replayed withdrawal erases the grant for
/// good, and every later pairing of the owner names the same grant, so a
/// withdrawal replays only while `home`, the machine the answering
/// connection proved, still stands here as a machine of this vault on the
/// key it proved. From any other answerer it is refused and nothing is
/// written; a revoke the owner signs reaches this machine through its
/// authority log instead.
///
/// # Errors
///
/// Storage errors, and a tombstone replay that fails here.
pub fn admit_own_device_grants(
    vault: &Vault,
    home: PeerMachine,
    asked: &BTreeMap<EntityId, BTreeSet<String>>,
    served: Vec<(EntityId, OwnDeviceGrantState)>,
) -> Result<OwnDeviceGrantAdmission> {
    let mut admission = OwnDeviceGrantAdmission::default();
    let home_proven = matches!(vault.peer_machine_stands(home), PeerMachine::Proven { .. });
    for (id, state) in served {
        let Some(holders) = asked.get(&id) else {
            admission.refused.insert(id);
            continue;
        };
        match state {
            OwnDeviceGrantState::Live(row) => {
                if land_grant_row(vault, id, holders, &row)? {
                    admission.landed.insert(id);
                } else {
                    admission.refused.insert(id);
                }
            }
            OwnDeviceGrantState::Withdrawn(tombstone) => {
                if home_proven && replay_withdrawal(vault, id, &tombstone)? {
                    admission.withdrawn.insert(id);
                } else {
                    admission.refused.insert(id);
                }
            }
        }
    }
    Ok(admission)
}

/// Lands `row` as grant `id` through the entity-ingest ladder when it is a
/// person's own-device grant held by one of `holders`. Whether the row
/// stands here now.
fn land_grant_row(
    vault: &Vault,
    id: EntityId,
    holders: &BTreeSet<String>,
    row: &[u8],
) -> Result<bool> {
    let Some(header) = EntityMetadataHeader::parse(row) else {
        return Ok(false);
    };
    if header.entity_type != ENTITY_TYPE_FEDERATION_GRANT {
        return Ok(false);
    }
    let Some(Ok(grant)) = row
        .get(ENTITY_METADATA_HEADER_LEN..)
        .map(decode_federation_grant_body)
    else {
        return Ok(false);
    };
    if !is_own_device_grant(&grant) || !holders.contains(&grant.member_ref.to_hex()) {
        return Ok(false);
    }
    // No window document rides with the row: its tombstones are this
    // vault's own delete markers, which the ladder reads beside an empty map.
    let carrier = loro::LoroDoc::new();
    let tombstones = TombstoneIndex::build(&carrier.get_map("tombstones"));
    let window = WindowKey::from_timestamp(header.learned_at);
    let ingest = IngestCtx::new(
        vault,
        &window.0,
        crate::sync::lease::DEFAULT_LEASE_VAULT_ID,
        &tombstones,
    );
    let key = id.to_hex();
    let _import = crate::sync::manager::import_scope();
    let steps = vault.with_write_txn_grouped(|wtxn| {
        ingest_rows_in_savepoint(&ingest, wtxn, &[(key.as_str(), Some(row))])
    })?;
    Ok(matches!(
        steps.first(),
        Some(EntityStep::Materialized(landed) | EntityStep::Unchanged(landed)) if *landed == id
    ))
}

/// Replays the withdrawal of grant `id` as the tombstone `value`, unless
/// this vault already holds its hard-delete marker. Refused, writing
/// nothing, when the row stored at `id` is another kind. Whether the
/// withdrawal stands here now.
fn replay_withdrawal(vault: &Vault, id: EntityId, value: &[u8]) -> Result<bool> {
    {
        let txn = vault.store.env.read_txn()?;
        if EntityStoreRead::port_entity_record(&vault.store, &txn, &id)?
            .is_some_and(|row| row.entity_type != ENTITY_TYPE_FEDERATION_GRANT)
        {
            return Ok(false);
        }
        if vault.local_hard_delete_marker_exists_in_txn(&txn, &id)? {
            return Ok(true);
        }
    }
    vault.apply_replayed_tombstone(&id, value)?;
    Ok(true)
}
