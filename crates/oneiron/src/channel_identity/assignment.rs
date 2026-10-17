//! Two-slot channel assignment index. Routing never ranks caller timestamps or IDs.
//!
//! A slot sits at the pair the identity's channel and address heads name
//! (OF-272), not the pair its row was born with: a claim correction that
//! moves either head re-keys the slot before its write commits.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CHANNEL_IDENTITY, ENTITY_TYPE_CLAIM};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;

use super::address::AssignmentKey;
use super::codec::{decode_channel_identity_body, is_channel_identity_claim_predicate};
use super::facts::{ChannelIdentityFacts, assignment_heads_in_txn, channel_identity_facts_in_txn};
use super::lifecycle::ChannelIdentityState;
use super::record::ChannelIdentity;

/// One assignment key's two slots: occupant id then predecessor id, zeros for an empty slot.
const SLOTS: SideTable<[u8; 32], [u8; 32], Raw> =
    SideTable::new(&side_table::CHANNEL_IDENTITY_ASSIGNMENT);
/// Deletion evidence for a retained header-only shell, staged with slot removal.
const ERASED: SideTable<EntityId, [u8; 1], Raw> =
    SideTable::new(&side_table::CHANNEL_IDENTITY_ASSIGNMENT_ERASED);

/// The only two rows allowed to influence a mailbox route. A predecessor is
/// a retiring delegated row; it never occupies the mailbox for re-consent.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
struct AssignmentSlot {
    occupant: Option<EntityId>,
    predecessor: Option<EntityId>,
}

/// Whether a claim correction that moves an identity to another pair frees
/// the pair it left (OF-272). The identity never really had that pair, so it
/// routes nothing there; freeing lets another identity take it. `false`
/// keeps it held by this id, as a self-held delete keeps its address.
const FREE_PAIR_LEFT_BY_CORRECTION: bool = true;

/// Where an identity's heads put its slot.
enum HeadsKey {
    /// One live channel head and one live address head.
    Settled(AssignmentKey),
    /// Neither: a family never seeded, or one withdrawn.
    Absent,
    /// One without the other, or two of either: a correction in flight.
    Unsettled,
}

fn heads_key(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<HeadsKey> {
    let (channels, addresses) = assignment_heads_in_txn(store, txn, id)?;
    Ok(match (channels.as_slice(), addresses.as_slice()) {
        ([], []) => HeadsKey::Absent,
        ([channel], [address]) => HeadsKey::Settled(AssignmentKey::of(channel, address)),
        _ => HeadsKey::Unsettled,
    })
}

fn unsettled() -> Error {
    Error::CorruptedIndex("channel identity channel or address heads unsettled")
}

fn index_key(key: &AssignmentKey) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let channel = key.channel().as_bytes();
    let address = key.address_or_handle().as_bytes();
    hasher.update(&(channel.len() as u64).to_be_bytes());
    hasher.update(channel);
    hasher.update(&(address.len() as u64).to_be_bytes());
    hasher.update(address);
    *hasher.finalize().as_bytes()
}

fn decode_id(bytes: &[u8]) -> Result<Option<EntityId>> {
    if bytes == [0; 16] {
        return Ok(None);
    }
    let raw: [u8; 16] = bytes
        .try_into()
        .map_err(|_| Error::CorruptedIndex("channel assignment slot"))?;
    EntityId::from_bytes(raw)
        .map(Some)
        .map_err(|_| Error::CorruptedIndex("channel assignment slot"))
}

fn read_slot(store: &Store, txn: &heed::RoTxn<'_>, key: &AssignmentKey) -> Result<AssignmentSlot> {
    let Some(value) = SLOTS.get(store, txn, &index_key(key))? else {
        return Ok(AssignmentSlot::default());
    };
    Ok(AssignmentSlot {
        occupant: decode_id(&value[..16])?,
        predecessor: decode_id(&value[16..])?,
    })
}

fn write_slot(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &AssignmentKey,
    slot: AssignmentSlot,
) -> Result<()> {
    let mut value = [0_u8; 32];
    if let Some(id) = slot.occupant {
        value[..16].copy_from_slice(id.as_bytes());
    }
    if let Some(id) = slot.predecessor {
        value[16..].copy_from_slice(id.as_bytes());
    }
    SLOTS.put(store, txn, &index_key(key), &value)?;
    Ok(())
}

/// Read a row named by an index slot, refusing a dangling index or a row of
/// another kind, with the identity's claim facts (OF-272). The facts say
/// which channel, address and state the identity has, so they key the slot;
/// the row keeps custody, and its own pair is never compared. Facts that are
/// absent, or name another key, route nothing at this key, though the slot
/// still holds the address against reuse.
fn read_indexed_row(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &AssignmentKey,
    id: EntityId,
) -> Result<(ChannelIdentity, Option<ChannelIdentityFacts>)> {
    let raw = store
        .port_entity_record(txn, &id)?
        .map(|row| row.encode())
        .ok_or(Error::CorruptedIndex(
            "channel assignment references absent identity",
        ))?;
    let header = EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("channel assignment header"))?;
    if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Err(Error::CorruptedIndex("channel assignment row kind"));
    }
    let row = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    let facts = channel_identity_facts_in_txn(store, txn, &id)?
        .filter(|facts| &AssignmentKey::of(&facts.channel, &facts.address_or_handle) == key);
    Ok((row, facts))
}

/// The live occupant or the last retiring delegated predecessor. A pending
/// occupant does not hide in-flight inbound addressed to the predecessor.
/// Each state is the identity's state head; whether a predecessor was
/// delegated is its custody's answer, never a claim's.
pub(super) fn by_assignment(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &AssignmentKey,
) -> Result<Option<(EntityId, ChannelIdentity)>> {
    let slot = read_slot(store, txn, key)?;
    let occupant = match slot.occupant {
        // A deleted self-held row's hold on its address routes nothing.
        Some(id) if ERASED.get(store, txn, &id)?.is_some() => None,
        held => held
            .map(|id| read_indexed_row(store, txn, key, id).map(|(row, facts)| (id, row, facts)))
            .transpose()?,
    };
    if let Some((id, row, Some(facts))) = &occupant
        && matches!(
            facts.state,
            ChannelIdentityState::Active
                | ChannelIdentityState::Rotating
                | ChannelIdentityState::Released
                | ChannelIdentityState::Quarantine
        )
    {
        return Ok(Some((*id, row.clone())));
    }
    if let Some(id) = slot.predecessor {
        let (row, facts) = read_indexed_row(store, txn, key, id)?;
        if row.is_delegated()
            && facts.is_some_and(|facts| facts.state == ChannelIdentityState::Released)
        {
            return Ok(Some((id, row)));
        }
    }
    Ok(occupant.and_then(|(id, row, facts)| facts.map(|_| (id, row))))
}

/// Cheap preflight for typed writers. The put door independently maintains
/// and enforces the same slot under the write transaction. A stored identity
/// is checked at its heads' pair; a born one's heads are seeded from this
/// body in the same write, so its own pair is the one it takes.
pub(super) fn conflicts(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    row: &ChannelIdentity,
) -> Result<bool> {
    if !row.occupies_assignment_key() {
        return Ok(false);
    }
    let key = match heads_key(store, txn, id)? {
        HeadsKey::Settled(key) => key,
        HeadsKey::Absent => row.assignment_key(),
        // The put door refuses this write itself.
        HeadsKey::Unsettled => return Ok(false),
    };
    let slot = read_slot(store, txn, &key)?;
    Ok(slot.occupant.is_some_and(|other| other != *id))
}

/// The one slot law for put, claim re-key and rebuild (OF-272). An occupying
/// identity takes the occupant slot and never evicts another occupant. A
/// retiring delegated identity leaves the occupant slot for the predecessor
/// one, never evicting an occupant, and only with `held`: proof it occupied
/// or retired from this pair, or from the pair a correction moved it off.
/// A retiring identity born at a fresh id has no such proof.
fn stage_assignment_slot(
    slot: &mut AssignmentSlot,
    id: EntityId,
    occupies: bool,
    held: bool,
) -> Result<()> {
    if occupies {
        if slot.occupant.is_some_and(|other| other != id) {
            return Err(Error::Record(RecordError::ChannelIdentityAlreadyExists));
        }
        slot.occupant = Some(id);
    } else if slot.occupant == Some(id) {
        slot.occupant = None;
        slot.predecessor = Some(id);
    } else if held {
        slot.predecessor = Some(id);
    } else {
        return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
            "retired delegated identity must have occupied this assignment",
        )));
    }
    Ok(())
}

/// Stages `id` at `key` under [`stage_assignment_slot`], first taking it out
/// of every other pair it is in: its heads moved, so it routes nothing there
/// (see [`FREE_PAIR_LEFT_BY_CORRECTION`]). Only this id's references go; an
/// unrelated occupant or predecessor stays and an emptied slot is deleted.
/// This is a move, not a delete: no hold is kept and nothing is marked
/// erased. `known` says the row existed before this write, which a held
/// reference needs to count as proof.
fn move_assignment_slot(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    key: &AssignmentKey,
    occupies: bool,
    known: bool,
) -> Result<()> {
    let own = index_key(key);
    let mut left = Vec::new();
    for item in SLOTS.iter_from(store, &*txn, &[])? {
        let (at, mut slot) = item?;
        let (occupant, predecessor) = slot.split_at_mut(16);
        if at == own || (occupant != id.as_bytes() && predecessor != id.as_bytes()) {
            continue;
        }
        for half in [occupant, predecessor] {
            if half == id.as_bytes() {
                half.fill(0);
            }
        }
        left.push((at, slot));
    }
    let moved = !left.is_empty();
    if FREE_PAIR_LEFT_BY_CORRECTION {
        for (at, slot) in left {
            if slot == [0; 32] {
                SLOTS.delete(store, txn, &at)?;
            } else {
                SLOTS.put(store, txn, &at, &slot)?;
            }
        }
    }
    let mut slot = read_slot(store, txn, key)?;
    let held = known && (moved || slot.predecessor == Some(*id));
    stage_assignment_slot(&mut slot, *id, occupies, held)?;
    write_slot(store, txn, key, slot)
}

/// Enforce occupancy and stage the slot in the SAME write transaction as the
/// body. A retiring body at a fresh ID has no prior row and is refused. The
/// slot goes where the identity's heads say, which the family door seeds
/// from the body before it writes the row; a row with no heads takes none.
pub(crate) fn maintain_assignment_put(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    bytes: &[u8],
) -> Result<()> {
    let next = decode_channel_identity_body(bytes)?;
    let prior = store.port_entity_record(txn, id)?.map(|row| row.encode());
    if let Some(raw) = &prior {
        let header = EntityMetadataHeader::parse(raw)
            .ok_or(Error::CorruptedIndex("channel assignment prior header"))?;
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::CorruptedIndex("channel assignment prior kind"));
        }
        let old = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if old.assignment_key() != next.assignment_key()
            || old.shape() != next.shape()
            || old.grant() != next.grant()
            || old.binding() != next.binding()
        {
            return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                "channel identity assignment, custody and binding are immutable",
            )));
        }
    } else if next.is_delegated() && next.state() != ChannelIdentityState::Requested {
        return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
            "delegated identity must be born Requested",
        )));
    }
    let key = match heads_key(store, txn, id)? {
        HeadsKey::Settled(key) => Some(key),
        HeadsKey::Absent => None,
        HeadsKey::Unsettled => return Err(unsettled()),
    };
    // A deleted self-held id still holds its own address. Coming back on
    // another one would drop that hold with its marker, and coming back
    // delegated would make it a hold the next delete frees (H102).
    if ERASED.get(store, txn, id)?.is_some() {
        let own = key.as_ref().map(index_key);
        for item in SLOTS.iter_from(store, &*txn, &[])? {
            let (held, slot) = item?;
            if slot[..16] == *id.as_bytes() && (Some(held) != own || next.is_delegated()) {
                return Err(Error::Record(RecordError::InvalidChannelIdentityBody(
                    "channel identity assignment, custody and binding are immutable",
                )));
            }
        }
    }
    if let Some(key) = key {
        move_assignment_slot(
            store,
            txn,
            id,
            &key,
            next.occupies_assignment_key(),
            prior.is_some(),
        )?;
    }
    // A newly admitted row at a formerly erased id is live again.
    ERASED.delete(store, txn, id)?;
    Ok(())
}

/// Re-keys one identity's slot from its final channel and address heads
/// (OF-272), once a write unit has staged all its claim rows, edges and
/// closures. Whether it occupies is its row's custody answer; the pair is
/// its heads'. Nothing moves, and the slot keeps holding its pair, for
/// anything but a live identity (absent, a deleted shell, another kind) or
/// for heads that settle on no single pair: none, withdrawn, or a
/// correction still in flight across transactions. No pair is ever taken
/// from the row. A slot conflict is returned so the whole write rolls back.
fn reconcile_assignment_from_claim_heads_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(row) = store.port_entity_record(txn, id)? else {
        return Ok(());
    };
    if row.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY || ERASED.get(store, txn, id)?.is_some() {
        return Ok(());
    }
    let identity = decode_channel_identity_body(&row.body)?;
    let HeadsKey::Settled(key) = heads_key(store, txn, id)? else {
        return Ok(());
    };
    move_assignment_slot(
        store,
        txn,
        id,
        &key,
        identity.occupies_assignment_key(),
        true,
    )
}

/// Identities a CLAIM put moved a `channel_identity.*` head of, per store
/// environment: one write transaction's set, since LMDB runs one write
/// transaction per environment at a time. Only a write unit that opened
/// [`AssignmentRekeys`] has an entry.
type PendingRekeys = BTreeMap<usize, BTreeSet<EntityId>>;

static PENDING_REKEYS: Mutex<PendingRekeys> = Mutex::new(BTreeMap::new());

fn pending_rekeys<T>(f: impl FnOnce(&mut PendingRekeys) -> T) -> T {
    f(&mut PENDING_REKEYS
        .lock()
        .unwrap_or_else(PoisonError::into_inner))
}

fn pending_key(store: &Store) -> usize {
    // Identity only: never dereferenced or kept past the write unit.
    std::ptr::from_ref(&store.env) as usize
}

/// A write unit's assignment re-key (OF-272). The owner of a raw write
/// transaction that may write `channel_identity.*` claims opens it with the
/// transaction and finishes it once, right before commit, after the whole
/// logical write. One opened inside an open one joins it, so only the
/// outermost owner re-keys. Dropping an unfinished owner (an abort, an
/// error, an unwind) discards what it noted, so nothing reaches the next
/// transaction.
#[must_use]
pub(crate) struct AssignmentRekeys {
    key: usize,
    owner: bool,
}

impl AssignmentRekeys {
    pub(crate) fn begin(store: &Store) -> Self {
        let key = pending_key(store);
        let owner = pending_rekeys(|pending| {
            if pending.contains_key(&key) {
                return false;
            }
            pending.insert(key, BTreeSet::new());
            true
        });
        Self { key, owner }
    }

    /// Re-keys every identity noted since [`Self::begin`] from its final
    /// heads in `txn`. An error (a slot conflict is
    /// [`RecordError::ChannelIdentityAlreadyExists`]) must roll the write back.
    pub(crate) fn finish(mut self, store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
        if !self.owner {
            return Ok(());
        }
        self.owner = false;
        let noted = pending_rekeys(|pending| pending.remove(&self.key)).unwrap_or_default();
        for id in &noted {
            reconcile_assignment_from_claim_heads_in_txn(store, txn, id)?;
        }
        Ok(())
    }
}

impl Drop for AssignmentRekeys {
    fn drop(&mut self) {
        if self.owner {
            pending_rekeys(|pending| {
                pending.remove(&self.key);
            });
        }
    }
}

/// Notes, for the open [`AssignmentRekeys`], the identity a CLAIM put writes
/// a `channel_identity.*` head for and the one the claim it overwrites was
/// about. The put chokepoint calls it before the new body lands; with no
/// re-key open it reads and records nothing.
pub(crate) fn note_claim_put_for_rekey(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: Option<&ClaimBody>,
) -> Result<()> {
    let Some(body) = body else {
        return Ok(());
    };
    let key = pending_key(store);
    if !pending_rekeys(|pending| pending.contains_key(&key)) {
        return Ok(());
    }
    let mut noted = Vec::new();
    noted.extend(rekey_subject(body));
    if let Some(prior) = store.port_entity_record(txn, id)?
        && prior.entity_type == ENTITY_TYPE_CLAIM
        && let Ok(old) = crate::claim::decode_claim_body(&prior.body, true)
    {
        noted.extend(rekey_subject(&old));
    }
    pending_rekeys(|pending| {
        if let Some(set) = pending.get_mut(&key) {
            set.extend(noted);
        }
    });
    Ok(())
}

fn rekey_subject(body: &ClaimBody) -> Option<EntityId> {
    match body.subject {
        ClaimSubject::Entity(subject) if is_channel_identity_claim_predicate(&body.predicate) => {
            Some(subject)
        }
        _ => None,
    }
}

/// Clears every reference to a deleted ChannelIdentity before its body is
/// removed or soft-erased. The caller supplies the stored type while the row
/// is still readable, and stages this in the SAME write transaction as deletion.
///
/// Scan the small assignment projection rather than deriving just one key
/// from the body: a damaged body or stray second slot must not leave a dangling
/// occupant or predecessor behind. A successor in the other slot is preserved.
///
/// A self-held row holds its address forever (never-recycle), so its delete
/// keeps it as the key's occupant: the record goes, the address stays bound to
/// the deleted id, and a fresh id is refused (H102). The deletion marker below
/// is what tells readers that occupant routes nothing. A delegated row frees
/// its key, as its retirement does.
pub(crate) fn clear_assignment_for_delete(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> Result<()> {
    if entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Ok(());
    }
    let holds_address = match store.port_entity_record(txn, id)? {
        Some(row) => match decode_channel_identity_body(&row.body) {
            Ok(row) => !row.is_delegated(),
            // A soft erase's shell kept the hold it took then.
            Err(_) => ERASED.get(store, txn, id)?.is_some(),
        },
        None => false,
    };
    let mut changed = Vec::new();
    for item in SLOTS.iter_from(store, &*txn, &[])? {
        let (key, mut slot) = item?;
        let mut touched = false;
        let (occupant, predecessor) = slot.split_at_mut(16);
        if occupant == id.as_bytes() && !holds_address {
            occupant.fill(0);
            touched = true;
        }
        if predecessor == id.as_bytes() {
            predecessor.fill(0);
            touched = true;
        }
        if touched {
            changed.push((key, slot));
        }
    }
    for (key, slot) in changed {
        if slot == [0; 32] {
            SLOTS.delete(store, txn, &key)?;
        } else {
            SLOTS.put(store, txn, &key, &slot)?;
        }
    }
    // Soft erase retains the type-index row and a metadata-only shell. This
    // marker proves that empty body was deleted rather than live corruption,
    // and on either tier marks a kept occupant as a hold. It is retired on put.
    ERASED.put(store, txn, id, &[1])?;
    Ok(())
}

/// Closes a deleted ChannelIdentity's own `channel_identity.*` heads, the
/// claim half of [`clear_assignment_for_delete`] (OF-272). The caller stages
/// it in the SAME write transaction as the deletion, with the type it read
/// while the row was still readable, and BEFORE the deletion tears the
/// `claim_of` edges the heads are found by: each live head is closed
/// `retracted` at `now` on the family's engine-owned setting, so a deleted
/// identity has no live facts and its heads leave the live postings. Other
/// kinds are left alone.
pub(crate) fn close_claim_heads_for_delete_in_txn(
    writer: &crate::counterparty_contact::ClaimHeadWriter<'_>,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    now: u64,
) -> Result<()> {
    if entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
        return Ok(());
    }
    writer.retract_subject_heads_in_txn(
        txn,
        id,
        super::codec::is_channel_identity_claim_predicate,
        now,
    )?;
    Ok(())
}

/// Explicit CID-7 recovery. Only this door scans stored rows; normal routing
/// and write admission use the index. Pre-release vaults have no ABI migration.
pub(super) fn rebuild(store: &Store, txn: &mut heed::RwTxn<'_>) -> Result<()> {
    // A deleted self-held row's hold has no row left to rebuild it from, so
    // recovery carries it over.
    let mut holds = Vec::new();
    for item in SLOTS.iter_from(store, &*txn, &[])? {
        let (key, slot) = item?;
        if let Some(id) = decode_id(&slot[..16])?
            && ERASED.get(store, txn, &id)?.is_some()
        {
            let mut held = [0_u8; 32];
            held[..16].copy_from_slice(id.as_bytes());
            holds.push((key, held));
        }
    }
    SLOTS.delete_from(store, txn, &[])?;
    for (key, held) in holds {
        SLOTS.put(store, txn, &key, &held)?;
    }
    let mut rows = Vec::new();
    for item in store.port_entity_ids_by_type(txn, ENTITY_TYPE_CHANNEL_IDENTITY, None)? {
        let id = item?;
        let raw = store
            .port_entity_record(txn, &id)?
            .map(|row| row.encode())
            .ok_or(Error::CorruptedIndex(
                "channel identity type index dangling",
            ))?;
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("channel identity header"))?;
        if header.entity_type != ENTITY_TYPE_CHANNEL_IDENTITY {
            return Err(Error::CorruptedIndex("channel identity type index kind"));
        }
        // A canonical soft deletion retains a header-only shell and a marker
        // staged in the SAME deletion transaction. Header-only corruption of a
        // live row has no marker and remains a recovery error.
        if raw.len() == ENTITY_METADATA_HEADER_LEN {
            match ERASED.get(store, txn, &id)? {
                Some([1]) => continue,
                _ => {
                    return Err(Error::CorruptedIndex(
                        "channel identity shell without deletion",
                    ));
                }
            }
        }
        let row = decode_channel_identity_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        rows.push((header.learned_at, id, row));
    }
    rows.sort_unstable_by_key(|(learned, id, _)| (*learned, *id));
    for (_, id, row) in rows {
        // The pair is the identity's heads' (OF-272). Heads that settle on
        // none give no slot: recovery never takes a pair from the row.
        let key = match heads_key(store, txn, &id)? {
            HeadsKey::Settled(key) => key,
            HeadsKey::Absent => continue,
            HeadsKey::Unsettled => return Err(unsettled()),
        };
        let mut slot = read_slot(store, txn, &key)?;
        stage_assignment_slot(&mut slot, id, row.occupies_assignment_key(), true)?;
        write_slot(store, txn, &key, slot)?;
    }
    Ok(())
}
