//! The target index's seal (FIX 4296): a running digest over every control
//! put one target's machine-history index takes, kept in the writer that
//! takes it, so it commits or rolls back with the put.
//!
//! Each put chains the control's id and its body as the codec writes it.
//! Two equal seals name the same puts in the same order, and a control's
//! row is immutable under its content-addressed id, so a reader that carried
//! what it read at one seal reads only what was put since
//! (`history_advance`). A control's delete scatters its target's seal and a
//! history's retire drops it, so no carried read outlives its row.
//!
//! Beside the seal, each target keeps a gate fingerprint (FIX 12374): the
//! seal, the pin's content hash, the vault-wide gate sequence and the settled
//! verdict the carrier loop proved for that exact triple, so an adoption
//! whose inputs have not moved skips re-reading every carrier's gate rows.
//! The sequence bumps in the writer that takes any gate write; any absence,
//! decode failure or mismatch falls back to today's loop, and only the
//! adoption repair writes the row. Both are local `vault_meta` state, never
//! replicated and never read from a peer packet.

use rand_core::RngCore;

use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result, StoreError};
use crate::side_table::{Raw, SideTable};
use crate::store::Store;

use super::ClaimBody;
use super::history_store::machine_history_kind;

const SEAL: SideTable<EntityId, [u8; 40], Raw> =
    SideTable::new(&crate::side_table::CLAIM_MACHINE_HISTORY_SEAL);
const SEAL_DOMAIN: &str = "oneiron/machine-history-index-seal/v1";
const GATE_FINGERPRINT: SideTable<EntityId, [u8; 81], Raw> =
    SideTable::new(&crate::side_table::CLAIM_MACHINE_HISTORY_GATE_FINGERPRINT);
const GATE_SEQUENCE: SideTable<(), u64, Raw> =
    SideTable::new(&crate::side_table::CLAIM_MACHINE_HISTORY_GATE_SEQUENCE);

/// How many control puts a target's index took, and their chained digest.
/// The default is a target no put reached.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct IndexSeal {
    puts: u64,
    digest: [u8; 32],
}

impl IndexSeal {
    /// The seal after one more put: the control `id`, whose body digest
    /// ([`control_body_digest`]) is `body`.
    pub(crate) fn after(self, id: EntityId, body: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(SEAL_DOMAIN);
        hasher.update(&self.digest);
        hasher.update(id.as_bytes());
        hasher.update(body);
        Self {
            puts: self.puts.saturating_add(1),
            digest: *hasher.finalize().as_bytes(),
        }
    }

    fn encode(self) -> [u8; 40] {
        let mut out = [0; 40];
        out[..8].copy_from_slice(&self.puts.to_be_bytes());
        out[8..].copy_from_slice(&self.digest);
        out
    }

    fn decode(bytes: [u8; 40]) -> Self {
        let mut puts = [0; 8];
        puts.copy_from_slice(&bytes[..8]);
        let mut digest = [0; 32];
        digest.copy_from_slice(&bytes[8..]);
        Self {
            puts: u64::from_be_bytes(puts),
            digest,
        }
    }
}

/// The digest a control's put chains into its target's seal: its body as
/// the claim codec writes it.
pub(crate) fn control_body_digest(body: &ClaimBody) -> Result<[u8; 32]> {
    Ok(*blake3::hash(&super::encode_claim_body(body)?).as_bytes())
}

/// `target`'s index seal in `txn`.
pub(crate) fn read_index_seal(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<IndexSeal> {
    Ok(SEAL
        .get(store, txn, &target)?
        .map(IndexSeal::decode)
        .unwrap_or_default())
}

/// Chains one control put, `id` with `body`, into `target`'s seal, in the
/// writer that puts it.
pub(crate) fn chain_index_seal_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    target: EntityId,
    id: EntityId,
    body: &ClaimBody,
) -> Result<()> {
    let seal = read_index_seal(store, wtxn, target)?.after(id, &control_body_digest(body)?);
    SEAL.put(store, wtxn, &target, &seal.encode())
}

/// Drops `target`'s seal and its gate fingerprint with its index, when its history retires.
pub(crate) fn drop_index_seal_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    target: EntityId,
) -> Result<()> {
    SEAL.delete(store, wtxn, &target)?;
    drop_gate_fingerprint_in_txn(store, wtxn, target)
}

/// Before the row at `id` is deleted: when it is a machine-history control,
/// its target's seal, if any, takes a random digest, so no read carried at
/// an earlier seal stands for the deleted row. Any other row is left alone.
pub(crate) fn scatter_index_seal_for_delete(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, id)? else {
        return Ok(());
    };
    if !EntityMetadataHeader::parse(&raw)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
    {
        return Ok(());
    }
    let Ok(body) = super::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true) else {
        return Ok(());
    };
    let (Some(_), super::ClaimSubject::Entity(target)) =
        (machine_history_kind(&body.predicate), body.subject)
    else {
        return Ok(());
    };
    // The deleted control moves its target's history: the fingerprint goes
    // beside the seal, so no later reader trusts the earlier verdict.
    drop_gate_fingerprint_in_txn(store, wtxn, target)?;
    let Some(stored) = SEAL.get(store, wtxn, &target)? else {
        return Ok(());
    };
    let mut seal = IndexSeal::decode(stored);
    rand_core::OsRng.fill_bytes(&mut seal.digest);
    SEAL.put(store, wtxn, &target, &seal.encode())
}

/// The gate verdict a carrier loop proved for one exact triple (FIX 12374):
/// the target's seal, its pin's content hash and the vault-wide gate
/// sequence. 81 bytes: the seal's 40, the pin hash's 32, the sequence as u64
/// BE, and the verdict (`1` settled, `0` held).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateFingerprint {
    seal: IndexSeal,
    pin: [u8; 32],
    gate: u64,
    settled: bool,
}

impl GateFingerprint {
    fn encode(self) -> [u8; 81] {
        let mut out = [0; 81];
        out[..40].copy_from_slice(&self.seal.encode());
        out[40..72].copy_from_slice(&self.pin);
        out[72..80].copy_from_slice(&self.gate.to_be_bytes());
        out[80] = u8::from(self.settled);
        out
    }

    fn decode(bytes: &[u8; 81]) -> Option<Self> {
        let seal = IndexSeal::decode(bytes[..40].try_into().ok()?);
        let pin: [u8; 32] = bytes[40..72].try_into().ok()?;
        let gate = u64::from_be_bytes(bytes[72..80].try_into().ok()?);
        let settled = match bytes[80] {
            0 => false,
            1 => true,
            _ => return None,
        };
        Some(Self {
            seal,
            pin,
            gate,
            settled,
        })
    }
}

/// Whether `error` is a row that does not decode, as opposed to a storage
/// failure: the fingerprint reader falls back on the former only.
fn is_row_decode(error: &Error) -> bool {
    matches!(error, Error::Store(StoreError::SideTableRow { .. }))
}

/// `target`'s gate fingerprint row, when one is stored and decodes. Absence
/// or a row that does not decode is `None`: the reader runs today's carrier
/// loop. A storage failure still fails.
pub(crate) fn read_gate_fingerprint(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<Option<GateFingerprint>> {
    match GATE_FINGERPRINT.get(store, txn, &target) {
        Ok(row) => Ok(row.and_then(|bytes| GateFingerprint::decode(&bytes))),
        Err(error) if is_row_decode(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The vault-wide gate sequence: how many gate writes landed since the last
/// clear. Absent reads as 0: no gate write yet, or a clear. Every writer
/// writes exactly eight bytes, so a row that does not decode fails, as a
/// seal row that does not decode does.
pub(crate) fn read_gate_sequence(store: &Store, txn: &heed::RoTxn<'_>) -> Result<u64> {
    Ok(GATE_SEQUENCE.get(store, txn, &())?.unwrap_or(0))
}

/// Whether `target`'s stored fingerprint proves today's gate verdict without
/// the carrier loop: the echoed seal, pin hash and gate sequence all match
/// what `txn` reads now. `Some(settled)` on a full match; `None` on any
/// absence, decode failure or mismatch, or when no pin is stored, and the
/// caller runs today's loop unchanged. A storage failure still fails.
pub(crate) fn matching_gate_verdict(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    target: EntityId,
) -> Result<Option<bool>> {
    let seal = match read_index_seal(store, txn, target) {
        Ok(seal) => seal,
        Err(error) if is_row_decode(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(raw) = store
        .vault_meta
        .get(txn, &super::history_projection::pin_key(target))?
    else {
        return Ok(None);
    };
    let pin = super::ClaimHistoryHandoff::decode(&raw)
        .ok()
        .and_then(|packet| packet.content_hash().ok());
    let Some(pin) = pin else {
        return Ok(None);
    };
    let gate = match read_gate_sequence(store, txn) {
        Ok(gate) => gate,
        Err(error) if is_row_decode(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(stored) = read_gate_fingerprint(store, txn, target)? else {
        return Ok(None);
    };
    Ok((stored.seal == seal && stored.pin == pin && stored.gate == gate).then_some(stored.settled))
}

/// Stores `target`'s fingerprint for the verdict just proved, over the seal,
/// pin and gate sequence `wtxn` reads now. An input the writer cannot read
/// (no pin yet, a row that does not decode) skips the store, and the next
/// adoption repairs it. Called only after a successful
/// `resolved_machine_history_from`, before the heal put.
pub(crate) fn store_gate_fingerprint_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    target: EntityId,
    settled: bool,
) -> Result<()> {
    let seal = match read_index_seal(store, wtxn, target) {
        Ok(seal) => seal,
        Err(error) if is_row_decode(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let Some(raw) = store
        .vault_meta
        .get(wtxn, &super::history_projection::pin_key(target))?
    else {
        return Ok(());
    };
    let pin = super::ClaimHistoryHandoff::decode(&raw)
        .ok()
        .and_then(|packet| packet.content_hash().ok());
    let Some(pin) = pin else {
        return Ok(());
    };
    let gate = match read_gate_sequence(store, wtxn) {
        Ok(gate) => gate,
        Err(error) if is_row_decode(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    GATE_FINGERPRINT.put(
        store,
        wtxn,
        &target,
        &GateFingerprint {
            seal,
            pin,
            gate,
            settled,
        }
        .encode(),
    )
}

/// Drops `target`'s fingerprint row beside its seal, when its history
/// retires or one of its controls is deleted.
pub(crate) fn drop_gate_fingerprint_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    target: EntityId,
) -> Result<()> {
    GATE_FINGERPRINT.delete(store, wtxn, &target)?;
    Ok(())
}

/// Bumps the vault-wide gate sequence in the writer that took a gate write.
/// Exactly the four leaf writers call this (obligation put/delete, tray
/// put/remove); nested leaf writes in one transaction bump once each, which
/// only invalidates conservatively. On `u64` overflow every fingerprint row
/// and the counter go, so later reads fall back to the loop and a later bump
/// starts from the empty state: no wrap, no refusal, no clock.
pub(crate) fn bump_gate_sequence_in_txn(store: &Store, wtxn: &mut heed::RwTxn<'_>) -> Result<()> {
    match read_gate_sequence(store, wtxn)?.checked_add(1) {
        Some(next) => GATE_SEQUENCE.put(store, wtxn, &(), &next),
        None => {
            GATE_FINGERPRINT.delete_from(store, wtxn, &[])?;
            GATE_SEQUENCE.delete(store, wtxn, &())?;
            Ok(())
        }
    }
}
