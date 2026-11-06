//! Which machine wrote a MESSAGE row's exact bytes (FIX 12113).
//!
//! The own-device lane (`own_device`) admits a replicated MESSAGE in the
//! owner's `user` bucket. A proven connection shows only which own machine
//! relayed the row, and the peer origin record that keeps a federation
//! peer's row apart is a second window root map: an LWW race between that
//! map and `entities` can leave a peer's bytes with no origin beside them.
//! So the lane also asks for the writer's own proof of the exact bytes.
//!
//! A writer proof is the writing machine's Ed25519 signature, with its
//! machine key, over this module's domain, the vault's genesis-bound id, the
//! writer, the row id and the BLAKE3 digest of the whole row (header and
//! body) as the window carries it. It rides in the window root map
//! [`MESSAGE_WRITER_MAP`] under the row id. It names the digest it signs, so
//! a proof that a race left beside other bytes proves nothing: a split can
//! withhold the lane, never grant it.
//!
//! This machine signs only a row its own local put wrote: the put records
//! the staged row's digest ([`note_message_put_in_txn`]), and the reverse
//! scan signs the row it publishes only while that record names its bytes
//! ([`publish_writer_proof`]). A replicated put the lane admitted records the
//! writer's proof instead, which the scan publishes again as it came; any
//! other replicated put records nothing. No pass signs bytes it did not
//! write, whatever its store holds. The record is this install's own: no
//! checkpoint images it, and a removed carrier takes it.

use heed::{RoTxn, RwTxn};
use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;
use crate::sync::loro_support::{
    map_delete, map_for_each_value_bytes, map_get_bytes, map_insert_bytes,
};
use crate::{EntityId, Vault};

/// The window root map that carries, under a MESSAGE row's id, its writer's
/// proof of the row's exact bytes (FIX 12113; the wire key).
pub(in crate::sync) const MESSAGE_WRITER_MAP: &str = "message_writers";

/// The domain a writer proof's signature is bound to.
const DOMAIN: &[u8] = b"oneiron/sync-message-writer/v1";

/// Which machine wrote the MESSAGE row this install stores, by its id: the
/// row's digest (32 bytes) for a row this install's local put wrote, or a
/// whole proof ([`PROOF_LEN`] bytes) for a row the own-device lane admitted.
/// Key: hex32 (MESSAGE id).
const WRITTEN: SideTable<HexId, Vec<u8>, Raw> = SideTable::new(&side_table::SYNC_MESSAGE_WRITER);

/// A proof's bytes: the row digest, the writer machine, the signature.
const PROOF_LEN: usize = 32 + 16 + 64;

/// One writer's proof of one row's exact bytes.
struct WriterProof {
    /// BLAKE3 of the whole row the window carries.
    row: [u8; 32],
    writer: EntityId,
    signature: [u8; 64],
}

impl WriterProof {
    fn encode(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(PROOF_LEN);
        raw.extend_from_slice(&self.row);
        raw.extend_from_slice(self.writer.as_bytes());
        raw.extend_from_slice(&self.signature);
        raw
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != PROOF_LEN {
            return None;
        }
        Some(Self {
            row: raw[..32].try_into().ok()?,
            writer: EntityId::from_bytes(raw[32..48].try_into().ok()?).ok()?,
            signature: raw[48..].try_into().ok()?,
        })
    }
}

/// The bytes a writer signs for the row of digest `row` at `id`.
fn transcript(vault: &[u8; 32], writer: &EntityId, id: &EntityId, row: &[u8; 32]) -> Vec<u8> {
    let mut signed = Vec::with_capacity(DOMAIN.len() + 32 + 16 + 16 + 32);
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(vault);
    signed.extend_from_slice(writer.as_bytes());
    signed.extend_from_slice(id.as_bytes());
    signed.extend_from_slice(row);
    signed
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn is_message(row: &[u8]) -> bool {
    EntityMetadataHeader::parse(row).is_some_and(|header| header.entity_type == ENTITY_TYPE_MESSAGE)
}

fn carries_writers(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(MESSAGE_WRITER_MAP))
}

/// Records, in the commit of a put that staged the MESSAGE row `id`, which
/// machine wrote it: this install for a local put (not `replicated`), the
/// lane's writer for a replicated put the own-device lane admitted
/// (`lane_proof`, the proof it verified). A replicated put with no lane proof
/// forgets the record: no one here vouches for its bytes.
pub(crate) fn note_message_put_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    replicated: bool,
    lane_proof: Option<&[u8]>,
) -> Result<()> {
    let record = if replicated {
        lane_proof.map(<[u8]>::to_vec)
    } else {
        let staged = crate::ports::EntityStoreRead::port_entity_raw_wiped(store, wtxn, id)?;
        staged
            .filter(|row| is_message(row))
            .map(|row| digest(&row).to_vec())
    };
    match record {
        Some(record) => WRITTEN.put(store, wtxn, &HexId(*id), &record),
        None => {
            WRITTEN.delete(store, wtxn, &HexId(*id))?;
            Ok(())
        }
    }
}

/// Forgets which machine wrote the row `id`, in the transaction that erases
/// it, whether or not a window carries it: the record holds a digest of the
/// erased bytes, which could confirm a guess of them.
pub(crate) fn forget_message_writer_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    WRITTEN.delete(store, wtxn, &HexId(*id))?;
    Ok(())
}

/// Drops the record of each MESSAGE carrier a local path removes when it
/// names those exact bytes.
pub(in crate::sync) fn forget_written_rows(
    vault: &Vault,
    carriers: &[(EntityId, Vec<u8>)],
) -> Result<()> {
    if !carriers.iter().any(|(_, carrier)| is_message(carrier)) {
        return Ok(());
    }
    vault.with_write_txn_grouped(|wtxn| {
        for (id, carrier) in carriers.iter().filter(|(_, carrier)| is_message(carrier)) {
            let removed = digest(carrier);
            if WRITTEN
                .get(&vault.store, wtxn, &HexId(*id))?
                .is_some_and(|record| record.get(..32) == Some(&removed[..]))
            {
                WRITTEN.delete(&vault.store, wtxn, &HexId(*id))?;
            }
        }
        Ok(())
    })
}

/// Puts the writer proof of the MESSAGE row `row` at `id` beside it in
/// `doc`, which carries the row with exactly these bytes: this install
/// signs a row its own put wrote, and passes on the proof the own-device
/// lane admitted a row with. A row `doc` carries with other bytes, one
/// whose proof `doc` already carries, and one this install did not write
/// and holds no proof for take none. Returns whether it wrote; the caller
/// commits.
pub(in crate::sync) fn publish_writer_proof(
    vault: &Vault,
    doc: &LoroDoc,
    id: &EntityId,
    row: &[u8],
) -> Result<bool> {
    let key = id.to_hex();
    if !is_message(row) || map_get_bytes(&doc.get_map("entities"), &key).as_deref() != Some(row) {
        return Ok(false);
    }
    let sent = digest(row);
    if carries_writers(doc)
        && map_get_bytes(&doc.get_map(MESSAGE_WRITER_MAP), &key)
            .is_some_and(|carried| carried.get(..32) == Some(&sent[..]))
    {
        return Ok(false);
    }
    let record = {
        let txn = vault.store.env.read_txn()?;
        WRITTEN.get(&vault.store, &txn, &HexId(*id))?
    };
    let proof = match record {
        Some(native) if native.as_slice() == sent.as_slice() => sign(vault, id, &sent)?,
        Some(carried) => WriterProof::decode(&carried).filter(|proof| proof.row == sent),
        None => None,
    };
    let Some(proof) = proof else {
        return Ok(false);
    };
    map_insert_bytes(&doc.get_map(MESSAGE_WRITER_MAP), &key, &proof.encode())?;
    Ok(true)
}

/// This install's proof that it wrote the row of digest `row` at `id`, or
/// `None` when it holds no signer or the vault has no genesis-bound id yet.
fn sign(vault: &Vault, id: &EntityId, row: &[u8; 32]) -> Result<Option<WriterProof>> {
    if let Err(error) = vault.prepare_install_signing() {
        tracing::warn!(kind = ?error.kind(), "a MESSAGE row published with no writer proof: no signer here");
        return Ok(None);
    }
    let txn = vault.store.env.read_txn()?;
    let Some(genesis) = vault.authority_view_readonly_in_txn(&txn)?.vault_id else {
        return Ok(None);
    };
    let (writer, key) = match crate::store::install_identity::machine_signer_in_txn(vault, &txn) {
        Ok(signer) => signer,
        Err(error) => {
            tracing::warn!(kind = ?error.kind(), "a MESSAGE row published with no writer proof: no signer here");
            return Ok(None);
        }
    };
    let signature = ed25519_dalek::Signer::sign(&key, &transcript(&genesis, &writer, id, row));
    Ok(Some(WriterProof {
        row: *row,
        writer,
        signature: signature.to_bytes(),
    }))
}

/// The machine whose proof `carried` vouches for the MESSAGE row `row` at
/// `id`: its signature verifies, over these exact bytes and this vault's
/// genesis-bound id, under the key this install's fold holds for that
/// machine now, the one a connection from it must prove to stand here as an
/// own machine (`Vault::peer_machine_stands`, FIX 11709). `None` for any
/// proof that does not decode, names other bytes, or names a machine that
/// does not stand here.
pub(in crate::sync) fn verified_writer_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    id: &EntityId,
    row: &[u8],
    carried: &[u8],
) -> Result<Option<EntityId>> {
    let Some(proof) = WriterProof::decode(carried).filter(|proof| proof.row == digest(row)) else {
        return Ok(None);
    };
    let view = vault.authority_view_readonly_in_txn(txn)?;
    let Some(genesis) = view.vault_id else {
        return Ok(None);
    };
    let Some(machine_key) = view.machine_proof_key(proof.writer) else {
        return Ok(None);
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&machine_key) else {
        return Ok(None);
    };
    let signed = transcript(&genesis, &proof.writer, id, &proof.row);
    let signature = ed25519_dalek::Signature::from_bytes(&proof.signature);
    Ok(key
        .verify_strict(&signed, &signature)
        .is_ok()
        .then_some(proof.writer))
}

/// The proof `doc` carries for the row at `id`, as it carries it.
pub(in crate::sync) fn carried_proof(doc: &LoroDoc, id: &EntityId) -> Option<Vec<u8>> {
    carries_writers(doc)
        .then(|| map_get_bytes(&doc.get_map(MESSAGE_WRITER_MAP), &id.to_hex()))
        .flatten()
}

/// Copies into `out` the proof `source` carries for each row `out` holds
/// with the exact bytes it names. The caller commits.
pub(in crate::sync) fn copy_writer_proofs(source: &LoroDoc, out: &LoroDoc) -> Result<()> {
    if !carries_writers(source) {
        return Ok(());
    }
    let carried = source.get_map(MESSAGE_WRITER_MAP);
    let mut rows = Vec::new();
    map_for_each_value_bytes(&out.get_map("entities"), |key, row| {
        if let Some(sent) = row.filter(|row| is_message(row)).map(digest)
            && let Some(proof) = map_get_bytes(&carried, key)
            && proof.get(..32) == Some(&sent[..])
        {
            rows.push((key.to_owned(), proof));
        }
    });
    if rows.is_empty() {
        return Ok(());
    }
    let copied = out.get_map(MESSAGE_WRITER_MAP);
    for (key, proof) in &rows {
        map_insert_bytes(&copied, key, proof)?;
    }
    Ok(())
}

/// Drops the proof `doc` carries for each of `ids` whose row it no longer
/// holds with the bytes the proof names. Returns whether any went; the
/// caller commits.
pub(in crate::sync) fn forget_stale_writer_proofs(doc: &LoroDoc, ids: &[EntityId]) -> Result<bool> {
    if !carries_writers(doc) {
        return Ok(false);
    }
    let carried = doc.get_map(MESSAGE_WRITER_MAP);
    let entities = doc.get_map("entities");
    let mut dropped = false;
    for id in ids {
        let key = id.to_hex();
        let Some(proof) = map_get_bytes(&carried, &key) else {
            continue;
        };
        if map_get_bytes(&entities, &key)
            .is_none_or(|row| proof.get(..32) != Some(&digest(&row)[..]))
        {
            map_delete(&carried, &key)?;
            dropped = true;
        }
    }
    Ok(dropped)
}

fn refused() -> Error {
    Error::InvalidConfig("MESSAGE writer proof refused: not a proof filed under its row".into())
}

/// Admits one insert into a window's [`MESSAGE_WRITER_MAP`]: a proof of
/// [`PROOF_LEN`] bytes filed under the canonical id of its row. Whether it
/// proves anything is the lane's question, asked of the row it lands with.
pub(in crate::sync) fn admit_writer_proof_carrier(map_key: &str, value: &LoroValue) -> Result<()> {
    let filed = EntityId::from_hex(map_key).is_ok_and(|id| id.to_hex() == map_key);
    if filed && matches!(value, LoroValue::Binary(bytes) if bytes.len() == PROOF_LEN) {
        return Ok(());
    }
    Err(refused())
}

/// [`admit_writer_proof_carrier`] over every row `map` holds.
pub(in crate::sync) fn admit_writer_proof_map(map: &LoroMap) -> Result<()> {
    let mut admitted = Ok(());
    map.for_each(|map_key, value| {
        if admitted.is_ok() {
            admitted = match value {
                ValueOrContainer::Value(value) => admit_writer_proof_carrier(map_key, &value),
                ValueOrContainer::Container(_) => Err(refused()),
            };
        }
    });
    admitted
}
