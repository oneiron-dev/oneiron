//! Durable signer sequence maxima and content-addressed first-observation receipts.
//!
//! Each immutable hash retains the maximum that existed BEFORE its first
//! observation, and re-putting those bytes cannot refresh that receipt: the
//! put reads it to count each row's ingest exactly once. No fold reads a
//! maximum or a receipt (Engine RULING SEQ-FLOOR-SHAPE = A, 15 Nov 16:37):
//! a row's sequence floor comes from the rows themselves (`rows_floor`), so
//! the order rows arrived in decides no verdict.

use std::collections::BTreeSet;

use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable};
use crate::store::Store;

use super::*;

/// Durable high-water mark of a signer's highest observed authority-log sequence number.
/// Key: string (peer id, or peer id and world for a side entry).
const SEQ_HWM: SideTable<String, u64, Raw> = SideTable::new(&side_table::AUTHLOG_SEQ_HWM);
/// First-observation receipt of the signer sequence high-water mark that existed before one
/// entry hash was first observed. Key: hex64.
const SEQ_OBSERVATION: SideTable<String, SequenceReceipt, Raw> =
    SideTable::new(&side_table::AUTHLOG_SEQ_OBSERVATION);

/// The high-water mark that existed before this hash's first observation: `None` for genesis
/// (no prior mark), `Some` otherwise. Raw layout: `[0]`, or `[1]` + 8 big-endian bytes.
struct SequenceReceipt(Option<u64>);

impl RawValue for SequenceReceipt {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        let mut out = vec![u8::from(self.0.is_some())];
        if let Some(previous) = self.0 {
            out.extend_from_slice(&previous.to_be_bytes());
        }
        Ok(out)
    }

    fn from_raw(raw: &[u8]) -> std::result::Result<Self, CodecError> {
        match raw {
            [0] => Ok(Self(None)),
            [1, rest @ ..] if rest.len() == 8 => Ok(Self(Some(read_u64(rest)?))),
            _ => Err(Error::CorruptedIndex("authority sequence observation receipt").into()),
        }
    }
}

pub(super) struct AuthorityLocalObservations {
    /// Rows a handoff vouches for: no floor refuses them.
    pub(super) vouched: BTreeSet<AuthorityEntryHash>,
    /// Neither a handoff nor a removal vouches for anything: the fold that
    /// bounds every vouched fold's install view (`install_fold::NoVouch`).
    pub(super) unvouched: bool,
    pub(super) policy: AuthorityObservationPolicy,
}

impl AuthorityLocalObservations {
    /// The same observations with `line`, a handoff's line, vouched for: no
    /// floor refuses a row of it, so its settlement does not turn on which
    /// sibling this vault happened to see first. The handoff grants nothing
    /// this install held back: the install view comes from the fold with no
    /// vouch (Astra #1430b; the Engine's ruling on Sol P2 round 17).
    pub(super) fn vouching(&self, line: &BTreeSet<AuthorityEntryHash>) -> Self {
        let mut vouched = self.vouched.clone();
        if !self.unvouched {
            vouched.extend(line);
        }
        Self {
            vouched,
            unvouched: self.unvouched,
            policy: self.policy,
        }
    }

    /// The same observations with no handoff's or removal's vouch, now or
    /// later.
    pub(super) fn without_vouch(&self) -> Self {
        Self {
            vouched: BTreeSet::new(),
            unvouched: true,
            policy: self.policy,
        }
    }
}

/// Stable signer identity, including the suite to separate key encodings.
pub(super) fn authority_observation_peer_id(signer: &AuthorityKey) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron/authority-observation/v1/peer");
    match signer {
        AuthorityKey::Ed25519(bytes) => {
            hasher.update(b"ed25519");
            hasher.update(bytes);
        }
        AuthorityKey::P256(bytes) => {
            hasher.update(b"p256");
            hasher.update(bytes);
        }
    }
    hasher.finalize().to_hex().to_string()
}

/// A signer's sequences order within one scope: the main log, or one world's
/// side branch, the same scopes the rows floors keep (`rows_floor`). Entries
/// of different worlds never name each other. A world's settings edits are
/// main-log rows (mesh contract §6); inside a world the scope is one stream
/// over its key records (Astra #1422c F2, F3).
fn sequence_key(entry: &AuthorityLogEntry) -> String {
    sequence_key_of(
        entry.signer_key(),
        super::world_privacy::side_world(&entry.op),
    )
}

fn sequence_key_of(signer: &AuthorityKey, world: Option<crate::EntityId>) -> String {
    let peer = authority_observation_peer_id(signer);
    match world {
        None => peer,
        Some(world) => format!("{peer}:{}", world.to_hex()),
    }
}

fn receipt_key(hash: &AuthorityEntryHash) -> String {
    crate::entity_id::bytes_to_hex_lower(hash)
}

fn read_u64(raw: &[u8]) -> Result<u64> {
    decode_authority_first_seen_secs(raw)
        .ok_or(Error::CorruptedIndex("authority sequence high-water mark"))
}

/// Called at the shared successful-put site in the row's own transaction.
/// Returns whether this is a new hash, for exactly-once ingest accounting.
pub(crate) fn record_authority_sequence_observation_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    entry: &AuthorityLogEntry,
    hash: &AuthorityEntryHash,
) -> Result<bool> {
    let receipt_key = receipt_key(hash);
    if SEQ_OBSERVATION.get(store, txn, &receipt_key)?.is_some() {
        return Ok(false);
    }
    let key = sequence_key(entry);
    let previous = SEQ_HWM.get(store, txn, &key)?;
    SEQ_OBSERVATION.put(store, txn, &receipt_key, &SequenceReceipt(previous))?;
    let next = previous.map_or(entry.seq, |value| value.max(entry.seq));
    SEQ_HWM.put(store, txn, &key, &next)?;
    Ok(true)
}

/// This install's local fold inputs: its observation policy, with no vouch
/// yet. No sequence floor is read here: each row's floor comes from the
/// rows themselves (`rows_floor`), never from the order they arrived in.
pub(super) fn authority_local_observations_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<AuthorityLocalObservations> {
    Ok(AuthorityLocalObservations {
        vouched: BTreeSet::new(),
        unvouched: false,
        policy: authority_observation_policy_in_txn(store, txn)?,
    })
}
