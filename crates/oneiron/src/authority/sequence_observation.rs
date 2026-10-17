//! Durable signer sequence maxima and content-addressed first-observation receipts.
//!
//! A maximum alone is not a fold input: comparing the entire stored history to
//! today's maximum would reject genesis and every accepted predecessor on the
//! next recomputation. Each immutable hash therefore retains the maximum that
//! existed BEFORE its first observation. Re-putting those bytes cannot refresh
//! that receipt. All records still enter the log; only the local fold decides
//! whether a newly observed old sequence can authorize.

use std::collections::{BTreeMap, BTreeSet};

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
    pub(super) sequence_floors: BTreeMap<AuthorityEntryHash, u64>,
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
            sequence_floors: self.sequence_floors.clone(),
            vouched,
            unvouched: self.unvouched,
            policy: self.policy,
        }
    }

    /// The same observations with no handoff's or removal's vouch, now or
    /// later.
    pub(super) fn without_vouch(&self) -> Self {
        Self {
            sequence_floors: self.sequence_floors.clone(),
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
/// side branch. Entries of different worlds never name each other, so one
/// world's later entry is no rollback floor for another's. Inside a world
/// the floor is one stream over settings edits and key records alike, the
/// defence against backdating either kind (Astra #1422c F2, F3). Each row a
/// machine signs in a world names its previous one there, so a later row
/// that arrives first vouches for the earlier (Astra #1422b F1).
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

pub(super) fn authority_local_observations_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entries: &[AuthorityLogEntry],
) -> Result<AuthorityLocalObservations> {
    let rows = entries
        .iter()
        .map(|entry| {
            Ok(super::fold_resume::RowMeta::of(
                Some(authority_entry_hash(entry)?),
                entry,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    authority_local_observations_of_rows_in_txn(store, txn, &rows)
}

/// [`authority_local_observations_in_txn`] over the rows' metadata: each
/// row's hash, signer, world and sequence are all its receipts key on.
pub(super) fn authority_local_observations_of_rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    rows: &[super::fold_resume::RowMeta<'_>],
) -> Result<AuthorityLocalObservations> {
    let mut sequence_floors = BTreeMap::new();
    for row in rows {
        let hash = row
            .hash
            .ok_or(Error::CorruptedIndex("authority entry hash"))?;
        let current = SEQ_HWM.get(store, txn, &sequence_key_of(row.signer, row.world))?;
        let receipt = SEQ_OBSERVATION.get(store, txn, &receipt_key(&hash))?;
        let floor = match receipt {
            Some(SequenceReceipt(observed)) => {
                if current.is_none_or(|current| current < row.seq)
                    || observed.is_some_and(|floor| current.is_none_or(|now| floor > now))
                {
                    return Err(Error::CorruptedIndex("authority sequence high-water mark"));
                }
                observed
            }
            // A missing receipt is never an exemption from an existing mark.
            None => current,
        };
        if let Some(floor) = floor {
            sequence_floors.insert(hash, floor);
        }
    }
    Ok(AuthorityLocalObservations {
        sequence_floors,
        vouched: BTreeSet::new(),
        unvouched: false,
        policy: authority_observation_policy_in_txn(store, txn)?,
    })
}
