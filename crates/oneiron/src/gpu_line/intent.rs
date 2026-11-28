//! The intent key every lane-economy write door takes (design pass 32
//! section 5; the spawn-intent form of
//! `agent_dispatch::planner_live::intent`). A write names a non-blank
//! intent key. The first write under a key keeps one row: the asker, the
//! verb, the digest of the ask and the key of the row the write made. The
//! same asker asking the same verb under the same key again writes nothing:
//! the door answers the row the first write made, marked `replayed`. The
//! same key with another ask is refused, and nothing is written. A refused
//! write keeps no row, so its key may be asked again.
//!
//! The row holds no answer bytes: a door rebuilds its answer from the row
//! the first write made, so an erase that forgets an actor in that row
//! leaves no copy of it here. An erase of the asker drops its rows.

use serde::{Deserialize, Serialize};

use crate::entity_id::bytes_to_hex_lower;
use crate::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INVALID_STATE, MemoryError};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// Domain of an intent's row key.
const INTENT_KEY_CONTEXT: &str = "oneiron lane economy intent key v1";
/// Domain of an ask's digest.
const ASK_DIGEST_CONTEXT: &str = "oneiron lane economy intent ask v2";

/// The refusal of a key that already names another ask.
pub const DIFFERENT_ASK: &str = "this intent key already names a different ask; repeat that \
     ask, or ask under a new intent key";

/// Framed (asker, verb, intent key) -> the write it names.
const INTENTS: SideTable<[u8; 32], LaneIntent, Named> =
    SideTable::new(&side_table::LANE_ECONOMY_INTENT);

/// One kept write of a lane-economy door.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneIntent {
    /// Who asked: the owner's actor or the agent's.
    pub asker: EntityId,
    /// The verb asked.
    pub verb: String,
    /// BLAKE3 over the ask's canonical encoding, lower hex.
    pub ask_digest: String,
    /// The key of the row the write made, in that table's own key bytes.
    pub written: Vec<u8>,
    /// When the write landed, on the vault's clock.
    pub at_ms: u64,
}

/// One write ask under its intent key, framed and digested before the
/// door's write transaction opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentAsk {
    asker: EntityId,
    verb: String,
    row_key: [u8; 32],
    ask_digest: String,
}

/// Why an intent key refuses an ask; nothing is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentRefused {
    /// The intent key is blank.
    BlankKey,
    /// The ask does not encode.
    Unencodable,
    /// The key already names another ask.
    DifferentAsk,
}

impl std::fmt::Display for IntentRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::BlankKey => "a lane-economy write names a non-blank intent key",
            Self::Unencodable => "the ask does not encode",
            Self::DifferentAsk => DIFFERENT_ASK,
        })
    }
}

impl std::error::Error for IntentRefused {}

impl From<IntentRefused> for MemoryError {
    fn from(refused: IntentRefused) -> Self {
        match refused {
            IntentRefused::BlankKey | IntentRefused::Unencodable => Self::new(
                MEMORY_CODE_BAD_REQUEST,
                refused.to_string(),
                &["Name the write by a non-blank intent key."],
            ),
            IntentRefused::DifferentAsk => Self::new(
                MEMORY_CODE_INVALID_STATE,
                DIFFERENT_ASK,
                &["Repeat the first ask under this key, or ask under a new intent key."],
            ),
        }
    }
}

/// Where an ask stands under its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentStand {
    /// No write holds the key: the door writes, then keeps the intent.
    New,
    /// The same ask already wrote: the key of the row it made.
    Replayed(Vec<u8>),
}

impl IntentAsk {
    /// Frames `ask` from `asker` to `verb` under `intent_key`.
    ///
    /// # Errors
    ///
    /// [`IntentRefused::BlankKey`] for a blank key;
    /// [`IntentRefused::Unencodable`] for an ask that does not encode.
    pub fn new<A: Serialize>(
        asker: EntityId,
        verb: &str,
        intent_key: &str,
        ask: &A,
    ) -> Result<Self, IntentRefused> {
        if intent_key.trim().is_empty() {
            return Err(IntentRefused::BlankKey);
        }
        // The ask's canonical JSON (object keys sorted at every depth), so
        // two encodings of one ask, such as a map in another iteration
        // order, digest alike (review-10396 P1).
        let value = serde_json::to_value(ask).map_err(|_| IntentRefused::Unencodable)?;
        let mut digest = blake3::Hasher::new_derive_key(ASK_DIGEST_CONTEXT);
        oneiron_records::receipt::call::write_canonical(&mut digest, &value);
        Ok(Self {
            asker,
            verb: verb.to_owned(),
            row_key: intent_row_key(&asker, verb, intent_key),
            ask_digest: bytes_to_hex_lower(digest.finalize().as_bytes()),
        })
    }

    /// The digest of the ask, without its intent key: what a door's logical
    /// key compares when another intent key names the same thing.
    #[must_use]
    pub fn ask_digest(&self) -> &str {
        &self.ask_digest
    }

    /// Where this ask stands under its key, read in the door's write
    /// transaction before anything is written.
    ///
    /// # Errors
    ///
    /// A store read failure; the inner [`IntentRefused::DifferentAsk`] when
    /// the key names another ask.
    pub fn stand_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
    ) -> crate::Result<Result<IntentStand, IntentRefused>> {
        Ok(match INTENTS.get(&vault.store, txn, &self.row_key)? {
            None => Ok(IntentStand::New),
            Some(row) if row.ask_digest == self.ask_digest && row.verb == self.verb => {
                Ok(IntentStand::Replayed(row.written))
            }
            Some(_) => Err(IntentRefused::DifferentAsk),
        })
    }

    /// Keeps this ask's write, in the same write transaction that made the
    /// row `written` names.
    ///
    /// # Errors
    ///
    /// A store write failure.
    pub fn keep_in_txn(
        &self,
        vault: &Vault,
        wtxn: &mut heed::RwTxn<'_>,
        written: Vec<u8>,
        at_ms: u64,
    ) -> crate::Result<()> {
        INTENTS.put(
            &vault.store,
            wtxn,
            &self.row_key,
            &LaneIntent {
                asker: self.asker,
                verb: self.verb.clone(),
                ask_digest: self.ask_digest.clone(),
                written,
                at_ms,
            },
        )
    }
}

/// The row key: BLAKE3 over the framed asker, verb and intent key.
fn intent_row_key(asker: &EntityId, verb: &str, intent_key: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(INTENT_KEY_CONTEXT);
    hasher.update(asker.as_bytes());
    hasher.update(&(verb.len() as u64).to_be_bytes());
    hasher.update(verb.as_bytes());
    hasher.update(&(intent_key.len() as u64).to_be_bytes());
    hasher.update(intent_key.as_bytes());
    *hasher.finalize().as_bytes()
}

/// The asker a stored `LANE_ECONOMY_INTENT` value names, whose erase drops the row
/// ([`erase_intent_asker_in_txn`]): the record the whole-vault export reads it to be about.
/// `None` for bytes that do not read as an intent.
pub(crate) fn intent_row_asker(value: &[u8]) -> Option<EntityId> {
    INTENTS.decode_value(value).ok().map(|row| row.asker)
}

/// Drops every intent the erased actor asked (the side table's actor
/// scrub). Its keys hash the asker, so no other caller could replay them.
pub(crate) fn erase_intent_asker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    for (key, row) in INTENTS.scan(&vault.store, wtxn)? {
        if row.asker == *actor {
            INTENTS.delete(&vault.store, wtxn, &key)?;
        }
    }
    Ok(())
}
