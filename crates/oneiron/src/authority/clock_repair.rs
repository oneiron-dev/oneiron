//! The owner's repair of a damaged authority clock floor (FIX 10106,
//! `vault.authority.clock.repair`).
//!
//! The floor is the least second this vault has observed; every authority
//! reading stands on it, and a damaged one is never read as zero
//! (`first_seen_clock`). The repair replaces it with the highest second this
//! vault itself can prove it observed: each authority row's first-seen stamp
//! and this handle's anchored reading. It never takes a peer's time, a row's
//! signed `ts`, a number a caller hands it or the wall clock. With no such
//! proof the repair says so, and the floor stays as it is.
//!
//! The repair does not stand behind the clock it repairs: in its own writer
//! it stages the proven floor, then judges the owner's proof as every owner
//! door does, against that floor, and commits the floor and its provenance
//! receipt together only when the proof holds. The authority cache moves to
//! a new generation with them.

use serde::{Deserialize, Serialize};

use super::*;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};

/// Where the proven floor comes from (CALLS `FIX 10106 authority clock
/// repair evidence`): this vault's own local observations only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityClockRepairEvidence {
    /// The first-seen stamps of its authority rows and this handle's anchored
    /// reading.
    LocalObservations,
}

/// The one evidence rule the repair takes.
pub const AUTHORITY_CLOCK_REPAIR_EVIDENCE: AuthorityClockRepairEvidence =
    AuthorityClockRepairEvidence::LocalObservations;

/// The repair's provenance receipts, one per repair, in the first-seen
/// family beside the floor they replaced (Key: `clock_repair:` and the
/// repair's id): canonical JSON of [`AuthorityClockRepairReceipt`].
const AUTHORITY_CLOCK_REPAIRS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::AUTHLOG_FIRST_SEEN_SIDECAR);

/// What one repair found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityClockRepairOutcome {
    /// The floor reads whole, or no floor exists yet: nothing was written.
    Sound,
    /// The damaged floor was replaced by the proven one.
    Repaired,
    /// The floor is damaged and this vault holds no observation that proves
    /// a replacement: nothing was written.
    Unproven,
}

/// `vault.authority.clock.repair`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityClockRepair {
    pub outcome: AuthorityClockRepairOutcome,
    /// The floor that stands after the repair, in unix seconds; None while it
    /// is absent or still damaged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor: Option<u64>,
    /// The first-seen stamps the proof read.
    pub observations: u64,
    /// This handle's anchored reading the proof read, when it holds one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchored: Option<u64>,
}

/// The provenance one repair commits with the floor it writes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityClockRepairReceipt {
    /// The floor written, in unix seconds.
    floor: u64,
    /// The BLAKE3 (lowercase hex) of the damaged row's bytes, and their
    /// length: what the repair replaced, never the bytes themselves.
    damaged_digest: String,
    damaged_len: u64,
    /// The first-seen stamps the proof read, and its anchored reading.
    observations: u64,
    anchored: Option<u64>,
    /// The owner whose proof the repair held to (hex).
    actor: String,
}

/// The highest second this vault proves it observed: its authority rows'
/// first-seen stamps (each 64-hex key in the family; the floor, the backfill
/// marker and repair receipts are not stamps), and how many it read.
fn observed_stamps_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<(Option<u64>, u64)> {
    let mut highest = None;
    let mut count = 0u64;
    for row in AUTHORITY_FIRST_SEEN.iter_raw_from(store, txn, &[])? {
        let (key, value) = row?;
        let stamp_key = key.len() == AUTHORITY_HASH_LEN * 2
            && key
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte));
        let Some(stamp) = stamp_key
            .then(|| AUTHORITY_FIRST_SEEN.decode_value(&value).ok())
            .flatten()
        else {
            continue;
        };
        count += 1;
        highest = highest.max(Some(stamp));
    }
    Ok((highest, count))
}

impl crate::Vault {
    /// Repairs a damaged authority clock floor for `owner` (FIX 10106). A
    /// whole or absent floor is left as it is ([`AuthorityClockRepairOutcome::Sound`]);
    /// a damaged one is replaced by the highest second this vault proves it
    /// observed ([`AUTHORITY_CLOCK_REPAIR_EVIDENCE`]), staged in this
    /// writer before the owner's proof is judged against it, and committed
    /// with its provenance receipt only when that proof holds. With no proof
    /// it is [`AuthorityClockRepairOutcome::Unproven`]. Every outcome
    /// revalidates `owner` in this writer.
    pub fn repair_authority_clock(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<AuthorityClockRepair> {
        let txn = self.store.env.write_txn()?;
        let key = authority_first_seen_clock_key();
        let damaged = match AUTHORITY_FIRST_SEEN.get_bytes(&self.store, &txn, &key)? {
            Some(bytes) if AUTHORITY_FIRST_SEEN.decode_value(&bytes).is_err() => bytes,
            whole => {
                owner.revalidate_in_txn(self, &txn)?;
                let floor = whole
                    .map(|bytes| AUTHORITY_FIRST_SEEN.decode_value(&bytes))
                    .transpose()?;
                return Ok(AuthorityClockRepair {
                    outcome: AuthorityClockRepairOutcome::Sound,
                    floor,
                    observations: 0,
                    anchored: None,
                });
            }
        };
        let anchored = authority_anchored_secs(&self.store);
        let (stamped, observations) = match AUTHORITY_CLOCK_REPAIR_EVIDENCE {
            AuthorityClockRepairEvidence::LocalObservations => {
                observed_stamps_in_txn(&self.store, &txn)?
            }
        };
        let Some(floor) = stamped.max(anchored) else {
            owner.revalidate_in_txn(self, &txn)?;
            return Ok(AuthorityClockRepair {
                outcome: AuthorityClockRepairOutcome::Unproven,
                floor: None,
                observations,
                anchored,
            });
        };
        // The owner's proof is judged against the staged floor, and a first
        // reading it seeds into this handle's anchor is undone unless the
        // repair commits.
        let clock = || {
            self.store
                .authority_local_clock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        };
        let anchor = clock().anchor_state();
        let receipt = AuthorityClockRepairReceipt {
            floor,
            damaged_digest: blake3::hash(&damaged).to_hex().to_string(),
            damaged_len: damaged.len() as u64,
            observations,
            anchored,
            actor: String::new(),
        };
        if let Err(error) = self.commit_clock_repair(txn, owner, receipt) {
            clock().restore_anchor(anchor);
            return Err(error);
        }
        Ok(AuthorityClockRepair {
            outcome: AuthorityClockRepairOutcome::Repaired,
            floor: Some(floor),
            observations,
            anchored,
        })
    }

    /// Stages `receipt`'s floor in `txn`, judges `owner`'s proof against it,
    /// and commits the floor, a new authority cache generation and the
    /// receipt together.
    fn commit_clock_repair(
        &self,
        mut txn: heed::RwTxn<'_>,
        owner: &AuthenticatedOwner,
        mut receipt: AuthorityClockRepairReceipt,
    ) -> Result<()> {
        AUTHORITY_FIRST_SEEN.put(
            &self.store,
            &mut txn,
            &authority_first_seen_clock_key(),
            &receipt.floor,
        )?;
        advance_authority_cache_generation(&self.store, &mut txn)?;
        receipt.actor = owner.revalidate_in_txn(self, &txn)?.to_hex();
        let key = format!("clock_repair:{}", self.store.clock.entity_id()?.to_hex());
        let bytes = serde_json::to_vec(&receipt)
            .map_err(|_| crate::error::Error::InvariantViolation("clock repair receipt"))?;
        AUTHORITY_CLOCK_REPAIRS.put(&self.store, &mut txn, &key, &bytes)?;
        txn.commit()?;
        Ok(())
    }
}
