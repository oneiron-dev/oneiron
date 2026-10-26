//! The owner's repair of a damaged authority clock floor (FIX 10106,
//! `vault.authority.clock.repair`).
//!
//! The floor is the least second this vault has observed; every authority
//! reading stands on it, and a damaged one is never read as zero
//! (`first_seen_clock`). The repair replaces it only with the committed
//! high-water this vault itself proves: the floor's own high-water copy,
//! written in the same writer as every floor, or this handle's live anchor;
//! the result is at least every first-seen stamp and every earlier repair's
//! floor too. It never takes a peer's time, a row's signed `ts`, a number a
//! caller hands it or the wall clock. When the vault cannot prove its
//! high-water (no whole copy and no live anchor, or an earlier repair receipt
//! that does not read), the repair answers Unproven and changes nothing: a
//! stale first-seen stamp alone could roll the clock back.
//!
//! The repair does not stand behind the clock it repairs: in its own writer
//! it stages the proven floor (for an Unproven answer, the best proven lower
//! bound, then aborts), then judges the owner's proof as every owner door
//! does, against that floor, and commits the floor, its high-water copy and
//! its provenance receipt together only when the proof holds. The authority
//! cache moves to a new generation with them. A slip holder reaches it through
//! [`crate::Vault::repair_authority_clock_by_slip`], whose request proof is
//! judged in that same writer.

use serde::{Deserialize, Serialize};

use super::*;
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::error::Result;
use crate::side_table::{self, Raw, SideTable};

/// Where the proven floor comes from (CALLS `FIX 10106 authority clock
/// repair evidence`): this vault's own local observations only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityClockRepairEvidence {
    /// The floor's high-water copy or this handle's anchored reading proves
    /// the committed high-water; the first-seen stamps of its authority rows
    /// and every earlier repair receipt bound it from below.
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
    /// The floor is damaged and this vault cannot prove its committed
    /// high-water: nothing was written.
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

/// The key prefix of a repair receipt in the first-seen family.
const REPAIR_RECEIPT_PREFIX: &str = "clock_repair:";

/// The floor's high-water copy as it reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HighWater {
    Whole(u64),
    Absent,
    Damaged,
}

/// What this vault holds of its own clock without its floor.
#[derive(Debug, Clone, Copy)]
pub(super) struct ClockEvidence {
    /// The latest first-seen stamp of an authority row, and how many read.
    stamped: Option<u64>,
    observations: u64,
    high_water: HighWater,
    /// The latest earlier repair's floor, and whether every receipt read.
    repaired: Option<u64>,
    receipts_whole: bool,
    /// This handle's anchored reading.
    anchored: Option<u64>,
}

impl ClockEvidence {
    /// The highest second any of it proves this vault observed.
    pub(super) fn lower_bound(&self) -> Option<u64> {
        let copy = match self.high_water {
            HighWater::Whole(floor) => Some(floor),
            HighWater::Absent | HighWater::Damaged => None,
        };
        [self.stamped, copy, self.repaired, self.anchored]
            .into_iter()
            .flatten()
            .max()
    }

    /// The committed high-water, when this vault proves it: a whole
    /// high-water copy or a live anchor, with every repair receipt read.
    fn proven_floor(&self) -> Option<u64> {
        let proven = matches!(self.high_water, HighWater::Whole(_)) || self.anchored.is_some();
        (proven && self.receipts_whole)
            .then(|| self.lower_bound())
            .flatten()
    }
}

/// Reads [`ClockEvidence`] in `txn`: the first-seen stamps (each 64-hex key
/// of the family), the floor's high-water copy, the repair receipts, and this
/// handle's anchored reading.
pub(super) fn clock_evidence_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
) -> Result<ClockEvidence> {
    let high_water_key = authority_clock_high_water_key();
    let mut evidence = ClockEvidence {
        stamped: None,
        observations: 0,
        high_water: HighWater::Absent,
        repaired: None,
        receipts_whole: true,
        anchored: authority_anchored_secs(store),
    };
    for row in AUTHORITY_FIRST_SEEN.iter_raw_from(store, txn, &[])? {
        let (key, value) = row?;
        if key == high_water_key.as_bytes() {
            evidence.high_water = AUTHORITY_FIRST_SEEN
                .decode_value(&value)
                .map_or(HighWater::Damaged, HighWater::Whole);
        } else if key.starts_with(REPAIR_RECEIPT_PREFIX.as_bytes()) {
            match serde_json::from_slice::<AuthorityClockRepairReceipt>(&value) {
                Ok(receipt) => evidence.repaired = evidence.repaired.max(Some(receipt.floor)),
                Err(_) => evidence.receipts_whole = false,
            }
        } else if key.len() == AUTHORITY_HASH_LEN * 2
            && key
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
            && let Ok(stamp) = AUTHORITY_FIRST_SEEN.decode_value(&value)
        {
            evidence.observations += 1;
            evidence.stamped = evidence.stamped.max(Some(stamp));
        }
    }
    Ok(evidence)
}

/// The floor row as a repair finds it: whole (or absent), or its damaged
/// bytes.
enum FloorRow {
    Whole(Option<u64>),
    Damaged(Vec<u8>),
}

fn floor_row_in_txn(store: &crate::store::Store, txn: &heed::RoTxn<'_>) -> Result<FloorRow> {
    Ok(
        match AUTHORITY_FIRST_SEEN.get_bytes(store, txn, &authority_first_seen_clock_key())? {
            None => FloorRow::Whole(None),
            Some(bytes) => match AUTHORITY_FIRST_SEEN.decode_value(&bytes) {
                Ok(floor) => FloorRow::Whole(Some(floor)),
                Err(_) => FloorRow::Damaged(bytes),
            },
        },
    )
}

fn sound(floor: Option<u64>) -> AuthorityClockRepair {
    AuthorityClockRepair {
        outcome: AuthorityClockRepairOutcome::Sound,
        floor,
        observations: 0,
        anchored: None,
    }
}

impl crate::Vault {
    /// Repairs a damaged authority clock floor for `owner` (FIX 10106). A
    /// whole or absent floor is left as it is
    /// ([`AuthorityClockRepairOutcome::Sound`]); a damaged one is replaced by
    /// the committed high-water this vault proves
    /// ([`AUTHORITY_CLOCK_REPAIR_EVIDENCE`]), staged in this writer before the
    /// owner's proof is judged against it, and committed with its provenance
    /// receipt only when that proof holds. When the high-water is not proven
    /// it is [`AuthorityClockRepairOutcome::Unproven`] and nothing changes.
    /// Every outcome revalidates `owner` in this writer.
    pub fn repair_authority_clock(
        &self,
        owner: &AuthenticatedOwner,
    ) -> Result<AuthorityClockRepair> {
        let txn = self.store.env.write_txn()?;
        match floor_row_in_txn(&self.store, &txn)? {
            FloorRow::Whole(floor) => {
                owner.revalidate_in_txn(self, &txn)?;
                Ok(sound(floor))
            }
            FloorRow::Damaged(damaged) => {
                self.repair_damaged_floor(txn, &damaged, |txn| owner.revalidate_in_txn(self, txn))
            }
        }
    }

    /// [`Self::repair_authority_clock`] for a request that carries the
    /// owner's own full slip and its holder proof (`timestamp`, `signature`,
    /// `nonce`), as the repair's own ingress takes it: the slip and the proof
    /// are judged, and the proof's nonce spent, in the repair's writer, after
    /// it stages the floor, so a damaged floor never refuses them first. Only
    /// the owner's own unattenuated human slip binds; a host root acts as
    /// nobody here.
    pub fn repair_authority_clock_by_slip(
        &self,
        slip: &CapabilitySlip,
        timestamp: u64,
        signature: &[u8],
        nonce: &[u8],
    ) -> Result<AuthorityClockRepair> {
        let holder = slip.claims.holder_ref.as_str();
        let actor = EntityId::from_hex(holder).map_err(|_| {
            crate::error::Error::Gate(crate::error::GateError::ConsentOwnerNotAuthenticated(
                "the slip names no person",
            ))
        })?;
        let owner =
            self.authenticate_owner(actor, holder, true, crate::store::GateDecisionId::now())?;
        let bind = |txn: &mut heed::RwTxn<'_>| -> Result<EntityId> {
            let verified =
                self.admit_capability_slip_request_in_txn(txn, slip, timestamp, signature, nonce)?;
            self.bind_owner_credential_in_txn(txn, owner.clone(), verified)
        };
        let mut txn = self.store.env.write_txn()?;
        match floor_row_in_txn(&self.store, &txn)? {
            FloorRow::Whole(floor) => {
                bind(&mut txn)?;
                txn.commit()?;
                Ok(sound(floor))
            }
            FloorRow::Damaged(damaged) => self.repair_damaged_floor(txn, &damaged, bind),
        }
    }

    /// Stages the proven floor (or, unproven, the best proven lower bound) in
    /// `txn`, judges the caller with `judge` against it, and commits the
    /// proven floor with its receipt; an unproven one aborts. A reading the
    /// staged floor seeded into this handle's anchor is undone unless the
    /// repair commits.
    fn repair_damaged_floor(
        &self,
        mut txn: heed::RwTxn<'_>,
        damaged: &[u8],
        judge: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<EntityId>,
    ) -> Result<AuthorityClockRepair> {
        let evidence = match AUTHORITY_CLOCK_REPAIR_EVIDENCE {
            AuthorityClockRepairEvidence::LocalObservations => {
                clock_evidence_in_txn(&self.store, &txn)?
            }
        };
        let proven = evidence.proven_floor();
        let staged = proven
            .or_else(|| evidence.lower_bound())
            .ok_or_else(authority_clock_corrupt)?;
        let clock = || {
            self.store
                .authority_local_clock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        };
        let anchor = clock().anchor_state();
        let judged = self.stage_clock_floor(&mut txn, staged, judge);
        let committed = match (judged, proven) {
            (Ok(actor), Some(floor)) => self.commit_clock_repair(
                txn,
                &AuthorityClockRepairReceipt {
                    floor,
                    damaged_digest: blake3::hash(damaged).to_hex().to_string(),
                    damaged_len: damaged.len() as u64,
                    observations: evidence.observations,
                    anchored: evidence.anchored,
                    actor: actor.to_hex(),
                },
            ),
            (Ok(_), None) => {
                drop(txn);
                clock().restore_anchor(anchor);
                return Ok(AuthorityClockRepair {
                    outcome: AuthorityClockRepairOutcome::Unproven,
                    floor: None,
                    observations: evidence.observations,
                    anchored: evidence.anchored,
                });
            }
            (Err(error), _) => Err(error),
        };
        if let Err(error) = committed {
            clock().restore_anchor(anchor);
            return Err(error);
        }
        Ok(AuthorityClockRepair {
            outcome: AuthorityClockRepairOutcome::Repaired,
            floor: proven,
            observations: evidence.observations,
            anchored: evidence.anchored,
        })
    }

    /// Writes `floor` and a new authority cache generation in `txn`, then
    /// judges the caller against them.
    fn stage_clock_floor(
        &self,
        txn: &mut heed::RwTxn<'_>,
        floor: u64,
        judge: impl FnOnce(&mut heed::RwTxn<'_>) -> Result<EntityId>,
    ) -> Result<EntityId> {
        put_authority_clock_floor_in_txn(&self.store, txn, floor)?;
        advance_authority_cache_generation(&self.store, txn)?;
        judge(txn)
    }

    /// Commits the staged floor with `receipt`.
    fn commit_clock_repair(
        &self,
        mut txn: heed::RwTxn<'_>,
        receipt: &AuthorityClockRepairReceipt,
    ) -> Result<()> {
        let key = format!(
            "{REPAIR_RECEIPT_PREFIX}{}",
            self.store.clock.entity_id()?.to_hex()
        );
        let bytes = serde_json::to_vec(receipt)
            .map_err(|_| crate::error::Error::InvariantViolation("clock repair receipt"))?;
        AUTHORITY_CLOCK_REPAIRS.put(&self.store, &mut txn, &key, &bytes)?;
        txn.commit()?;
        Ok(())
    }
}
