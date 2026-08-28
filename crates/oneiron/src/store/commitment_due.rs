//! The commitment due index (CMT-2, ONE-1539).
//!
//! An additive `vault_meta` sidecar family — four key spaces, no named LMDB
//! database, no [`DB_MANIFEST`] entry, no storage migration. Existing vaults
//! open unchanged and simply have no rows here.
//!
//! It is deliberately NOT the attempt queue. The attempt queue answers "what
//! work is queued to run"; this index answers "what is owed, and when does it
//! become visible". Reusing job rows would have made a commitment's due date
//! indistinguishable from a retry backoff, and would have coupled the
//! obligation's lifetime to a runner's.
//!
//! Four key spaces:
//!
//! * **primary** — `prefix ‖ at(u64 BE) ‖ phase(u8) ‖ series(16) ‖
//!   instance_or_zero(16)`. `at` leads so the whole index sorts by time and
//!   "what is next" is one first-key read.
//! * **reverse** — `prefix ‖ instance(16) ‖ phase(u8) → primary key`. Lets a
//!   close remove an instance's rows without scanning by time.
//! * **series-project** — `prefix ‖ series(16) → primary key`. At most ONE
//!   pending Project row per active series; a series edit removes it by name.
//! * **series-instance history** — `prefix ‖ series(16) ‖ window.start(BE) ‖
//!   due_at(BE) ‖ ordinal(BE) ‖ instance(16)`. Membership, NEVER deleted on
//!   close: it is what the evaluator reads as `history`, so forgetting it would
//!   make a completed series look unstarted.
//!
//! Every parse is fail-closed. A short key, an unknown version byte, an
//! unknown phase, an inverted window, a dangling reverse key, or an all-zero
//! instance slot outside the Project phase is
//! [`Error::CorruptedIndex`] — never a silently empty answer, because "no due
//! work" is exactly the wrong thing to tell a commitment engine.

use heed::{RoTxn, RwTxn};

use crate::commitment_schedule::{
    CommitmentDueEntry, CommitmentDueIndexSnapshot, CommitmentDuePhase, CommitmentOccurrence,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::temporal::TimeRange;

use super::*;

/// Value-format version for a due row. Bumping it is an index rebuild, not a
/// silent read.
pub(crate) const COMMITMENT_DUE_INDEX_VERSION: u8 = 1;

pub(crate) const COMMITMENT_DUE_KEY_PREFIX: &[u8] = b"commitment_due:v1:";
pub(crate) const COMMITMENT_DUE_REVERSE_PREFIX: &[u8] = b"commitment_due_rev:v1:";
pub(crate) const COMMITMENT_DUE_SERIES_PROJECT_PREFIX: &[u8] = b"commitment_series_project:v1:";
pub(crate) const COMMITMENT_DUE_SERIES_INSTANCE_PREFIX: &[u8] = b"commitment_series_instance:v1:";

/// `at(8) ‖ phase(1) ‖ series(16) ‖ instance_or_zero(16)`.
const PRIMARY_KEY_BODY_LEN: usize = 8 + 1 + 16 + 16;
/// `version(1) ‖ due_at(8) ‖ window.start(8) ‖ window.end(8) ‖ ordinal(4)`.
const VALUE_LEN: usize = 1 + 8 + 8 + 8 + 4;

const ZERO_INSTANCE: [u8; 16] = [0_u8; 16];

const CORRUPT: &str = "commitment due index";

fn corrupt() -> Error {
    Error::CorruptedIndex(CORRUPT)
}

pub(crate) fn commitment_due_primary_key(entry: &CommitmentDueEntry) -> Vec<u8> {
    let mut key = Vec::with_capacity(COMMITMENT_DUE_KEY_PREFIX.len() + PRIMARY_KEY_BODY_LEN);
    key.extend_from_slice(COMMITMENT_DUE_KEY_PREFIX);
    key.extend_from_slice(&entry.at.to_be_bytes());
    key.push(entry.phase.as_u8());
    key.extend_from_slice(entry.series_ref.as_bytes());
    key.extend_from_slice(
        entry
            .instance_ref
            .as_ref()
            .map_or(&ZERO_INSTANCE, EntityId::as_bytes),
    );
    key
}

fn reverse_key(instance_ref: &EntityId, phase: CommitmentDuePhase) -> Vec<u8> {
    let mut key = Vec::with_capacity(COMMITMENT_DUE_REVERSE_PREFIX.len() + 17);
    key.extend_from_slice(COMMITMENT_DUE_REVERSE_PREFIX);
    key.extend_from_slice(instance_ref.as_bytes());
    key.push(phase.as_u8());
    key
}

fn series_project_key(series_ref: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(COMMITMENT_DUE_SERIES_PROJECT_PREFIX.len() + 16);
    key.extend_from_slice(COMMITMENT_DUE_SERIES_PROJECT_PREFIX);
    key.extend_from_slice(series_ref.as_bytes());
    key
}

fn series_instance_prefix(series_ref: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(COMMITMENT_DUE_SERIES_INSTANCE_PREFIX.len() + 16);
    key.extend_from_slice(COMMITMENT_DUE_SERIES_INSTANCE_PREFIX);
    key.extend_from_slice(series_ref.as_bytes());
    key
}

fn series_instance_key(
    series_ref: &EntityId,
    occurrence: &CommitmentOccurrence,
    instance_ref: &EntityId,
) -> Vec<u8> {
    let mut key = series_instance_prefix(series_ref);
    key.extend_from_slice(&occurrence.window.start.to_be_bytes());
    key.extend_from_slice(&occurrence.due_at.to_be_bytes());
    key.extend_from_slice(&occurrence.ordinal.to_be_bytes());
    key.extend_from_slice(instance_ref.as_bytes());
    key
}

fn encode_value(entry: &CommitmentDueEntry) -> Vec<u8> {
    let mut value = Vec::with_capacity(VALUE_LEN);
    value.push(COMMITMENT_DUE_INDEX_VERSION);
    value.extend_from_slice(&entry.occurrence.due_at.to_be_bytes());
    value.extend_from_slice(&entry.occurrence.window.start.to_be_bytes());
    value.extend_from_slice(&entry.occurrence.window.end.to_be_bytes());
    value.extend_from_slice(&entry.occurrence.ordinal.to_be_bytes());
    value
}

fn be_u64(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| corrupt())?,
    ))
}

fn be_u32(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(
        bytes.try_into().map_err(|_| corrupt())?,
    ))
}

fn entity_at(bytes: &[u8]) -> Result<EntityId> {
    let raw: [u8; 16] = bytes.try_into().map_err(|_| corrupt())?;
    EntityId::from_bytes(raw).map_err(|_| corrupt())
}

/// Parses one primary row. Every length, the version byte, the phase byte, both
/// entity ids, the window ordering, and the Project-only zero-instance rule are
/// checked here so no caller can act on a half-understood row.
pub(crate) fn decode_commitment_due_row(key: &[u8], value: &[u8]) -> Result<CommitmentDueEntry> {
    let body = key
        .strip_prefix(COMMITMENT_DUE_KEY_PREFIX)
        .ok_or_else(corrupt)?;
    if body.len() != PRIMARY_KEY_BODY_LEN || value.len() != VALUE_LEN {
        return Err(corrupt());
    }
    if value[0] != COMMITMENT_DUE_INDEX_VERSION {
        return Err(corrupt());
    }
    let at = be_u64(&body[..8])?;
    let phase = CommitmentDuePhase::from_u8(body[8]).ok_or_else(corrupt)?;
    let series_ref = entity_at(&body[9..25])?;
    let instance_slot = &body[25..41];
    let instance_ref = if instance_slot == ZERO_INSTANCE {
        // The all-zero slot is a legal *absence* marker, and only for a series
        // Project row. Anywhere else it is a lost id, not an empty one.
        if phase != CommitmentDuePhase::Project {
            return Err(corrupt());
        }
        None
    } else {
        Some(entity_at(instance_slot)?)
    };
    let window = TimeRange {
        start: be_u64(&value[9..17])?,
        end: be_u64(&value[17..25])?,
    };
    if window.end < window.start {
        return Err(corrupt());
    }
    Ok(CommitmentDueEntry {
        at,
        phase,
        series_ref,
        instance_ref,
        occurrence: CommitmentOccurrence {
            due_at: be_u64(&value[1..9])?,
            window,
            ordinal: be_u32(&value[25..29])?,
        },
    })
}

impl Store {
    /// Writes one due row plus whichever secondary key its phase owns, in the
    /// caller's transaction. Primary and secondary land together or not at all.
    pub(crate) fn commitment_due_put_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        entry: &CommitmentDueEntry,
    ) -> Result<()> {
        entry.validate()?;
        let key = commitment_due_primary_key(entry);
        self.vault_meta.put(wtxn, &key, &encode_value(entry))?;
        match entry.instance_ref {
            Some(instance_ref) => {
                self.vault_meta
                    .put(wtxn, &reverse_key(&instance_ref, entry.phase), &key)?;
            }
            None => {
                self.vault_meta
                    .put(wtxn, &series_project_key(&entry.series_ref), &key)?;
            }
        }
        Ok(())
    }

    /// Records durable series membership for a minted instance. Written with
    /// the instance's phase rows and never removed by a close.
    pub(crate) fn commitment_due_put_membership_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        series_ref: &EntityId,
        occurrence: &CommitmentOccurrence,
        instance_ref: &EntityId,
    ) -> Result<()> {
        self.vault_meta.put(
            wtxn,
            &series_instance_key(series_ref, occurrence, instance_ref),
            &[COMMITMENT_DUE_INDEX_VERSION],
        )?;
        Ok(())
    }

    /// Every instance this series ever minted, ascending by window then due
    /// then ordinal.
    pub(crate) fn commitment_due_series_members_in_txn(
        &self,
        txn: &RoTxn<'_>,
        series_ref: &EntityId,
    ) -> Result<Vec<(CommitmentOccurrence, EntityId)>> {
        let prefix = series_instance_prefix(series_ref);
        let mut members = Vec::new();
        for row in self.vault_meta.prefix_iter(txn, &prefix)? {
            let (key, value) = row?;
            if value.as_ref() != [COMMITMENT_DUE_INDEX_VERSION] {
                return Err(corrupt());
            }
            let body = key.strip_prefix(prefix.as_slice()).ok_or_else(corrupt)?;
            if body.len() != 8 + 8 + 4 + 16 {
                return Err(corrupt());
            }
            let window_start = be_u64(&body[..8])?;
            let due_at = be_u64(&body[8..16])?;
            let ordinal = be_u32(&body[16..20])?;
            members.push((
                CommitmentOccurrence {
                    due_at,
                    window: TimeRange {
                        start: window_start,
                        // The window end is not part of the membership key; it
                        // is carried by the phase rows and by the instance's
                        // own payload. Callers that need it read the claim.
                        end: due_at.max(window_start),
                    },
                    ordinal,
                },
                entity_at(&body[20..36])?,
            ));
        }
        Ok(members)
    }

    /// The row for one instance in one phase, resolved through the reverse key.
    /// A reverse key whose primary row is gone is corruption, not absence.
    pub(crate) fn commitment_due_row_for_in_txn(
        &self,
        txn: &RoTxn<'_>,
        instance_ref: &EntityId,
        phase: CommitmentDuePhase,
    ) -> Result<Option<CommitmentDueEntry>> {
        let Some(primary) = self.vault_meta.get(txn, &reverse_key(instance_ref, phase))? else {
            return Ok(None);
        };
        let Some(value) = self.vault_meta.get(txn, primary.as_ref())? else {
            return Err(corrupt());
        };
        let entry = decode_commitment_due_row(primary.as_ref(), value.as_ref())?;
        if entry.instance_ref != Some(*instance_ref) || entry.phase != phase {
            return Err(corrupt());
        }
        Ok(Some(entry))
    }

    /// The pending Project row for a series, if it still has one.
    pub(crate) fn commitment_due_series_project_in_txn(
        &self,
        txn: &RoTxn<'_>,
        series_ref: &EntityId,
    ) -> Result<Option<CommitmentDueEntry>> {
        let Some(primary) = self.vault_meta.get(txn, &series_project_key(series_ref))? else {
            return Ok(None);
        };
        let Some(value) = self.vault_meta.get(txn, primary.as_ref())? else {
            return Err(corrupt());
        };
        let entry = decode_commitment_due_row(primary.as_ref(), value.as_ref())?;
        if entry.series_ref != *series_ref || entry.phase != CommitmentDuePhase::Project {
            return Err(corrupt());
        }
        Ok(Some(entry))
    }

    /// Removes one row and its secondary key together.
    pub(crate) fn commitment_due_delete_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        entry: &CommitmentDueEntry,
    ) -> Result<bool> {
        let key = commitment_due_primary_key(entry);
        let existed = self.vault_meta.delete(wtxn, &key)?;
        match entry.instance_ref {
            Some(instance_ref) => {
                self.vault_meta
                    .delete(wtxn, &reverse_key(&instance_ref, entry.phase))?;
            }
            None => {
                self.vault_meta
                    .delete(wtxn, &series_project_key(&entry.series_ref))?;
            }
        }
        Ok(existed)
    }

    /// Drops every active phase row for one instance. Series membership
    /// survives: a closed occurrence is still an occurrence.
    pub(crate) fn commitment_due_clear_instance_phases_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        instance_ref: &EntityId,
    ) -> Result<usize> {
        let mut removed = 0;
        for phase in CommitmentDuePhase::INSTANCE_PHASES {
            let Some(entry) = self.commitment_due_row_for_in_txn(&*wtxn, instance_ref, phase)?
            else {
                continue;
            };
            if self.commitment_due_delete_in_txn(wtxn, &entry)? {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Drops a series' pending Project row, if any.
    pub(crate) fn commitment_due_clear_series_project_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        series_ref: &EntityId,
    ) -> Result<bool> {
        let Some(entry) = self.commitment_due_series_project_in_txn(&*wtxn, series_ref)? else {
            return Ok(false);
        };
        self.commitment_due_delete_in_txn(wtxn, &entry)
    }

    /// The index summary the driver arms its timer from.
    ///
    /// `next_due_at` is ONE first-key read: the primary key leads with `at`, so
    /// the first row under the prefix is the global minimum. The per-phase
    /// minima need a forward scan, which stops the moment all four phases have
    /// been seen rather than reading the whole index.
    pub(crate) fn commitment_due_snapshot_in_txn(
        &self,
        txn: &RoTxn<'_>,
    ) -> Result<CommitmentDueIndexSnapshot> {
        let mut phase_minima: [Option<u64>; CommitmentDuePhase::COUNT] =
            [None; CommitmentDuePhase::COUNT];
        let mut next_due_at = None;
        let mut seen = 0_usize;
        for row in self.vault_meta.prefix_iter(txn, COMMITMENT_DUE_KEY_PREFIX)? {
            let (key, value) = row?;
            let entry = decode_commitment_due_row(key.as_ref(), value.as_ref())?;
            if next_due_at.is_none() {
                next_due_at = Some(entry.at);
            }
            let slot = &mut phase_minima[entry.phase.as_index()];
            if slot.is_none() {
                *slot = Some(entry.at);
                seen += 1;
                if seen == CommitmentDuePhase::COUNT {
                    break;
                }
            }
        }
        Ok(CommitmentDueIndexSnapshot::new(next_due_at, phase_minima))
    }

    /// Every row in `phases` whose visible instant has arrived, ascending.
    pub(crate) fn commitment_due_entries_through_in_txn(
        &self,
        txn: &RoTxn<'_>,
        now: u64,
        phases: &[CommitmentDuePhase],
    ) -> Result<Vec<CommitmentDueEntry>> {
        let mut entries = Vec::new();
        for row in self.vault_meta.prefix_iter(txn, COMMITMENT_DUE_KEY_PREFIX)? {
            let (key, value) = row?;
            let entry = decode_commitment_due_row(key.as_ref(), value.as_ref())?;
            if entry.at > now {
                break;
            }
            if phases.contains(&entry.phase) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    /// The earliest row in `phases`, wherever it sits in the index.
    pub(crate) fn commitment_due_first_in_phases_in_txn(
        &self,
        txn: &RoTxn<'_>,
        phases: &[CommitmentDuePhase],
    ) -> Result<Option<CommitmentDueEntry>> {
        for row in self.vault_meta.prefix_iter(txn, COMMITMENT_DUE_KEY_PREFIX)? {
            let (key, value) = row?;
            let entry = decode_commitment_due_row(key.as_ref(), value.as_ref())?;
            if phases.contains(&entry.phase) {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }

    /// Instances whose LifecycleDue row is strictly in the past.
    ///
    /// STATUS-UNFILTERED on purpose: a row that survived a crash between the
    /// terminal status write and the close hook is exactly the row that needs
    /// repairing, and filtering by status would hide it forever.
    pub(crate) fn commitment_due_overdue_instances_in_txn(
        &self,
        txn: &RoTxn<'_>,
        now: u64,
    ) -> Result<Vec<EntityId>> {
        let mut ids = Vec::new();
        for row in self.vault_meta.prefix_iter(txn, COMMITMENT_DUE_KEY_PREFIX)? {
            let (key, value) = row?;
            let entry = decode_commitment_due_row(key.as_ref(), value.as_ref())?;
            if entry.at >= now {
                break;
            }
            if entry.phase == CommitmentDuePhase::LifecycleDue {
                ids.push(entry.instance_ref.ok_or_else(corrupt)?);
            }
        }
        Ok(ids)
    }

    /// TEST-SUPPORT ONLY: plants a malformed primary row so the fail-closed
    /// corruption path can be exercised from OUTSIDE this crate (the driver's
    /// deadline-source test proves a corrupt index answers `Err`, never a quiet
    /// "no due work"). Compiled only under the `test-support` feature.
    #[cfg(feature = "test-support")]
    pub(crate) fn corrupt_commitment_due_row_for_test_in_txn(
        &self,
        wtxn: &mut RwTxn<'_>,
        at: u64,
    ) -> Result<()> {
        let mut key = Vec::from(COMMITMENT_DUE_KEY_PREFIX);
        key.extend_from_slice(&at.to_be_bytes());
        key.push(CommitmentDuePhase::Project.as_u8());
        key.extend_from_slice(&[0x5a_u8; 32]);
        self.vault_meta.put(wtxn, &key, &[0xff_u8; VALUE_LEN])?;
        Ok(())
    }
}
