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
use crate::side_table::{self, Raw, SideTable};
use crate::temporal::TimeRange;

use super::*;

/// Value-format version for a due row. Bumping it is an index rebuild, not a
/// silent read.
pub(crate) const COMMITMENT_DUE_INDEX_VERSION: u8 = 1;

/// Kept as a standalone constant — not just `PRIMARY.decl().prefix` — because
/// [`decode_commitment_due_row`] and [`commitment_due_primary_key`] are relied
/// on directly by `crate::commitment_schedule::tests`, outside this migration
/// slice.
#[cfg(test)]
const COMMITMENT_DUE_KEY_PREFIX: &[u8] = b"commitment_due:v1:";

/// Typed doors for the four `commitment_due*` key spaces. Every row's value is
/// the module's own fixed byte layout (or, for the primary table, one more
/// hand-rolled layout on top), so all four stay on [`Raw`] with a `Vec<u8>`
/// key: the module's existing codec functions keep spelling the exact bytes,
/// and the table only takes over the raw get/put/delete/scan plumbing.
const PRIMARY: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::COMMITMENT_DUE_PRIMARY);
const REVERSE: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::COMMITMENT_DUE_REVERSE);
const SERIES_PROJECT: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::COMMITMENT_SERIES_PROJECT);
const SERIES_INSTANCE: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::COMMITMENT_SERIES_INSTANCE);

/// `at(8) ‖ phase(1) ‖ series(16) ‖ instance_or_zero(16)`.
const PRIMARY_KEY_BODY_LEN: usize = 8 + 1 + 16 + 16;
/// `version(1) ‖ due_at(8) ‖ window.start(8) ‖ window.end(8) ‖ ordinal(4)`.
const VALUE_LEN: usize = 1 + 8 + 8 + 8 + 4;

const ZERO_INSTANCE: [u8; 16] = [0_u8; 16];

const CORRUPT: &str = "commitment due index";

fn corrupt() -> Error {
    Error::CorruptedIndex(CORRUPT)
}

/// Bytes after [`COMMITMENT_DUE_KEY_PREFIX`]: `at(8) ‖ phase(1) ‖ series(16) ‖
/// instance_or_zero(16)`.
fn primary_key_body(entry: &CommitmentDueEntry) -> Vec<u8> {
    let mut key = Vec::with_capacity(PRIMARY_KEY_BODY_LEN);
    key.extend_from_slice(&entry.at.to_be_bytes());
    key.push(entry.phase.as_u8());
    key.extend_from_slice(entry.series_ref.as_bytes());
    key.extend_from_slice(
        entry
            .instance_ref
            .as_ref()
            .map_or(&ZERO_INSTANCE, |id| id.as_bytes()),
    );
    key
}

/// The full stored primary key, prefix included — relied on directly by
/// `crate::commitment_schedule::tests`.
#[cfg(test)]
pub(crate) fn commitment_due_primary_key(entry: &CommitmentDueEntry) -> Vec<u8> {
    PRIMARY.key_bytes(&primary_key_body(entry))
}

fn reverse_key_body(instance_ref: &EntityId, phase: CommitmentDuePhase) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.extend_from_slice(instance_ref.as_bytes());
    key.push(phase.as_u8());
    key
}

fn series_project_key_body(series_ref: &EntityId) -> Vec<u8> {
    series_ref.as_bytes().to_vec()
}

fn series_instance_key_body(
    series_ref: &EntityId,
    occurrence: &CommitmentOccurrence,
    instance_ref: &EntityId,
) -> Vec<u8> {
    let mut key = series_ref.as_bytes().to_vec();
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
    Ok(u64::from_be_bytes(bytes.try_into().map_err(|_| corrupt())?))
}

fn be_u32(bytes: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| corrupt())?))
}

fn entity_at(bytes: &[u8]) -> Result<EntityId> {
    let raw: [u8; 16] = bytes.try_into().map_err(|_| corrupt())?;
    EntityId::from_bytes(raw).map_err(|_| corrupt())
}

/// Parses one primary row. Every length, the version byte, the phase byte, both
/// entity ids, the window ordering, and the Project-only zero-instance rule are
/// checked here so no caller can act on a half-understood row.
#[cfg(test)]
pub(crate) fn decode_commitment_due_row(key: &[u8], value: &[u8]) -> Result<CommitmentDueEntry> {
    let body = key
        .strip_prefix(COMMITMENT_DUE_KEY_PREFIX)
        .ok_or_else(corrupt)?;
    decode_commitment_due_body(body, value)
}

/// [`decode_commitment_due_row`] minus the prefix strip, for callers that
/// already hold the typed table's key suffix.
fn decode_commitment_due_body(body: &[u8], value: &[u8]) -> Result<CommitmentDueEntry> {
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
        let key = primary_key_body(entry);
        let full_key = PRIMARY.key_bytes(&key);
        PRIMARY.put(self, wtxn, &key, &encode_value(entry))?;
        match entry.instance_ref {
            Some(instance_ref) => {
                REVERSE.put(
                    self,
                    wtxn,
                    &reverse_key_body(&instance_ref, entry.phase),
                    &full_key,
                )?;
            }
            None => {
                SERIES_PROJECT.put(
                    self,
                    wtxn,
                    &series_project_key_body(&entry.series_ref),
                    &full_key,
                )?;
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
        SERIES_INSTANCE.put(
            self,
            wtxn,
            &series_instance_key_body(series_ref, occurrence, instance_ref),
            &vec![COMMITMENT_DUE_INDEX_VERSION],
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
        let mut members = Vec::new();
        for row in SERIES_INSTANCE.iter_from(self, txn, series_ref.as_bytes())? {
            let (key, value) = row?;
            if value != [COMMITMENT_DUE_INDEX_VERSION] {
                return Err(corrupt());
            }
            let body = key.get(16..).ok_or_else(corrupt)?;
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
    fn commitment_due_row_for_in_txn(
        &self,
        txn: &RoTxn<'_>,
        instance_ref: &EntityId,
        phase: CommitmentDuePhase,
    ) -> Result<Option<CommitmentDueEntry>> {
        let Some(primary) = REVERSE.get(self, txn, &reverse_key_body(instance_ref, phase))? else {
            return Ok(None);
        };
        let body = primary
            .strip_prefix(PRIMARY.decl().prefix)
            .ok_or_else(corrupt)?
            .to_vec();
        let Some(value) = PRIMARY.get(self, txn, &body)? else {
            return Err(corrupt());
        };
        let entry = decode_commitment_due_body(&body, &value)?;
        if entry.instance_ref != Some(*instance_ref) || entry.phase != phase {
            return Err(corrupt());
        }
        Ok(Some(entry))
    }

    /// The pending Project row for a series, if it still has one.
    fn commitment_due_series_project_in_txn(
        &self,
        txn: &RoTxn<'_>,
        series_ref: &EntityId,
    ) -> Result<Option<CommitmentDueEntry>> {
        let Some(primary) = SERIES_PROJECT.get(self, txn, &series_project_key_body(series_ref))?
        else {
            return Ok(None);
        };
        let body = primary
            .strip_prefix(PRIMARY.decl().prefix)
            .ok_or_else(corrupt)?
            .to_vec();
        let Some(value) = PRIMARY.get(self, txn, &body)? else {
            return Err(corrupt());
        };
        let entry = decode_commitment_due_body(&body, &value)?;
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
        let existed = PRIMARY.delete(self, wtxn, &primary_key_body(entry))?;
        match entry.instance_ref {
            Some(instance_ref) => {
                REVERSE.delete(self, wtxn, &reverse_key_body(&instance_ref, entry.phase))?;
            }
            None => {
                SERIES_PROJECT.delete(self, wtxn, &series_project_key_body(&entry.series_ref))?;
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
        for row in PRIMARY.iter_from(self, txn, &[])? {
            let (key, value) = row?;
            let entry = decode_commitment_due_body(&key, &value)?;
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
        for row in PRIMARY.iter_from(self, txn, &[])? {
            let (key, value) = row?;
            let entry = decode_commitment_due_body(&key, &value)?;
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
        for row in PRIMARY.iter_from(self, txn, &[])? {
            let (key, value) = row?;
            let entry = decode_commitment_due_body(&key, &value)?;
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
        for row in PRIMARY.iter_from(self, txn, &[])? {
            let (key, value) = row?;
            let entry = decode_commitment_due_body(&key, &value)?;
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
        let mut body = Vec::with_capacity(PRIMARY_KEY_BODY_LEN);
        body.extend_from_slice(&at.to_be_bytes());
        body.push(CommitmentDuePhase::Project.as_u8());
        body.extend_from_slice(&[0x5a_u8; 32]);
        PRIMARY.put(self, wtxn, &body, &vec![0xff_u8; VALUE_LEN])?;
        Ok(())
    }
}

impl Store {
    pub(crate) fn rebuild_commitment_due_sidecars(&self, txn: &mut RwTxn<'_>) -> Result<()> {
        let entries: Vec<_> = PRIMARY
            .iter_from(self, &*txn, &[])?
            .map(|row| {
                let (key, value) = row?;
                decode_commitment_due_body(&key, &value)
            })
            .collect::<Result<_>>()?;
        for entry in entries {
            self.commitment_due_put_in_txn(txn, &entry)?;
        }
        Ok(())
    }
}
