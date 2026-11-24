//! The arm reads, `vault.arms.get` and `vault.arms.list`: the owner reads
//! every arm; an agent whose live owner Grant names the verb reads the arms
//! of each line that Grant reaches, and no other. An arm the caller may not
//! read answers as one that does not exist.
use std::collections::BTreeMap;

use crate::EntityId;
use crate::Vault;
use crate::gpu_line::VerbGrantHolder;
use crate::memory::{MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult};

use super::{ArmList, ArmListRequest, ArmView};

/// The verb that reads one arm.
pub const ARMS_GET_VERB: &str = "vault.arms.get";
/// The verb that lists arms.
pub const ARMS_LIST_VERB: &str = "vault.arms.list";

impl Vault {
    /// `vault.arms.get`: the arm `arm`, when `caller` may read its line.
    ///
    /// # Errors
    ///
    /// `not_found` for an arm that is not stored or that the caller may not
    /// read; `forbidden` for a caller no Grant admits; a store read failure.
    pub fn experiment_arm_view(
        &self,
        caller: VerbGrantHolder<'_>,
        arm: &EntityId,
    ) -> MemoryResult<ArmView> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let found = self.experiment_arm_in_txn(&txn, arm)?;
        match found {
            Some(found) if caller.reads_line_in_txn(self, &txn, ARMS_GET_VERB, found.line)? => {
                Ok(ArmView::of(found, false))
            }
            Some(_) | None => {
                // A caller with no standing Grant is refused rather than told
                // the arm is missing.
                caller.admitted_in_txn(self, &txn, ARMS_GET_VERB)?;
                Err(arm_not_found())
            }
        }
    }

    /// `vault.arms.list`: the arms `caller` may read under `request`'s
    /// filters, newest first.
    ///
    /// # Errors
    ///
    /// `bad_request` for a filter id that does not parse; `forbidden` for a
    /// caller no Grant admits; a store read failure.
    pub fn experiment_arm_list(
        &self,
        caller: VerbGrantHolder<'_>,
        request: &ArmListRequest,
    ) -> MemoryResult<ArmList> {
        let (line, family) = request.filters()?;
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let mut readable: BTreeMap<EntityId, bool> = BTreeMap::new();
        let mut arms = Vec::new();
        for arm in self.experiment_arms_in_txn(&txn)? {
            if line.is_some_and(|line| line != arm.line)
                || family.is_some_and(|family| family != arm.family)
                || (request.open_only && !arm.is_open())
            {
                continue;
            }
            let reads = match readable.get(&arm.line) {
                Some(reads) => *reads,
                None => {
                    let reads = caller.reads_line_in_txn(self, &txn, ARMS_LIST_VERB, arm.line)?;
                    readable.insert(arm.line, reads);
                    reads
                }
            };
            if reads {
                arms.push(ArmView::of(arm, false));
            }
        }
        if readable.is_empty() {
            // No arm matched: still refuse a caller no Grant admits.
            caller.admitted_in_txn(self, &txn, ARMS_LIST_VERB)?;
        }
        arms.sort_by(|a, b| {
            (b.arm.admitted_at_ms, b.arm.id).cmp(&(a.arm.admitted_at_ms, a.arm.id))
        });
        Ok(ArmList { arms })
    }
}

fn arm_not_found() -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_NOT_FOUND,
        "no experiment arm of a line the caller may read has this id",
        &["List the arms with vault.arms.list."],
    )
}
