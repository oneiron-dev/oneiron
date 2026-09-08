//! Entity-put builder doors including the sync/test replicated door.

use super::super::*;
use super::BatchBuilder;
#[cfg(any(test, all(feature = "sync", feature = "test-hooks")))]
use super::ops::replicated_put_op;

use crate::Vault;
use crate::entity_id::EntityId;
#[cfg(any(test, all(feature = "sync", feature = "test-hooks")))]
use crate::error::Error;
use crate::registry::ENTITY_TYPE_TASK;
use crate::temporal::TimeRange;

impl<'a> BatchBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            ops: Vec::new(),
            validation_error: None,
        }
    }

    /// Adds an entity put operation to the batch.
    ///
    /// Validates `entity_type` eagerly via the entity type registry. If validation
    /// fails, the error is stored and surfaced on [`commit()`](Self::commit).
    pub fn put(
        mut self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        if self.validation_error.is_none()
            && let Err(e) = self.vault.store.validate_public_entity_type(entity_type)
        {
            self.validation_error = Some(e);
        }
        if self.validation_error.is_none()
            && let Err(e) =
                validate_public_raw_put(entity_type, data, learned_at, RawPutDoor::Public)
        {
            self.validation_error = Some(e);
        }
        self.ops.push(BatchOp::Put {
            id: *id,
            entity_type,
            occurred,
            learned_at,
            data: data.to_vec(),
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        });
        self
    }

    /// TEST-ONLY MESSAGE seeding (ONE-1686).
    ///
    /// Unrelated fixtures across the crate need one MESSAGE row to exist —
    /// a VAD annotation target, a conversion source, a citation — without the
    /// conversation, turn, actor and edges a real witness call mints, because
    /// those extra entities are exactly what those fixtures are counting.
    /// Routing them through the witness door would change what they measure;
    /// leaving them on the public raw door would mean the door was never
    /// closed.
    ///
    /// This is NOT a bypass of the envelope law: the op still lands in
    /// `apply_put`, which proves the bytes are the canonical six-axis envelope
    /// on every road, so a fixture can only seed a row a real witness could
    /// also have written. What it skips is the ACTOR-bound ceiling, which a
    /// fixture with no actor has nothing to present to — and it exists only
    /// under `cfg(test)`, so no production caller can reach it at all.
    #[cfg(test)]
    pub(crate) fn put_canonical_message_for_test(
        mut self,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        self.ops.push(BatchOp::Put {
            id: *id,
            entity_type: crate::registry::ENTITY_TYPE_MESSAGE,
            occurred,
            learned_at,
            data: data.to_vec(),
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        });
        self
    }

    /// Appends an immutable TASK/HabitCheckin child under an existing Habit TASK.
    ///
    /// The check-in is stored as its own TASK entity and linked with a
    /// `ChildOf` edge (`checkin -> habit`). The shared apply path rejects
    /// divergent same-id re-put of check-ins and rejects attachments whose
    /// parent is not a Habit-role TASK.
    pub fn put_habit_checkin(
        self,
        habit_id: &EntityId,
        checkin_id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        let mut builder = self.put(checkin_id, ENTITY_TYPE_TASK, occurred, learned_at, data);
        if builder.validation_error.is_none()
            && let Err(e) = validate_habit_checkin_body(data)
        {
            builder.validation_error = Some(e);
        }
        builder.edge_checked(checkin_id, habit_id, 1.0)
    }

    /// Sync-replay door (replicated flavor of the old internal put path):
    /// engine-internal put for CRDT→LMDB rematerialization. It admits BOTH
    /// engine-authored bands that the public [`put`](Self::put) gate rejects:
    ///
    /// * the engine-authored system zone (e.g. REDACTION_AUDIT), validated
    ///   via the registry-only entity-type gate so GDPR receipts
    ///   survive cross-node sync / replay — public writes still fail with
    ///   `MaintenanceKindNotWritable`, and genuinely unknown bytes still
    ///   fail here with `InvalidEntityType`;
    /// * the reserved `edge.*` predicate namespace (D17) on type-0 CLAIM
    ///   bodies, so `edge.provenance` truth-Claims authored on a remote node
    ///   rematerialize — public writes still fail with `ReservedPredicate`.
    ///
    /// The door bypasses nothing except those two band rejections: `apply_put`
    /// still runs the full D18 structural validation on every type-0 body, so
    /// ungrammatical predicates and malformed bodies fail typed even here.
    ///
    /// FIXTURE DOOR: this non-transactional flavor has NO production caller.
    /// Production replay runs through `TxnBatchBuilder::put_replicated`, which
    /// stays `sync`-gated (`window::forward_rematerialize` and the other sync
    /// doors call THAT flavor). The gate below is exactly its consumer set:
    ///
    /// * `test` — in-crate fixtures seeding replicated-shape rows without a
    ///   live sync stack, including featureless builds, where the op-level
    ///   admit flags it sets are ordinary base machinery;
    /// * `sync` + `test-hooks` — `sync::selector::put_selector_test_federation_grant`,
    ///   the cross-crate test-only seam, which is compiled into the non-test
    ///   library whenever both features are on.
    ///
    /// Keeping the gate this tight is load-bearing: under plain `--features
    /// sync` the method would otherwise be dead code under `-D warnings`.
    #[cfg(any(test, all(feature = "sync", feature = "test-hooks")))]
    pub(crate) fn put_replicated(
        mut self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        if self.validation_error.is_none()
            && let Err(e) = self.vault.store.validate_entity_type(entity_type)
        {
            self.validation_error = Some(e);
        }
        if self.validation_error.is_none() && occurred.start > occurred.end {
            self.validation_error = Some(Error::InvalidTimeRange {
                start: occurred.start,
                end: occurred.end,
            });
        }
        self.ops.push(replicated_put_op(
            id,
            entity_type,
            occurred,
            learned_at,
            data,
        ));
        self
    }
}
