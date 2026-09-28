//! Entity-put builder doors: the public put, the typed crate doors, and the
//! sync/test replicated door.

use super::super::*;
use super::BatchBuilder;
#[cfg(any(feature = "sync", test))]
use super::ops::replicated_put_op;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TASK;
use crate::temporal::TimeRange;

/// A check the committing terminal runs before it opens its transaction, on
/// the put op at the index it names.
///
/// The type byte of a public put, and the envelope of a replicated fixture
/// put, were always judged at call time on the committing builder, so a bad
/// byte there refuses before its transaction opens. The caller-transaction
/// terminal never ran them: its puts meet the same gates inside the
/// transaction (`validate_put_type` and `apply_put`), because a runtime pack
/// handle resolved outside it would be read from a snapshot that cannot see
/// the caller's uncommitted registrations. Recording them here keeps both
/// terminals exactly where they were.
pub(super) enum CommitCheck {
    PublicType(usize),
    #[cfg(any(feature = "sync", test))]
    Replicated(usize),
}

impl CommitCheck {
    /// Runs every check in call order. Checks are recorded only while no
    /// builder-time error is captured, so each one precedes that error.
    pub(super) fn run_all(checks: &[Self], vault: &Vault, ops: &[BatchOp]) -> Result<()> {
        for check in checks {
            match *check {
                Self::PublicType(index) => {
                    let (entity_type, _) = put_envelope(ops, index)?;
                    vault.store.validate_public_entity_type(entity_type)?;
                }
                #[cfg(any(feature = "sync", test))]
                Self::Replicated(index) => {
                    let (entity_type, occurred) = put_envelope(ops, index)?;
                    if crate::registry::zone_of(entity_type)
                        != crate::registry::TypeByteZone::PackHandle
                    {
                        vault.store.validate_entity_type(entity_type)?;
                    }
                    if occurred.start > occurred.end {
                        return Err(Error::InvalidTimeRange {
                            start: occurred.start,
                            end: occurred.end,
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

fn put_envelope(ops: &[BatchOp], index: usize) -> Result<(u8, TimeRange)> {
    match ops.get(index) {
        Some(BatchOp::Put {
            entity_type,
            occurred,
            ..
        }) => Ok((*entity_type, *occurred)),
        _ => Err(Error::InvariantViolation(
            "a commit check names a put op the batch does not hold",
        )),
    }
}

impl BatchBuilder<'_> {
    /// Adds an entity put operation to the batch.
    ///
    /// This is a PUBLIC door and is held to the public checks on both
    /// terminals. The committing terminal validates `entity_type` through the
    /// entity type registry before it opens its transaction; the
    /// caller-transaction terminal validates it inside the caller's
    /// transaction. A body the public checks refuse is captured here and
    /// surfaced by the terminal.
    ///
    /// Crate callers that legitimately write a TASK whose deadline has already
    /// passed — settling an expired task is the whole example — say so by name
    /// through the crate-private internal put instead.
    pub fn put(
        mut self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        if self.validation_error.is_none() {
            self.commit_checks
                .push(CommitCheck::PublicType(self.ops.len()));
        }
        self.put_through(
            id,
            entity_type,
            occurred,
            learned_at,
            data,
            RawPutDoor::Public,
        )
    }

    /// [`Self::put`] through the INTERNAL door: everything the public door
    /// checks except the born-expired TASK deadline.
    ///
    /// The expiry lane's whole job is to write to a task whose deadline has
    /// passed. Refusing that would make settling an expired task impossible,
    /// so the lane names its exemption here rather than the door quietly
    /// granting it to every caller.
    pub(crate) fn put_internal(
        self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        self.put_through(
            id,
            entity_type,
            occurred,
            learned_at,
            data,
            RawPutDoor::Internal,
        )
    }

    /// The ONE-1686 witness MESSAGE put: the only door that stages an
    /// `ENTITY_TYPE_MESSAGE` row.
    ///
    /// It takes the ceiling door's own [`WitnessMessageAuthorization`] and
    /// writes the bytes THAT value carries — never a separately supplied body —
    /// so the axes the door authorized and the bytes that land cannot diverge,
    /// and nothing between the check and the put can substitute an envelope.
    /// Holding the authorization is the permission: its only constructor is
    /// [`crate::gate::check_witness_message_ceiling`], which runs inside this
    /// same write transaction against the same policy snapshot.
    ///
    /// [`WitnessMessageAuthorization`]: crate::gate::WitnessMessageAuthorization
    pub(crate) fn put_witness_message(
        self,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        authorization: &crate::gate::WitnessMessageAuthorization<'_>,
    ) -> Self {
        let body = authorization.body();
        self.put_through(
            id,
            crate::registry::ENTITY_TYPE_MESSAGE,
            occurred,
            learned_at,
            body,
            RawPutDoor::WitnessMessage,
        )
    }

    fn put_through(
        mut self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
        door: RawPutDoor,
    ) -> Self {
        if self.validation_error.is_none()
            && let Err(e) = validate_public_raw_put(entity_type, data, learned_at, door)
        {
            self.validation_error = Some(e);
        }
        self.ops
            .push(plain_put_op(id, entity_type, occurred, learned_at, data));
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
        self.ops.push(plain_put_op(
            id,
            crate::registry::ENTITY_TYPE_MESSAGE,
            occurred,
            learned_at,
            data,
        ));
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

    /// Engine-authored TASK facts cannot pass a raw put, which refuses their
    /// reserved role. The materialization checks still run at apply time.
    pub(crate) fn put_task_fact(mut self, id: &EntityId, data: &[u8], at: u64) -> Self {
        if self.validation_error.is_none() {
            self.validation_error = match crate::habit::task_role_from_body_bytes(data) {
                Ok(crate::habit::TaskRole::AuthorityFact) => None,
                Ok(_) => Some(Error::Record(crate::error::RecordError::InvalidTaskBody(
                    "task fact requires AuthorityFact role",
                ))),
                Err(error) => Some(error),
            };
        }
        self.ops.push(plain_put_op(
            id,
            ENTITY_TYPE_TASK,
            TimeRange { start: at, end: at },
            at,
            data,
        ));
        self
    }

    /// Adds the actor-attributed NOTE put behind
    /// [`Memory::author_take`](crate::memory::Memory::author_take)
    /// — the only door that may write `ENTITY_TYPE_NOTE`, since the raw put
    /// rejects the type outright.
    ///
    /// The typed door earns that bypass rather than inheriting it: it decodes
    /// the body under the pinned NOTE ABI and requires the stored
    /// `author_ref` to be `author`, the actor the caller has already verified
    /// against the store in this transaction. What the raw door cannot do is
    /// name that actor; this one is handed it.
    pub(crate) fn put_authored_note(
        mut self,
        id: &EntityId,
        author: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        if self.validation_error.is_none()
            && let Err(e) = validate_authored_note_body(author, data)
        {
            self.validation_error = Some(e);
        }
        self.ops.push(plain_put_op(
            id,
            crate::registry::ENTITY_TYPE_NOTE,
            occurred,
            learned_at,
            data,
        ));
        self
    }

    /// Adds a type-0 (CLAIM) put whose predicate may live in the reserved
    /// `edge.*` namespace (D17 reserved-namespace door).
    ///
    /// This is the ONLY path that may write `edge.*` predicates; it exists
    /// for the engine's provenance unit (`edge.provenance` Claims). Full
    /// structural body validation (D18) still applies at apply time — the
    /// door bypasses nothing except the reserved-namespace rejection.
    #[cfg(test)]
    pub(crate) fn put_reserved_claim(
        mut self,
        id: &EntityId,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        self.ops.push(BatchOp::Put {
            id: *id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data: data.to_vec(),
            allow_maintenance: false,
            allow_reserved_predicate: true,
            hub_sync_imported: false,
        });
        self
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
    /// Production replay (`window::forward_rematerialize`,
    /// `bridge::materialize_entity_blob_in_txn` and the other sync doors)
    /// applies it in the caller's transaction, where the type byte and the
    /// occurred range meet `validate_put_type` and `apply_put`, and a
    /// federated import tier ([`Self::with_import_tier`]) sends the body
    /// through federation admission first. The committing terminal, which
    /// only fixtures use, refuses a bad type byte or a reversed range before
    /// it opens its transaction. The gate is exactly its consumer set:
    ///
    /// * `sync` — the production replay doors, and
    ///   `sync::selector::put_selector_test_federation_grant`, the
    ///   cross-crate test-only seam compiled in with `test-hooks`;
    /// * `test` — in-crate fixtures seeding replicated-shape rows without a
    ///   live sync stack, including featureless builds, where the op-level
    ///   admit flags it sets are ordinary base machinery.
    #[cfg(any(feature = "sync", test))]
    pub(crate) fn put_replicated(
        mut self,
        id: &EntityId,
        entity_type: u8,
        occurred: TimeRange,
        learned_at: u64,
        data: &[u8],
    ) -> Self {
        #[cfg(feature = "sync")]
        if matches!(
            self.import_tier,
            crate::sync::client::ImportTier::Federated(_)
        ) {
            self.federated_puts.push(self.ops.len());
        }
        if self.validation_error.is_none() {
            self.commit_checks
                .push(CommitCheck::Replicated(self.ops.len()));
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

/// A put op with every admit flag closed: the shape every local door stages.
fn plain_put_op(
    id: &EntityId,
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    data: &[u8],
) -> BatchOp {
    BatchOp::Put {
        id: *id,
        entity_type,
        occurred,
        learned_at,
        data: data.to_vec(),
        allow_maintenance: false,
        allow_reserved_predicate: false,
        hub_sync_imported: false,
    }
}
