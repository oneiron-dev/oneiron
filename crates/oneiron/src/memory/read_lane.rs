//! The bound actor's one read lane. Every Memory read verb opens it, so each
//! verb admits exactly what `ScopedRead` admits and returns its receipt.

use super::structural::kind_string_for_type;
use super::support::*;
use super::*;

use crate::claim::{
    ClaimReadStatus, PointRead, ReadRow, ScopedRead, ScopedReadActorKey, ScopedReadReceipt,
    ScopedReadResult,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::vault::ReadMode;

/// One resolved read target: the entity a reference names, at its frontier.
/// `None` is a reference that resolves to nothing, never a withheld row.
pub(super) type ReadTargetSlot = Option<(EntityId, ReadMode)>;

impl Memory<'_> {
    /// Opens the bound actor's scoped read.
    ///
    /// The actor row must hold its class (store truth). An actor bound to a
    /// verified credential reads under that credential's key. Otherwise the
    /// vault owner, a human actor whose owner verification passes, reads
    /// under the owner's key: DEC-0005's own-device ceiling, all of the
    /// owner's vault. Every other actor reads under its grants. `claims` is
    /// the verb's contract: record verbs serve every claim status, retrieval
    /// channels only surfaceable claims. A handle bound to a room turn reads
    /// inside that room on every lane.
    pub(crate) fn read_lane(&self, claims: ClaimReadStatus) -> MemoryResult<ScopedRead<'_>> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|error| MemoryError::from(Error::from(error)))?;
        verify_actor_binding_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
        if let Some(proof) = &self.read_proof {
            let key = (proof.claims().holder_ref == self.actor.to_hex())
                .then(|| ScopedReadActorKey::from_verified_slip(proof))
                .flatten()
                .ok_or_else(|| {
                    MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        "the bound read credential does not grant this actor a read",
                        &["Present a credential minted for this actor that carries the read verb."],
                    )
                })?;
            return Ok(self
                .vault
                .scoped_read(self.in_room_turn(key))
                .with_claim_status(claims));
        }
        let owner = if self.actor_class == crate::EdgeActorClass::Human
            && self.actor == crate::vault::embedded_owner_actor_id()?
        {
            // The local embedded-owner reader is the host's own-device read lane.
            // A separately paired authority root does not turn it into a peer.
            true
        } else {
            match self.verify_owner_in_txn(&txn) {
                Ok(()) => true,
                // Not the owner: a human without the binding, or another class.
                Err(error)
                    if error.code == MEMORY_CODE_OWNER_BINDING_REQUIRED
                        || error.code == MEMORY_CODE_FORBIDDEN =>
                {
                    false
                }
                Err(error) => return Err(error),
            }
        };
        let key = if owner {
            ScopedReadActorKey::vault_owner(self.actor)
        } else {
            ScopedReadActorKey::with_actor_class(
                self.actor.to_hex(),
                self.actor_class.gate_actor_class(),
            )
            .ok_or_else(|| {
                MemoryError::bad_request("bound actor cannot be used as a scoped read key")
            })?
            .require_access_grants(Some(self.actor))
        };
        Ok(self
            .vault
            .scoped_read(self.in_room_turn(key))
            .with_claim_status(claims))
    }

    /// Carries a bound room turn onto a read key, so any lane built from the
    /// key, here or deeper in retrieval, reads inside the room (ARCH-0067 §8).
    pub(crate) fn in_room_turn(&self, key: ScopedReadActorKey) -> ScopedReadActorKey {
        match &self.room_turn {
            Some(turn) => key.in_room_turn(turn.clone()),
            None => key,
        }
    }

    /// Resolves a facade ref for a read on `lane`. A ref that resolves to
    /// nothing is `NOT_FOUND` carrying the lane's receipt.
    pub(super) fn resolve_ref_in_lane(
        &self,
        lane: &ScopedRead<'_>,
        reference: &str,
    ) -> MemoryResult<EntityId> {
        match self.resolve_ref(reference) {
            Ok(id) => Ok(id),
            Err(error) => Err(self.with_lane_receipt(lane, error)?),
        }
    }

    /// Attaches the lane's receipt to a `NOT_FOUND`; other refusals pass.
    pub(super) fn with_lane_receipt(
        &self,
        lane: &ScopedRead<'_>,
        error: MemoryError,
    ) -> MemoryResult<MemoryError> {
        if error.code != MEMORY_CODE_NOT_FOUND {
            return Ok(error);
        }
        Ok(error.with_read_receipt(lane.read_receipt(None, 0)?))
    }

    /// Resolves one entity reference at `mode` without reading its body.
    /// Resolution maps a name to an id; admission is the lane's read.
    pub(super) fn read_target(
        &self,
        reference: &str,
        mode: ReadMode,
    ) -> MemoryResult<ReadTargetSlot> {
        let id = match mode {
            ReadMode::Pinned(revision) => self
                .vault
                .resolve_pinned_entity_reference(reference, revision)?,
            _ => match self.resolve_ref(reference) {
                Ok(id) => Some(id),
                Err(error) if error.code == MEMORY_CODE_NOT_FOUND => None,
                Err(error) => return Err(error),
            },
        };
        Ok(id.map(|id| (id, mode)))
    }

    /// Reads every resolved target through `lane` in one snapshot and one
    /// receipt, projecting each admitted row to its view. Slots stay in order.
    pub(super) fn read_views(
        &self,
        lane: &ScopedRead<'_>,
        targets: &[ReadTargetSlot],
    ) -> MemoryResult<ScopedReadResult<Vec<Option<EntityView>>>> {
        self.read_views_after(lane, targets, || {})
    }

    /// The callback is a test seam for a write between row admission and
    /// projection; production callers pass an empty callback.
    pub(super) fn read_views_after(
        &self,
        lane: &ScopedRead<'_>,
        targets: &[ReadTargetSlot],
        after_read: impl FnOnce(),
    ) -> MemoryResult<ScopedReadResult<Vec<Option<EntityView>>>> {
        let reads: Vec<_> = targets
            .iter()
            .flatten()
            .map(|(id, mode)| PointRead::id(*id).at(*mode))
            .collect();
        lane.read_projected(&reads, None, |txn, value| {
            after_read();
            let mut rows = value.into_iter();
            let mut views = Vec::with_capacity(targets.len());
            for target in targets {
                let view = match target {
                    Some((_, mode)) => match rows.next().flatten() {
                        Some(row) => self.entity_view_of_in_txn(txn, row, *mode)?,
                        None => None,
                    },
                    None => None,
                };
                views.push(view);
            }
            Ok::<_, MemoryError>(views)
        })
    }

    /// Projects one admitted row to the typed entity view. A deleted shell
    /// has no body and projects to nothing.
    pub(super) fn entity_view_of_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        row: ReadRow,
        mode: ReadMode,
    ) -> MemoryResult<Option<EntityView>> {
        let Some(body) = row.body else {
            return Ok(None);
        };
        let short_ref = self.short_ref_of_in_txn(txn, &row.id)?.map(|reference| {
            let short = reference.split(':').next().unwrap_or(&reference);
            match mode {
                ReadMode::Pinned(revision) => {
                    format!("{short}:{:02x}@{}", row.content_hash, revision.to_hex())
                }
                _ => format!("{short}:{:02x}", row.content_hash),
            }
        });
        Ok(Some(EntityView {
            id_hex: row.id.to_hex(),
            short_ref,
            kind: kind_string_for_type(row.entity_type),
            occurred_start: row.occurred.start,
            occurred_end: row.occurred.end,
            learned_at: row.learned_at,
            body: decode_body_json(&body),
        }))
    }
}

/// Folds a later read on the same lane into the verb's receipt.
pub(super) fn fold_receipt(receipt: &mut Option<ScopedReadReceipt>, later: ScopedReadReceipt) {
    match receipt {
        Some(receipt) => receipt.restrict_with(&later),
        None => *receipt = Some(later),
    }
}
