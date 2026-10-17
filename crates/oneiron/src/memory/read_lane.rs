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
    /// The actor row must hold its class (store truth). The vault owner, a
    /// human actor whose owner verification passes, reads under the owner's
    /// key: DEC-0005's own-device ceiling, all of the owner's vault. So does
    /// the owner bound to its own live, full owner-grade credential. Any
    /// other actor bound to a verified credential reads under that
    /// credential's key; one other than the owner reads a relationship-scoped
    /// or private row only on a live grant for its relationship, and an
    /// unscoped row as the credential's records allow. Every other actor
    /// reads under its grants. `claims` is the verb's contract: record verbs
    /// serve every claim status, retrieval channels only surfaceable claims.
    /// A handle bound to a room turn reads inside that room on every lane.
    pub(crate) fn read_lane(&self, claims: ClaimReadStatus) -> MemoryResult<ScopedRead<'_>> {
        // The room resolver opens its own snapshots, so it runs only once the
        // verification snapshot here has closed: LMDB allows one per thread.
        let key = self.actor_read_key()?;
        Ok(self
            .vault
            .scoped_read(self.in_room_turn(key)?)
            .with_claim_status(claims))
    }

    /// The key every read verb on this handle reads under: its proof's, its
    /// locality's and its room turn's. A verb hook a call fires reads
    /// through it, capped by the hook's grant (ARCH-0080 §3).
    ///
    /// # Errors
    ///
    /// As [`Self::read_lane`] refuses.
    pub fn read_key(&self) -> MemoryResult<ScopedReadActorKey> {
        self.in_room_turn(self.actor_read_key()?)
    }

    /// The bound actor's own read, without a bound room turn's ceiling: what
    /// its grants alone admit. A room read checks it beside membership; it
    /// never serves a row inside a turn.
    pub(crate) fn own_read_lane(&self, claims: ClaimReadStatus) -> MemoryResult<ScopedRead<'_>> {
        Ok(self
            .vault
            .scoped_read(self.actor_read_key()?)
            .with_claim_status(claims))
    }

    /// The bound actor's read key, verified in one snapshot, for the caller
    /// where it sits.
    fn actor_read_key(&self) -> MemoryResult<ScopedReadActorKey> {
        Ok(self.identity_read_key()?.at(self.locality))
    }

    /// The bound actor's read key by identity alone.
    fn identity_read_key(&self) -> MemoryResult<ScopedReadActorKey> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|error| MemoryError::from(Error::from(error)))?;
        verify_actor_binding_in_txn(self.vault, &txn, self.actor, self.actor_class)?;
        let owner = self.is_vault_owner_in_txn(&txn)?;
        if let Some(proof) = &self.read_proof {
            // The one key every proof-backed door builds (credential_key.rs).
            return self
                .vault
                .credential_read_key_in_txn(&txn, proof, self.actor, owner)?
                .ok_or_else(|| {
                    MemoryError::new(
                        MEMORY_CODE_FORBIDDEN,
                        "the bound read credential does not grant this actor a read",
                        &["Present a credential minted for this actor that carries the read verb."],
                    )
                });
        }
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
        Ok(key)
    }

    /// How a serving door hands the bound actor a file stored with keys in
    /// it (OF-560): the vault owner's own key reads the stored bytes, every
    /// other actor a copy with each key overwritten.
    pub(crate) fn secret_sight(&self) -> MemoryResult<crate::secret_custody::SecretSight> {
        Ok(if self.identity_read_key()?.reads_as_vault_owner() {
            crate::secret_custody::SecretSight::Owner
        } else {
            crate::secret_custody::SecretSight::Masked
        })
    }

    /// Of `ids`, the ones a handle bound to a read credential reads, each
    /// judged by the lane's point read in one snapshot, as `get_entity`
    /// judges it. `None` is a handle bound to no credential: its surfaces
    /// show what the actor's own verbs do.
    pub(crate) fn credential_readable_ids(
        &self,
        ids: &[EntityId],
    ) -> MemoryResult<Option<std::collections::BTreeSet<EntityId>>> {
        if self.read_proof.is_none() {
            return Ok(None);
        }
        let reads: Vec<_> = ids.iter().map(|id| PointRead::id(*id)).collect();
        let rows = self
            .read_lane(ClaimReadStatus::Recorded)?
            .read(&reads, None)
            .map_err(MemoryError::from)?
            .value;
        Ok(Some(
            rows.into_iter()
                .flatten()
                .filter(|row| row.body.is_some())
                .map(|row| row.id)
                .collect(),
        ))
    }

    /// Whether the bound actor is the vault owner now: the local embedded
    /// owner, or a human whose owner binding verifies. A row the owner may
    /// read beside its caller asks it (FIX 2279).
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn is_vault_owner(&self) -> MemoryResult<bool> {
        let txn = self
            .vault
            .store
            .env
            .read_txn()
            .map_err(|error| MemoryError::from(Error::from(error)))?;
        self.is_vault_owner_in_txn(&txn)
    }

    /// Whether the bound actor is the vault owner: the local embedded owner,
    /// or a human whose owner binding verifies.
    pub(super) fn is_vault_owner_in_txn(&self, txn: &heed::RoTxn<'_>) -> MemoryResult<bool> {
        super::credential_key::actor_is_vault_owner_in_txn(
            self.vault,
            txn,
            self.actor,
            self.actor_class,
        )
    }

    /// Carries a bound room turn onto a read key, so any lane built from the
    /// key, here or deeper in retrieval, reads inside the room (ARCH-0067 §8).
    /// The ceiling is the room's as of this read, never only as it opened.
    pub(crate) fn in_room_turn(&self, key: ScopedReadActorKey) -> MemoryResult<ScopedReadActorKey> {
        Ok(match self.room_turn_now()? {
            Some(turn) => key.in_room_turn(turn),
            None => key,
        })
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

    /// [`Self::read_views`] for a door whose output no read can follow
    /// exactly (a pack writer lays a body's fields out in its own rows): a
    /// body the write door refuses, stored while the owner's scan was off, is
    /// withheld whole, as one no decoder reads is, whatever the switch is now.
    pub(super) fn read_views_whole_body(
        &self,
        lane: &ScopedRead<'_>,
        targets: &[ReadTargetSlot],
    ) -> MemoryResult<ScopedReadResult<Vec<Option<EntityView>>>> {
        self.read_views_in(lane, targets, true, || {})
    }

    /// The callback is a test seam for a write between row admission and
    /// projection; production callers pass an empty callback.
    pub(super) fn read_views_after(
        &self,
        lane: &ScopedRead<'_>,
        targets: &[ReadTargetSlot],
        after_read: impl FnOnce(),
    ) -> MemoryResult<ScopedReadResult<Vec<Option<EntityView>>>> {
        self.read_views_in(lane, targets, false, after_read)
    }

    fn read_views_in(
        &self,
        lane: &ScopedRead<'_>,
        targets: &[ReadTargetSlot],
        whole_body: bool,
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
                        Some(row) => {
                            let refused = whole_body
                                && row
                                    .body
                                    .as_deref()
                                    .is_some_and(crate::batch::export::write_door_refuses_body);
                            self.entity_view_of_in_txn(lane, txn, row, *mode)?
                                .map(|view| EntityView {
                                    body: view.body.filter(|_| !refused),
                                    ..view
                                })
                        }
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
    /// Projects a row `lane` admitted; its short ref is read where the lane
    /// reads, a room's view included.
    pub(super) fn entity_view_of_in_txn(
        &self,
        lane: &ScopedRead<'_>,
        txn: &heed::RoTxn<'_>,
        row: ReadRow,
        mode: ReadMode,
    ) -> MemoryResult<Option<EntityView>> {
        let Some(body) = row.body else {
            return Ok(None);
        };
        let short_ref = short_ref_in_txn(&lane.store_read(), txn, &row.id)?.map(|reference| {
            let short = reference.split(':').next().unwrap_or(&reference);
            match mode {
                ReadMode::Pinned(revision) => {
                    format!("{short}:{:02x}@{}", row.content_hash, revision.to_hex())
                }
                _ => format!("{short}:{:02x}", row.content_hash),
            }
        });
        let mut body = decode_body_json(&body);
        // A key the lift sweep marked in a record's text reads as its handle
        // to all but the owner (OF-067).
        if let Some(value) = &mut body
            && self.reads_lifted_keys_masked()?
        {
            let keys = crate::batch::secret_scan::LiftedKeys::of_json_in_txn(
                &self.vault().store,
                txn,
                value,
            )?;
            keys.mask_json(value);
        }
        Ok(Some(EntityView {
            id_hex: row.id.to_hex(),
            short_ref,
            kind: kind_string_for_type(row.entity_type),
            occurred_start: row.occurred.start,
            occurred_end: row.occurred.end,
            learned_at: row.learned_at,
            body,
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
