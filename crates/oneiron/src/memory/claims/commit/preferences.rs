//! Stated-preference matching: the prior-claim lookup and preference conflicts. Answer
//! agreement is [`crate::claim::preference_answers_agree`], which the Dreamer's promotion shares.
//! `Memory::find_prior_claim` and the two preference-conflict reads are its call surface.
//! `memory::claims::commit` defines `MemoryKey`, the key these match on.

use super::*;

impl Memory<'_> {
    /// Prior-claim match for auto-supersede: the standing head on `key`.
    /// Deterministic when multiple actives match: the newest id (UUIDv7
    /// order) wins. A write held `beside_stated` (OF-023) never replaces a
    /// `UserStated` head, so those are passed over.
    pub(super) fn find_prior_claim(
        &self,
        key: &MemoryKey<'_>,
        exclude: &EntityId,
        beside_stated: bool,
    ) -> MemoryResult<Option<EntityId>> {
        let ids = self.vault.claims_for_subject(&key.subject)?;
        let mut best: Option<EntityId> = None;
        for id in ids {
            if id == *exclude {
                continue;
            }
            let Some(body) = self.vault.get_claim(&id)? else {
                continue;
            };
            if !key.stands(&body) || (beside_stated && body.source == Some(ClaimSource::UserStated))
            {
                continue;
            }
            best = match best {
                Some(current) if current.to_hex() >= id.to_hex() => Some(current),
                _ => Some(id),
            };
        }
        Ok(best)
    }

    /// [`Self::find_prior_claim`] read in `rtxn` (FIX 9403): an atomic
    /// batch's writer sees the heads its own earlier elements staged there.
    pub(super) fn find_prior_claim_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        key: &MemoryKey<'_>,
        exclude: &EntityId,
        beside_stated: bool,
    ) -> crate::Result<Option<EntityId>> {
        let mut best: Option<EntityId> = None;
        for id in self.vault.claims_for_subject_in_txn(rtxn, &key.subject)? {
            if id == *exclude {
                continue;
            }
            let Some(body) = self.vault.get_claim_in_txn(rtxn, &id)? else {
                continue;
            };
            if !key.stands(&body) || (beside_stated && body.source == Some(ClaimSource::UserStated))
            {
                continue;
            }
            best = match best {
                Some(current) if current.to_hex() >= id.to_hex() => Some(current),
                _ => Some(id),
            };
        }
        Ok(best)
    }

    /// OF-023: the standing `UserStated` peers on `key` whose answer differs
    /// from the observed `value`, read in the write transaction. Every peer
    /// counts, not one advisory newest prior. An incoming id that already
    /// names a stated claim is refused: holding the pair takes two ids.
    pub(super) fn stated_preference_conflicts_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        key: &MemoryKey<'_>,
        id: EntityId,
        value: &Value,
    ) -> crate::Result<Vec<EntityId>> {
        if self
            .vault
            .get_claim_in_txn(rtxn, &id)?
            .is_some_and(|existing| existing.source == Some(ClaimSource::UserStated))
        {
            return Err(Error::InvalidClaimBody(
                "an observed preference cannot reuse a user-stated claim's id",
            ));
        }
        let mut conflicts = Vec::new();
        for peer in self.vault.claims_for_subject_in_txn(rtxn, &key.subject)? {
            let Some(body) = self.vault.get_claim_in_txn(rtxn, &peer)? else {
                continue;
            };
            if body.source == Some(ClaimSource::UserStated)
                && key.stands(&body)
                && !crate::claim::preference_answers_agree(value, &body.value)
            {
                conflicts.push(peer);
            }
        }
        Ok(conflicts)
    }

    /// OF-023: one `core.conflict.open` marker per disagreeing stated peer,
    /// naming `[observed, stated]` under the pair's deterministic id, so a
    /// replay finds its marker and writes nothing. Peers must currently be
    /// valid and share the landed observation's facet and project. The marker
    /// is signed on its own and lands through this actor's content transaction.
    pub(super) fn open_preference_conflicts_in_txn(
        &self,
        content: &mut crate::federation::ActorContentTxn<'_, '_, '_>,
        observed: EntityId,
        stated: &[EntityId],
        envelope: &crate::WriteEnvelope,
        now: u64,
    ) -> crate::Result<()> {
        let body = self
            .vault
            .get_claim_in_txn(content.read(), &observed)?
            .ok_or(Error::EntityNotFound)?;
        let standing_at = self.vault.store.clock.now_recorded_at();
        for old in stated {
            let Some(peer) = self.vault.get_claim_in_txn(content.read(), old)? else {
                continue;
            };
            if peer.scope_facet != body.scope_facet
                || peer.scope_project != body.scope_project
                || peer.valid_from.is_some_and(|start| start > standing_at)
                || peer.valid_to.is_some_and(|end| end <= standing_at)
            {
                continue;
            }
            let marker = crate::claim::conflict_marker(&observed, old, &body, envelope)?;
            if marker.landed_in_txn(self.vault, content.read())? {
                continue;
            }
            let crate::claim::ConflictMarker {
                id,
                candidate,
                mut envelope,
            } = marker;
            // The facade's own signer first; a host-retained one otherwise,
            // as the supersession coaching writer signs its marker.
            self.sign_machine_claim_in_txn(content.read(), id, &candidate, &mut envelope)?;
            self.vault.sign_retained_machine_claim_in_txn(
                content.read(),
                &id,
                &candidate,
                &mut envelope,
            )?;
            content.apply_claim_ops(
                vec![BatchOp::ClaimCandidate {
                    id,
                    candidate: Box::new(candidate),
                    envelope,
                    occurred: TimeRange {
                        start: now,
                        end: now,
                    },
                    learned_at: now,
                    internal_lexical_query_hint: false,
                }],
                self.vault.text_index_trusted.load(Ordering::Acquire),
                ApplyOpsGateMode::new(true, true),
            )?;
        }
        Ok(())
    }
}
