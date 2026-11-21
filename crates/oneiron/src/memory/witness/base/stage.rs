//! Base witness staging: the turn's one batch, its text ops, the session bump and its membership.

use super::*;

impl Memory<'_> {
    /// Stages the admitted turn into base: one batch, its text ops, the open
    /// session's activity bump and the turn's session membership. A minted
    /// quoted turn also takes its `RepliesTo` edge and a project thread
    /// reply's `Parent` here, in the TURN's own write (OF-460); its messages'
    /// citation pins were written by the room guard in this same write.
    pub(in crate::memory::witness) fn stage_in_base(
        &self,
        plan: &WitnessPlan<'_>,
        admission: &WitnessAdmission<'_>,
        sink: &BaseSink<'_>,
        mint_conversation: bool,
        quoted: Option<&crate::conversation_dag::QuotedReply>,
        wtxn: &mut heed::RwTxn<'_>,
    ) -> MemoryResult<()> {
        // A source landing marks each row it stamps born in this write before
        // it stages it: the write door admits the stamp under that mark
        // alone, and binding the row takes it away (fix list row 16256).
        let birth = plan
            .imported
            .as_ref()
            .and_then(|stamp| stamp.source_audience.as_ref());
        if let Some(birth) = birth {
            let turn_put =
                matches!(admission.turn, AdmittedTurn::Mint { .. }) || admission.has_new_messages();
            let stamped = mint_conversation
                .then_some(plan.conversation_id)
                .into_iter()
                .chain(turn_put.then_some(plan.turn_id))
                .chain(plan.message_ids());
            for id in stamped {
                crate::source_audience::mark_birth_in_txn(self.vault, wtxn, birth, &id)?;
            }
        }
        // A TURN an import births is born under its stamp's facet, when it
        // names one; the vault default otherwise.
        let mut batch = self
            .vault
            .batch_in()
            .mask(plan.imported.as_ref().and_then(|stamp| stamp.facet));
        if mint_conversation {
            batch = put_container(
                batch,
                birth,
                plan.phone_birth.as_ref(),
                &plan.conversation_id,
                ENTITY_TYPE_CONVERSATION,
                (plan.occurred, plan.learned_at),
                &plan.conversation_body,
            );
        }
        match &admission.turn {
            // The structural TURN → CONVERSATION edge, minted with the row:
            // `ChildOf` is the ONLY reader-side answer to "which conversation
            // is this turn in", so a turn minted without it is one no
            // consolidation round can group.
            AdmittedTurn::Mint { body } => {
                batch = put_container(
                    batch,
                    birth,
                    plan.phone_birth.as_ref(),
                    &plan.turn_id,
                    ENTITY_TYPE_TURN,
                    (plan.occurred, plan.learned_at),
                    body,
                )
                .edge(&plan.turn_id, EdgeKind::ChildOf, &plan.conversation_id, 1.0);
                if let Some(quoted) = quoted {
                    batch = quoted.edges(batch, &plan.turn_id, plan.learned_at);
                }
            }
            // Only a genuinely new child re-dirties an established TURN. A
            // byte-identical deterministic MESSAGE retry is a transcript no-op;
            // moving the TURN watermark on every CAS retry would make
            // idempotency observable downstream. A pinned DAG TURN is never
            // re-put: its new MESSAGE children land under it unchanged, and
            // the same-transaction re-dirty below moves it (OF-460).
            AdmittedTurn::Existing(record) if admission.has_new_messages() => {
                if !crate::conversation_dag::record_is_append_only_in_txn(
                    &self.vault.store,
                    wtxn,
                    &plan.turn_id,
                )? {
                    let redirtied_at = plan.learned_at.max(record.learned_at.saturating_add(1));
                    batch = put_container(
                        batch,
                        birth,
                        plan.phone_birth.as_ref(),
                        &plan.turn_id,
                        ENTITY_TYPE_TURN,
                        (record.occurred, redirtied_at),
                        &record.body,
                    );
                }
            }
            AdmittedTurn::Existing(_) => {}
        }
        for (((planned, authorized), exists), author) in plan
            .messages
            .iter()
            .zip(&admission.authorized)
            .zip(&admission.message_exists)
            .zip(&admission.authors)
        {
            // An exact retry: its canonical body and bindings were proved and
            // re-authorized under the current policy; the transcript stays
            // byte-for-byte unchanged.
            if *exists {
                continue;
            }
            // Rule A: the message is born in its writer's class from nothing
            // the door read, so only a person's message has a birth to name.
            // A handed-on credential acts as its key's holder, not the person (HANDED-ON-SLIP-PERSON).
            let birth = RowBirth::written(
                self.write_actor(),
                MadeByClass::of_write_actor(self.bound_write_actor()),
                "witness.message",
                &[],
                &[],
                plan.learned_at,
            );
            // The PUT consumes the authorization itself, not a body handed
            // alongside it: `put_witness_message` is reachable only with the
            // door's own value and writes exactly the bytes it proved.
            batch = batch
                .put_witness_message(&planned.id, planned.occurred, plan.learned_at, authorized)
                .made_by(&planned.id, birth)
                .edge(&planned.id, EdgeKind::PartOf, &plan.turn_id, 1.0)
                .edge(&planned.id, EdgeKind::BelongsTo, &plan.conversation_id, 1.0);
            // The one target admission expected: the writer of a native user
            // or companion row; for an imported row the PERSON its source
            // names as the speaker (FIX 15412), never the importer, which
            // its birth above names instead.
            if let Some(author) = author {
                batch = batch.edge(&planned.id, EdgeKind::AuthoredBy, author, 1.0);
            }
        }
        batch.apply(wtxn)?;
        // The re-put moves the TURN only to `old + 1`, which a scope cursor a
        // later TURN advanced can already be past; the re-dirty carrier puts it
        // past every cursor in this same commit.
        if matches!(admission.turn, AdmittedTurn::Existing(_)) && admission.has_new_messages() {
            crate::dreamer_consolidation::redirty::redirty_turn_in_txn(
                self.vault,
                wtxn,
                &plan.turn_id,
            )?;
        }
        let text_ops: Vec<BatchOp> = plan
            .messages
            .iter()
            .zip(&admission.message_exists)
            .filter(|(planned, exists)| !**exists && !planned.message.content.is_empty())
            .map(|(planned, _)| BatchOp::Text {
                id: planned.id,
                fields: vec![("content".to_owned(), planned.message.content.clone())],
            })
            .collect();
        if !text_ops.is_empty() {
            apply_ops(
                &self.vault.store,
                &self.vault.config,
                &self.vault.analyzer,
                wtxn,
                text_ops,
                sink.text_index_trusted,
                false,
                true,
            )?;
        }
        // An imported turn happened in its source, not in the sitting that is
        // open now: it neither bumps the session nor joins it.
        if plan.imported.is_some() {
            return Ok(());
        }
        // RT-03 (ONE-1685): a witnessed turn bumps the open session's
        // activity clock — atomically with the turn write, so a crash
        // cannot record the turn without the bump.
        let session_key = match self.session_key {
            Some(key) => Some(key),
            None => crate::identity::read_machine_id_in_txn(self.vault, wtxn)?.map(|machine| {
                crate::session_lifecycle::SessionKey {
                    actor: self.actor,
                    machine,
                }
            }),
        };
        let bumped_session = match session_key {
            Some(key) => crate::session_lifecycle::bump_open_session_activity_in_txn(
                &self.vault.store,
                wtxn,
                key,
                plan.learned_at,
            )?,
            None => None,
        };
        // DREAM-008 (ONE-1250): the TURN → SESSION membership fact, in THIS
        // transaction for the same reason the bump is — a crash cannot record
        // a turn without its sitting, so the compaction handoff door can prove
        // which session a turn came from instead of trusting a packet's claim.
        // Minted turns only: an append to an already-stored turn never
        // re-homes it into whatever sitting is open now, and a turn witnessed
        // outside any session records nothing (ARCH-0002 open-endedness).
        let membership_session =
            bumped_session.filter(|_| matches!(admission.turn, AdmittedTurn::Mint { .. }));
        crate::session_lifecycle::record_turn_session_membership_in_txn(
            &self.vault.store,
            wtxn,
            &plan.turn_id,
            membership_session,
        )?;
        Ok(())
    }
}
