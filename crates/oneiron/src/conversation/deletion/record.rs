//! A room record's delete as its author, or as a room owner or admin for
//! policy: the gate it meets and the rail it runs. A private thread's root
//! and its own messages also delete for the vault's Owner, or an Admin
//! while the Owner's switch allows it ([`super::private_thread`]).
use super::private_thread::private_thread_delete_in;
use super::*;

pub(super) fn require_room_policy(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    action: crate::gate::RoomAction,
    role: RoomRole,
) -> Result<()> {
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    if crate::gate::room_policy_allows(&policy, room, action, role) {
        Ok(())
    } else {
        Err(denied())
    }
}

fn check_delete(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    actor: WriteActor,
    reason: DeleteReason,
    subject: Option<EntityId>,
) -> Result<RoomRole> {
    actor_in_txn(&vault.store, txn, actor)?;
    let author = if let Some((message_room, author)) = message_room_author(vault, txn, record)? {
        if message_room != room {
            return Err(denied());
        }
        author
    } else {
        if conversation_of(&vault.store, txn, &record)? != room {
            return Err(denied());
        }
        author_in(vault, txn, record)?
    };
    match reason {
        DeleteReason::UserDelete | DeleteReason::UserHardDelete
            if author == Some(actor.entity_ref()) =>
        {
            authorize(vault, txn, actor)?;
            require_room_policy(
                vault,
                txn,
                room,
                crate::gate::RoomAction::AuthorDelete,
                RoomRole::Member,
            )?;
            Ok(RoomRole::Member)
        }
        DeleteReason::PolicyDelete => {
            // A private thread's root, or one of its own messages: an Admin
            // the Owner's switch turns away is refused here, before any room
            // role answers (FIX 6382).
            let thread = private_thread_delete_in(vault, txn, room, record, actor)?;
            let seated = roles::role_in(vault, txn, room, actor).and_then(|role| {
                require_room_policy(
                    vault,
                    txn,
                    room,
                    crate::gate::RoomAction::PolicyDelete,
                    role,
                )
                .map(|()| role)
            });
            let role = match (seated, thread) {
                (Ok(role), _) => role,
                // The Owner, or an Admin, deletes that root and its own
                // messages with no room role (FIX 6381): this record's
                // authority, never a role in the room.
                (Err(Error::Record(RecordError::ConversationDenied)), Some(thread)) => {
                    thread.role()
                }
                (Err(error), _) => return Err(error),
            };
            // No role deletes an audience edit its live root keeps (FIX 5639).
            crate::workspace_roster::reject_audience_edit_delete(&vault.store, txn, &record)?;
            Ok(role)
        }
        DeleteReason::GdprDelete if subject.is_some() && subject == author => {
            let personal = Some(actor.entity_ref()) == author;
            let role = if personal {
                authorize(vault, txn, actor)?;
                RoomRole::Member
            } else {
                roles::role_in(vault, txn, room, actor)?
            };
            require_room_policy(
                vault,
                txn,
                room,
                if personal {
                    crate::gate::RoomAction::GdprSelf
                } else {
                    crate::gate::RoomAction::GdprManage
                },
                role,
            )?;
            Ok(role)
        }
        _ => Err(denied()),
    }
}

/// Re-prove authority against the current transaction, including the
/// content-free custody retained by an already soft-erased TURN.
fn reverify_record_delete(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    actor: WriteActor,
    reason: DeleteReason,
    subject: Option<EntityId>,
) -> Result<()> {
    check_delete(vault, txn, room, record, actor, reason, subject).map(|_| ())
}

impl Vault {
    /// `progress` is the erase request's kept set: a GDPR split here skips
    /// what the request already kept and adds what it newly keeps.
    pub(super) fn delete_room_record_as(
        &self,
        room: EntityId,
        record: EntityId,
        actor: WriteActor,
        reason: DeleteReason,
        subject: Option<EntityId>,
        progress: &mut PrivacyEraseProgress,
    ) -> Result<DeleteEntityOutcome> {
        let txn = self.store.env.read_txn()?;
        let role = check_delete(self, &txn, room, record, actor, reason, subject)?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        let context = DeletionGateContext::new_room(
            actor.entity_ref(),
            actor.actor_class(),
            crate::gate::POLICY_SCHEMA_VERSION.to_owned(),
            policy.read_frontier_hash()?,
            room,
            role,
        );
        drop(txn);
        let reverify = |txn: &heed::RoTxn<'_>| {
            reverify_record_delete(self, txn, room, record, actor, reason, subject)
        };
        // A GDPR erase keeps what a legal hold names (C5). The MESSAGEs and
        // the reactions below are split each on their own; a held one is
        // left in place and the erase goes on. One the request already kept
        // through another path is not split, logged or counted again.
        let privacy = reason == DeleteReason::GdprDelete;
        // Delete selected MESSAGE content before its TURN loses the PartOf
        // edge. A personal operation never purges a different actor's row.
        if self
            .get_raw_unsealed(&record)?
            .is_some_and(|raw| raw.first() == Some(&ENTITY_TYPE_TURN))
        {
            let mut cursor = None;
            loop {
                let txn = self.store.env.read_txn()?;
                let ids = messages_in_turn(self, &txn, record, cursor)?;
                let mut targets = Vec::new();
                for id in &ids {
                    match message_room_author(self, &txn, *id)? {
                        Some((owner, _)) if owner != room => return Err(denied()),
                        Some((_, author))
                            if reason == DeleteReason::PolicyDelete
                                || author == subject.or(Some(actor.entity_ref())) =>
                        {
                            targets.push(*id);
                        }
                        _ => {}
                    }
                }
                drop(txn);
                if privacy {
                    targets = progress.unheld(self, &targets, actor, &reverify)?;
                }
                for message in targets {
                    self.delete_room_record_as(room, message, actor, reason, subject, progress)?;
                }
                if ids.len() < ERASE_PAGE {
                    break;
                }
                cursor = ids.last().copied();
            }
        }
        // Reactions about the record go first, under the same reason: a hard
        // delete removes the claims' subject edges, and a failure here leaves
        // the record in place for a retry to find them again.
        let mut reactions = {
            let txn = self.store.env.read_txn()?;
            crate::reaction::record_reaction_claims_in(self, &txn, record)?
        };
        if privacy {
            reactions = progress.unheld(self, &reactions, actor, &reverify)?;
        }
        crate::reaction::erase_reaction_claims(self, &reactions, reason)?;
        self.delete_entity_with_reason_gated(
            &record,
            reason,
            GatedDeletion::new(context, &reverify),
        )
    }

    /// Deletes a room record as its author, or as a room owner/admin for policy.
    /// The underlying receipt is correlated to the actor/role gate decision.
    pub fn delete_room_record(
        &self,
        room: EntityId,
        record: EntityId,
        actor: WriteActor,
        reason: DeleteReason,
    ) -> Result<DeleteEntityOutcome> {
        if !matches!(
            reason,
            DeleteReason::UserDelete | DeleteReason::UserHardDelete | DeleteReason::PolicyDelete
        ) {
            return Err(denied());
        }
        self.delete_room_record_as(
            room,
            record,
            actor,
            reason,
            None,
            &mut PrivacyEraseProgress::default(),
        )
    }

    /// Test seam for suites whose subject is a downstream effect of deletion:
    /// resolves the record's room and recorded author, then deletes through
    /// [`Self::delete_room_record`] as that author. The door's checks all run.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn delete_own_room_record(
        &self,
        record: EntityId,
        reason: DeleteReason,
    ) -> Result<DeleteEntityOutcome> {
        let txn = self.store.env.read_txn()?;
        let (room, author) = match message_room_author(self, &txn, record)? {
            Some(found) => found,
            None => (
                conversation_of(&self.store, &txn, &record)?,
                author_in(self, &txn, record)?,
            ),
        };
        let author = author.ok_or_else(denied)?;
        let class =
            match crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &author)?
                .and_then(|raw| raw.first().copied())
            {
                Some(crate::registry::ENTITY_TYPE_AGENT_DEF) => crate::edge::EdgeActorClass::Agent,
                Some(crate::registry::ENTITY_TYPE_MACHINE) => crate::edge::EdgeActorClass::System,
                _ => crate::edge::EdgeActorClass::Human,
            };
        drop(txn);
        self.delete_room_record(room, record, WriteActor::new(author, class), reason)
    }
}
