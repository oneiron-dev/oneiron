//! Who a pending notification is delivered to, as its recipient markers
//! decide from the body a restore brings back. Its text and its
//! acknowledged and surfaced markers are content.
use super::Decision;
use super::reads::kept;
use crate::context_board::{
    NotificationRecipientScope, notification_body_json, notification_recipient_scope,
};
use crate::ports::EntityStoreRead;
use crate::registry::ENTITY_TYPE_NOTIFICATION;
use crate::{EntityId, Result, Vault};
use std::collections::BTreeSet;

/// The callers a notification is delivered to: those every recipient marker
/// in its stored body names, or every caller when it carries none
/// (`notification_recipient_scope`, which the context board's delivery reads
/// through `notification_scoped_to_caller`). Each answer stands for every
/// caller string, named or not, so no caller is guessed at.
pub(super) struct NotificationRecipients;

impl Decision for NotificationRecipients {
    type Subject = EntityId;
    type Answer = NotificationRecipientScope;

    fn subjects(vaults: [&Vault; 2]) -> Result<BTreeSet<EntityId>> {
        kept(vaults, &[ENTITY_TYPE_NOTIFICATION])
    }

    /// A body that does not read as a notification object is delivered to
    /// no one.
    fn answers(
        vault: &Vault,
        subjects: &BTreeSet<EntityId>,
    ) -> Result<Vec<Option<NotificationRecipientScope>>> {
        let txn = vault.store.env.read_txn()?;
        Ok(subjects
            .iter()
            .map(|id| {
                let record = vault.store.port_entity_record(&txn, id).ok()??;
                if record.entity_type != ENTITY_TYPE_NOTIFICATION {
                    return None;
                }
                notification_recipient_scope(&notification_body_json(&record.body)?)
            })
            .collect())
    }

    /// Delivered now to every caller, it can be delivered to no more. Named
    /// callers widen when the restored body delivers to everyone, or to one
    /// they do not include.
    fn loosens(live: &NotificationRecipientScope, restored: &NotificationRecipientScope) -> bool {
        match (live, restored) {
            (NotificationRecipientScope::Everyone, _) => false,
            (NotificationRecipientScope::Callers(_), NotificationRecipientScope::Everyone) => true,
            (
                NotificationRecipientScope::Callers(live),
                NotificationRecipientScope::Callers(restored),
            ) => !restored.is_subset(live),
        }
    }

    fn refusal() -> Option<NotificationRecipientScope> {
        Some(NotificationRecipientScope::Callers(BTreeSet::new()))
    }
}
