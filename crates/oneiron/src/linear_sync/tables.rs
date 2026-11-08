//! The side tables `linear_sync` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One TASK's mirror control (OF-427 C6): whether it is opted out, its mapping revision and
    /// its last mapping edit. Key: id16 (TASK).
    LINEAR_MIRROR_CONTROL: VaultMeta b"linear.mirror_control.v1/" Named Engine
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_mirror_control_actor_in_txn;
    /// One mirror event (OF-427): a webhook delivery, a sent push, a mapping edit or a title
    /// edit, with its external evidence and receipt. Key: direction byte + 32-byte digest.
    LINEAR_MIRROR_EVENT: VaultMeta b"linear.mirror_event.v1/" Named
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_mirror_event_actor_in_txn;
    /// One TASK's mirror events by time; the value is empty. Key: id16 (TASK) + u64be (at) +
    /// 33-byte event key.
    LINEAR_MIRROR_EVENT_BY_TASK: VaultMeta b"linear.mirror_event_by_task.v1/" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// A Linear webhook delivery id and its body, bound to each other for good at its first
    /// verified preflight (OF-427 C4); the value is the other side's 32-byte digest. Key: tag
    /// byte (1 delivery key's digest, 2 body digest) + 32-byte digest.
    LINEAR_WEBHOOK_BINDING: VaultMeta b"linear.webhook_binding.v1/" Raw Engine
        [restore: live] [family: unclassified] [tier: canonical];
    /// An owner press one actor's admission of a Linear mirror operation spent, kept for that
    /// operation's retry once the admission committed (FIX 6424 part 2a): the actor's role tag,
    /// the pressing actor and the mirrored TASK (FIX 6835). Key: 32-byte operation id + the
    /// press's 32-byte approve-once digest.
    LINEAR_EFFECT_APPROVAL: VaultMeta b"linear:effect_approval:v1/" Raw
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_effect_approval_actor_in_txn;
    /// Frozen Linear effect binding digest, verified writer, scheduler and TASK, so hard erase
    /// can retire the authorization (FIX 12508). Key: 32-byte operation id.
    LINEAR_EFFECT_AUTHORIZED: VaultMeta b"linear:effect_authorized:v1/" Raw
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::store::actor_scrubs::erase_effect_authorized_actor_in_txn;
    /// Task to tracker issue link state. Key: id16.
    LINEAR_SYNC_LINK: VaultMeta b"linear_sync:link:v4:" LegacyJson Authored [accepts: crate::linear_sync::linear_sync_link_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
}
