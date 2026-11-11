// Declared `vault_meta` tables whose prefix starts with `n` to `r`, in prefix order.

side_tables! {
    /// Named entity secondary index. Key: byte + (u64be|id16) + id16.
    PORTS_NAMED_ENTITY_INDEX: VaultMeta b"named_entity:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Last owner policy-row change sequence (u64be). Key: ().
    OWNER_POLICY_CHANGE_SEQUENCE: VaultMeta b"owner_policy:change:seq:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Delivery cursor over the queued owner policy notifications. Key: ().
    OWNER_POLICY_NOTIFICATION_CURSOR: VaultMeta b"owner_policy:notification:cursor:v1" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner policy digest rows of one recipient. Key: recipient ':' tag.
    OWNER_POLICY_NOTIFICATION_DIGEST_RECIPIENT: VaultMeta b"owner_policy:notification:digest_recipient:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Open owner policy digest window of one recipient. Key: recipient.
    OWNER_POLICY_NOTIFICATION_DIGEST_WINDOW: VaultMeta b"owner_policy:notification:digest_window:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Failed delivery of one queued owner policy notification. Key: its queue key suffix.
    OWNER_POLICY_NOTIFICATION_FAILURE: VaultMeta b"owner_policy:notification:failure:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Owner policy notification preference of one recipient. Key: recipient.
    OWNER_POLICY_NOTIFICATION_PREFERENCE: VaultMeta b"owner_policy:notification:preference:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Queued owner policy notification. Key: queue order ‖ recipient.
    OWNER_POLICY_NOTIFICATION_QUEUED: VaultMeta b"owner_policy:notification:queued:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Receipt of one owner policy notification rule. Key: receipt id.
    OWNER_POLICY_NOTIFICATION_RULE_RECEIPT: VaultMeta b"owner_policy:notification:rule_receipt:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// A record admitted into a leader chat before its batch settles. Key: id16 (record id).
    PROJECT_LEADER_CHAT_PERMIT: VaultMeta b"project.leader_chat.permit.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The authenticated speaker proof one leader-chat record carries. Key: id16 (record id).
    PROJECT_LEADER_CHAT_PROOF: VaultMeta b"project.leader_chat.proof.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Marks a conversation as a project's direct leader chat. Key: id16 (conversation id).
    PROJECT_LEADER_CHAT: VaultMeta b"project.leader_chat.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The project converted from one room thread's message. Key: id16 (project id).
    PROJECT_ORIGIN_BY_PROJECT: VaultMeta b"project.origin_by_project.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Projects minted from one room message. Key: id16 (message id) + id16 (project id).
    PROJECT_ORIGIN_MESSAGE: VaultMeta b"project.origin_message.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// The project a room thread was converted into. Key: id16 (room id) + id16 (thread id).
    PROJECT_ORIGIN_THREAD: VaultMeta b"project.origin_thread.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// A cross-project widen ask a project raised on another board. Key: id16 (ask id).
    PROJECT_WIDEN_ASK: VaultMeta b"project.widen_ask.v1/" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Log of checkpoint restore/wake/migrate events, one row per epoch. Key: u64be(sequence).
    RESTORE_EPOCH: VaultMeta b"restore:epoch:v1:" Named
        [restore: live] [family: unclassified] [tier: canonical];
}
