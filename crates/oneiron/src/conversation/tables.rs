//! The side tables `conversation` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A self agent's per-reply chat breakpoint (FIX 4465 D): the answering agent, its reader,
    /// the conversation and branch, the request its rung sent and the digest of its offer, the
    /// retained turns and summaries it was read from, by revision, and the user turn it answers
    /// (FIX 5033). Host-only; read only to reuse the prefix for the reply's Continue and Retry.
    /// A hard erase of its reader or its agent drops the row (FIX 5033). Key:
    /// id16(conversation) + id16(message) + id16(stream generation).
    CHAT_BREAKPOINT: VaultMeta b"chat_breakpoint:v1:" Named Authored [accepts: crate::conversation::chat_breakpoint_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::conversation::scrub_chat_breakpoint_actor_in_txn;
    /// Actor id (id16) that created a room; an unrooted vault reads it as the room's owner. Key:
    /// id16 (room).
    CONVERSATION_CREATOR: VaultMeta b"conversation:creator:v1:" Raw
        [restore: refuse_image_entities "room roles and membership"]
        [family: unclassified]
        [tier: canonical];
    /// Per-person room erasure fence: `[1]` while the sweep is in flight, `[2]` once it completed.
    /// Key: id16 (room) + id16 (person).
    CONVERSATION_ERASED_PERSON: VaultMeta b"conversation:erased_person:v1:" Raw
        [restore: live] [family: unclassified] [tier: canonical];
    /// Durable room (id16) of a MESSAGE, kept after its incident edges are purged. Key: id16
    /// (message).
    CONVERSATION_MESSAGE_OWNER: VaultMeta b"conversation:message_owner:v1:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Single-byte `[1]` marker that a room pin door is rewriting a room body's shared pins or
    /// their policy, set and cleared inside its write transaction. Key: id16 (room).
    CONVERSATION_PIN_UPDATE: VaultMeta b"conversation:pin_update:" Raw
        [restore: refuse_image_entities "room roles and membership"]
        [family: unclassified]
        [tier: canonical];
    /// Host-local room role grant of one current member. Key: id16 (room) + id16 (person).
    CONVERSATION_ROLE_GRANT: VaultMeta b"conversation:role_grant:v1:" Named
        [restore: refuse_image_entities "room roles and membership"]
        [family: unclassified]
        [tier: canonical];
    /// Single-byte `[1]` marker that the room role door is rewriting a room body, set and cleared
    /// inside its write transaction. Key: id16 (room).
    CONVERSATION_ROLE_UPDATE: VaultMeta b"conversation:role_update:" Raw
        [restore: refuse_image_entities "room roles and membership"]
        [family: unclassified]
        [tier: canonical];
    /// Row count / next-sequence counter (u64be) for a conversation's membership ledger. Key: id16.
    CONVERSATION_MEMBERSHIP_SEQ: VaultMeta b"conversation_membership:seq:v1:" Raw
        [restore: refuse_image_entities "room roles and membership"]
        [family: unclassified]
        [tier: canonical];
    /// One append-only membership-ledger event (join/leave/history-visibility change) for a
    /// conversation, keyed by conversation then sequence. Key: id16 + u64be.
    CONVERSATION_MEMBERSHIP_ROW: VaultMeta b"conversation_membership:v1:" Named
        [restore: refuse_image_entities "room roles and membership"]
        [family: unclassified]
        [tier: canonical];
    /// One person's fold of a room's membership ledger (ARCH-0052, ASTRA-1406b): their windows in ledger order and the ledger index of the Join that opened their current membership; derived from CONVERSATION_MEMBERSHIP_ROW, kept by the ledger's append, rebuilt by a restore. Key: id16 (room) + id16 (person).
    CONVERSATION_MEMBERSHIP_PERSON: VaultMeta b"conversation_membership:person:v1:" Named
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// The ledger revision (u64be row count) the per-person rows above fold for a room; they serve reads only while it equals CONVERSATION_MEMBERSHIP_SEQ. Key: id16 (room).
    CONVERSATION_MEMBERSHIP_INDEXED: VaultMeta b"conversation_membership:indexed:v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
}
