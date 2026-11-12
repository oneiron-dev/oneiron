//! The side tables `outbound` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Index from a principal reference to every standing outbound grant naming it. Key: u16be(len) +
    /// string(principal_ref) + id16.
    OUTBOUND_GRANT_PRINCIPAL_INDEX: VaultMeta b"outbound_grant/principal/v1\0" Raw
        [restore: not_imaged] [family: not_imaged] [tier: derived];
    /// The first agent send through each outbound channel (DEC-0006 #undo-send): its TASK and
    /// when it was scheduled, the send that carries the one-line hint that a delay can be set.
    /// Written once per channel. Key: string (the channel, as its manifest names it).
    UNDO_SEND_FIRST_AGENT_SEND: VaultMeta b"outbound:undo_send_first_agent_send:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// One send in its undo-send window (DEC-0006 #undo-send): the attempt the window holds
    /// Scheduled and the instant it goes. Dropped by the owner's undo, and once the window has
    /// closed. Key: id16 (the connector-send TASK).
    UNDO_SEND_HELD: VaultMeta b"outbound:undo_send_held:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// The owner's override of where one reader's weave digest is sent (FIX 1262): off, or
    /// another of the vault's channel identities the reader has a live contact on. Absent means
    /// the send is on, to the reader's primary route. Key: id16 (reader).
    WEAVE_DIGEST_CHANNEL_OVERRIDE: VaultMeta b"weave:digest_channel_override:v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::outbound::erase_weave_digest_channel_override_actor_in_txn;
}
