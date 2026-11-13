//! The side tables `feeds` keeps (untangle slice 6.8): each row declares one, and the crate's build
//! script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// A change feed subscription: its actor, what it follows and when it was made. Key: id16
    /// (actor) + id16 (subscription).
    FEED_SUBSCRIPTION: VaultMeta b"feeds:subscription:v1:" Named
        // Restore class: content, as its cursors and the feed rows they point into are, and as
        // a fact hook's binding, cursor and feed are: a restore takes a subscription and its
        // cursors back together (review #6897).
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::feeds::erase_feed_actor_in_txn;
    /// The type of an entity a physical delete removed, kept in that delete's own write while a
    /// subscription follows the change log, which names no type: a withdrawal is judged by its
    /// type (review #6897 round 2). The type byte alone, never content. Key: id16 (entity).
    FEED_WITHDRAWN_TYPE: VaultMeta b"feeds:withdrawn_type:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A subscription's cursor in one source: the last position its actor acknowledged.
    /// Key: id16 (subscription) + u8 (source).
    FEED_CURSOR: VaultMeta b"feeds:cursor:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// Which subscriptions follow one source, so a write asks "does anyone follow this?" with one
    /// seek. Written and deleted with each subscription. Key: u8 (source) + id16 (subscription).
    FEED_FOLLOWING: VaultMeta b"feeds:following:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The edge feed: one edge added or removed, written in the edge write's own commit while a
    /// subscription follows edges. Key: u64be (sequence).
    FEED_EDGE: VaultMeta b"feeds:edge:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The last edge feed sequence handed out. Key: ().
    FEED_EDGE_NEXT: VaultMeta b"feeds:edge_next:v1" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The redirty feed: a TURN whose words changed with no new version of its own, written in
    /// that commit while a subscription follows redirty notices. Key: u64be (sequence).
    FEED_REDIRTY: VaultMeta b"feeds:redirty:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// The last redirty feed sequence handed out. Key: ().
    FEED_REDIRTY_NEXT: VaultMeta b"feeds:redirty_next:v1" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
