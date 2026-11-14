//! The side tables `context_board` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Revision-ref frontier (16 bytes) a board-selection CLAIM was written under, authenticated on
    /// every read. Key: id16.
    BOARD_HISTORY_CLAIM_FRONTIER: VaultMeta b"board_history:claim_frontier:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Loro CRDT snapshot backing one owner's board-selection/document history. Key: id16.
    BOARD_HISTORY_DOC: VaultMeta b"board_history:doc:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Marker that compaction folded a TURN, so its board never reconstructs, whether it was recorded
    /// before or after the fold. Key: id16.
    BOARD_HISTORY_FOLDED: VaultMeta b"board_history:folded:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Monotonic compaction horizon (u64be earliest retained turn time) per board-history owner. Key:
    /// id16.
    BOARD_HISTORY_HORIZON: VaultMeta b"board_history:horizon:" Raw
        [restore: content] [family: unclassified] [tier: canonical];
    /// Last committed (at, learned_at) monotonic stamp per board-history owner, guarding against out-
    /// of-order turns. Key: id16.
    BOARD_HISTORY_LAST: VaultMeta b"board_history:last:" LegacyCompact
        [restore: content] [family: unclassified] [tier: canonical];
    /// Turn anchor recording the board-history CRDT frontier and selection snapshot a TURN committed.
    /// Key: id16.
    BOARD_HISTORY_TURN: VaultMeta b"board_history:turn:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One actor-private versioned board block (actor, section-name length+bytes, block ref) appended
    /// under an admitted plugin section. Key: id16 + u64be + string + id16.
    CONTEXT_BOARD_PLUGIN_BLOCK: VaultMeta b"context_board.block.v1:" LegacyJson Authored [accepts: crate::context_board::context_board_plugin_block_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical];
    /// One actor's own board layout (BOARD-LAYOUT): the live layout its board
    /// renders under and its one pending batch. Key: id16 (actor).
    CONTEXT_BOARD_LAYOUT: VaultMeta b"context_board.layout.v1:" Named Engine
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::context_board::erase_board_layout_actor_in_txn;
    /// Session scratchpad pointers: the `scratchpad` NOTE each (actor, session) writes (tag 1), the
    /// actor's one unsealed pad (tag 2) and every pad with its author and session (tag 3); the
    /// seal is NOTE_SEAL. Key: u8 tag + id16 [+ string].
    CONTEXT_BOARD_SCRATCHPAD: VaultMeta b"context_board.scratchpad.v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A wake a committed TASK owes, staged by the board publisher (census L2-38): a failed
    /// TASK's to its owner (tag `f`) or a queued consult's to its addressee (tag `a`). Value: the
    /// envelope id it was staged under; nothing of the TASK. Node-local; a restore never takes it
    /// from an image. Key: id16(task) + tag + id16(recipient).
    CONTEXT_BOARD_TASK_WAKE: VaultMeta b"context_board.task_wake.v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
    /// An AGENT child's try that ended done, failed or abandoned, staged by the write that settles
    /// it for its spawner's board STREAM (census L2-38): the spawner's actor and the end. Taken by
    /// the host's next pass; a row no pass took is dropped after a day. Node-local; a restore never
    /// takes it from an image. Key: u64be(settled at) + id16(child attempt). Value: id16(spawner) +
    /// end tag.
    CONTEXT_BOARD_CHILD_DONE: VaultMeta b"context_board.child_done.v1:" Raw
        [restore: not_imaged] [family: not_imaged] [tier: runtime];
}
