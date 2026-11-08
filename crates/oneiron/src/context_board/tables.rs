//! The side tables `context_board` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// Revision-ref frontier (16 bytes) a board-selection CLAIM was written under, authenticated on
    /// every read. Key: id16.
    BOARD_HISTORY_CLAIM_FRONTIER: VaultMeta b"board_history:claim_frontier:" Raw;
    /// Loro CRDT snapshot backing one owner's board-selection/document history. Key: id16.
    BOARD_HISTORY_DOC: VaultMeta b"board_history:doc:" Raw;
    /// Marker that compaction folded a TURN, so its board never reconstructs, whether it was recorded
    /// before or after the fold. Key: id16.
    BOARD_HISTORY_FOLDED: VaultMeta b"board_history:folded:" Raw;
    /// Monotonic compaction horizon (u64be earliest retained turn time) per board-history owner. Key:
    /// id16.
    BOARD_HISTORY_HORIZON: VaultMeta b"board_history:horizon:" Raw;
    /// Last committed (at, learned_at) monotonic stamp per board-history owner, guarding against out-
    /// of-order turns. Key: id16.
    BOARD_HISTORY_LAST: VaultMeta b"board_history:last:" LegacyCompact;
    /// Turn anchor recording the board-history CRDT frontier and selection snapshot a TURN committed.
    /// Key: id16.
    BOARD_HISTORY_TURN: VaultMeta b"board_history:turn:" Named;
    /// One actor-private versioned board block (actor, section-name length+bytes, block ref) appended
    /// under an admitted plugin section. Key: id16 + u64be + string + id16.
    CONTEXT_BOARD_PLUGIN_BLOCK: VaultMeta b"context_board.block.v1:" LegacyJson Authored [accepts: crate::context_board::context_board_plugin_block_accepts_masked];
    /// One actor's own board layout (BOARD-LAYOUT): the live layout its board
    /// renders under and its one pending batch. Key: id16 (actor).
    CONTEXT_BOARD_LAYOUT: VaultMeta b"context_board.layout.v1:" Named Engine
        => crate::context_board::erase_board_layout_actor_in_txn;
    /// Session scratchpad pointers: the `scratchpad` NOTE each (actor, session) writes (tag 1), the
    /// actor's one unsealed pad (tag 2) and every pad with its author and session (tag 3); the
    /// seal is NOTE_SEAL. Key: u8 tag + id16 [+ string].
    CONTEXT_BOARD_SCRATCHPAD: VaultMeta b"context_board.scratchpad.v1:" Named;
}
