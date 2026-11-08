//! The side tables `agent_inbox_lens` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// OF-414: one agent's read state of one row of its own INBOX (open, later, done), the row's
    /// newest entry time when written and when. Key: id16(actor) + string (row handle).
    AGENT_INBOX_READ_MARK: VaultMeta b"agent.inbox.read_mark.v1\0" Named Engine
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::agent_inbox_lens::erase_agent_inbox_read_marks_actor_in_txn;
}
