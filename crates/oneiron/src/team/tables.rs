//! The side tables `team` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// One participant's explicit team choice. Key: caller attempt hex, `:`, team reference.
    TEAM_BALLOT: VaultMeta b"team:ballot:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A team deliverable's owner review: team, leader, root TASK, output revision, reviewed
    /// claim fingerprint and what the review asks. Key: id16 (reviewed claim).
    TEAM_DELIVERABLE: VaultMeta b"team:deliverable:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One run's market: signed referee, lease shares, central ledger, submissions and result.
    /// Key: string (team reference).
    TEAM_MARKET: VaultMeta b"team:market:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// A workflow skill's binding to the coordination pattern it teaches, with its works-well-for
    /// line. Key: id16 (skill entity).
    TEAM_PATTERN_SKILL: VaultMeta b"team:pattern_skill:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
    /// One team run's receipt (type, pattern, models, shape, who decided, coverage, confessions,
    /// anchored outcome). Key: string (team reference).
    TEAM_RECEIPT: VaultMeta b"team:receipt:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::learning::erase_team_receipt_scope_in_txn;
    /// One team start as the host saw it: stamp, leader, root TASK, queued members and widenings.
    /// Key: string (leader attempt hex, `:`, team reference).
    TEAM_RUN: VaultMeta b"team:run:v1:" Named
        [restore: content] [family: unclassified] [tier: canonical];
}
