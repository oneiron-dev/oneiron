//! The side tables `browser_library` keeps (core split slice 1): each row declares one, and the crate's
//! build script places it in `side_table`'s catalogue.

crate::side_table::side_tables! {
    /// CUA E8b: a browser program admission job's receipt, and the program a filing in its run
    /// filed, written in that filing's write: references and a typed outcome only. Key: id16.
    BROWSER_PROGRAM_ADMISSION: VaultMeta b"browser.program.admission.v1\0" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// CUA E8a: the source authority a solved browser run was captured under, by its evidence
    /// claim: scope, group digest, credential reference and witness digest, and the signed
    /// binding itself until an admission job that used it ends (CUA E8b). Key: id16.
    BROWSER_PROGRAM_AUTHORITY: VaultMeta b"browser.program.authority.v1\0" Named Engine
        [restore: live] [family: unclassified] [tier: canonical]
        => crate::browser_library::erase_authority_actor_in_txn;
    /// CUA E8a: a replay library program whose library runs failed, live or retired, with its
    /// site hash, group digest and generation. Key: id16.
    BROWSER_PROGRAM_FAILURE: VaultMeta b"browser.program.failure.v1\0" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// CUA E8: a candidate program's induction already proposed, by its input fingerprint. Key:
    /// hash32.
    BROWSER_PROGRAM_SEEN: VaultMeta b"browser.program.seen.v1\0" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// CUA E8a: a live replay library program covering a solved group. Key: hash32 (group) +
    /// id16.
    BROWSER_SOLVED_COVERAGE: VaultMeta b"browser.solved.coverage.v1\0" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// CUA E8a: a solved group's full scoped key with its changed and processed generations.
    /// Key: hash32 (group).
    BROWSER_SOLVED_DIRTY: VaultMeta b"browser.solved.dirty.v1\0" Named Authored [accepts: crate::browser_library::browser_solved_dirty_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::browser_library::erase_dirty_actor_in_txn;
    /// CUA E8a: one solved run's evidence claim in its group: its run and capture time, never its
    /// body. Key: hash32 (group) + id16.
    BROWSER_SOLVED_GROUP: VaultMeta b"browser.solved.group.v1\0" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// FIX 7880: a live replay library program's site hash, by its id alone, for resolving it
    /// without scanning the site-first program table. Key: id16.
    BROWSER_WORKFLOW_BY_ID: VaultMeta b"browser.workflow.by_id.v1\0" Named Engine
        [restore: content] [family: unclassified] [tier: canonical];
    /// A replay library program a retire took out, with whose word, when and why. Key: id16.
    BROWSER_WORKFLOW_RETIRED: VaultMeta b"browser.workflow.retired.v1\0" Named Authored [accepts: crate::browser_library::browser_workflow_retired_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::browser_library::erase_retired_actor_in_txn;
    /// Replay library program a solved browser run became, with its two checks' proof. Key: hash32 (site) + id16.
    BROWSER_WORKFLOW: VaultMeta b"browser.workflow.v1\0" Named Authored [accepts: crate::browser_library::browser_workflow_accepts_masked]
        [restore: content] [family: unclassified] [tier: canonical]
        => crate::browser_library::erase_workflow_actor_in_txn;
}
