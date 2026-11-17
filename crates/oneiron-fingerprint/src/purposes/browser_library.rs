//! Purposes of the browser library (`oneiron-records`' and the core's
//! `browser_library`).
//!
//! Each legacy purpose here is an id by the legacy material rule
//! (`EntityId::derive_legacy_material`): plain BLAKE3, the tag's bytes first, then a u64
//! little-endian salt, then each part as its u64 little-endian length and its bytes. The
//! id is the first 16 bytes, with no version stamp; a reserved result takes the next salt.
//! Every one of these ids is a key that vaults already hold, so its bytes are kept until
//! the launch reset (PLAN-UC-04 stage 9).

purposes! {}

legacy_purposes! {
    /// The claim of a program's filing anchor for one group, so one program's anchor for
    /// one group is one claim however often it is refiled (`evidence::workflow_filing_id`,
    /// FIX 10513). Parts: the program, the group digest.
    WORKFLOW_FILING = (Blake3, HashedFirst, "oneiron:browser-workflow-filing:v1");

    /// A solved run's evidence claim (CUA E8a, CALLS row "evidence identity";
    /// `browser_library::evidence`): the same capture delivered again is the same claim. Parts:
    /// the scoped group's digest, the run, whether a call is named (one byte), the call, the
    /// draft's after and through sequence numbers (big-endian), the durable body's bytes; never
    /// the capture time.
    SOLVED_RUN = (Blake3, HashedFirst, "oneiron:browser-solved-run:v1");
}
