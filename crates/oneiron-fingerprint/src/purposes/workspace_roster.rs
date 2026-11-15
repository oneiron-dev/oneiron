//! Purposes of the workspace roster (`crates/oneiron/src/workspace_roster`).

purposes! {}

legacy_purposes! {
    /// A project revision's logical hash (`oneiron-records`
    /// `workspace_roster::project::revision::hash_of`): plain BLAKE3, the tag's bytes, then
    /// the revision's canonical body (named MessagePack). The revision's companion id
    /// derives from it, and later revisions name their parents by it, on every replica.
    PROJECT_REVISION_HASH = (Blake3, HashedFirst, "oneiron/project-revision/v1/");
}
