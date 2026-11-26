//! Purposes of an attached session's folder project (`crates/oneiron/src/session_project.rs`)
//! and of the folder digests its clients name a folder by
//! (`crates/oneiron-server/src/workspace_identity.rs`). Each value is written as `blake3:` and
//! the fingerprint's 64 lower-case hex digits.

purposes! {
    /// A folder digest: what an attached session and `oneiron project bind` name a folder by
    /// (`oneiron-server` `workspace_identity::folder_digest`). Parts: the bytes of the folder's
    /// canonical checkout path. Only the digest leaves the machine, never the path.
    FOLDER_DIGEST = "oneiron.workspace.v1";

    /// A workspace id: the item a folder's `workspace.project` row is named by
    /// (`session_project::workspace_id_of`). Parts: the vault's store id, then the folder
    /// digest's text. Keyed by the store id, so one folder's ids do not correlate across vaults.
    WORKSPACE_ID = "oneiron.workspace-id.v1";
}

legacy_purposes! {}
