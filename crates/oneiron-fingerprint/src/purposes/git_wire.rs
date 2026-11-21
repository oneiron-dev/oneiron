//! Purposes of the git wire (`oneiron-store`'s `git_wire` and `crates/oneiron/src/git_wire`).
//!
//! Every git-wire digest is plain BLAKE3 with no tag: its first two fields are the domain
//! `oneiron:git-wire:v2` and the digest's own label, and each tag below joins the two. Every
//! field is framed by its length as a u32 big-endian (`u32::MAX` for a field above 4 GiB).

purposes! {}

legacy_purposes! {
    /// A durable record's capability hash (`git_wire::record`,
    /// `StoredGitWireRecord::capability_hash`). The domain and `capability`; the record key,
    /// the repo identity and the operation; per publication the ref name, the expected oid
    /// (`*` for none) and the next oid (`-` for none); per observed ref the name and the oid
    /// (`-` for none); each kept ref; the worktree commit (`-` for none); the worktree
    /// settings hash (`-` for none); the start time (8 bytes, u64 big-endian). A prepared
    /// capability carries it to the caller, and commit compares it with the stored row's
    /// (`git_wire::wire_stage`).
    CAPABILITY = (Blake3, NotHashed, "oneiron:git-wire:v2:capability");

    /// A ref publication's record key (`git_wire::record::ref_record_key`). The domain and
    /// `ref-effect`; the repo identity; per publication the ref name, the expectation
    /// (`absent`, the oid or `any`) and the next oid (`delete` for none). The journal row's
    /// key.
    REF_RECORD_KEY = (Blake3, NotHashed, "oneiron:git-wire:v2:ref-effect");

    /// A staged plan's record key (`git_wire::record::stage_record_key`). The domain and
    /// `stage`; the repo identity; the plan hash (`PLAN_HASH`). The journal row's key, which
    /// a restaged identical plan finds again.
    STAGE_RECORD_KEY = (Blake3, NotHashed, "oneiron:git-wire:v2:stage");

    /// A worktree effect's record key (`git_wire::record::worktree_record_key`). The domain
    /// and `worktree`; the repo identity; the operation; the worktree scope
    /// (`WORKTREE_SCOPE`). The journal row's key.
    WORKTREE_RECORD_KEY = (Blake3, NotHashed, "oneiron:git-wire:v2:worktree");

    /// A repository's identity (`git_wire::repo::repo_identity_for`). The domain and
    /// `repo-identity`; the canonical common dir's bytes. Stored in every journal row
    /// (`repo_identity`) and bound into each record key; its hex is the projection ingress
    /// identity.
    REPO_IDENTITY = (Blake3, NotHashed, "oneiron:git-wire:v2:repo-identity");

    /// A plan's content hash (`git_wire::plan`, `GitWirePlan::plan_hash`). The domain and
    /// `plan`; per object write its argv operation and its stdin (a retained object's spool
    /// bytes, empty when none); each existing object's oid; per publication the ref name,
    /// the expectation (`absent`, the oid or `any`) and the target (`written:<n>`,
    /// `existing:<n>` or `delete`). Bound into `STAGE_RECORD_KEY`.
    PLAN_HASH = (Blake3, NotHashed, "oneiron:git-wire:v2:plan");

    /// A worktree handle's scope (`git_wire::wire_worktree::worktree_scope`). The domain and
    /// `worktree-scope`; the normalized path's bytes. Stored in the worktree record
    /// (`worktree_scope`), bound into `WORKTREE_RECORD_KEY`, and compared with each
    /// registered worktree on recovery.
    WORKTREE_SCOPE = (Blake3, NotHashed, "oneiron:git-wire:v2:worktree-scope");
}
