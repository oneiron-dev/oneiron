//! Moved from `crates/oneiron/src/authority/fold_state.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;
use oneiron_contracts::entity_id::EntityId;
use std::collections::BTreeSet;

/// Fold issue retained for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthorityFoldIssue {
    /// Entry failed shape or signature verification.
    InvalidEntry(AuthorityEntryHash),
    /// Entry references a missing or invalid parent.
    InvalidAncestry(AuthorityEntryHash),
    /// Entry is signed by a key a handoff or a revocation retired, outside
    /// that row's own ancestry.
    RetiredSigner(AuthorityEntryHash),
    /// A handoff that conflicts with another (a fork, a cycle) or yields to
    /// one whose fence stands: it installs no successor.
    UnsettledHandoff(AuthorityEntryHash),
    /// Entry signer was not valid in its own ancestry.
    SignerNotInAncestry(AuthorityEntryHash),
    /// Entry sequence did not exceed its ancestry or persisted first-observation high-water mark.
    NonMonotonicSeq(AuthorityEntryHash),
    /// Approval outlived the local first-seen window after a participant was revoked.
    StaleRosterApproval(AuthorityEntryHash),
    /// Entry binds the wrong vault id.
    WrongVault(AuthorityEntryHash),
    /// The fold contains more than one independently rooted vault id.
    ConflictingVaultRoot {
        /// Entry folded under a vault id that conflicts with another root.
        entry: AuthorityEntryHash,
        /// Conflicting vault id.
        vault_id: AuthorityVaultId,
    },
    /// Entry lacks an active owner/admin signer or co-signer in its ancestry.
    MissingAuthorityConsent(AuthorityEntryHash),
    /// Entry requires a distinct active co-signer quorum.
    MissingQuorum(AuthorityEntryHash),
    /// Federation lifecycle entry rejected by the pact state machine.
    FederationLifecycleRejected {
        /// Rejected entry hash.
        entry: AuthorityEntryHash,
        /// Deterministic rejection reason.
        reason: FederationLifecycleRejection,
    },
    /// Distinct sibling entries collided on a critical confirmation id or nonce.
    CriticalWriteConfirmConflict {
        /// Deterministic surviving confirmation id.
        confirm_id: [u8; 32],
    },
    /// A Bind/Rebind/RevokeActor op failed the binding transition table.
    ActorBindingRejected {
        /// Rejected entry hash.
        entry: AuthorityEntryHash,
        /// Deterministic rejection reason.
        reason: ActorBindingRejection,
    },
    /// The fold's projected peak passes the
    /// `authority_log_fold_memory_floor` policy row (H72). The fold refused
    /// all of it and holds no root.
    FoldMemoryFloor {
        /// The floor, in bytes.
        floor_bytes: u64,
    },
    /// A root appointment this install does not count (row
    /// OWNER-ANCHOR-ROOT-RECOVERY): it is refused here, with its
    /// descendants, and keeps no fold state.
    AppointmentRefused {
        /// The refused appointment.
        entry: AuthorityEntryHash,
        /// Its verdict, the same on every install that judges it.
        verdict: AppointmentVerdict,
    },
    /// The anchor of this install's pinned root is burned: one of its
    /// appointments is void, or two valid ones stand beside each other. It
    /// appoints no more; the owner re-issues the kit.
    AnchorBurned {
        /// The burned anchor's Ed25519 key.
        anchor: [u8; 32],
    },
    /// The folded roster holds no live root key (`ROLE_OWNER`): a handoff
    /// conflict, a cycle of revocations, a settled handoff to a key without
    /// `ROLE_OWNER`, or a revocation of the last one. No roster row settles
    /// it; the pinned root's anchor appoints a successor
    /// (OWNER-ANCHOR-ROOT-RECOVERY).
    NoRootKey,
}

/// Why a root appointment is void. A void appointment burns its anchor.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum AppointmentVoidReason {
    /// Its ancestry holds no owner root of its id that its anchor signed and
    /// the anchor fold took, or folds into another vault (V2).
    NoOwnerRoot,
    /// Its sequence is not above its anchor's own rows in its ancestry (V2).
    SequenceNotAdvanced,
    /// Its ancestry, folded canonically, still holds a live root key (V3).
    RootedAncestry,
    /// Its anchor is burned in its ancestry, or at an earlier appointment of
    /// this install's log (V4).
    AnchorBurned,
}

/// A root appointment's verdict on this install.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum AppointmentVerdict {
    /// Not judged: this install pins no root of the appointing anchor.
    Unjudged,
    /// Its ancestry is incomplete here, or its proof fold passed the fold's
    /// memory floor. It is judged again when that changes.
    Pending,
    /// A row of its ancestry names the successor key (V1). It burns nothing.
    SuccessorNotFresh,
    /// V2, V3 or V4 failed. It burns its anchor.
    Void(AppointmentVoidReason),
    /// V1 to V4 hold.
    Valid,
}

/// Why the fold refused an actor-binding op.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ActorBindingRejection {
    /// `BindActor` on a key that already holds a live binding (use rebind).
    BindingExists,
    /// `RebindActor` on a key with no live binding.
    BindingMissing,
    /// Epoch did not advance past the watermark or the prior binding.
    EpochNotAdvanced,
    /// Bound key is absent from, or revoked in, the ancestry roster.
    KeyNotInRoster,
    /// A `"human"`-class bind whose key lacks owner/admin consent capability.
    OwnerCapabilityRequired,
}

/// One folded `{signing_key_id, actor_ref, actor_class, epoch, status}` tuple.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FoldedActorBinding {
    /// Store actor entity the key speaks for.
    pub actor_ref: EntityId,
    /// EXACT bound class: `"human"`, `"agent"`, or `"system"`.
    pub actor_class: String,
    /// Binding epoch.
    pub epoch: u64,
    /// Whether this binding currently authorizes.
    pub status: ActorBindingStatus,
}

/// Liveness of a folded actor binding.
///
/// `Revoked` deliberately covers watermark-dead, merge-conflicted, AND
/// roster-dead bindings: one dead state, no taxonomy inflation. Callers only
/// ever need "does this bind authorize".
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ActorBindingStatus {
    /// Binding authorizes: live epoch, unconflicted, live roster key.
    Active,
    /// Binding does not authorize, for any reason.
    Revoked,
}

/// Fold-internal binding content for one authority key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActorBindingState {
    /// Valid revoke entries in this bind's ancestry. This is fold-only state.
    pub observed_revocations: BTreeSet<AuthorityEntryHash>,
    /// Store actor entity the key speaks for.
    pub actor_ref: EntityId,
    /// EXACT bound class.
    pub actor_class: String,
    /// Binding epoch.
    pub epoch: u64,
    /// Set when divergent same-epoch bindings merged — fail-closed dead.
    pub conflicted: bool,
}
