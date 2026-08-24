//! Folded-state data model and the two-state merge.
//!
//! This is the module's shared type surface: the fold-internal `FoldState`,
//! every derived roster / fork / pact / actor-binding shape, and
//! [`merge_states`], which must be edited in lockstep with the `FoldState`
//! field list because it folds every field 1:1.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::*;

/// Folded roster entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldedDevice {
    /// Authority key.
    pub key: AuthorityKey,
    /// Assurance tier.
    pub tier: AuthorityTier,
    /// Role bits after most-restrictive conflict folding.
    pub roles: u16,
    /// Whether any valid revocation tombstone removed this key.
    pub revoked: bool,
}

/// Local pending-widen state exposed by the fold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityPendingWiden {
    /// Pending authority entry.
    pub entry_hash: AuthorityEntryHash,
    /// Local first-seen monotonic timestamp, if the caller supplied one.
    pub first_seen_at_secs: Option<u64>,
    /// Local timestamp at which the entry becomes eligible.
    pub eligible_at_secs: Option<u64>,
    /// Delay window chosen by genesis for this vault.
    pub delay_secs: u64,
}

/// Fold issue retained for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityFoldIssue {
    /// Entry failed shape or signature verification.
    InvalidEntry(AuthorityEntryHash),
    /// Entry references a missing or invalid parent.
    InvalidAncestry(AuthorityEntryHash),
    /// Entry signer was not valid in its own ancestry.
    SignerNotInAncestry(AuthorityEntryHash),
    /// Entry sequence was not strictly greater than that signer's ancestry high-water mark.
    NonMonotonicSeq(AuthorityEntryHash),
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
    /// One key signed divergent content at the same sequence number.
    EquivocationDetected {
        /// Equivocating authority key.
        signer: AuthorityKey,
        /// Conflicting signer sequence number.
        seq: u64,
    },
    /// Entry lost deterministic selection to the winner of its equivocation group.
    EquivocationLoser {
        /// Losing entry hash.
        entry: AuthorityEntryHash,
        /// Equivocating authority key.
        signer: AuthorityKey,
        /// Conflicting signer sequence number.
        seq: u64,
        /// Deterministically selected entry hash.
        winner: AuthorityEntryHash,
    },
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
}

/// Why the fold refused an actor-binding op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Fold-visible AUTH-5 state for one detected signer fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityForkStatus {
    /// Transient same-pass edge where the fold observes divergent entries and raises the alarm.
    ///
    /// Stable fold output records the immediately following `Quarantined` state.
    Forked,
    /// Forked key is quarantined until a valid quorum revoke folds in.
    Quarantined,
    /// A valid quorum revoke for the forked key has folded in.
    Resolved,
}

/// Queryable fold row for one signer fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityFork {
    /// Equivocating authority key.
    pub signer: AuthorityKey,
    /// Conflicting signer sequence number.
    pub seq: u64,
    /// First conflicting entry hash, sorted lexicographically.
    pub first_hash: AuthorityEntryHash,
    /// Second conflicting entry hash, sorted lexicographically.
    pub second_hash: AuthorityEntryHash,
    /// Current deterministic fork state.
    pub status: AuthorityForkStatus,
}

/// Typed owner-facing alarm row for one authority fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityForkAlarm {
    /// Equivocating authority key.
    pub signer: AuthorityKey,
    /// Conflicting signer sequence number.
    pub seq: u64,
    /// First conflicting entry hash, sorted lexicographically.
    pub first_hash: AuthorityEntryHash,
    /// Second conflicting entry hash, sorted lexicographically.
    pub second_hash: AuthorityEntryHash,
}

impl AuthorityForkAlarm {
    /// Stable alarm discriminator for owner-facing surfaces.
    pub const KIND: &'static str = AUTHORITY_FORK_ALARM_KIND;
}

/// Deterministic authority fold output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityFold {
    /// Derived vault id.
    pub vault_id: Option<AuthorityVaultId>,
    /// Valid entry hashes.
    pub valid_entries: BTreeSet<AuthorityEntryHash>,
    /// Fold-derived active/revoked roster.
    pub roster: BTreeMap<AuthorityKey, FoldedDevice>,
    /// Most-restrictive tier floor.
    pub tier_floor: Option<AuthorityTier>,
    /// Software-tier widens that are valid but not yet locally eligible.
    pub pending_widens: BTreeMap<AuthorityEntryHash, AuthorityPendingWiden>,
    /// Pending widen hashes killed by a valid owner veto.
    pub vetoed_widens: BTreeSet<AuthorityEntryHash>,
    /// AUTH-5 signer-fork state rows.
    pub authority_forks: Vec<AuthorityFork>,
    /// Owner-facing AUTHORITY FORK alarms, one per detected fork.
    pub fork_alarms: Vec<AuthorityForkAlarm>,
    /// Fold-derived federation pact states keyed by pact id.
    pub federation_pacts: BTreeMap<[u8; 32], FederationPactState>,
    pub critical_write_confirms: BTreeMap<[u8; 32], CriticalWriteConfirmState>,
    pub consumed_critical_write_confirm_nonces: BTreeSet<[u8; 16]>,
    /// Confirm ids made unusable by a deterministic sibling collision.
    pub conflicted_critical_write_confirms: BTreeSet<[u8; 32]>,
    /// Every (grant_ref → pact ids) binding a folded valid Connect has EVER
    /// established, merged by union across branches.
    ///
    /// Concurrent valid Connects can bind one pact id to two different
    /// grant_refs on divergent branches; the pact-state merge keeps a single
    /// deterministic binding, so this registry is what keeps the DISCARDED
    /// binding pact-bound: a grant that appears here never falls back to
    /// `Unpacted` legacy-allow.
    pub federation_grant_bindings: BTreeMap<EntityId, BTreeSet<[u8; 32]>>,
    /// Folded actor-binding tuples keyed by authority key (ONE-1604-D2).
    pub actor_bindings: BTreeMap<AuthorityKey, FoldedActorBinding>,
    /// Fold diagnostics.
    pub issues: Vec<AuthorityFoldIssue>,
}

/// One folded `{signing_key_id, actor_ref, actor_class, epoch, status}` tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorBindingStatus {
    /// Binding authorizes: live epoch, unconflicted, live roster key.
    Active,
    /// Binding does not authorize, for any reason.
    Revoked,
}

/// True iff `actor_ref` holds an ACTIVE binding at EXACTLY `actor_class`.
///
/// This is the owner-verb predicate. Multiple keys may bind one actor, so any
/// Active hit passes. For class `"human"` the bound key must itself carry
/// owner capability (enforced at fold time — see the bind transition table),
/// so `Active` here is sufficient and callers need no second roster lookup.
#[must_use]
pub fn actor_binding_is_active(
    fold: &AuthorityFold,
    actor_ref: &EntityId,
    actor_class: &str,
) -> bool {
    fold.actor_bindings.values().any(|binding| {
        binding.status == ActorBindingStatus::Active
            && binding.actor_ref == *actor_ref
            && binding.actor_class == actor_class
    })
}

impl AuthorityFold {
    /// True when [`Self::vault_id`] is `None` because the log carries MORE THAN
    /// ONE independently rooted vault, not because it carries no root at all.
    ///
    /// The two `None`s mean opposite things to a caller: an unrooted log has
    /// declared no authority yet, while a multi-root log declared authority and
    /// then collapsed — the fold clears the roster, bindings, and pacts and
    /// keeps only the [`AuthorityFoldIssue::ConflictingVaultRoot`] rows. Every
    /// authority gate MUST fail closed on the second, so the distinction is
    /// exposed here rather than re-derived (and inevitably mis-derived) at each
    /// call site.
    #[must_use]
    pub fn vault_root_is_conflicted(&self) -> bool {
        self.vault_id.is_none()
            && self
                .issues
                .iter()
                .any(|issue| matches!(issue, AuthorityFoldIssue::ConflictingVaultRoot { .. }))
    }

    /// Pact state governing `grant_ref`, if any lifecycle entries name it.
    ///
    /// Concurrent Connects on divergent branches can bind one grant_ref under
    /// two pact ids; the MOST-RESTRICTIVE status wins (Dissolved >
    /// Disconnected > Promoted > Suspended > Active; ties: lowest pact id) so
    /// a grant shadowed by any non-Active pact never authorizes.
    #[must_use]
    pub fn pact_for_grant(&self, grant_ref: &EntityId) -> Option<&FederationPactState> {
        let mut best: Option<&FederationPactState> = None;
        for state in self.federation_pacts.values() {
            if state.grant_ref != *grant_ref {
                continue;
            }
            if best.is_none_or(|current| state.status > current.status) {
                best = Some(state);
            }
        }
        best
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FoldState {
    pub(super) vault_id: AuthorityVaultId,
    pub(super) roster: BTreeMap<AuthorityKey, FoldedDevice>,
    pub(super) tier_floor: AuthorityTier,
    pub(super) pending_widen_delay_secs: u64,
    pub(super) pending_widens: BTreeMap<AuthorityEntryHash, AuthorityPendingWiden>,
    pub(super) vetoed_widens: BTreeSet<AuthorityEntryHash>,
    /// Delayed software rotations that revoked old owner/admin keys.
    ///
    /// These keys are retained only to validate vetoes against widens that were
    /// concurrent with, or older than, the delayed rotation that revoked them.
    pub(super) delayed_rotation_veto_revocations:
        BTreeMap<AuthorityKey, BTreeSet<AuthorityEntryHash>>,
    /// Keys revoked by operations allowed to resolve authority forks.
    ///
    /// Rotation revocations are deliberately excluded: a forked signer cannot
    /// clear its own alarm by making a self-rotation the equivocation winner.
    pub(super) fork_resolution_revocations: BTreeSet<AuthorityKey>,
    pub(super) authority_forks: BTreeMap<(AuthorityKey, u64), AuthorityFork>,
    pub(super) federation_pacts: BTreeMap<[u8; 32], FederationPactState>,
    pub(super) critical_write_confirms: BTreeMap<[u8; 32], CriticalWriteConfirmState>,
    pub(super) consumed_critical_write_confirm_nonces: BTreeSet<[u8; 16]>,
    /// Every confirmation id ever observed for each consumed nonce.
    ///
    /// This is kept apart from `critical_write_confirms`, whose deterministic
    /// winner selection can discard a sibling needed to poison nonce reuse.
    pub(super) critical_write_confirm_nonce_provenance: BTreeMap<[u8; 16], BTreeSet<[u8; 32]>>,
    pub(super) conflicted_critical_write_confirms: BTreeSet<[u8; 32]>,
    pub(super) federation_grant_bindings: BTreeMap<EntityId, BTreeSet<[u8; 32]>>,
    /// Live binding content per authority key (`RevokeActor` never edits this).
    ///
    /// Kept SEPARATE from the revocation watermarks so a `RevokeActor` folding
    /// on a branch that never saw the bind needs no placeholder content.
    pub(super) actor_bindings: BTreeMap<AuthorityKey, ActorBindingState>,
    /// Inclusive revocation watermark per authority key, merged by max.
    pub(super) actor_binding_revocations: BTreeMap<AuthorityKey, u64>,
    pub(super) seqs: BTreeMap<AuthorityKey, u64>,
}

/// Fold-internal binding content for one authority key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorBindingState {
    /// Store actor entity the key speaks for.
    pub actor_ref: EntityId,
    /// EXACT bound class.
    pub actor_class: String,
    /// Binding epoch.
    pub epoch: u64,
    /// Set when divergent same-epoch bindings merged — fail-closed dead.
    pub conflicted: bool,
}

impl FoldState {
    /// A binding is live iff it out-epochs the revocation watermark and no
    /// divergent same-epoch merge poisoned it. Liveness is DERIVED, never
    /// stored, so revoke and bind can arrive in any order.
    pub(super) fn live_actor_binding(&self, key: &AuthorityKey) -> Option<&ActorBindingState> {
        let binding = self.actor_bindings.get(key)?;
        let watermark = self
            .actor_binding_revocations
            .get(key)
            .copied()
            .unwrap_or(0);
        (binding.epoch > watermark && !binding.conflicted).then_some(binding)
    }
}

/// Projects fold-internal binding state onto the public tuple.
///
/// Status is computed HERE rather than stored, so roster death propagates for
/// free: `RevokeDevice`/`RotateKey`/`RecoveryReboot` kill dependent bindings
/// automatically and order-independently, with no cascade written into binding
/// state. A rotation deliberately does NOT migrate a binding — the old binding
/// dies with the old key and the new key needs a fresh `BindActor`.
///
/// Roster presence alone is NOT enough. The projection re-runs the bind
/// transition table's key predicate against the MERGED roster, because two
/// things can invalidate a key AFTER a valid bind folded:
///
/// * The merge's most-restrictive `roles &=` can strip the OWNER|ADMIN bits (or
///   demote the tier) that admitted a `"human"` bind on a divergent branch. A
///   binding whose key can no longer give owner consent must not keep backing
///   the owner class.
/// * AUTH-5 equivocation quarantines the key itself. A key that signed
///   divergent content at one sequence is exactly the key an attacker holds;
///   letting it keep speaking for a human owner is the fail-open the quarantine
///   exists to prevent. Quarantine is a live-fork property, so it is read from
///   the reported forks rather than from roster state.
pub(super) fn folded_actor_bindings(
    state: &FoldState,
    authority_forks: &[AuthorityFork],
) -> BTreeMap<AuthorityKey, FoldedActorBinding> {
    state
        .actor_bindings
        .iter()
        .map(|(key, binding)| {
            let status = if folded_binding_key_still_qualifies(state, authority_forks, key, binding)
                && state.live_actor_binding(key).is_some()
            {
                ActorBindingStatus::Active
            } else {
                ActorBindingStatus::Revoked
            };
            (
                key.clone(),
                FoldedActorBinding {
                    actor_ref: binding.actor_ref,
                    actor_class: binding.actor_class.clone(),
                    epoch: binding.epoch,
                    status,
                },
            )
        })
        .collect()
}

/// The bind transition table's key predicate, re-evaluated post-merge.
///
/// Mirrors `apply_actor_binding` exactly — live roster row for every class,
/// plus owner-consent capability for `"human"` — so a role/tier restriction
/// that would have REJECTED the bind also kills it retroactively. Any key with
/// a still-quarantined fork fails outright, whatever its roles.
fn folded_binding_key_still_qualifies(
    state: &FoldState,
    authority_forks: &[AuthorityFork],
    key: &AuthorityKey,
    binding: &ActorBindingState,
) -> bool {
    if authority_forks
        .iter()
        .any(|fork| fork.signer == *key && fork.status == AuthorityForkStatus::Quarantined)
    {
        return false;
    }
    let Some(device) = state.roster.get(key).filter(|device| !device.revoked) else {
        return false;
    };
    binding.actor_class != "human" || folded_device_can_authority_consent(device)
}

pub(super) fn merge_states(left: &FoldState, right: &FoldState) -> FoldState {
    debug_assert_eq!(left.vault_id, right.vault_id);
    let mut merged = left.clone();
    merged
        .consumed_critical_write_confirm_nonces
        .extend(right.consumed_critical_write_confirm_nonces.iter().copied());
    merged
        .conflicted_critical_write_confirms
        .extend(right.conflicted_critical_write_confirms.iter().copied());
    for (nonce, confirm_ids) in &right.critical_write_confirm_nonce_provenance {
        merged
            .critical_write_confirm_nonce_provenance
            .entry(*nonce)
            .or_default()
            .extend(confirm_ids.iter().copied());
    }
    // Detect reuse from append-only provenance, not from the lossy winner map.
    // A same-id sibling may have been evicted before a later nonce contender is
    // merged, but every id that ever used the nonce must remain unusable.
    for confirm_ids in merged.critical_write_confirm_nonce_provenance.values() {
        if confirm_ids.len() > 1 {
            merged
                .conflicted_critical_write_confirms
                .extend(confirm_ids.iter().copied());
        }
    }
    for (id, candidate) in &right.critical_write_confirms {
        if let Some(existing) = merged.critical_write_confirms.get(id)
            && existing.authority_entry_hash != candidate.authority_entry_hash
        {
            merged.conflicted_critical_write_confirms.insert(*id);
        }
        match merged.critical_write_confirms.get(id) {
            Some(existing) if existing.authority_entry_hash <= candidate.authority_entry_hash => {}
            _ => {
                merged
                    .critical_write_confirms
                    .insert(*id, candidate.clone());
            }
        }
    }
    merged.tier_floor = most_restrictive_tier_floor(left.tier_floor, right.tier_floor);
    merged.pending_widen_delay_secs = left
        .pending_widen_delay_secs
        .max(right.pending_widen_delay_secs);
    merged.pending_widens.extend(
        right
            .pending_widens
            .iter()
            .map(|(hash, pending)| (*hash, pending.clone())),
    );
    merged
        .vetoed_widens
        .extend(right.vetoed_widens.iter().copied());
    for (key, revocations) in &right.delayed_rotation_veto_revocations {
        merged
            .delayed_rotation_veto_revocations
            .entry(key.clone())
            .or_default()
            .extend(revocations.iter().copied());
    }
    merged
        .fork_resolution_revocations
        .extend(right.fork_resolution_revocations.iter().cloned());
    for (key, fork) in &right.authority_forks {
        merged
            .authority_forks
            .entry(key.clone())
            .and_modify(|existing| {
                if fork.status == AuthorityForkStatus::Resolved {
                    existing.status = AuthorityForkStatus::Resolved;
                }
            })
            .or_insert_with(|| fork.clone());
    }
    for vetoed in &merged.vetoed_widens {
        merged.pending_widens.remove(vetoed);
    }
    for (pact_id, right_pact) in &right.federation_pacts {
        match merged.federation_pacts.get_mut(pact_id) {
            Some(left_pact) => {
                *left_pact = merge_pact_states(left_pact, right_pact);
            }
            None => {
                merged.federation_pacts.insert(*pact_id, right_pact.clone());
            }
        }
    }
    for (grant_ref, pact_ids) in &right.federation_grant_bindings {
        merged
            .federation_grant_bindings
            .entry(*grant_ref)
            .or_default()
            .extend(pact_ids.iter().copied());
    }
    for (key, device) in &right.roster {
        match merged.roster.get_mut(key) {
            Some(existing) => {
                existing.revoked |= device.revoked;
                existing.roles &= device.roles;
                existing.tier = most_restrictive_device_tier(existing.tier, device.tier);
            }
            None => {
                merged.roster.insert(key.clone(), device.clone());
            }
        }
    }
    for (key, epoch) in &right.actor_binding_revocations {
        merged
            .actor_binding_revocations
            .entry(key.clone())
            .and_modify(|current| *current = (*current).max(*epoch))
            .or_insert(*epoch);
    }
    for (key, binding) in &right.actor_bindings {
        match merged.actor_bindings.get_mut(key) {
            Some(existing) => *existing = merge_actor_bindings(existing, binding),
            None => {
                merged.actor_bindings.insert(key.clone(), binding.clone());
            }
        }
    }
    for (key, seq) in &right.seqs {
        merged
            .seqs
            .entry(key.clone())
            .and_modify(|current| *current = (*current).max(*seq))
            .or_insert(*seq);
    }
    merged
}

/// Higher epoch wins; conflict poison is per-epoch, carried by the winner.
///
/// Equal epoch with divergent content is the dangerous case: two branches each
/// believe a different actor holds this key. Keeping the byte-wise smaller
/// tuple makes the merge deterministic in every arrival order, and
/// `conflicted` makes it never Active — a fork over identity fails closed
/// rather than silently picking a winner.
///
/// Poison deliberately does NOT leak across epochs: a strictly higher epoch
/// supersedes the conflicted state outright. It has to, or one historical
/// divergence would brick the key forever with no way to rebind. The
/// fail-closed property survives because two branches that each advance past
/// a conflict must themselves land on the same epoch to be concurrent, and
/// that tie re-poisons at the new epoch.
fn merge_actor_bindings(left: &ActorBindingState, right: &ActorBindingState) -> ActorBindingState {
    match left.epoch.cmp(&right.epoch) {
        Ordering::Greater => left.clone(),
        Ordering::Less => right.clone(),
        Ordering::Equal => {
            let left_tuple = (left.actor_ref, left.actor_class.as_str());
            let right_tuple = (right.actor_ref, right.actor_class.as_str());
            let mut winner = if left_tuple <= right_tuple {
                left.clone()
            } else {
                right.clone()
            };
            winner.conflicted |= left_tuple != right_tuple || left.conflicted || right.conflicted;
            winner
        }
    }
}

pub(super) fn most_restrictive_device_tier(
    left: AuthorityTier,
    right: AuthorityTier,
) -> AuthorityTier {
    left.min(right)
}

pub(super) fn most_restrictive_tier_floor(
    left: AuthorityTier,
    right: AuthorityTier,
) -> AuthorityTier {
    left.max(right)
}
