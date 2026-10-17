//! Folded-state data model and the two-state merge.
//!
//! This is the module's shared type surface: the fold-internal `FoldState`,
//! every derived roster / pact / actor-binding shape, and
//! [`merge_states`], which must be edited in lockstep with the `FoldState`
//! field list because it folds every field 1:1.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use crate::entity_id::EntityId;

use super::*;

/// Fold issue retained for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthorityFoldIssue {
    /// Entry failed shape or signature verification.
    InvalidEntry(AuthorityEntryHash),
    /// Entry references a missing or invalid parent.
    InvalidAncestry(AuthorityEntryHash),
    /// Entry is signed by a key a handoff retired, outside that handoff's
    /// own ancestry.
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

/// Deterministic authority fold output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AuthorityFold {
    /// The heads a new main-log entry names: every main-log head but the rows
    /// of anchors this install does not pin.
    pub(super) append_heads: BTreeSet<AuthorityEntryHash>,
    /// Each unpinned anchor's own heads, which only that anchor's rows name.
    pub(super) anchor_heads: BTreeMap<[u8; 32], BTreeSet<AuthorityEntryHash>>,
    /// Each signer's latest valid row of each world, a settings edit or a key
    /// record, with its sequence: the parent that signer's next row of the
    /// world names (Astra #1422b F1, #1422c).
    pub(super) scope_heads: BTreeMap<(AuthorityKey, EntityId), (u64, AuthorityEntryHash)>,
    pub(super) append_sequences: BTreeMap<AuthorityKey, u64>,
    /// Historical actor/class pairs affected by a key revocation, including rebind-away.
    pub actor_revocation_affected_writers: BTreeSet<(EntityId, String)>,
    /// Known causal frontiers that observed every revocation before regrant.
    pub actor_write_frontiers: BTreeMap<AuthorityKey, BTreeSet<AuthorityEntryHash>>,
    /// Keys with any actor revocation in valid history; missing write frontiers then quarantine.
    pub revoked_actor_keys: BTreeSet<AuthorityKey>,
    /// Log-derived mint tree and monotone revocation/consumption tombstones.
    pub slips: SlipAuthorityState,
    /// Derived vault id.
    pub vault_id: Option<AuthorityVaultId>,
    /// Valid entry hashes.
    pub valid_entries: BTreeSet<AuthorityEntryHash>,
    /// Fold-derived active/revoked roster.
    pub roster: BTreeMap<AuthorityKey, FoldedDevice>,
    /// Keys a handoff (`ReRoot`) retired. They stay revoked on every branch:
    /// no entry they sign stands outside the handoff's own ancestry.
    pub retired_keys: BTreeSet<AuthorityKey>,
    /// The handoffs whose fences stand: settled, or in conflict.
    pub(super) closed_handoffs: BTreeSet<AuthorityEntryHash>,
    /// Owner dismissed saving the recovery secret and no second device has enrolled.
    pub genesis_fragile: bool,
    /// Fold-derived federation pact states keyed by pact id.
    pub federation_pacts: BTreeMap<[u8; 32], FederationPactState>,
    /// Consumed federation confirmation ids and nonces, bound to signed entries.
    pub federation_confirms: BTreeMap<AuthorityEntryHash, AuthorityConfirmAction>,
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
    /// Each physical machine's folded standing, keyed by its MACHINE row.
    pub machines: BTreeMap<EntityId, FoldedMachine>,
    /// This install's pinned root while the fold holds it as a valid root:
    /// the pin [`AuthorityFold::trusted_machine`] reads. `None` trusts the
    /// accepted roster revisions alone.
    pub pinned_root: Option<PinnedRoot>,
    pub(super) root_anchors: BTreeMap<[u8; 32], BTreeSet<RecoveryRootId>>,
    /// The entries that folded through an owner anchor's branch: the
    /// stale-roster window never expires them, and none renews a roster
    /// revision.
    pub(super) anchor_entries: BTreeSet<AuthorityEntryHash>,
    /// The roster marks a key P1 accepts signed, judged on the merged
    /// history: the only marks that renew a stale trusted roster revision.
    pub(super) accepted_roster_marks: BTreeSet<AuthorityEntryHash>,
    /// Each edited world's settings, keyed by its WORLD row.
    pub worlds: BTreeMap<EntityId, FoldedWorld>,
    /// Well-signed world edits from a machine that could not edit that
    /// world: valid entries without effect.
    pub refused_world_edits: BTreeSet<AuthorityEntryHash>,
    /// What this install holds back beside the roster rule (Astra #1430).
    pub(super) install: InstallBound,
    /// The counted ancestor pairs the fold indexed: those of rows other than
    /// the slip issuer's slip ops.
    pub(super) counted_ancestor_pairs: u64,
    /// Every world key with a counted record, keyed by id (world first).
    pub(super) world_keys: BTreeMap<WorldKeyId, FoldedWorldKey>,
    /// Well-signed key records that count for nothing under this install's
    /// pin: valid entries without effect.
    pub refused_world_keys: BTreeSet<AuthorityEntryHash>,
    /// Fold diagnostics.
    pub issues: Vec<AuthorityFoldIssue>,
}

/// What bounds this install's view beside the roster rule (Astra #1430).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct InstallBound {
    /// The machine revisions and world edits this install holds back: each
    /// revision that landed restriction only, and each edit that never counts
    /// at full strength here, one valid without effect included.
    pub(super) held_back: BTreeSet<AuthorityEntryHash>,
    /// The first still-future second at which the fold with no vouch that
    /// bounds this view changes (`install_fold::NoVouch`). A cached view
    /// lasts no longer.
    pub(super) no_vouch_deadline: Option<u64>,
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
    /// call site. A log refused at its fold's memory floor
    /// ([`AuthorityFoldIssue::FoldMemoryFloor`]) collapses the same way.
    #[must_use]
    pub fn vault_root_is_conflicted(&self) -> bool {
        self.vault_id.is_none()
            && self.issues.iter().any(|issue| {
                matches!(
                    issue,
                    AuthorityFoldIssue::ConflictingVaultRoot { .. }
                        | AuthorityFoldIssue::FoldMemoryFloor { .. }
                )
            })
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

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct FoldState {
    pub(super) slips: SlipAuthorityState,
    pub(super) vault_id: AuthorityVaultId,
    pub(super) roster: BTreeMap<AuthorityKey, FoldedDevice>,
    pub(super) genesis_recovery_dismissed: bool,
    pub(super) recovery_redundancy_established: bool,
    pub(super) federation_pacts: BTreeMap<[u8; 32], FederationPactState>,
    pub(super) federation_confirms: BTreeMap<AuthorityEntryHash, AuthorityConfirmAction>,
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
    pub(super) actor_revocation_hashes: BTreeMap<AuthorityKey, BTreeSet<AuthorityEntryHash>>,
    pub(super) seqs: BTreeMap<AuthorityKey, u64>,
    pub(super) machines: BTreeMap<EntityId, BTreeMap<MachineAdmitter, MachineChain>>,
    /// Every claim of each install key (the machine, its admitter, and an
    /// owner-held roster signer), merged by union.
    pub(super) machine_keys: BTreeMap<[u8; 32], BTreeSet<KeyClaim>>,
    /// Each valid root's anchor key, mapped to every root id it signed,
    /// merged by union. No root record is fold state.
    pub(super) root_anchors: BTreeMap<[u8; 32], BTreeSet<RecoveryRootId>>,
    /// The entries that folded through an owner anchor's branch (its roots
    /// and its marks), merged by union. They rest on no roster key, even when
    /// a roster also names the anchor's public key.
    pub(super) anchor_entries: BTreeSet<AuthorityEntryHash>,
    /// Roster keys marked as the host's, merged by union: each key a host
    /// enrolled as its own root, and each key marked for the cloud (role or
    /// tier). Custody also passes along `key_admitters`.
    pub(super) host_custody_keys: BTreeSet<AuthorityKey>,
    pub(super) worlds: BTreeMap<EntityId, WorldFrontier>,
    pub(super) refused_world_edits: BTreeSet<AuthorityEntryHash>,
    /// Each world key's counted records, merged by union.
    pub(super) world_keys:
        BTreeMap<WorldKeyId, std::sync::Arc<super::world_key_fold::WorldKeyState>>,
    /// Well-signed key records that count for nothing here, merged by union.
    pub(super) refused_world_keys: BTreeSet<AuthorityEntryHash>,
    /// Each roster key's admitters, merged by union: the keys that enrolled,
    /// rotated to or re-rooted to it, on any branch. A key is in the host's
    /// custody when it, or any key up this graph, is marked as the host's,
    /// whatever labels it carries and whichever branch carried the mark.
    pub(super) key_admitters: BTreeMap<AuthorityKey, BTreeSet<AuthorityKey>>,
    /// The fold judges a hosted vault (`FoldContext::hosted`), fixed at genesis.
    pub(super) hosted: bool,
    /// Every row an accepted bind or rebind named, merged by union: the
    /// actor merge keeps one winner, and a row bound on a losing branch is
    /// still no physical machine.
    pub(super) actor_rows: BTreeSet<EntityId>,
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
        (binding.epoch > watermark
            && !binding.conflicted
            && self
                .actor_revocation_hashes
                .get(key)
                .is_none_or(|revocations| revocations.is_subset(&binding.observed_revocations)))
        .then_some(binding)
    }
}

/// Projects fold-internal binding state onto the public tuple.
///
/// Status is computed HERE rather than stored, so roster death propagates for
/// free: `RevokeDevice`/`RotateKey`/`ReRoot` kill dependent bindings
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
pub(super) fn folded_actor_bindings(
    state: &FoldState,
    consent_arm: fn(&FoldedDevice) -> bool,
) -> BTreeMap<AuthorityKey, FoldedActorBinding> {
    state
        .actor_bindings
        .iter()
        .map(|(key, binding)| {
            let status = if folded_binding_key_still_qualifies(state, key, binding, consent_arm)
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
/// that would have REJECTED the bind also kills it retroactively.
fn folded_binding_key_still_qualifies(
    state: &FoldState,
    key: &AuthorityKey,
    binding: &ActorBindingState,
    consent_arm: fn(&FoldedDevice) -> bool,
) -> bool {
    let Some(device) = state.roster.get(key).filter(|device| !device.revoked) else {
        return false;
    };
    binding.actor_class != ACTOR_CLASS_HUMAN || consent_arm(device)
}

pub(super) fn merge_states(left: &FoldState, right: &FoldState) -> FoldState {
    debug_assert_eq!(left.vault_id, right.vault_id);
    let mut merged = left.clone();
    merged.slips.merge_from(&right.slips);
    merged.genesis_recovery_dismissed |= right.genesis_recovery_dismissed;
    merged.recovery_redundancy_established |= right.recovery_redundancy_established;
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
    merged
        .federation_confirms
        .extend(right.federation_confirms.clone());
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
    for (key, hashes) in &right.actor_revocation_hashes {
        merged
            .actor_revocation_hashes
            .entry(key.clone())
            .or_default()
            .extend(hashes.iter().copied());
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
    merge_machine_maps(&mut merged.machines, &mut merged.machine_keys, right);
    for (anchor, roots) in &right.root_anchors {
        merged
            .root_anchors
            .entry(*anchor)
            .or_default()
            .extend(roots.iter().copied());
    }
    merged
        .anchor_entries
        .extend(right.anchor_entries.iter().copied());
    merge_world_frontiers(&mut merged.worlds, &right.worlds);
    merged
        .refused_world_edits
        .extend(right.refused_world_edits.iter().copied());
    super::world_key_fold::merge_world_keys(&mut merged.world_keys, &right.world_keys);
    merged
        .refused_world_keys
        .extend(right.refused_world_keys.iter().copied());
    merged
        .host_custody_keys
        .extend(right.host_custody_keys.iter().cloned());
    for (key, admitters) in &right.key_admitters {
        merged
            .key_admitters
            .entry(key.clone())
            .or_default()
            .extend(admitters.iter().cloned());
    }
    merged.actor_rows.extend(right.actor_rows.iter().copied());
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
            winner.observed_revocations = left
                .observed_revocations
                .intersection(&right.observed_revocations)
                .copied()
                .collect();
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
