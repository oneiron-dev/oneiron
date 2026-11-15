//! The fold's grant lines (Fable pass 28, DESIGN 3.1): for each FEDERATION_GRANT row, the
//! counted acts that give it and the counted acts that end it. A Grant row is state; what it
//! confers is what these acts say (`Vault::standing_grant_in_txn`).
//!
//! A giving act states the Grant's terms. Per Grant the givings are world privacy's
//! multi-value register over the authority DAG ([`super::world_strength`]): a giving replaces
//! the live givings its parents carry, and two givings the fold cannot order stay side by
//! side, so the Grant stands on neither until a later giving replaces both, as two concurrent
//! re-pacts suspend a pact instead of picking a winner (ARCH-0043:162). An end is forever: no
//! later act gives an ended Grant back, so a row put again at its id stands for nothing.
//!
//! The givings are the owner's agent Grant mints (`AgentGrantAct`, FIX 5628). The ends are his
//! revokes, a `SlipGrantRevoke`, and the Grants a carrier-signed `MembershipExecution`
//! withdraws (FIX 12335). An owner's act counts as every owner act does: some chain of its
//! machine names the signing key, the one carrier rule admits the machine at the act's parents
//! ([`super::owner_act_signer_admits`], pin-free) and the owner is live there
//! ([`super::owner_act::owner_live_at`]); otherwise it is valid and without effect. A giving
//! gives on this install only where it counts here in full: an end only takes away, so it
//! needs no more than to count.
//!
//! The fold reads the log alone: a giving need not find its row, and a row need not find its
//! act. Only the reader puts the two together.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entity_id::EntityId;
use crate::federation::{
    FederationGrant, FederationGrantKind, FederationGrantPreset, FederationGrantRole,
    FederationGrantScope, GitPushBounds, RepoAccessBounds, Scope, WalletRef, WorkingViewEditBounds,
};

use super::machine_standing::{InstallCounted, Standing, StandingView};
use super::world_strength::{FrontierEdit, WorldFrontier, merge_world_frontiers};
use super::*;

/// What a giving act states of its Grant.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum GrantTerms {
    /// The register's empty value. No act states it, and it gives no Grant.
    #[default]
    Nothing,
    /// The owner's agent Grant mint, every term in clear.
    OwnerAgentMint(Box<OwnerAgentMint>),
}

impl GrantTerms {
    /// Whether `grant` is exactly the row these terms state.
    pub(crate) fn matches_row(&self, grant: &FederationGrant) -> bool {
        match self {
            Self::Nothing => false,
            Self::OwnerAgentMint(mint) => mint.row(grant.scope.clone()) == *grant,
        }
    }
}

/// The owner's agent Grant mint as its act states it (`AgentGrantChange::Mint`): who gave it,
/// and every term of the row it writes but the row's residence scope, which no mint carries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct OwnerAgentMint {
    owner: EntityId,
    member: EntityId,
    scope: Scope,
    expires_at: Option<u64>,
    repo_bounds: Option<RepoAccessBounds>,
    grant_kind: FederationGrantKind,
    git_push_bounds: Option<GitPushBounds>,
    verb_classes: BTreeSet<String>,
    wallet_ref: Option<WalletRef>,
    steward: bool,
    working_view_bounds: Option<WorkingViewEditBounds>,
}

impl OwnerAgentMint {
    /// `owner`'s mint `change`; `None` for a revoke.
    fn of(owner: EntityId, change: &AgentGrantChange) -> Option<Self> {
        let AgentGrantChange::Mint {
            member,
            scope,
            expires_at,
            repo_bounds,
            grant_kind,
            git_push_bounds,
            verb_classes,
            wallet_ref,
            steward,
            working_view_bounds,
        } = change
        else {
            return None;
        };
        Some(Self {
            owner,
            member: *member,
            scope: scope.clone(),
            expires_at: *expires_at,
            repo_bounds: repo_bounds.clone(),
            grant_kind: *grant_kind,
            git_push_bounds: git_push_bounds.clone(),
            verb_classes: verb_classes.clone(),
            wallet_ref: wallet_ref.clone(),
            steward: *steward,
            working_view_bounds: *working_view_bounds,
        })
    }

    /// The FEDERATION_GRANT row this mint writes at residence `residence`, as its three
    /// writers write it: the owner's agent grant (`Vault::mint_agent_grant_in_txn`), his git
    /// push grant (`federation/git_push/mint.rs`) and a base agent's Steward grant
    /// (`put_steward_grant_row_in_txn`, which names no delegator).
    fn row(&self, residence: FederationGrantScope) -> FederationGrant {
        let (role, preset) = if self.steward {
            (FederationGrantRole::Steward, FederationGrantPreset::Steward)
        } else {
            (
                FederationGrantRole::Delegate,
                FederationGrantPreset::Delegate,
            )
        };
        FederationGrant {
            authority_scope: self.scope.clone(),
            scope: residence,
            member_ref: self.member,
            role,
            preset,
            expires_at: self.expires_at,
            delegated_by: (!self.steward).then_some(self.owner),
            guest: None,
            owner_agent: !self.steward && self.grant_kind == FederationGrantKind::Access,
            repo_bounds: self.repo_bounds.clone(),
            kind: self.grant_kind,
            git_push_bounds: self.git_push_bounds.clone(),
            detach_on_member_leave: None,
            verb_classes: self.verb_classes.clone(),
            wallet_ref: self.wallet_ref.clone(),
            inquiry_terms: None,
            working_view_bounds: self.working_view_bounds,
        }
    }
}

/// Every Grant's counted givings and ends, as one entry's parents hold them.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct GrantLines {
    /// Each Grant's counted givings: the live ones and every one a later giving replaced.
    givings: BTreeMap<EntityId, WorldFrontier<GrantTerms>>,
    /// Each Grant's counted ends.
    ends: BTreeMap<EntityId, BTreeSet<AuthorityEntryHash>>,
    /// Well-signed grant acts whose carrier or owner did not stand at their parents: valid
    /// entries without effect.
    refused: BTreeSet<AuthorityEntryHash>,
}

impl GrantLines {
    /// Joins `right` in: a giving replaced on either side is replaced, two copies of one
    /// giving meet, and an end on either side ends.
    pub(super) fn merge(&mut self, right: &Self) {
        merge_world_frontiers(&mut self.givings, &right.givings);
        for (grant, ends) in &right.ends {
            self.ends
                .entry(*grant)
                .or_default()
                .extend(ends.iter().copied());
        }
        self.refused.extend(right.refused.iter().copied());
    }

    /// Records the counted act `hash` that ends `grant`.
    pub(super) fn end(&mut self, grant: EntityId, hash: AuthorityEntryHash) {
        self.ends.entry(grant).or_default().insert(hash);
    }
}

/// What the counted acts say of one Grant, as this install counts them.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FoldedGrantLine {
    /// Each live giving and the machine that carried it, counted here or not: what that
    /// machine's next profile revision lists as seen ([`live_givings_by`]).
    pub(crate) live: BTreeMap<AuthorityEntryHash, EntityId>,
    /// The one live giving that counts here in full, by its act: `None` when no giving
    /// does, or when two live givings the fold cannot order both stand.
    pub(crate) giving: Option<(AuthorityEntryHash, GrantTerms)>,
    /// A counted act ended the Grant.
    pub(crate) ended: bool,
}

impl AuthorityFold {
    /// What the counted acts say of `grant` on this install; `None` when no counted act
    /// names it.
    pub(crate) fn grant_line(&self, grant: EntityId) -> Option<&FoldedGrantLine> {
        self.grant_lines.get(&grant)
    }
}

/// The `AgentGrantAct` transition's grant line, once `apply_agent_grant_act` took the entry
/// as valid: a counted mint gives its Grant the terms it states, replacing the givings its
/// parents carry; a counted revoke ends the Grant. A carrier the one rule does not admit, or
/// an owner the act's parents hold removed, carries a valid act without effect.
pub(super) fn apply_owner_agent_grant_line(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    record: &AgentGrantActRecord,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
    restriction_only: bool,
) {
    let signer = entry.signer_key();
    let AuthorityKey::Ed25519(key) = signer else {
        return;
    };
    let key = *key;
    let standing = Standing::new(state, pin, counted);
    let roster = StandingView::Under(MachineAdmitter::Roster);
    let admitted = standing.admits_owner_act_signer(record.machine, &key, roster);
    let marks = standing.live_signing_chains(record.machine, signer);
    let narrow_only =
        !standing.admits_owner_act_signer(record.machine, &key, StandingView::Install);
    drop(standing);
    if !admitted || !super::owner_act::owner_live_at(state, record.act.owner) {
        state.grant_lines.refused.insert(hash);
        return;
    }
    let Some(mint) = OwnerAgentMint::of(record.act.owner, &record.change) else {
        state.grant_lines.end(record.grant, hash);
        return;
    };
    let frontier = state.grant_lines.givings.entry(record.grant).or_default();
    let seen = std::mem::take(&mut frontier.live);
    let replaced = seen.keys().copied().collect();
    frontier.superseded.extend(seen);
    frontier.live.insert(
        hash,
        Arc::new(FrontierEdit {
            settings: GrantTerms::OwnerAgentMint(Box::new(mint)),
            machine: record.machine,
            key,
            replaced,
            narrow_only,
            marks,
            restriction_only,
            disputed: false,
        }),
    );
}

/// Full strength on this install: not disputed, counted here at its parents, landed in full,
/// stating terms, and its removal race passes now ([`Standing::owner_act_race`]).
fn counts_here(
    standing: &Standing<'_>,
    hash: &AuthorityEntryHash,
    giving: &FrontierEdit<GrantTerms>,
) -> bool {
    !giving.disputed
        && !giving.narrow_only
        && !giving.restriction_only
        && giving.settings != GrantTerms::Nothing
        && standing.owner_act_race(
            giving.machine,
            hash,
            &giving.key,
            &giving.marks,
            StandingView::Install,
        )
}

/// The fold's view of every Grant a counted act names, under this install's pin and holds.
pub(super) fn folded_grant_lines(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> BTreeMap<EntityId, FoldedGrantLine> {
    let standing = Standing::new(state, pin, counted);
    let lines = &state.grant_lines;
    let named: BTreeSet<EntityId> = lines
        .givings
        .keys()
        .chain(lines.ends.keys())
        .copied()
        .collect();
    named
        .into_iter()
        .map(|grant| {
            let frontier = lines.givings.get(&grant);
            let live = frontier.map_or_else(BTreeMap::new, |frontier| {
                frontier
                    .live
                    .iter()
                    .map(|(hash, giving)| (*hash, giving.machine))
                    .collect()
            });
            let giving = frontier.and_then(|frontier| {
                let mut live = frontier.live.iter();
                let (hash, giving) = live.next()?;
                (live.next().is_none() && counts_here(&standing, hash, giving))
                    .then(|| (*hash, giving.settings.clone()))
            });
            let ended = lines.ends.contains_key(&grant);
            (
                grant,
                FoldedGrantLine {
                    live,
                    giving,
                    ended,
                },
            )
        })
        .collect()
}

/// The live givings `machine` carried, for its next profile revision's acknowledged set
/// ([`super::world_privacy::live_edits_by`]): a removal of that machine that saw a giving
/// leaves it standing, as it leaves a grant travel choice.
pub(super) fn live_givings_by(
    fold: &AuthorityFold,
    machine: EntityId,
) -> impl Iterator<Item = AuthorityEntryHash> + '_ {
    fold.grant_lines
        .values()
        .flat_map(|line| line.live.iter())
        .filter(move |(_, carrier)| **carrier == machine)
        .map(|(hash, _)| *hash)
}

/// The grant acts that never count at full strength on this install: each one valid without
/// effect, and each live or replaced giving this install does not count in full.
pub(super) fn held_grant_acts(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
    out: &mut BTreeSet<AuthorityEntryHash>,
) {
    out.extend(state.grant_lines.refused.iter().copied());
    let standing = Standing::new(state, pin, counted);
    for frontier in state.grant_lines.givings.values() {
        out.extend(
            frontier
                .live
                .iter()
                .chain(&frontier.superseded)
                .filter(|(hash, giving)| !counts_here(&standing, hash, giving))
                .map(|(hash, _)| *hash),
        );
    }
}

/// Bounds each Grant's giving by `bound`'s, the fold with no vouch (`install_fold::NoVouch`):
/// a Grant that fold gives by no act, or by another act, stands on nothing here, unless only
/// givings after a settled handoff stand in it (`fresh`).
pub(super) fn cap_grant_lines(
    lines: &mut BTreeMap<EntityId, FoldedGrantLine>,
    bound: &BTreeMap<EntityId, FoldedGrantLine>,
    fresh: &BTreeSet<EntityId>,
) {
    for (grant, line) in lines.iter_mut() {
        if fresh.contains(grant) {
            continue;
        }
        let act = |line: &FoldedGrantLine| line.giving.as_ref().map(|(act, _)| *act);
        if bound.get(grant).and_then(act) != act(line) {
            line.giving = None;
        }
    }
}
