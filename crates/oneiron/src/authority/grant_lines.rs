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
//! The givings are the owner's agent Grant mints (`AgentGrantAct`, FIX 5628) and a general
//! grant act's givings (`GrantAct`, pass 28 R2), which commit to their row's terms under the
//! row's own key. The ends are his revokes, a general grant act's ends, a `SlipGrantRevoke`,
//! and the Grants a carrier-signed `MembershipExecution` withdraws (FIX 12335). An owner's act
//! counts as every owner act does: some chain of its machine names the signing key, the one
//! carrier rule admits the machine at the act's parents ([`super::owner_act_signer_admits`],
//! pin-free) and the owner is live there ([`super::owner_act::owner_live_at`]); otherwise it is
//! valid and without effect. A general grant act needs its carrier alone: whether its deciding
//! person could give those terms reads rows (a vault's owners, an admin's powers), so the
//! reader judges it. A giving gives on this install only where it counts here in full: an end
//! only takes away, so it needs no more than to count.
//!
//! A Grant's line keeps one family for good: the owner's agent Grant (its mint and revoke, and
//! a lapse's end) or one general grant act family. A grant act of another family than the acts
//! the line already holds is valid and without effect, so a shared vault's admin who names the
//! owner's agent Grant in a member giving neither replaces his mint nor ends it. Two branches
//! the fold cannot order that name a Grant in two families leave it standing on neither, for
//! good: no later act of either family counts on it, and an end of either family ends nothing
//! there, so a concurrent end in another family is never stronger than a descendant one. A
//! writer never gives or ends one id in two families; a Grant so suspended is given again at a
//! fresh id. Membership withdrawals and slip revokes end any Grant they name, of any family.
//!
//! The fold reads the log alone: a giving need not find its row, and a row need not find its
//! act. Only the reader puts the two together, asking the family it reads.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entity_id::EntityId;
use crate::federation::{
    FederationGrant, FederationGrantKind, FederationGrantPreset, FederationGrantRole,
    FederationGrantScope, GitPushBounds, GrantTermsKey, RepoAccessBounds, Scope, WalletRef,
    WorkingViewEditBounds, federation_grant_terms,
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
    /// A general grant act's giving: its terms by their keyed commitment alone.
    Committed(CommittedTerms),
    /// A person's statement of an agent definition's switches, in clear (pass 28 R2d).
    AgentSwitches(StatedSwitches),
}

impl GrantTerms {
    /// The family of Grant these terms give; `None` for the empty value.
    pub(crate) fn family(&self) -> Option<GrantFamily> {
        match self {
            Self::Nothing => None,
            Self::OwnerAgentMint(_) => Some(GrantFamily::OwnerAgent),
            Self::Committed(committed) => Some(committed.family),
            Self::AgentSwitches(_) => Some(GrantFamily::AgentDefinition),
        }
    }

    /// Whether `grant`, the row `id` holding the terms key `terms_key`, is exactly the row
    /// these terms state. A committed giving opens only with the row's own key.
    pub(crate) fn matches_row(
        &self,
        id: EntityId,
        grant: &FederationGrant,
        terms_key: Option<&GrantTermsKey>,
    ) -> bool {
        match self {
            // A statement of switches names an AGENT_DEF row, never a Grant row.
            Self::Nothing | Self::AgentSwitches(_) => false,
            Self::OwnerAgentMint(mint) => mint.row(grant.scope.clone()) == *grant,
            Self::Committed(committed) => terms_key.is_some_and(|key| {
                federation_grant_terms(id, grant, key).is_ok_and(|terms| terms == committed.terms)
            }),
        }
    }
}

/// A general grant act's giving as the fold holds it (`GrantActChange::Give`): the row's
/// family, the person who gave it, and the keyed commitment to the row's terms.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CommittedTerms {
    /// The row's family, whose rule judges the giver.
    pub(crate) family: GrantFamily,
    /// The deciding person.
    pub(crate) giver: EntityId,
    /// The commitment ([`federation_grant_terms`]).
    pub(crate) terms: [u8; 32],
}

/// A statement of an agent definition's switches as the fold holds it
/// (`GrantActChange::State`): who stated them, and the switches. The fold does not judge
/// the person; the AGENT_DEF reader stands on a statement only when they own the vault.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct StatedSwitches {
    /// The deciding person.
    pub(crate) giver: EntityId,
    /// The switches stated.
    pub(crate) switches: AgentSwitches,
}

/// The owner's agent Grant mint as its act states it (`AgentGrantChange::Mint`): who gave it,
/// and every term of the row it writes but the row's residence scope, which no mint carries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct OwnerAgentMint {
    owner: EntityId,
    pub(super) member: EntityId,
    pub(super) scope: Scope,
    pub(super) expires_at: Option<u64>,
    repo_bounds: Option<RepoAccessBounds>,
    pub(super) grant_kind: FederationGrantKind,
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
    /// Each Grant's counted ends, each with the family its act named: none for a membership
    /// withdrawal or a slip revoke, which end a Grant of any family.
    ends: BTreeMap<EntityId, BTreeMap<AuthorityEntryHash, Option<GrantFamily>>>,
    /// Well-signed grant acts whose carrier or owner did not stand at their parents, or that
    /// named a Grant an act of another family named first: valid entries without effect.
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
                .extend(ends.iter().map(|(hash, family)| (*hash, *family)));
        }
        self.refused.extend(right.refused.iter().copied());
    }

    /// Records the counted act `hash` that ends `grant`, whatever its family: a membership
    /// withdrawal or a slip revoke.
    pub(super) fn end(&mut self, grant: EntityId, hash: AuthorityEntryHash) {
        self.ends.entry(grant).or_default().insert(hash, None);
    }

    /// Records the counted act `hash` of `family` that ends `grant`.
    pub(super) fn end_in_family(
        &mut self,
        grant: EntityId,
        hash: AuthorityEntryHash,
        family: GrantFamily,
    ) {
        self.ends
            .entry(grant)
            .or_default()
            .insert(hash, Some(family));
    }

    /// Whether the act `hash` counted here as an end of `grant`, of `family` (`None`: a
    /// membership withdrawal or a slip revoke). A valid act carried without effect is no end.
    pub(super) fn counted_end(
        &self,
        grant: EntityId,
        hash: &AuthorityEntryHash,
        family: Option<GrantFamily>,
    ) -> bool {
        self.ends
            .get(&grant)
            .and_then(|ends| ends.get(hash))
            .is_some_and(|counted| *counted == family)
    }

    /// Every family the acts naming `grant` hold: its givings, live or replaced, and its ends.
    fn families(&self, grant: EntityId) -> BTreeSet<GrantFamily> {
        let givings = self.givings.get(&grant).into_iter().flat_map(|frontier| {
            frontier
                .live
                .values()
                .chain(frontier.superseded.values())
                .filter_map(|giving| giving.settings.family())
        });
        let ends = self
            .ends
            .get(&grant)
            .into_iter()
            .flat_map(|ends| ends.values().flatten().copied());
        givings.chain(ends).collect()
    }

    /// Whether an act of `family` may give or end `grant`: no act of another family named it.
    /// The set of families only grows, so a refusal is for good.
    pub(super) fn admits(&self, grant: EntityId, family: GrantFamily) -> bool {
        self.families(grant).iter().all(|held| *held == family)
    }

    /// Records the counted act `hash` that gives `grant` as `edit` says, replacing every live
    /// giving the act's parents carry.
    fn give(&mut self, grant: EntityId, hash: AuthorityEntryHash, edit: FrontierEdit<GrantTerms>) {
        let frontier = self.givings.entry(grant).or_default();
        let seen = std::mem::take(&mut frontier.live);
        let replaced = seen.keys().copied().collect();
        frontier.superseded.extend(seen);
        frontier
            .live
            .insert(hash, Arc::new(FrontierEdit { replaced, ..edit }));
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
    /// The one family the acts naming the Grant hold: `None` when only a membership withdrawal
    /// or a slip revoke names it, or when two branches name it in two families (then no giving
    /// counts here).
    pub(crate) family: Option<GrantFamily>,
}

#[cfg(any(test, oneiron_test_support))]
impl FoldedGrantLine {
    /// The person whose general grant act gives the Grant here in full: `None` when no such
    /// giving counts (none, two unordered, or an owner's agent mint).
    pub(crate) fn committed_giver(&self) -> Option<EntityId> {
        match &self.giving {
            Some((_, GrantTerms::Committed(terms))) => Some(terms.giver),
            _ => None,
        }
    }
}

impl AuthorityFold {
    /// What the counted acts say of `grant` on this install; `None` when no counted act
    /// names it.
    pub(crate) fn grant_line(&self, grant: EntityId) -> Option<&FoldedGrantLine> {
        self.grant_lines.get(&grant)
    }

    /// The owner's agent Grant mint that gives `grant` on this install: its line holds the
    /// owner's agent Grant family alone, no counted act ended it, and one mint counts here in
    /// full. `None` for every other Grant: one no counted mint gives, one revoked, one two
    /// mints the fold cannot order both give, and one given in another family.
    pub(super) fn standing_owner_agent_mint(&self, grant: EntityId) -> Option<&OwnerAgentMint> {
        let line = self
            .grant_line(grant)
            .filter(|line| !line.ended && line.family == Some(GrantFamily::OwnerAgent))?;
        match &line.giving {
            Some((_, GrantTerms::OwnerAgentMint(mint))) => Some(mint),
            _ => None,
        }
    }

    /// The switches the one counted statement on agent definition `definition`'s line
    /// states, and the person who stated them: `None` when no statement counts here in full,
    /// when two the fold cannot order both stand, or when the line holds another family.
    /// Whether that person may state them (the vault's owner) is the reader's to judge.
    pub(crate) fn stated_agent_switches(
        &self,
        definition: EntityId,
    ) -> Option<(EntityId, &AgentSwitches)> {
        let line = self
            .grant_line(definition)
            .filter(|line| !line.ended && line.family == Some(GrantFamily::AgentDefinition))?;
        match &line.giving {
            Some((_, GrantTerms::AgentSwitches(stated))) => Some((stated.giver, &stated.switches)),
            _ => None,
        }
    }
}

/// The `AgentGrantAct` transition's grant line, once `apply_agent_grant_act` took the entry
/// as valid: a counted mint gives its Grant the terms it states, replacing the givings its
/// parents carry; a counted revoke ends the Grant. A carrier the one rule does not admit, an
/// owner the act's parents hold removed, or a Grant a general grant act already named carries
/// a valid act without effect.
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
    if !admitted
        || !super::owner_act::owner_live_at(state, record.act.owner)
        || !state
            .grant_lines
            .admits(record.grant, GrantFamily::OwnerAgent)
    {
        state.grant_lines.refused.insert(hash);
        return;
    }
    let Some(mint) = OwnerAgentMint::of(record.act.owner, &record.change) else {
        state
            .grant_lines
            .end_in_family(record.grant, hash, GrantFamily::OwnerAgent);
        return;
    };
    state.grant_lines.give(
        record.grant,
        hash,
        FrontierEdit {
            settings: GrantTerms::OwnerAgentMint(Box::new(mint)),
            machine: record.machine,
            key,
            replaced: BTreeSet::new(),
            narrow_only,
            marks,
            restriction_only,
            disputed: false,
        },
    );
}

/// The `GrantAct` transition's grant line, once `super::grant_act::apply_grant_act` took the
/// entry as valid: a counted giving gives its row the terms it commits to, replacing the
/// givings its parents carry; a counted end ends the row and withdraws the slips minted under
/// it. A carrier the one rule does not admit, or a Grant an act of another family already
/// named, carries a valid act without effect. The deciding person is not judged here: the
/// fold holds no shared vault's owners or admins, so the reader judges them by the family's
/// own rule.
pub(super) fn apply_grant_act_line(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    record: &GrantActRecord,
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
    if !admitted || !state.grant_lines.admits(record.subject, record.family) {
        state.grant_lines.refused.insert(hash);
        return;
    }
    let settings = match (&record.change, record.decider_person()) {
        (GrantActChange::Give { terms }, Some(giver)) => GrantTerms::Committed(CommittedTerms {
            family: record.family,
            giver,
            terms: *terms,
        }),
        (GrantActChange::State { switches }, Some(giver)) => {
            GrantTerms::AgentSwitches(StatedSwitches {
                giver,
                switches: switches.clone(),
            })
        }
        // An end withdraws the slips minted under the row too, as a membership execution's
        // withdrawal does (FIX 12335).
        (GrantActChange::End, _) => {
            state.slips.revoke_grant(record.subject.to_hex());
            state
                .grant_lines
                .end_in_family(record.subject, hash, record.family);
            return;
        }
        // `GrantActRecord::validate` refuses a rule's giving before any fold; should one
        // reach here, it gives nothing and never turns into an end no one decided.
        (GrantActChange::Give { .. } | GrantActChange::State { .. }, None) => {
            state.grant_lines.refused.insert(hash);
            return;
        }
    };
    state.grant_lines.give(
        record.subject,
        hash,
        FrontierEdit {
            settings,
            machine: record.machine,
            key,
            replaced: BTreeSet::new(),
            narrow_only,
            marks,
            restriction_only,
            disputed: false,
        },
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
            let families = lines.families(grant);
            let family = match families.len() {
                1 => families.first().copied(),
                _ => None,
            };
            let giving = frontier.and_then(|frontier| {
                let mut live = frontier.live.iter();
                let (hash, giving) = live.next()?;
                (family.is_some() && live.next().is_none() && counts_here(&standing, hash, giving))
                    .then(|| (*hash, giving.settings.clone()))
            });
            // An end of the line's own family, or of none (a membership withdrawal, a slip
            // revoke), ends it; an end of another family, from a branch the fold cannot order,
            // ends nothing, as it would end nothing after the line's acts.
            let ended = lines.ends.get(&grant).is_some_and(|ends| {
                ends.values()
                    .any(|end| end.is_none() || (family.is_some() && *end == family))
            });
            (
                grant,
                FoldedGrantLine {
                    live,
                    giving,
                    ended,
                    family,
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
/// givings after a settled handoff stand in it (`fresh`). The giving alone is bounded: a line
/// with no giving stands for nothing whatever its family and end say, so neither is touched.
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
