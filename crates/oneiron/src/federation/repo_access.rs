//! The repo admission seams on an owner's agent Grant (FIX 6867): the L02
//! seams the Engine approved for L11 G1. A door that lets an agent read or
//! edit a repo calls one of them in the snapshot it commits in, before it
//! resolves or shows anything the caller named.
//!
//! [`Vault::admit_repo_member_in_txn`] admits the real actor to one repo
//! handle. [`Vault::admit_repo_read_in_txn`] and
//! [`Vault::admit_repo_edit_in_txn`] admit it again, then judge one
//! [`RepoTarget`] under the same Grant with [`Scope::admit_repo_target`].
//! Each reads, in the caller's snapshot:
//! - the actor's own standing, by the shipped principal rule
//!   (`authority::principal_standing_in_txn`): a live, enabled agent
//!   principal with a live Grant from a live owner that lists the verb;
//! - one owner's agent Grant that alone names the actor and carries repo
//!   bounds for the handle, live (a revoke deletes the row), unexpired, given
//!   by a live owner, listing the verb with the bounds' PROJECT in its
//!   audience. On a shared vault the Grant also passes the shipped
//!   membership gate for that one grant
//!   (`Vault::authenticated_grant_membership_in_txn`: vault not deleted, root
//!   not conflicted, pact not inactive); on a personal vault it is under the
//!   home's residence scope. Grants are never unioned;
//! - the CODE anchor: a live CODE_ARTIFACT whose stored repo_ref parses (the
//!   current repo) and that belongs to the bounds' live PROJECT.
//!
//! The owner's own doors never call these: his live proof admits him as it
//! did. A missing or unreadable record is a typed refusal here, never an
//! error on a path that answers today.

use crate::Vault;
use crate::authority::{
    NoStanding, PACT_STANDING_LAPSED, principal_standing_in_txn, principal_standing_or_lapse_in_txn,
};
use crate::codebase::RepoRef;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EdgeStoreRead;
use crate::registry::ENTITY_TYPE_CODE_ARTIFACT;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

use super::{
    AgentGrantStanding, FederationGrantScope, REPO_READ_VERB, RepoAccessBounds, RepoAccessIntent,
    RepoAccessRefusal, RepoTarget, Scope, own_device_residence_scope,
};

/// A mint names repo bounds its Scope cannot use.
const NOT_IN_AUDIENCE: &str =
    "an agent grant with repo bounds lists read and names the bounds' PROJECT in its audience";
/// A mint names repo bounds whose anchor is no repo of that PROJECT.
const NOT_IN_PROJECT: &str =
    "repo bounds name a live CODE_ARTIFACT that belongs to the live PROJECT they name";
/// No single live Grant from an Owner lists a review policy door's verb
/// vault-wide for its caller (FIX 8268); the code leads the text.
const QUEUE_REVIEW_POLICY_NOT_GRANTED: &str = "queue_review_policy_not_granted: no \
     single live Grant an Owner gave this caller lists the verb without repo bounds";

/// What one admitted repo act stands on, as the caller's snapshot read it.
#[derive(Debug, Clone)]
pub(crate) struct RepoMembership {
    /// The real actor admitted.
    pub(crate) actor: EntityId,
    /// Its class, as the host bound it.
    pub(crate) class: EdgeActorClass,
    /// The one owner's agent Grant that admits it.
    pub(crate) grant: EntityId,
    /// That Grant's repo bounds.
    pub(crate) bounds: RepoAccessBounds,
    /// The CODE anchor's current repo.
    pub(crate) repo_ref: RepoRef,
}

/// An admission: the membership, or the typed reason it was refused.
pub(crate) type RepoAdmission = std::result::Result<RepoMembership, RepoAccessRefusal>;

// The run repo doors (L11 G1 PR2) call these three seams, as the manual
// publish doors (FIX 6866) will.
impl Vault {
    /// Admits `actor`, of `class`, to the repo handle `repo` (a CODE anchor)
    /// in the caller's snapshot `txn`. `actor` and `class` are the ones the
    /// host bound, never a request's. `Ok(Err(NoMembership))` when no single
    /// Grant admits it; no other id is resolved first.
    ///
    /// # Errors
    /// A store, fold or clock failure; never "no membership".
    #[allow(
        dead_code,
        reason = "the run doors admit a target; the manual publish doors (FIX 6866) call this"
    )]
    pub(crate) fn admit_repo_member_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        class: EdgeActorClass,
        repo: EntityId,
    ) -> Result<RepoAdmission> {
        self.admit_repo_in_txn(txn, actor, class, repo, None)
    }

    /// Admits `actor` to the repo handle `repo` as
    /// [`Self::admit_repo_member_in_txn`] does, then judges `target` for a
    /// read under that Grant's bounds: `WrongRepo` when the target names
    /// another repo than the admitted handle, then `WrongRef`, then
    /// `PathOutsideScope` against the readable globs alone.
    ///
    /// # Errors
    /// A store, fold or clock failure; never a refusal.
    pub(crate) fn admit_repo_read_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        class: EdgeActorClass,
        repo: EntityId,
        target: &RepoTarget,
    ) -> Result<RepoAdmission> {
        self.admit_repo_in_txn(
            txn,
            actor,
            class,
            repo,
            Some((target, RepoAccessIntent::Read)),
        )
    }

    /// [`Self::admit_repo_read_in_txn`] for an edit: the Grant must list the
    /// edit verb, and every path, the old and new name of a rename and the
    /// path of a delete among them, must match an editable glob. A Grant
    /// whose editable set is empty edits nothing.
    ///
    /// # Errors
    /// A store, fold or clock failure; never a refusal.
    pub(crate) fn admit_repo_edit_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        class: EdgeActorClass,
        repo: EntityId,
        target: &RepoTarget,
    ) -> Result<RepoAdmission> {
        self.admit_repo_in_txn(
            txn,
            actor,
            class,
            repo,
            Some((target, RepoAccessIntent::Edit)),
        )
    }

    /// The one admission the three seams share. With no `ask` it admits the
    /// membership alone; with one, the first Grant (in id order) whose
    /// bounds admit the target wins, and the refusal is the one that got
    /// furthest across the actor's Grants for this handle.
    fn admit_repo_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        class: EdgeActorClass,
        repo: EntityId,
        ask: Option<(&RepoTarget, RepoAccessIntent)>,
    ) -> Result<RepoAdmission> {
        let verb = ask.map_or(REPO_READ_VERB, |(_, intent)| intent.verb());
        if principal_standing_in_txn(self, txn, actor, class, verb)?.is_none() {
            return Ok(Err(RepoAccessRefusal::NoMembership));
        }
        let now = self.instant_in_txn(txn)?.secs();
        let owners = crate::policy_model::owners_in_txn(self, txn)?;
        let shared = self
            .shared_vault_creation_in_txn(txn)?
            .map(|creation| creation.vault_id);
        let mut refusal = RepoAccessRefusal::NoMembership;
        for standing in self.agent_grants_in_txn(txn)? {
            let grant = &standing.grant;
            let Some(bounds) = grant.repo_bounds.as_ref() else {
                continue;
            };
            if bounds.repo != repo
                || grant.member_ref != actor
                || !grant.confers_at(now)
                || !owners.contains(&standing.delegated_by)
                || !grant.authority_scope.admits_repo_member(bounds)
                || !self.agent_grant_stands_in_txn(txn, &standing, shared)?
            {
                continue;
            }
            let Some(repo_ref) = self.repo_anchor_in_txn(txn, bounds)? else {
                continue;
            };
            if let Some((target, intent)) = ask
                && let Err(refused) = grant
                    .authority_scope
                    .admit_repo_target(bounds, target, intent)
            {
                refusal = refusal.max(refused);
                continue;
            }
            return Ok(Ok(RepoMembership {
                actor,
                class,
                grant: standing.id,
                bounds: bounds.clone(),
                repo_ref,
            }));
        }
        Ok(Err(refusal))
    }

    /// Whether the agent Grant stands under this vault's own rule. On a
    /// shared vault (`shared` is its id): under the vault's scope and
    /// admitted by the shipped membership gate for that one grant, whose
    /// refusal (a conflicted root among them) is no membership here. On a
    /// personal vault: under the home's residence scope; the personal
    /// standing rule already ran.
    fn agent_grant_stands_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        standing: &AgentGrantStanding,
        shared: Option<u64>,
    ) -> Result<bool> {
        let grant = &standing.grant;
        let Some(vault_id) = shared else {
            return Ok(grant.scope == own_device_residence_scope());
        };
        if grant.scope != FederationGrantScope::vault(vault_id) {
            return Ok(false);
        }
        match self.authenticated_grant_membership_in_txn(
            txn,
            grant.scope,
            grant.member_ref,
            standing.id,
        ) {
            Ok(membership) => Ok(membership.is_some()),
            Err(Error::Claim(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

// The manual publish doors' seam (FIX 6866, an L02 addition beside G1's
// three): no existing body above changes.
impl Vault {
    /// [`Self::admit_repo_read_in_txn`] over the SAME live candidate Grants,
    /// in the same id order, for a door that also needs something of the one
    /// Grant it stands on: the first Grant that admits the read AND passes
    /// `passes` wins, so an earlier Grant that only reads never masks a later
    /// one that passes. Grants are never unioned. `Ok(Err(Some(refused)))`:
    /// no Grant admits the read (the furthest refusal, as the read seam
    /// answers); `Ok(Err(None))`: a Grant admits the read, none of those
    /// passes.
    ///
    /// # Errors
    /// A store, fold or clock failure; never a refusal.
    pub(crate) fn admit_repo_read_passing_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        class: EdgeActorClass,
        repo: EntityId,
        target: &RepoTarget,
        passes: impl Fn(&AgentGrantStanding) -> bool,
    ) -> Result<std::result::Result<RepoMembership, Option<RepoAccessRefusal>>> {
        let intent = RepoAccessIntent::Read;
        if principal_standing_in_txn(self, txn, actor, class, intent.verb())?.is_none() {
            return Ok(Err(Some(RepoAccessRefusal::NoMembership)));
        }
        let now = self.instant_in_txn(txn)?.secs();
        let owners = crate::policy_model::owners_in_txn(self, txn)?;
        let shared = self
            .shared_vault_creation_in_txn(txn)?
            .map(|creation| creation.vault_id);
        let mut refusal = Some(RepoAccessRefusal::NoMembership);
        for standing in self.agent_grants_in_txn(txn)? {
            let grant = &standing.grant;
            let Some(bounds) = grant.repo_bounds.as_ref() else {
                continue;
            };
            if bounds.repo != repo
                || grant.member_ref != actor
                || !grant.confers_at(now)
                || !owners.contains(&standing.delegated_by)
                || !grant.authority_scope.admits_repo_member(bounds)
                || !self.agent_grant_stands_in_txn(txn, &standing, shared)?
            {
                continue;
            }
            let Some(repo_ref) = self.repo_anchor_in_txn(txn, bounds)? else {
                continue;
            };
            if let Err(refused) = grant
                .authority_scope
                .admit_repo_target(bounds, target, intent)
            {
                refusal = refusal.map(|furthest| furthest.max(refused));
                continue;
            }
            if !passes(&standing) {
                refusal = None;
                continue;
            }
            return Ok(Ok(RepoMembership {
                actor,
                class,
                grant: standing.id,
                bounds: bounds.clone(),
                repo_ref,
            }));
        }
        Ok(Err(refusal))
    }
}

// The vault-wide merge queue review policy doors' seam (FIX 8268, an L02
// addition): no existing body above changes.
impl Vault {
    /// Admits `actor`, of `class` (the ones the host bound, never a
    /// request's), to the vault-wide review policy door `verb`
    /// (`vault.code.merge_queue.review_policy.get` or `.set`) under one
    /// owner's agent Grant, in the caller's snapshot `txn`: the shipped
    /// principal rule first ([`principal_standing_or_lapse_in_txn`]), then
    /// the first live Grant, in id order, that alone stands for the actor and
    /// `verb` ([`AgentGrantStanding::stands_in_txn`]), stands under this
    /// vault's own rule, and carries no repo bounds: a vault setting is no
    /// one repo's. Grants are never unioned and a repo Grant is not this
    /// authority. The Owner's own proof never comes here.
    ///
    /// `Ok(Ok(grant))` names the admitting Grant; `Ok(Err(reason))` is
    /// [`PACT_STANDING_LAPSED`] when a shared vault's pact lapse alone took
    /// the Grant, else [`QUEUE_REVIEW_POLICY_NOT_GRANTED`].
    ///
    /// # Errors
    /// A store, fold or clock failure; never a refusal.
    pub(crate) fn admit_queue_review_policy_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        actor: EntityId,
        class: EdgeActorClass,
        verb: &str,
    ) -> Result<std::result::Result<EntityId, &'static str>> {
        match principal_standing_or_lapse_in_txn(self, txn, actor, class, verb)? {
            Ok(_) => {}
            Err(NoStanding::PactStandingLapsed) => return Ok(Err(PACT_STANDING_LAPSED)),
            Err(NoStanding::NotStanding) => return Ok(Err(QUEUE_REVIEW_POLICY_NOT_GRANTED)),
        }
        let now = self.instant_in_txn(txn)?.secs();
        let owners = crate::policy_model::owners_in_txn(self, txn)?;
        let shared = self
            .shared_vault_creation_in_txn(txn)?
            .map(|creation| creation.vault_id);
        for standing in self.agent_grants_in_txn(txn)? {
            if standing.grant.repo_bounds.is_none()
                && standing.stands_in_txn(self, txn, actor, verb, now, &owners)
                && self.agent_grant_stands_in_txn(txn, &standing, shared)?
            {
                return Ok(Ok(standing.id));
            }
        }
        Ok(Err(QUEUE_REVIEW_POLICY_NOT_GRANTED))
    }
}

impl Vault {
    /// The owner's repo `bounds` for a new agent grant of `scope`, checked in
    /// the minting writer: their grammar, a Scope that lists read with their
    /// PROJECT in its audience, and a live CODE anchor in that live PROJECT.
    /// Only a mint that names bounds meets this check.
    ///
    /// # Errors
    /// `InvalidConfig` naming the rule the bounds break; a store failure.
    pub(super) fn check_repo_bounds_mint_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        scope: &Scope,
        bounds: &RepoAccessBounds,
    ) -> Result<()> {
        bounds
            .validate()
            .map_err(|reason| Error::InvalidConfig(reason.into()))?;
        if !scope.admits_repo_member(bounds) {
            return Err(Error::InvalidConfig(NOT_IN_AUDIENCE.into()));
        }
        if self.repo_anchor_in_txn(txn, bounds)?.is_none() {
            return Err(Error::InvalidConfig(NOT_IN_PROJECT.into()));
        }
        Ok(())
    }

    /// The CODE anchor's current repo in `txn`: a live CODE_ARTIFACT whose
    /// stored repo_ref parses, with a `belongs_to` edge to the live PROJECT
    /// the bounds name. `None` for anything else, an unreadable body
    /// included.
    fn repo_anchor_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        bounds: &RepoAccessBounds,
    ) -> Result<Option<RepoRef>> {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CODE_ARTIFACT,
            body,
        } = live_entity_row_in_txn(&self.store, txn, &bounds.repo)?
        else {
            return Ok(None);
        };
        let Some(repo_ref) = crate::code_artifact::decode_code_artifact_body(&body)
            .ok()
            .and_then(|artifact| RepoRef::parse(&artifact.repo_ref).ok())
        else {
            return Ok(None);
        };
        if !live_entity_row_in_txn(&self.store, txn, &bounds.project)?.is_live()
            || !crate::workspace_roster::is_project_entity(&self.store, txn, bounds.project)?
            || self
                .store
                .port_edge_get(txn, &bounds.repo, EdgeKind::BelongsTo, &bounds.project)?
                .is_none()
        {
            return Ok(None);
        }
        Ok(Some(repo_ref))
    }
}
