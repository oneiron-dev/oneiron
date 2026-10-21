//! FIX 6219 (L02 seam): whether a recorded principal still stands, for work a
//! host does later in that principal's name while no caller is present.
//!
//! The host holds no credential of the principal's (canon grants no such
//! custody): the authority of such work is the principal's own recorded act,
//! and this check, run again in each snapshot the work writes in, that the
//! principal is still live. A person stands while its PERSON row is live and
//! active. An agent stands while its agent row is live (an enabled, active
//! agent definition, or a base agent's MACHINE principal) AND one live Grant
//! the owner gave it names it, confers now and lists the work's verb, and,
//! on a shared vault, whose pact membership still stands (FIX 7511). Grants
//! are never unioned and no other holder is picked. It mints nothing, and
//! the work still crosses every gate it crosses for a caller.

use crate::Vault;
use crate::claim::ClaimLifecycleStatus;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::{AgentGrantStanding, FederationGrant, FederationGrantScope, ScopeAxis};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_MACHINE};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// A recorded principal that stood in one snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrincipalStanding {
    pub(crate) principal: EntityId,
    pub(crate) class: EdgeActorClass,
    /// The one live Grant that lists the work's verb, for an agent; `None`
    /// for a person.
    pub(crate) grant: Option<EntityId>,
}

/// Why a recorded principal does not stand, for a caller that refuses and
/// names the reason (FIX 7511).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoStanding {
    /// Every case [`principal_standing_in_txn`] answers `None` for but the
    /// one below.
    NotStanding,
    /// On a shared vault, a Grant stood for the agent's verb by the Grant
    /// rule ([`AgentGrantStanding::stands_for`]) but its authenticated pact
    /// membership is gone, and no other Grant stands.
    PactStandingLapsed,
}

/// The typed reason a refusing caller names for [`NoStanding::PactStandingLapsed`]
/// (CALLS `FIX 7511 lapse refusal`, accepted by the Engine 10-21 21:2x); its
/// code leads the text.
pub(crate) const PACT_STANDING_LAPSED: &str = "pact_standing_lapsed: on this shared vault the \
     agent's Grant for the verb stands only while its pact membership does, and that membership \
     has lapsed";

/// What the Grant rule does when the pact membership check itself fails with
/// a store or decode error rather than a refusal (CALLS `FIX 7511 membership
/// check error`, open).
#[derive(Debug, Clone, Copy)]
enum PactStandingCheckError {
    /// The Grant stands as it did before the check, and a key-only warning
    /// names the Grant and the error's kind.
    PreserveCurrentPath,
}

const PACT_STANDING_CHECK_ERROR: PactStandingCheckError =
    PactStandingCheckError::PreserveCurrentPath;

/// Whether `principal`, of `class`, still stands in `txn` for work under
/// `verb`.
///
/// `Ok(None)`: the principal is dead, retired, erased, switched off or of
/// another class, or, for an agent, no single live Grant names it, confers
/// now (unexpired, given by a live owner), lists `verb` and, on a shared
/// vault, keeps its pact membership.
/// # Errors
/// A store, fold or clock failure, or an agent definition that does not
/// decode; never "no principal".
pub(crate) fn principal_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    class: EdgeActorClass,
    verb: &str,
) -> Result<Option<PrincipalStanding>> {
    Ok(principal_standing_or_lapse_in_txn(vault, txn, principal, class, verb)?.ok())
}

/// [`principal_standing_in_txn`], naming why the principal does not stand:
/// [`NoStanding::PactStandingLapsed`] where a shared vault's pact lapse
/// alone took the agent's Grant, [`NoStanding::NotStanding`] for every
/// other `None`.
/// # Errors
/// As [`principal_standing_in_txn`].
pub(crate) fn principal_standing_or_lapse_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    class: EdgeActorClass,
    verb: &str,
) -> Result<std::result::Result<PrincipalStanding, NoStanding>> {
    let grant = match class {
        EdgeActorClass::Human => {
            if !crate::consent::person_is_live_in_txn(vault, txn, &principal)? {
                return Ok(Err(NoStanding::NotStanding));
            }
            None
        }
        EdgeActorClass::Agent | EdgeActorClass::System => {
            if !live_agent_principal_in_txn(vault, txn, principal, class)? {
                return Ok(Err(NoStanding::NotStanding));
            }
            match agent_grant_listing_in_txn(vault, txn, principal, verb)? {
                Ok(grant) => Some(grant),
                Err(no_standing) => return Ok(Err(no_standing)),
            }
        }
    };
    Ok(Ok(PrincipalStanding {
        principal,
        class,
        grant,
    }))
}

/// Whether `agent` is a live agent principal acting as `class`: an enabled,
/// active agent definition the archive has not taken, acting as an agent, or
/// a base agent's MACHINE principal, which acts as the system class.
fn live_agent_principal_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    class: EdgeActorClass,
) -> Result<bool> {
    match (class, live_entity_row_in_txn(&vault.store, txn, &agent)?) {
        (
            EdgeActorClass::Agent,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_AGENT_DEF,
                body,
            },
        ) => {
            if vault.archive_tombstone_in_txn(txn, &agent)?.is_some() {
                return Ok(false);
            }
            let definition = crate::agent_def::decode_agent_definition(&body)?;
            Ok(definition.enabled && definition.lifecycle_status == ClaimLifecycleStatus::Active)
        }
        (
            EdgeActorClass::System,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_MACHINE,
                ..
            },
        ) => crate::dreamer_runner::authority::is_base_agent_actor(&agent),
        _ => Ok(false),
    }
}

/// The first live owner-agent Grant, in id order, that alone names `agent`,
/// confers now, was given by a live owner of this vault, lists `verb` in its
/// explicit verb set and, on a shared vault, keeps its pact membership
/// ([`AgentGrantStanding::stands_in_txn`]). With none, the lapse when a
/// Grant failed on its pact membership alone.
fn agent_grant_listing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    verb: &str,
) -> Result<std::result::Result<EntityId, NoStanding>> {
    let now = vault.instant_in_txn(txn)?.secs();
    let owners = crate::policy_model::owners_in_txn(vault, txn)?;
    let mut lapsed = false;
    for standing in vault.agent_grants_in_txn(txn)? {
        if !standing.stands_for(agent, verb, now, &owners) {
            continue;
        }
        if standing.pact_standing_lapsed_in_txn(vault, txn) {
            lapsed = true;
            continue;
        }
        return Ok(Ok(standing.id));
    }
    Ok(Err(if lapsed {
        NoStanding::PactStandingLapsed
    } else {
        NoStanding::NotStanding
    }))
}

/// [`PACT_STANDING_CHECK_ERROR`] for a check of `grant` that failed with
/// `error`: never a lapse. The warning carries the Grant id and the error's
/// kind only.
fn lapse_on_check_error(grant: EntityId, error: &Error) -> bool {
    match PACT_STANDING_CHECK_ERROR {
        PactStandingCheckError::PreserveCurrentPath => {
            tracing::warn!(
                grant = %grant.to_hex(),
                error_kind = ?error.kind(),
                policy = ?PACT_STANDING_CHECK_ERROR,
                "an agent Grant's pact standing could not be read; the Grant stands as it did \
                 (FIX 7511)"
            );
            false
        }
    }
}

impl AgentGrantStanding {
    /// [`Self::stands_for`], and on a shared vault this Grant's own pact
    /// membership too (FIX 7511): the whole rule [`principal_standing_in_txn`]
    /// picks its Grant by, for a reader that takes every Grant it holds
    /// (FIX 7462). A personal vault reads as [`Self::stands_for`] alone.
    pub(crate) fn stands_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
        verb: &str,
        now: u64,
        owners: &[EntityId],
    ) -> bool {
        self.stands_for(agent, verb, now, owners) && !self.pact_standing_lapsed_in_txn(vault, txn)
    }

    /// Whether this Grant's pact standing has lapsed (FIX 7511, Engine 10-21
    /// 21:2x): on a shared vault, the shipped membership gate for this one
    /// Grant (`Vault::authenticated_grant_membership_in_txn`: vault not
    /// deleted, root not conflicted, the Grant live, unexpired and not
    /// inactive under its pact) no longer admits it, its refusal
    /// (`Error::Claim`) among them, as federation/repo_access.rs reads it. A
    /// personal vault has no pact standing to lapse. A store or decode
    /// failure of the check is no lapse ([`PACT_STANDING_CHECK_ERROR`]). The
    /// pact half of [`Self::stands_in_txn`], for a reader that picks its
    /// Grants by its own rule.
    pub(crate) fn pact_standing_lapsed_in_txn(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> bool {
        match vault.shared_vault_creation_in_txn(txn) {
            Ok(Some(_)) => {}
            Ok(None) => return false,
            Err(error) => return lapse_on_check_error(self.id, &error),
        }
        match vault.authenticated_grant_membership_in_txn(
            txn,
            self.grant.scope,
            self.grant.member_ref,
            self.id,
        ) {
            Ok(Some(_)) => false,
            Ok(None) | Err(Error::Claim(_)) => true,
            Err(error) => lapse_on_check_error(self.id, &error),
        }
    }

    /// Whether this Grant alone stands for `agent`'s work under `verb` at
    /// `now`: it names `agent`, confers now, was given by one of `owners`
    /// (this vault's live owners) and lists `verb` in its explicit verb set.
    /// The rule's half that reads no snapshot; [`Self::stands_in_txn`] adds
    /// the shared vault's pact membership.
    pub(crate) fn stands_for(
        &self,
        agent: EntityId,
        verb: &str,
        now: u64,
        owners: &[EntityId],
    ) -> bool {
        self.grant.member_ref == agent
            && self.grant.confers_at(now)
            && owners.contains(&self.delegated_by)
            && matches!(
                &self.grant.authority_scope.verbs,
                ScopeAxis::Some(verbs) if verbs.contains(verb)
            )
    }
}

/// [`AgentGrantStanding::pact_standing_lapsed_in_txn`] for a raw Grant row
/// (FIX 7548): the Grant `id`, its pact `scope` and its `member`, for a
/// reader that picks raw FEDERATION_GRANT rows by its own rule and holds no
/// [`AgentGrantStanding`]. The same membership gate, the same lapse and the
/// same [`PACT_STANDING_CHECK_ERROR`]; a personal vault has no pact standing
/// to lapse.
pub(crate) fn grant_pact_standing_lapsed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    scope: FederationGrantScope,
    member: EntityId,
) -> bool {
    match vault.shared_vault_creation_in_txn(txn) {
        Ok(Some(_)) => {}
        Ok(None) => return false,
        Err(error) => return lapse_on_check_error(id, &error),
    }
    match vault.authenticated_grant_membership_in_txn(txn, scope, member, id) {
        Ok(Some(_)) => false,
        Ok(None) | Err(Error::Claim(_)) => true,
        Err(error) => lapse_on_check_error(id, &error),
    }
}

/// [`grant_pact_standing_lapsed_in_txn`] for the live Grant row `id` as
/// `txn` holds it, for a reader that holds only the Grant's id (FIX 7548). A
/// row that is no live FEDERATION_GRANT, or does not decode, has no pact
/// standing here: its reader's own rule judges it. A failed read is no
/// lapse ([`PACT_STANDING_CHECK_ERROR`]).
pub(crate) fn grant_row_pact_standing_lapsed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> bool {
    match live_entity_row_in_txn(&vault.store, txn, &id) {
        Ok(LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_FEDERATION_GRANT,
            body,
        }) => crate::federation::decode_federation_grant_body(&body).is_ok_and(|grant| {
            grant_pact_standing_lapsed_in_txn(vault, txn, id, grant.scope, grant.member_ref)
        }),
        Ok(_) => false,
        Err(error) => lapse_on_check_error(id, &error),
    }
}

/// Which pact test a GitPush Grant takes (CALLS `FIX 7548 git push pact
/// standing`, accepted by the Engine 10-21 22:4x).
#[derive(Debug, Clone, Copy)]
enum GitPushPactStanding {
    /// On a shared vault, the pact activation of the exact Grant alone
    /// (`federation::pact_admits_grant`: unpacted or Active passes, Inactive
    /// lapses), for every holder alike, person or agent. Never the Access
    /// membership gate, which admits no GitPush Grant. A personal vault has
    /// no pact to lapse.
    PactActivationOnlyOnSharedVault,
}

const GIT_PUSH_PACT_STANDING: GitPushPactStanding =
    GitPushPactStanding::PactActivationOnlyOnSharedVault;

/// The typed reason a push refusal names when a GitPush Grant that would
/// admit it is inactive under its pact (FIX 7548); its code leads the text.
pub(crate) const GIT_PUSH_PACT_STANDING_LAPSED: &str = "pact_standing_lapsed: on this shared \
     vault a git_push Grant stands only while its pact does, and this Grant is inactive under \
     its pact";

/// Whether the GitPush Grant `id`, `grant` its decoded row, lapsed on its
/// pact ([`GIT_PUSH_PACT_STANDING`]). A store or fold failure of the check
/// is no lapse ([`PACT_STANDING_CHECK_ERROR`]).
pub(crate) fn git_push_pact_standing_lapsed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    grant: &FederationGrant,
) -> bool {
    match GIT_PUSH_PACT_STANDING {
        GitPushPactStanding::PactActivationOnlyOnSharedVault => {
            match vault.shared_vault_creation_in_txn(txn) {
                Ok(Some(_)) => {}
                Ok(None) => return false,
                Err(error) => return lapse_on_check_error(id, &error),
            }
            match vault.authority_fold_readonly_in_txn(txn) {
                Ok(fold) => !crate::federation::pact_admits_grant(&fold, &id, grant),
                Err(error) => lapse_on_check_error(id, &error),
            }
        }
    }
}
