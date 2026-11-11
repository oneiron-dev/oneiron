//! Scope authority shared by the purpose-specific stored grant envelopes.
use super::{Scope, ScopeAxis, ScopeId};
use std::collections::BTreeSet;
/// Old purpose-specific doors can prove a verb and base/default audience only.
/// A narrower content grant is evaluated by record-aware doors, never widened here.
pub(crate) fn admits_preset(scope: &Scope, verb: &str) -> bool {
    let mut record = Scope::top();
    record.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(crate::claim::base_world_id())]));
    record.audience = ScopeAxis::Some(BTreeSet::from([
        ScopeId(crate::claim::default_project_id()),
    ]));
    record.verbs = ScopeAxis::Some(BTreeSet::from([verb.to_owned()]));
    scope.admits(verb, &record, &Scope::top())
}

/// The Steward role in one plain sentence, said beside its name in the
/// roster verbs' output and in the SDK (ARCH-0043).
pub const STEWARD_ROLE_NOTE: &str = "A Steward looks after the vault's memory for its owners: it can read and organise everything in this vault, but it can only suggest who joins or what role they get, and it can never give itself more access.";

/// A Steward reads across its vault root.
pub(crate) const STEWARD_READ_VERB: &str = "read";
/// A Steward lands what it derives (for an agent: the Auto ceiling and the
/// `Generated` permit its consolidation needs).
pub(crate) const STEWARD_DERIVE_VERB: &str = "derive";
/// A Steward archives inside its grant, reversibly.
pub(crate) const STEWARD_ARCHIVE_VERB: &str = "archive";
/// A Steward deletes in scope.
pub(crate) const STEWARD_DELETE_VERB: &str = "delete";

/// A Steward tunes the engine's knobs (untangle 6.6, S66-1), one verb per
/// class of knob (lead 10 Nov 06:5x), so an owner gives an agent only the
/// classes it needs: maintenance cadence, work budgets inside the owner's
/// caps, system-agent wake cadence, and which recipe a knowledge job runs.
/// Owner acts stay outside them. No role default gives them: the Coach's
/// default grant names all four, and an owner can give any of them to any
/// agent.
pub(crate) const ENGINE_CONTROLS_MAINTENANCE_CADENCE_VERB: &str =
    "engine.controls.maintenance_cadence";
/// The work-budget class of `engine.controls` (see above).
pub(crate) const ENGINE_CONTROLS_WORK_BUDGET_VERB: &str = "engine.controls.work_budget";
/// The wake-cadence class of `engine.controls` (see above).
pub(crate) const ENGINE_CONTROLS_WAKE_CADENCE_VERB: &str = "engine.controls.wake_cadence";
/// The knowledge-recipe class of `engine.controls` (see above).
pub(crate) const ENGINE_CONTROLS_KNOWLEDGE_RECIPE_VERB: &str = "engine.controls.knowledge_recipe";

/// The four `engine.controls` class verbs.
pub(crate) const ENGINE_CONTROLS_VERBS: [&str; 4] = [
    ENGINE_CONTROLS_MAINTENANCE_CADENCE_VERB,
    ENGINE_CONTROLS_WORK_BUDGET_VERB,
    ENGINE_CONTROLS_WAKE_CADENCE_VERB,
    ENGINE_CONTROLS_KNOWLEDGE_RECIPE_VERB,
];

/// The verbs the shipped Steward default gives: read and derive across its
/// vault root, archive inside its grant, delete in scope.
pub(crate) const STEWARD_VERBS: [&str; 4] = [
    STEWARD_READ_VERB,
    STEWARD_DERIVE_VERB,
    STEWARD_ARCHIVE_VERB,
    STEWARD_DELETE_VERB,
];

/// Every verb a Steward's grant can carry: the default four and the four
/// `engine.controls` classes.
pub(crate) const STEWARD_CEILING_VERBS: [&str; 8] = [
    STEWARD_READ_VERB,
    STEWARD_DERIVE_VERB,
    STEWARD_ARCHIVE_VERB,
    STEWARD_DELETE_VERB,
    ENGINE_CONTROLS_MAINTENANCE_CADENCE_VERB,
    ENGINE_CONTROLS_WORK_BUDGET_VERB,
    ENGINE_CONTROLS_WAKE_CADENCE_VERB,
    ENGINE_CONTROLS_KNOWLEDGE_RECIPE_VERB,
];

pub(crate) fn membership_preset(role: super::FederationGrantRole) -> Scope {
    match role {
        super::FederationGrantRole::Owner => Scope::top(),
        // The ADMIN ceiling is structural. Which named powers it starts with
        // is chosen by vault-resident manifest rows at the minting writer.
        super::FederationGrantRole::Admin => Scope::top(),
        // The non-vault Delegate constructor keeps its historical narrow
        // ceiling; the vault minting writer resolves the policy row instead.
        super::FederationGrantRole::Delegate => super::scope_codec::read_preset(),
        // The Steward's ceiling (ARCH-0043, owner 9 Nov): read and derive
        // across the vault root, archive inside its grant, delete in scope,
        // and the four engine.controls classes (6.6). It names no admin power and no `write`,
        // so no vault or holder row can raise a Steward to membership acts or
        // general content writes.
        super::FederationGrantRole::Steward => {
            let mut scope = Scope::top();
            scope.verbs = ScopeAxis::Some(
                STEWARD_CEILING_VERBS
                    .iter()
                    .map(|verb| (*verb).to_owned())
                    .collect(),
            );
            scope
        }
        super::FederationGrantRole::Member => {
            let mut scope = Scope::top();
            scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
            scope
        }
        super::FederationGrantRole::Guest => Scope::default(),
        _ => super::scope_codec::read_preset(),
    }
}
