//! A Steward grant narrowed to one project, for the integration test of the
//! substrate reads behind a grant (untangle 6.6c; review of #6996), and a
//! settled team run of a project or of the vault, whose outcome a spawn
//! choice's learned value counts (UNBUILT-08).

use std::collections::BTreeMap;

use crate::claim::learning_evidence::Anchor;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::team::{DecidedBy, TeamAxis, TeamOutcome, TeamPattern, TeamReceipt, TeamShape};
use crate::vault::Vault;

/// Stands a Steward grant on the vault's root for `holder` with `verbs`,
/// its audience narrowed to the one project `project`, as a holder override
/// row leaves a member's grant.
///
/// # Errors
///
/// The vault's.
pub fn stand_project_steward_grant(
    vault: &Vault,
    holder: EntityId,
    verbs: &[&str],
    project: EntityId,
) -> Result<EntityId> {
    vault.stand_project_steward_grant_for_test(holder, verbs, project)
}

/// Records one solo team run of `width` agents in `project`, or in the
/// vault's own scope for `None`, at the root of the type tree in force
/// there, with an owner's verdict of success settled at `at`.
///
/// # Errors
///
/// The receipt writer's.
pub fn record_settled_team_run(
    vault: &Vault,
    project: Option<EntityId>,
    width: u32,
    at: u64,
) -> Result<()> {
    let team_ref = format!("substrate-scope-filter-{}", EntityId::now().to_hex());
    let receipt = TeamReceipt {
        team_ref: team_ref.clone(),
        project,
        type_ref: crate::task_type::type_tree(vault, project)?.root(),
        pattern: TeamPattern::Solo,
        pattern_skill: None,
        axis: TeamAxis::Converge,
        models: Vec::new(),
        shape: TeamShape {
            width,
            roles: BTreeMap::from([("solo".to_owned(), width)]),
        },
        decided_by: DecidedBy::Leader {
            actor: EntityId::now(),
        },
        coverage: None,
        confessions: None,
        spend: None,
        spend_cap: None,
        elapsed_secs: 0,
        calls: None,
        outcome: Some(TeamOutcome {
            receipt: team_ref,
            anchor: Anchor::OwnerVerdict,
            success: true,
            at,
            critics: None,
        }),
        at,
    };
    crate::team::record_team_receipt(vault, &receipt)
}
