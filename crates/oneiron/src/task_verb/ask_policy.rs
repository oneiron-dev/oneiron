//! Ask policy snapshot chosen at admission from trusted manifest rows.
use super::{TaskAskSpec, TaskAskSurface};
use crate::{EntityId, Result, Vault};

fn surface(policy: TaskAskSurface) -> crate::gate::AskPolicySurface {
    match policy {
        TaskAskSurface::Card => crate::gate::AskPolicySurface::Card,
        TaskAskSurface::None => crate::gate::AskPolicySurface::None,
    }
}
fn from_policy(policy: crate::gate::AskPolicySurface) -> TaskAskSurface {
    match policy {
        crate::gate::AskPolicySurface::Card => TaskAskSurface::Card,
        crate::gate::AskPolicySurface::None => TaskAskSurface::None,
    }
}

pub(super) fn confirmation_surface(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &TaskAskSpec,
    holders: &[EntityId],
) -> Result<TaskAskSurface> {
    if !spec.what.commitment {
        return Ok(spec.on_disagree.surface);
    }
    let resolved = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    let policy = resolved
        .ask_operational_policy()
        .ok_or_else(super::ask_record::invalid)?;
    let class_surface = spec
        .class
        .as_ref()
        .and_then(|class| class.soft_confirm_surface)
        .map(surface);
    let mut selected = TaskAskSurface::None;
    for holder in holders {
        let surface = from_policy(
            policy
                .surface_for(*holder, class_surface)
                .ok_or_else(super::ask_record::invalid)?,
        );
        if surface == TaskAskSurface::Card {
            selected = surface;
        }
    }
    Ok(selected)
}
