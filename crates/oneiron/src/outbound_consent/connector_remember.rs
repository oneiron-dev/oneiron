//! Native project and credential-lineage context for a connector call.

use crate::connector_key::ConnectorToolRememberContext;
use crate::memory::Memory;

/// Optional remembered consent never invents a project or credential. If its
/// context cannot be read, the call keeps its ordinary per-call consent path.
pub(super) fn capture(memory: &Memory<'_>) -> Option<ConnectorToolRememberContext> {
    let vault = memory.vault();
    let project = match memory.code_consent_site() {
        Some(site) => vault.browser_run_project(site.run_id).ok()?,
        None => None,
    };
    let lineage = memory.invocation_slip().and_then(|witness| {
        let txn = vault.store.env.read_txn().ok()?;
        let credential = vault.invocation_slip_in_txn(&txn, witness).ok()?;
        vault
            .slip_lineage_in_txn(&txn, &credential)
            .ok()?
            .last()
            .copied()
    });
    Some(ConnectorToolRememberContext {
        connection: None,
        project,
        lineage,
    })
}
