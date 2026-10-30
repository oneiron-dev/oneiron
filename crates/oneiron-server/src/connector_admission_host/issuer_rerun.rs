//! FIX 9304: the re-run an accepted issuer revision starts. The owner's
//! accept lifts the hold at once; this only refreshes the rows that depended
//! on the old issuer afterwards. It adds no hold, flips no key status, and a
//! failure never reverts the accept.
//!
//! Every dependent of one binding is its catalog connector's key or a
//! per-grant key derived from it, so the connector is listed, screened and
//! qualified once, through the credential door, at its installed endpoint
//! and pinned revision, as `/refresh` and `/qualify` reach it. The suite
//! runs with the kit the owner's last qualify of the catalog key used; with
//! none kept, only discovery and screening run, and the record says so.
//! Each dependent's outcome goes on its own key's audit, a named row the
//! connector no longer lists failing on its own; a failure is logged too.

use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::connector_key::qualification::qualify_connector;
use oneiron::connector_key::{
    ConnectorCredentialBinding, ConnectorIssuerRerunOutcome as Outcome,
    ConnectorIssuerRerunStage as Stage, ConnectorKeyStatus, ELICITATION_ROW_KEY,
};

use super::{HttpQualificationConnector, ListedTool, client, discover, with_credential};
use crate::config::connectors::normalize_name;
use crate::server::SyncServer;

/// Re-runs discovery, screening and qualification for the dependents of the
/// binding `binding_ref`, whose issuer revision the owner accepted, and
/// records each dependent's outcome on its key's audit. A binding with no
/// dependents runs nothing. Run it on a blocking worker: it holds the
/// connector's HTTP exchanges.
pub(crate) fn rerun_issuer_dependents(server: &SyncServer, binding_ref: EntityId) {
    let vault = server.vault();
    let binding = match vault.connector_credential_binding(&binding_ref) {
        Ok(Some(binding)) => binding,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(%error, "issuer revision re-run: the binding could not be read");
            return;
        }
    };
    if binding.dependents.is_empty() {
        return;
    }
    let Some(rerun) = rerun_connector(server, &binding) else {
        return;
    };
    for dependent in &binding.dependents {
        let outcome = rerun.outcome_for(dependent.tool.as_deref());
        if let Outcome::Failed(stage) = outcome {
            tracing::warn!(
                connector = %binding.connector,
                key = %dependent.key_ref.to_hex(),
                ?stage,
                "issuer revision re-run failed; the accept stands"
            );
        }
        if let Err(error) = vault.record_connector_issuer_rerun(&dependent.key_ref, outcome) {
            tracing::warn!(%error, "issuer revision re-run outcome not recorded");
        }
    }
}

/// What one re-run of a binding's connector found.
struct Rerun {
    outcome: Outcome,
    /// The tools discovery listed; empty when it did not get that far.
    listed: BTreeSet<String>,
}

impl Rerun {
    const fn failed(stage: Stage) -> Self {
        Self {
            outcome: Outcome::Failed(stage),
            listed: BTreeSet::new(),
        }
    }

    /// The outcome for a dependent on `row` (`None`: every row its key
    /// calls): a named tool the connector no longer lists fails on its own.
    fn outcome_for(&self, row: Option<&str>) -> Outcome {
        match row {
            Some(tool)
                if tool != ELICITATION_ROW_KEY
                    && !matches!(self.outcome, Outcome::Failed(_))
                    && !self.listed.contains(tool) =>
            {
                Outcome::Failed(Stage::RowUnlisted)
            }
            _ => self.outcome,
        }
    }
}

/// Lists, screens and qualifies the binding's catalog connector once.
/// `None` when its catalog key is gone or revoked: nothing is left to
/// re-run.
fn rerun_connector(server: &SyncServer, binding: &ConnectorCredentialBinding) -> Option<Rerun> {
    let vault = server.vault();
    let catalog = match vault.get_connector_key(&binding.catalog_key) {
        Ok(Some(record)) if record.status != ConnectorKeyStatus::Revoked => record,
        Ok(_) => return None,
        Err(error) => {
            tracing::warn!(%error, "issuer revision re-run: the catalog key could not be read");
            return None;
        }
    };
    let name = binding.connector.as_str();
    let Some(endpoint) = server
        .config
        .connectors
        .iter()
        .find(|(section, _)| normalize_name(section) == name)
        .map(|(_, installed)| installed.endpoint.clone())
    else {
        return Some(Rerun::failed(Stage::NotInstalled));
    };
    let Some(revision) = catalog.protocol_revision.clone() else {
        return Some(Rerun::failed(Stage::Unpinned));
    };
    let kit = match vault.connector_qualification_kit(&binding.catalog_key) {
        Ok(kit) => kit,
        Err(error) => {
            tracing::warn!(%error, "issuer revision re-run: the qualification kit could not be read");
            return Some(Rerun::failed(Stage::Qualification));
        }
    };
    let ran = with_credential(vault, catalog.secret_ref.as_deref(), name, |auth| {
        let client = client().map_err(|_| Stage::Discovery)?;
        let discovery =
            discover(&client, &endpoint, auth, Some(&revision)).map_err(|_| Stage::Discovery)?;
        let screened: Vec<_> = discovery.tools.iter().map(ListedTool::screened).collect();
        if !matches!(vault.screen_connector_tools(&screened, name), Ok(None)) {
            return Err(Stage::Screening);
        }
        let listed = discovery.tools.into_iter().map(|tool| tool.name).collect();
        let Some(kit) = kit else {
            return Ok(Rerun {
                outcome: Outcome::ListedWithoutKit,
                listed,
            });
        };
        let connector = HttpQualificationConnector::new(
            &client,
            &endpoint,
            auth,
            &revision,
            &kit.effect_state_uri,
        );
        qualify_connector(&connector, &kit.plan_for_run(), &kit).map_err(|failure| {
            tracing::warn!(%failure, "issuer revision re-run: qualification failed");
            Stage::Qualification
        })?;
        Ok(Rerun {
            outcome: Outcome::Qualified,
            listed,
        })
    });
    Some(match ran {
        Ok(Ok(rerun)) => rerun,
        Ok(Err(stage)) => Rerun::failed(stage),
        Err(error) => {
            tracing::warn!(%error, "issuer revision re-run: the credential was not presented");
            Rerun::failed(Stage::Credential)
        }
    })
}
