//! The owner's connector tool-consent doors: consenting a key's tools and the
//! consent view a settings screen reads.
//! Entry: `Vault::connector_consent_view`. The consent transaction stays in `tool_grant`.

use super::*;
use crate::connector_key::credential_binding::open_issuer_halt_for_connector_in_txn;

impl Vault {
    /// The owner consents to `consent.rows` of one catalog connector for one
    /// actor. All grants and keys commit together, or none do.
    pub fn consent_connector_tools(
        &self,
        owner: &AuthenticatedOwner,
        consent: &ConnectorToolConsent,
    ) -> Result<Vec<ConnectorToolGrant>> {
        let at = crate::unix_seconds_now();
        self.with_write_txn_grouped(|wtxn| {
            self.consent_connector_tools_in_txn(wtxn, owner, consent, at)
        })
    }

    /// What the owner is asked about one catalog connector, with `actor`'s
    /// (default: the owner's) live grant per tool. `None`: no such connector.
    pub fn connector_consent_view(
        &self,
        owner: &AuthenticatedOwner,
        connector: &str,
        actor: Option<EntityId>,
    ) -> Result<Option<ConnectorConsentView>> {
        let actor = match actor {
            Some(actor) => actor,
            None => owner.actor_for_read(self)?,
        };
        let principal_ref = actor.to_hex();
        let txn = self.store.env.read_txn()?;
        let Some((_, record)) = catalog_key_in_txn(&self.store, &txn, connector)? else {
            return Ok(None);
        };
        let issuer_halt = open_issuer_halt_for_connector_in_txn(&self.store, &txn, connector)?;
        let ready = admitted_catalog_in_txn(self, &txn, connector).is_ok();
        let slate = match record.slate_ref {
            Some(id) => read_connector_slate_in_txn(self, &txn, id)?,
            None => None,
        };
        let server = record
            .catalog
            .as_ref()
            .and_then(|catalog| canonical_scoped_server_segment(&catalog.name));
        let floor =
            crate::gate::resolve_policy_manifest(&self.store, &txn)?.read_frontier_hash()?;
        let mut live = Vec::new();
        for id in standing_outbound_grant_ids_for_principal(&self.store, &txn, &principal_ref)? {
            let Some(grant) = standing_outbound_grant_in_txn(&self.store, &txn, &id)? else {
                continue;
            };
            if grant.principal_ref != principal_ref || !grant.is_active_under_policy(&floor) {
                continue;
            }
            if let Some(scope) = grant.scope.scoped_mcp_grant()
                && server.as_deref() == Some(scope.server)
            {
                live.push((scope.tool.to_owned(), id, scope.data_class_ceiling));
            }
        }
        let rows = slate
            .iter()
            .flat_map(|slate| slate.manifest().iter().map(move |tool| (slate, tool)))
            .map(|(slate, tool)| {
                let grant = live.iter().find(|(name, ..)| *name == tool.name);
                ConnectorConsentRowView {
                    tool: tool.name.clone(),
                    data_class: tool.row_data_class(),
                    setting: slate.tool_setting(&tool.name),
                    header_parameters: tool.header_parameters.clone(),
                    destroys: tool.destroys,
                    grant_id: grant.map(|(_, id, _)| id.to_hex()),
                    grant_ceiling: grant.map(|(.., ceiling)| *ceiling),
                }
            })
            .collect();
        let elicitation = slate
            .as_ref()
            .and_then(ConnectorGrantSlate::elicitation_row)
            .map(SlateRow::effective_disposition);
        Ok(Some(ConnectorConsentView {
            connector: record.connector,
            actor: principal_ref,
            status: record.status.as_str().to_owned(),
            issuer_halt,
            protocol_revision: record.protocol_revision,
            ready,
            rows,
            elicitation,
        }))
    }
}
