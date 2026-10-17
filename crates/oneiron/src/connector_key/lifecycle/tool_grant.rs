//! The owner's consent to a catalog connector's tools (ONE-1794, OF-189).
//!
//! One owner act per connector. For each tool row the owner accepts, one
//! transaction writes one scoped-MCP standing grant and one per-grant
//! connector key `mcp:{server}:grant:{id}`. The grant is the authority: the
//! actor, server, tool, endpoint, payload ceiling and data classes. The key
//! carries the tool's admission, derived from the catalog key's own
//! qualification: a one-tool snapshot of the owner-stamped slate, pinned at
//! the catalog's revision, under a receipt naming the catalog's suite
//! report. The tool's setting stays the catalog slate's, read at call time.
//!
//! Consenting a tool again retires the actor's earlier grant and key for it.
//! Every change to the catalog key's status or admission reaches its derived
//! keys: suspension, a staged manifest or a protocol revision holds them;
//! a return to Active carries each whose tool is unchanged and still
//! allowed, and retires the rest; revoking or removing the catalog key
//! retires them all. No grant expires on a clock: canon replaces expiry
//! with the registry and the policy floor.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::outbound_consent::DataClass;
use crate::outbound_consent::tool_call::ToolGrantDataClass;
use crate::outbound_grant::{
    ScopedMcpGrantMintIntent, StandingOutboundGrantStatus,
    standing_outbound_grant_ids_for_principal, standing_outbound_grant_in_txn,
};
use crate::store::Store;
use crate::{EntityId, Vault};

use super::super::manifest_drift::{
    ConnectorManifestDrift, ConnectorToolSchema, ResolvedConnectorManifest,
};
use super::super::qualification::ConnectorQualificationReceipt;
use super::super::record::{
    ConnectorCharterBlock, ConnectorKeyRecord, ConnectorKeyStatus, PendingConnectorManifest,
    ScopedCapabilityProvenance, canonical_scoped_server_segment, normalize_connector_key,
};
use super::super::slate::{
    ConnectorGrantSlate, SlateDataClass, SlateDisposition, read_connector_slate_in_txn,
};
use super::super::txn::{
    CATALOG_NAME_INDEX, CONNECTOR_INDEX, append_connector_key_op_record, read_connector_key_in_txn,
    revoke_connector_key_in_txn, rewrite_connector_key_in_txn,
};

/// The component every connector-consent grant names as its origin.
pub const CONNECTOR_CONSENT_ORIGIN_COMPONENT_ID: &str = "connector_consent";
/// The owner act every connector-consent grant names.
pub const CONNECTOR_CONSENT_ORIGIN_ACTION_ID: &str = "connector.consent";
/// Why a per-grant key is suspended while its catalog connector is not
/// Active, or while the catalog holds a staged change to the key's tool.
/// The catalog's return lifts exactly this hold; nothing else does.
pub(in crate::connector_key) const CATALOG_HOLD_REASON: &str = "held by its catalog connector";

/// One tool row the owner accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorToolConsentRow {
    pub tool: String,
    /// The most sensitive payload the grant lets through without an ask.
    pub data_class_ceiling: DataClass,
    /// The owner also lets the tool's header parameters reach the wire.
    pub headers: bool,
}

/// Whose calls a connector consent covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorConsentTarget {
    /// The owner's own actor.
    Owner,
    /// One named actor: an agent, a facade credential, a connector actor.
    Actor(EntityId),
    /// The actor a held call runs as, read from its pending row.
    HeldCall(EntityId),
}

/// The owner's consent to some of one catalog connector's tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorToolConsent {
    /// The catalog connector's name.
    pub connector: String,
    pub target: ConnectorConsentTarget,
    /// The resolved endpoint the owner was shown: the one the host installed.
    pub endpoint: String,
    pub rows: Vec<ConnectorToolConsentRow>,
}

/// One tool's grant and the per-grant key that governs its calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectorToolGrant {
    pub tool: String,
    pub grant_id: String,
    pub key_id: String,
    /// `mcp:{server}:grant:{grant_id}`.
    pub key_connector: String,
}

/// One tool row as the owner sees it before consenting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectorConsentRowView {
    pub tool: String,
    pub data_class: SlateDataClass,
    pub setting: SlateDisposition,
    pub header_parameters: Vec<String>,
    pub destroys: bool,
    /// The actor's live grant for this tool, with its ceiling.
    pub grant_id: Option<String>,
    pub grant_ceiling: Option<DataClass>,
}

/// One catalog connector's consent view for one actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectorConsentView {
    pub connector: String,
    pub actor: String,
    pub status: &'static str,
    pub protocol_revision: Option<String>,
    /// Active, qualified and owner-stamped: a consent can be written now.
    pub ready: bool,
    pub rows: Vec<ConnectorConsentRowView>,
}

/// A catalog connector a consent can derive from.
struct AdmittedCatalog {
    server: String,
    revision: String,
    report_hash: String,
    slate: ConnectorGrantSlate,
}

impl Vault {
    /// The owner consents to `consent.rows` of one catalog connector for one
    /// actor. All grants and keys commit together, or none do.
    pub fn consent_connector_tools(
        &self,
        owner: &AuthenticatedOwner,
        consent: &ConnectorToolConsent,
    ) -> Result<Vec<ConnectorToolGrant>> {
        let mut seen = BTreeSet::new();
        if consent.rows.is_empty() || !consent.rows.iter().all(|row| seen.insert(&row.tool)) {
            return Err(invalid("name each tool once, and at least one"));
        }
        if !consent
            .rows
            .iter()
            .all(|row| row.data_class_ceiling.is_grantable())
        {
            return Err(invalid("a ceiling is public, personal or secret"));
        }
        let at = crate::unix_seconds_now();
        self.with_write_txn_grouped(|wtxn| {
            let owner_actor = owner.revalidate_in_txn(self, wtxn)?;
            let actor = match consent.target {
                ConnectorConsentTarget::Owner => owner_actor,
                ConnectorConsentTarget::Actor(actor) => actor,
                ConnectorConsentTarget::HeldCall(call_ref) => {
                    let (principal, name, _) = crate::outbound_consent::held_connector_call_in_txn(
                        &self.store,
                        wtxn,
                        &call_ref,
                    )?
                    .ok_or_else(|| invalid("no held call by that ref"))?;
                    if normalize_connector_key(&name) != normalize_connector_key(&consent.connector)
                    {
                        return Err(invalid("the held call names another connector"));
                    }
                    EntityId::from_hex(&principal)?
                }
            };
            let principal_ref = actor.to_hex();
            let admitted = admitted_catalog_in_txn(self, wtxn, &consent.connector)?;
            let mut granted = Vec::with_capacity(consent.rows.len());
            for row in &consent.rows {
                if !admitted
                    .slate
                    .row(&row.tool)
                    .is_some_and(|slate_row| slate_row.enabled())
                {
                    return Err(invalid("the slate allows no such tool"));
                }
                let manifest = tool_snapshot(&admitted.slate, &row.tool)?;
                self.retire_actor_tool_grants_in_txn(
                    wtxn,
                    &principal_ref,
                    &admitted.server,
                    &row.tool,
                    at,
                )?;
                let grant_id = EntityId::now();
                let mut tool_data_classes = vec![ToolGrantDataClass::Arguments];
                if row.headers {
                    tool_data_classes.push(ToolGrantDataClass::XMcpHeader);
                }
                self.mint_scoped_mcp_outbound_grant_in_txn(
                    wtxn,
                    &grant_id,
                    &ScopedMcpGrantMintIntent {
                        principal_ref: principal_ref.clone(),
                        origin_component_id: CONNECTOR_CONSENT_ORIGIN_COMPONENT_ID.to_owned(),
                        origin_action_id: CONNECTOR_CONSENT_ORIGIN_ACTION_ID.to_owned(),
                        origin_receipt_ref: None,
                        server: admitted.server.clone(),
                        tool: row.tool.clone(),
                        data_class_ceiling: row.data_class_ceiling,
                        tool_data_classes,
                        endpoint_allowlist: vec![consent.endpoint.clone()],
                    },
                    at,
                )?;
                let capability = ScopedCapabilityProvenance::mint(&admitted.server, &grant_id)
                    .ok_or_else(|| invalid("the connector name has no scoped identity"))?;
                // The grant exists in this transaction, so the per-grant key
                // registers Pending; the derived admission then activates it.
                let key_id = EntityId::now();
                let pending = ConnectorKeyRecord {
                    status: ConnectorKeyStatus::Pending,
                    ..ConnectorKeyRecord::active(capability.connector(), None, Vec::new(), at)
                };
                self.register_connector_key_in_txn(wtxn, &key_id, &pending)?;
                let active = ConnectorKeyRecord {
                    status: ConnectorKeyStatus::Active,
                    status_changed_at: Some(at),
                    ..derived_admission(pending, manifest, &admitted, at)?
                };
                active.validate()?;
                rewrite_connector_key_in_txn(&self.store, wtxn, &key_id, &active)?;
                append_op(
                    &self.store,
                    wtxn,
                    &key_id,
                    "gate.connector_key.consent",
                    &active,
                    at,
                )?;
                granted.push(ConnectorToolGrant {
                    tool: row.tool.clone(),
                    grant_id: grant_id.to_hex(),
                    key_id: key_id.to_hex(),
                    key_connector: active.connector,
                });
            }
            Ok(granted)
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
        Ok(Some(ConnectorConsentView {
            connector: record.connector,
            actor: principal_ref,
            status: record.status.as_str(),
            protocol_revision: record.protocol_revision,
            ready,
            rows,
        }))
    }

    /// Brings every per-grant key of a catalog key in line with the
    /// catalog, after any change to its status or admission:
    /// - a revoked or removed catalog retires them all, with their grants;
    /// - a catalog that is not Active holds each live one: Suspended, for
    ///   [`CATALOG_HOLD_REASON`];
    /// - an Active catalog re-derives each. A tool still allowed on the
    ///   owner-stamped slate, with the schema the key holds and that the
    ///   catalog's approved manifest still pins, carries to the catalog's
    ///   revision and report, and its hold lifts. A staged manifest change
    ///   to the tool is mirrored onto the key, whose calls then confirm
    ///   first. Any other is retired with its grant.
    pub(in crate::connector_key) fn sync_derived_keys_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        catalog: &ConnectorKeyRecord,
        at: u64,
    ) -> Result<()> {
        let Some(server) = catalog_server(catalog) else {
            return Ok(());
        };
        let derived = derived_keys_in_txn(&self.store, wtxn, &server)?;
        if derived.is_empty() {
            return Ok(());
        }
        // A catalog that qualified without a holding owner stamp carries
        // nothing: every derived tool goes back to the owner.
        let admitted = (catalog.status == ConnectorKeyStatus::Active)
            .then(|| admitted_from_record(self, wtxn, catalog, server.clone()).ok())
            .flatten();
        for (key_id, record) in derived {
            if record.status == ConnectorKeyStatus::Revoked {
                continue;
            }
            let Some(capability) =
                ScopedCapabilityProvenance::parse_owner_capability_key(&record.connector)
            else {
                continue;
            };
            match catalog.status {
                ConnectorKeyStatus::Active => {}
                ConnectorKeyStatus::Revoked => {
                    self.retire_tool_grant_in_txn(wtxn, &capability.grant_id(), &server, at)?;
                    continue;
                }
                ConnectorKeyStatus::Pending | ConnectorKeyStatus::Suspended => {
                    if record.status == ConnectorKeyStatus::Active {
                        let held = held(record, at);
                        rewrite_connector_key_in_txn(&self.store, wtxn, &key_id, &held)?;
                        append_op(
                            &self.store,
                            wtxn,
                            &key_id,
                            "gate.connector_key.suspend",
                            &held,
                            at,
                        )?;
                    }
                    continue;
                }
            }
            let carried = admitted.as_ref().and_then(|admitted| {
                let snapshot = record.retained_manifest.as_ref()?;
                let entry = snapshot.tools().first()?;
                (admitted
                    .slate
                    .row(&entry.name)
                    .is_some_and(|row| row.enabled())
                    && tool_snapshot(&admitted.slate, &entry.name).ok().as_ref() == Some(snapshot)
                    && approved_manifest_pins(catalog, &admitted.slate, &entry.name))
                .then(|| (admitted, entry.name.clone()))
            });
            let Some((admitted, tool)) = carried else {
                self.retire_tool_grant_in_txn(wtxn, &capability.grant_id(), &server, at)?;
                continue;
            };
            let current = record.protocol_revision.as_deref() == Some(admitted.revision.as_str())
                && record
                    .qualification_receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.report_hash == admitted.report_hash);
            let staged = catalog.tool_requires_confirmation(&tool);
            let was_held = is_held(&record);
            let status = record.status;
            let mut next = if current {
                record
            } else {
                derived_admission(record, tool_snapshot(&admitted.slate, &tool)?, admitted, at)?
            };
            // A staged change to the key's tool is mirrored onto the key, so
            // its calls confirm first as the catalog's own do; the key is
            // held only when the catalog stages nothing to mirror.
            let mirrored = staged
                .then(|| staged_tool_change(catalog, &tool, next.retained_manifest.as_ref()))
                .flatten();
            let op = match (staged, status) {
                (true, _)
                    if mirrored.is_some() && (status == ConnectorKeyStatus::Active || was_held) =>
                {
                    if current
                        && status == ConnectorKeyStatus::Active
                        && next.pending_manifest == mirrored
                    {
                        continue;
                    }
                    next = ConnectorKeyRecord {
                        status: ConnectorKeyStatus::Active,
                        status_changed_at: if was_held {
                            Some(at)
                        } else {
                            next.status_changed_at
                        },
                        suspended_reason: None,
                        pending_manifest: mirrored,
                        ..next
                    };
                    "gate.connector_key.manifest_stage"
                }
                (true, ConnectorKeyStatus::Active) => {
                    next = held(next, at);
                    "gate.connector_key.suspend"
                }
                (false, ConnectorKeyStatus::Suspended) if was_held => {
                    next = ConnectorKeyRecord {
                        status: ConnectorKeyStatus::Active,
                        status_changed_at: Some(at),
                        suspended_reason: None,
                        pending_manifest: None,
                        ..next
                    };
                    if current {
                        "gate.connector_key.resume"
                    } else {
                        "gate.connector_key.carry"
                    }
                }
                (false, _) if next.pending_manifest.is_some() => {
                    next.pending_manifest = None;
                    "gate.connector_key.manifest_revert"
                }
                _ if current => continue,
                _ => "gate.connector_key.carry",
            };
            next.validate()?;
            rewrite_connector_key_in_txn(&self.store, wtxn, &key_id, &next)?;
            append_op(&self.store, wtxn, &key_id, op, &next, at)?;
        }
        Ok(())
    }

    /// Retires the actor's live grants for one server and tool, so the call
    /// driver's first-match scan never picks an older consent.
    fn retire_actor_tool_grants_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        principal_ref: &str,
        server: &str,
        tool: &str,
        at: u64,
    ) -> Result<()> {
        for id in standing_outbound_grant_ids_for_principal(&self.store, wtxn, principal_ref)? {
            let Some(grant) = standing_outbound_grant_in_txn(&self.store, wtxn, &id)? else {
                continue;
            };
            if grant.principal_ref == principal_ref
                && grant.status == StandingOutboundGrantStatus::Active
                && grant
                    .scope
                    .scoped_mcp_grant()
                    .is_some_and(|scope| scope.server == server && scope.tool == tool)
            {
                self.retire_tool_grant_in_txn(wtxn, &id, server, at)?;
            }
        }
        Ok(())
    }

    /// Revokes one scoped grant and every live per-grant key minted for it.
    fn retire_tool_grant_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        grant_id: &EntityId,
        server: &str,
        at: u64,
    ) -> Result<()> {
        if standing_outbound_grant_in_txn(&self.store, wtxn, grant_id)?
            .is_some_and(|grant| grant.status == StandingOutboundGrantStatus::Active)
        {
            self.revoke_standing_outbound_grant_in_txn(wtxn, grant_id, at)?;
        }
        let Some(capability) = ScopedCapabilityProvenance::mint(server, grant_id) else {
            return Ok(());
        };
        let mut prefix = capability.connector().as_bytes().to_vec();
        prefix.push(0);
        for (key_id, record) in keys_under_in_txn(&self.store, wtxn, &prefix)? {
            if record.status != ConnectorKeyStatus::Revoked {
                let revoked = revoke_connector_key_in_txn(&self.store, wtxn, &key_id, &record, at)?;
                append_op(
                    &self.store,
                    wtxn,
                    &key_id,
                    "gate.connector_key.revoke",
                    &revoked,
                    at,
                )?;
            }
        }
        Ok(())
    }
}

/// The catalog key a per-grant key derives from: the catalog key whose name
/// is the key's scoped server, with the ordinary channel (`mcp:{server}`)
/// the key's calls travel on. `None` for any other key. This only says
/// whose settings, charter and shared budgets a call also meets; the grant
/// and the Gate stay the authority.
pub(in crate::connector_key) fn derived_key_catalog_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &ConnectorKeyRecord,
) -> Result<Option<(EntityId, ConnectorKeyRecord, String)>> {
    if key.catalog.is_some() {
        return Ok(None);
    }
    let Some(capability) = ScopedCapabilityProvenance::parse_owner_capability_key(&key.connector)
    else {
        return Ok(None);
    };
    Ok(catalog_key_in_txn(store, txn, capability.server())?
        .filter(|(_, catalog)| catalog_server(catalog).as_deref() == Some(capability.server()))
        .map(|(id, catalog)| (id, catalog, capability.ordinary_channel())))
}

/// The catalog slate a per-grant key derives from.
pub(in crate::connector_key) fn derived_key_catalog_slate_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &ConnectorKeyRecord,
) -> Result<Option<EntityId>> {
    Ok(derived_key_catalog_in_txn(store, txn, key)?.and_then(|(_, catalog, _)| catalog.slate_ref))
}

/// The charter of the catalog connector a per-grant key derives from. The
/// Gate and recovery read it beside the key's own, with the same matchers,
/// so a per-grant call meets the catalog's drift and never-list too.
pub(crate) fn catalog_charter_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &ConnectorKeyRecord,
) -> Result<Option<ConnectorCharterBlock>> {
    Ok(derived_key_catalog_in_txn(store, txn, key)?.and_then(|(_, catalog, _)| catalog.charter))
}

/// Whether a scoped call on `server` debits the `Sends` dimension: only when
/// the server's catalog entry is `CounterpartyComm`. ARCH-0054 gives the
/// Send class to counterparty communication alone and leaves scoped-MCP
/// calls unbudgeted by default, so an uncatalogued server debits no sends.
pub(crate) fn scoped_server_debits_sends_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    server: &str,
) -> Result<bool> {
    Ok(catalog_key_in_txn(store, txn, server)?
        .filter(|(_, catalog)| catalog_server(catalog).as_deref() == Some(server))
        .and_then(|(_, catalog)| catalog.catalog)
        .is_some_and(|entry| entry.call_class.debits_sends()))
}

/// Holds each Active per-grant key of a catalog key that is no longer
/// Active, inside the caller's transaction. The common suspend core calls
/// it, so a budget exhaust holds them as an owner suspend does; the
/// catalog's resume lifts the holds through `sync_derived_keys_in_txn`.
pub(in crate::connector_key) fn hold_derived_keys_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    catalog: &ConnectorKeyRecord,
    at: u64,
) -> Result<()> {
    if catalog.status == ConnectorKeyStatus::Active {
        return Ok(());
    }
    let Some(server) = catalog_server(catalog) else {
        return Ok(());
    };
    for (key_id, record) in derived_keys_in_txn(store, wtxn, &server)? {
        if record.status != ConnectorKeyStatus::Active
            || ScopedCapabilityProvenance::parse_owner_capability_key(&record.connector).is_none()
        {
            continue;
        }
        let held = held(record, at);
        rewrite_connector_key_in_txn(store, wtxn, &key_id, &held)?;
        append_op(
            store,
            wtxn,
            &key_id,
            "gate.connector_key.suspend",
            &held,
            at,
        )?;
    }
    Ok(())
}

/// The catalog key that a consent can derive from: Active, qualified at its
/// pinned revision, and bound to a slate whose owner stamp still holds.
fn admitted_catalog_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    connector: &str,
) -> Result<AdmittedCatalog> {
    let (_, record) = catalog_key_in_txn(&vault.store, txn, connector)?
        .ok_or_else(|| invalid("no catalog connector by that name"))?;
    if record.status != ConnectorKeyStatus::Active {
        return Err(invalid("the connector is not active"));
    }
    let server = catalog_server(&record)
        .ok_or_else(|| invalid("the connector name has no scoped identity"))?;
    admitted_from_record(vault, txn, &record, server)
}

fn admitted_from_record(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    record: &ConnectorKeyRecord,
    server: String,
) -> Result<AdmittedCatalog> {
    let (Some(slate_id), Some(revision), Some(receipt)) = (
        record.slate_ref,
        record.protocol_revision.clone(),
        record.qualification_receipt.as_ref(),
    ) else {
        return Err(invalid("the connector is not qualified"));
    };
    let slate = read_connector_slate_in_txn(vault, txn, slate_id)?
        .ok_or_else(|| invalid("the connector's slate is missing"))?;
    if slate.owner_actor().is_none()
        || !slate.stamp_holds()
        || record.slate_revision != Some(slate.revision())
    {
        return Err(invalid(
            "the connector's slate is not the owner-stamped one",
        ));
    }
    Ok(AdmittedCatalog {
        server,
        revision,
        report_hash: receipt.report_hash.clone(),
        slate,
    })
}

/// A per-grant key's admission, derived from the catalog's qualification:
/// the one-tool snapshot at the catalog's revision, under a receipt naming
/// the catalog's suite report, bound to this key's snapshot at `at`.
fn derived_admission(
    record: ConnectorKeyRecord,
    manifest: ResolvedConnectorManifest,
    admitted: &AdmittedCatalog,
    at: u64,
) -> Result<ConnectorKeyRecord> {
    let receipt = ConnectorQualificationReceipt::new(
        admitted.report_hash.clone(),
        admitted.revision.clone(),
        manifest.hash()?,
        at,
    )?;
    Ok(ConnectorKeyRecord {
        protocol_revision: Some(admitted.revision.clone()),
        qualification_receipt: Some(receipt),
        retained_manifest: Some(manifest),
        pending_manifest: None,
        ..record
    })
}

/// The catalog's staged change to one tool, mirrored onto that tool's
/// per-grant key: the key's own snapshot under the catalog's candidate,
/// marked changed for that tool alone, so the key's calls confirm first as
/// the catalog's do. `None` when the catalog stages no candidate, or one
/// that needs re-registration as a whole.
fn staged_tool_change(
    catalog: &ConnectorKeyRecord,
    tool: &str,
    snapshot: Option<&ResolvedConnectorManifest>,
) -> Option<PendingConnectorManifest> {
    let pending = catalog.pending_manifest.as_ref()?;
    if pending.drift.requires_reregistration {
        return None;
    }
    Some(PendingConnectorManifest {
        candidate_id: pending.candidate_id,
        manifest: snapshot?.clone(),
        protocol_revision: pending.protocol_revision.clone(),
        drift: ConnectorManifestDrift {
            kinds: pending.drift.kinds.clone(),
            affected_tools: BTreeSet::from([tool.to_owned()]),
            reconsent_tools: pending
                .drift
                .reconsent_tools
                .iter()
                .filter(|name| *name == tool)
                .cloned()
                .collect(),
            requires_reregistration: false,
        },
        qualification_report_hash: None,
    })
}

/// A per-grant key held while its catalog connector is not Active or holds
/// a staged change to the key's tool it cannot mirror.
fn held(record: ConnectorKeyRecord, at: u64) -> ConnectorKeyRecord {
    ConnectorKeyRecord {
        status: ConnectorKeyStatus::Suspended,
        status_changed_at: Some(at),
        suspended_reason: Some(CATALOG_HOLD_REASON.to_owned()),
        ..record
    }
}

/// The key is suspended by its catalog's hold, not on its own.
pub(in crate::connector_key) fn is_held(record: &ConnectorKeyRecord) -> bool {
    record.status == ConnectorKeyStatus::Suspended
        && record.suspended_reason.as_deref() == Some(CATALOG_HOLD_REASON)
}

/// The catalog's approved manifest, when it pins one, still lists the tool
/// with the resolved schema the stamped slate holds for it: the one both
/// were built from at admission.
fn approved_manifest_pins(
    catalog: &ConnectorKeyRecord,
    slate: &ConnectorGrantSlate,
    tool: &str,
) -> bool {
    let schema = slate
        .tool(tool)
        .and_then(|entry| entry.resolved_input_schema.as_ref());
    catalog.retained_manifest.as_ref().is_none_or(|approved| {
        approved
            .tools()
            .iter()
            .any(|entry| entry.name == tool && Some(&entry.input_schema) == schema)
    })
}

/// One tool of the stamped slate as a resolved one-tool manifest, the shape
/// the qualification suite admitted it in.
fn tool_snapshot(slate: &ConnectorGrantSlate, tool: &str) -> Result<ResolvedConnectorManifest> {
    let entry = slate
        .tool(tool)
        .ok_or_else(|| invalid("the slate allows no such tool"))?;
    let input_schema = entry
        .resolved_input_schema
        .clone()
        .ok_or_else(|| invalid("the tool's schema is unresolved"))?;
    ResolvedConnectorManifest::resolve(vec![ConnectorToolSchema {
        name: entry.name.clone(),
        permissions: BTreeSet::new(),
        triggers: entry.trigger.iter().cloned().collect(),
        input_schema,
    }])
}

fn catalog_key_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    name: &str,
) -> Result<Option<(EntityId, ConnectorKeyRecord)>> {
    let Some(id) = CATALOG_NAME_INDEX.get(store, txn, &normalize_connector_key(name))? else {
        return Ok(None);
    };
    let record = read_connector_key_in_txn(store, txn, &id)?
        .ok_or(Error::CorruptedIndex("connector catalog name index row"))?;
    Ok(record.catalog.is_some().then_some((id, record)))
}

fn catalog_server(record: &ConnectorKeyRecord) -> Option<String> {
    canonical_scoped_server_segment(&record.catalog.as_ref()?.name)
}

/// Every per-grant key on one scoped server.
fn derived_keys_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    server: &str,
) -> Result<Vec<(EntityId, ConnectorKeyRecord)>> {
    keys_under_in_txn(store, txn, format!("mcp:{server}:grant:").as_bytes())
}

fn keys_under_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    prefix: &[u8],
) -> Result<Vec<(EntityId, ConnectorKeyRecord)>> {
    CONNECTOR_INDEX
        .scan_from(store, txn, prefix)?
        .into_iter()
        .map(|(key, ())| {
            let record = read_connector_key_in_txn(store, txn, &key.id)?
                .ok_or(Error::CorruptedIndex("connector key index row"))?;
            Ok((key.id, record))
        })
        .collect()
}

fn append_op(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    op: &'static str,
    record: &ConnectorKeyRecord,
    at: u64,
) -> Result<()> {
    let policy = crate::gate::resolve_policy_manifest(store, &*wtxn)?;
    append_connector_key_op_record(
        store,
        wtxn,
        id,
        op,
        record,
        policy.read_frontier_hash()?,
        at,
    )
}

fn invalid(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("connector consent: {reason}"))
}
