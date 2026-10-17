//! `/v1/owner/connectors/register`, `/setup`, `/slate/accept` and
//! `/qualify`: the owner's first admission of a generic MCP catalog
//! connector (OF-189), up to the consent door.
//!
//! Register lists the tools at the endpoint `[connectors.<name>]`
//! installed, screens them, resolves their schemas, drafts the typed grant
//! slate and registers the key Pending. The owner reads it back and stamps
//! the slate, with any of the four settings per row. Qualify then stages
//! the resolved manifest under the ARCH-0028 probe suite, runs the suite
//! again to activate the key, and approves the exact candidate it staged.
//! Only then can `/v1/owner/connectors/consent` grant tools to an actor.
//! Each step is its own vault write, so a failed step keeps the earlier
//! ones and is retried by itself.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::connector_key::qualification::ConnectorQualificationReceipt;
use oneiron::connector_key::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorGrantSlate, ConnectorKeyRecord,
    ConnectorKeySpec, ConnectorKeyStatus, ConnectorQualificationError, ProbeManifestQualifier,
    SlateDisposition, SlateOwnerOverride, SlateRow, SlateToolManifest,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::{EntityId, Vault};
use reqwest::header::HeaderValue;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params, unix_seconds_now};
use crate::auth::CoreAuth;
use crate::config::connectors::normalize_name;
use crate::connector_admission_host::{self as host, QualificationKit, ToolClass};
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

/// A generic MCP catalog's entry-wide class: scoped-MCP tool calls,
/// unbudgeted for sends (ARCH-0054).
const CATALOG_CALL_CLASS: ConnectorCallClass = ConnectorCallClass::ScopedMcp;

/// A new stamp on an admitted connector would move its slate past the
/// revision the key accepted, and no door requalifies an admitted key yet.
const ADMITTED_SLATE_REFUSAL: &str = "the connector is already admitted; its settings change \
     through a refresh door this host does not have yet";

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/connectors/register", post(register))
        .route("/connectors/setup", get(setup))
        .route("/connectors/slate/accept", post(accept))
        .route("/connectors/qualify", post(qualify))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterRequest {
    /// The catalog name, as `[connectors.<name>]` installs it.
    connector: String,
    /// One line for the catalog.
    summary: String,
    /// The custody record holding the connector's credential, by name.
    #[serde(default)]
    secret_ref: Option<String>,
    /// Each tool's data class and spend, by tool name. A tool left out is
    /// personal and spends nothing.
    #[serde(default)]
    tools: BTreeMap<String, ToolClass>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupQuery {
    connector: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptRequest {
    connector: String,
    /// The slate revision the owner reviewed.
    revision: u64,
    /// The owner's setting per row: `always_allow`, `auto`, `always_ask` or
    /// `never_allow`. A row left out keeps its drafted setting.
    #[serde(default)]
    rows: BTreeMap<String, SlateDisposition>,
    /// The facets the grant reaches, as 32 hex each; none: every facet.
    #[serde(default)]
    facets: Option<Vec<String>>,
    /// Every row `always ask`; a `never allow` row stays removed.
    #[serde(default)]
    all_manual: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualifyRequest {
    connector: String,
    kit: QualificationKit,
}

#[derive(Debug, Serialize)]
struct Registered {
    connector: String,
    endpoint: String,
    key: String,
    status: &'static str,
    protocol_revision: Option<String>,
    slate: SlateView,
}

#[derive(Debug, Serialize)]
struct SlateView {
    id: String,
    revision: u64,
    /// An owner stamp whose manifest and grant still hold.
    stamped: bool,
    facet_limit: Option<Vec<String>>,
    manifest: Vec<SlateToolManifest>,
    rows: Vec<SlateRow>,
}

impl SlateView {
    fn new(id: EntityId, slate: &ConnectorGrantSlate) -> Self {
        Self {
            id: id.to_hex(),
            revision: slate.revision(),
            stamped: slate.owner_actor().is_some() && slate.stamp_holds(),
            facet_limit: slate
                .facet_limit()
                .map(|facets| facets.iter().map(EntityId::to_hex).collect()),
            manifest: slate.manifest().to_vec(),
            rows: slate.rows().to_vec(),
        }
    }
}

#[derive(Debug, Serialize)]
struct Setup {
    connector: String,
    summary: String,
    /// The endpoint this host installed; none: no transport.
    endpoint: Option<String>,
    key: KeyView,
    slate: Option<SlateView>,
}

#[derive(Debug, Serialize)]
struct KeyView {
    id: String,
    status: &'static str,
    secret_ref: Option<String>,
    protocol_revision: Option<String>,
    /// The slate revision the last qualification accepted.
    accepted_slate_revision: Option<u64>,
    consent_required: bool,
    qualification: Option<ConnectorQualificationReceipt>,
    /// The approved resolved manifest's hash, as 64 hex.
    manifest_hash: Option<String>,
    pending_manifest: Option<PendingView>,
}

impl KeyView {
    fn new(id: EntityId, record: ConnectorKeyRecord) -> OwnerResult<Self> {
        let manifest_hash = record
            .retained_manifest
            .as_ref()
            .map(|manifest| manifest.hash().map(|hash| hex(&hash)))
            .transpose()?;
        Ok(Self {
            id: id.to_hex(),
            status: record.status.as_str(),
            secret_ref: record.secret_ref,
            protocol_revision: record.protocol_revision,
            accepted_slate_revision: record.slate_revision,
            consent_required: record.consent_required,
            qualification: record.qualification_receipt,
            manifest_hash,
            pending_manifest: record.pending_manifest.map(|pending| PendingView {
                candidate: hex(&pending.candidate_id),
                protocol_revision: pending.protocol_revision,
                report_hash: pending.qualification_report_hash,
            }),
        })
    }
}

#[derive(Debug, Serialize)]
struct PendingView {
    candidate: String,
    protocol_revision: String,
    report_hash: Option<String>,
}

fn hex(bytes: &[u8; 32]) -> String {
    blake3::Hash::from(*bytes).to_hex().to_string()
}

/// An engine refusal as the owner reads it: a fixed sentence about the
/// request is a bad request, a concurrent change asks for a fresh read.
fn engine(error: oneiron::Error) -> OwnerError {
    match error {
        oneiron::Error::InvalidConfig(reason) => OwnerError::Invalid(reason),
        oneiron::Error::ConcurrentWrite(_) => {
            OwnerError::Changed("the connector changed since it was read; read it again".to_owned())
        }
        error if matches!(error.kind(), oneiron::ErrorKind::InvalidConnectorKeyBody) => {
            OwnerError::Invalid(error.to_string())
        }
        error => error.into(),
    }
}

/// The endpoint this host installed under the connector's name.
fn installed_endpoint(server: &SyncServer, name: &str) -> Option<String> {
    server
        .config
        .connectors
        .iter()
        .find(|(section, _)| normalize_name(section) == name)
        .map(|(_, installed)| installed.endpoint.clone())
}

/// The connector's name as the engine stores it, and its installed endpoint.
fn installed(server: &SyncServer, connector: &str) -> OwnerResult<(String, String)> {
    let name = normalize_name(connector);
    let endpoint = installed_endpoint(server, &name).ok_or_else(|| {
        OwnerError::Invalid("this host installed no transport for the connector".to_owned())
    })?;
    Ok((name, endpoint))
}

/// The catalog key registered under a name.
struct Catalog {
    key: EntityId,
    record: ConnectorKeyRecord,
    summary: String,
}

fn catalog(vault: &Vault, name: &str) -> OwnerResult<Catalog> {
    let description = vault
        .describe_connector(name)?
        .ok_or_else(|| OwnerError::NotFound("connector", name.to_owned()))?;
    let record = vault
        .get_connector_key(&description.key_ref)?
        .ok_or_else(|| OwnerError::NotFound("connector key", description.key_ref.to_hex()))?;
    Ok(Catalog {
        key: description.key_ref,
        record,
        summary: description.entry.summary,
    })
}

fn slate_of(
    vault: &Vault,
    record: &ConnectorKeyRecord,
) -> OwnerResult<(EntityId, ConnectorGrantSlate)> {
    let id = record
        .slate_ref
        .ok_or_else(|| OwnerError::Invalid("the connector has no grant slate".to_owned()))?;
    let slate = vault
        .connector_slate(id)?
        .ok_or_else(|| OwnerError::NotFound("grant slate", id.to_hex()))?;
    Ok((id, slate))
}

fn unresolvable() -> OwnerError {
    OwnerError::Invalid(
        "the connector's input schemas use a form this host cannot resolve".to_owned(),
    )
}

/// `POST /v1/owner/connectors/register`: lists the connector's tools at its
/// installed endpoint, screens and resolves them, drafts the grant slate
/// and registers the key Pending at the negotiated revision.
async fn register(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<RegisterRequest>, JsonRejection>,
) -> OwnerReply<Registered> {
    let _owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reply = blocking(move || register_connector(&server, request)).await?;
    Ok(Json(reply))
}

fn register_connector(server: &SyncServer, request: RegisterRequest) -> OwnerResult<Registered> {
    let vault = server.vault();
    let (name, endpoint) = installed(server, &request.connector)?;
    if vault.describe_connector(&name)?.is_some() {
        return Err(OwnerError::Invalid(
            "a connector is already registered under that name".to_owned(),
        ));
    }
    let discovery = host::with_credential(vault, request.secret_ref.as_deref(), &name, |auth| {
        host::discover(&host::client()?, &endpoint, auth, None)
    })
    .map_err(engine)?
    .map_err(engine)?;
    if let Some(unknown) = request
        .tools
        .keys()
        .find(|tool| !discovery.tools.iter().any(|listed| &listed.name == *tool))
    {
        return Err(OwnerError::Invalid(format!(
            "the connector lists no tool {unknown}"
        )));
    }
    let screened: Vec<_> = discovery
        .tools
        .iter()
        .map(host::ListedTool::screened)
        .collect();
    if let Some(reason) = vault.screen_connector_tools(&screened, &name)? {
        return Err(OwnerError::Refused(format!(
            "the connector's tools failed screening: {reason}"
        )));
    }
    let resolved = host::resolve(&discovery.tools).map_err(|_| unresolvable())?;
    let manifest = host::slate_manifest(&resolved, &discovery.tools, &request.tools);
    // No model drafter is bound on this host: the rule rung drafts every
    // row from the owner's past rulings.
    let slate_id = vault
        .draft_connector_admission_slate(&manifest, None)
        .map_err(engine)?;
    let now = unix_seconds_now();
    let (key, record) = vault
        .register_connector(
            ConnectorCatalogEntry {
                name: name.clone(),
                connector: name.clone(),
                summary: request.summary,
                verbs: manifest.iter().map(|tool| tool.name.clone()).collect(),
                call_class: CATALOG_CALL_CLASS,
                registered_at: now,
            },
            ConnectorKeySpec {
                connector: name.clone(),
                actor_entity_ref: None,
                budgets: Vec::new(),
                secret_ref: request.secret_ref,
                slate_ref: Some(slate_id),
                protocol_revision: Some(discovery.revision),
            },
            now,
        )
        .map_err(engine)?;
    let (_, slate) = slate_of(vault, &record)?;
    Ok(Registered {
        connector: name,
        endpoint,
        key: key.to_hex(),
        status: record.status.as_str(),
        protocol_revision: record.protocol_revision,
        slate: SlateView::new(slate_id, &slate),
    })
}

/// `GET /v1/owner/connectors/setup?connector=`: the connector's key, its
/// admission state and its grant slate, for a resumed setup.
async fn setup(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<SetupQuery>, QueryRejection>,
) -> OwnerReply<Setup> {
    let _owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let reply = blocking(move || -> OwnerResult<Setup> {
        let name = normalize_name(&query.connector);
        let catalog = catalog(server.vault(), &name)?;
        let slate = match catalog.record.slate_ref {
            Some(id) => server
                .vault()
                .connector_slate(id)?
                .map(|slate| SlateView::new(id, &slate)),
            None => None,
        };
        Ok(Setup {
            endpoint: installed_endpoint(&server, &name),
            connector: name,
            summary: catalog.summary,
            key: KeyView::new(catalog.key, catalog.record)?,
            slate,
        })
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/connectors/slate/accept`: the owner's one stamp on the
/// pending connector's slate, at the revision reviewed. It activates
/// nothing; qualification does.
async fn accept(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<AcceptRequest>, JsonRejection>,
) -> OwnerReply<SlateView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reply = blocking(move || accept_slate(server.vault(), &owner, request)).await?;
    Ok(Json(reply))
}

fn accept_slate(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    request: AcceptRequest,
) -> OwnerResult<SlateView> {
    let catalog = catalog(vault, &normalize_name(&request.connector))?;
    if catalog.record.status != ConnectorKeyStatus::Pending {
        return Err(OwnerError::Refused(ADMITTED_SLATE_REFUSAL.to_owned()));
    }
    let (id, _) = slate_of(vault, &catalog.record)?;
    let slate = if request.all_manual {
        if !request.rows.is_empty() || request.facets.is_some() {
            return Err(OwnerError::Invalid(
                "an all-manual accept takes no rows or facets".to_owned(),
            ));
        }
        vault.accept_connector_slate_all_manual(owner, id, request.revision)
    } else {
        let overrides = request
            .rows
            .into_iter()
            .map(|(tool, disposition)| (tool, SlateOwnerOverride { disposition }))
            .collect();
        let facets = request
            .facets
            .map(|facets| {
                facets
                    .iter()
                    .map(|facet| entity_id("facet", facet))
                    .collect::<OwnerResult<BTreeSet<_>>>()
            })
            .transpose()?;
        vault.stamp_connector_slate(owner, id, request.revision, &overrides, facets)
    }
    .map_err(engine)?;
    Ok(SlateView::new(id, &slate))
}

/// `POST /v1/owner/connectors/qualify`: runs the probe suite through the
/// installed endpoint with the owner's kit, activates the key, and
/// approves the exact manifest the suite ran on. A key the suite already
/// activated only has its staged manifest approved.
async fn qualify(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<QualifyRequest>, JsonRejection>,
) -> OwnerReply<KeyView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let reply = blocking(move || qualify_connector(&server, &owner, &request)).await?;
    Ok(Json(reply))
}

fn qualify_connector(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: &QualifyRequest,
) -> OwnerResult<KeyView> {
    let vault = server.vault();
    let (name, endpoint) = installed(server, &request.connector)?;
    let catalog = catalog(vault, &name)?;
    let revision =
        catalog.record.protocol_revision.clone().ok_or_else(|| {
            OwnerError::Invalid("the connector pins no protocol revision".to_owned())
        })?;
    match catalog.record.status {
        ConnectorKeyStatus::Pending => {
            host::with_credential(vault, catalog.record.secret_ref.as_deref(), &name, |auth| {
                probe(vault, &catalog, &endpoint, &revision, auth, &request.kit)
            })
            .map_err(engine)??;
        }
        ConnectorKeyStatus::Active if catalog.record.retained_manifest.is_none() => {}
        _ => {
            return Err(OwnerError::Refused(
                "the connector is already admitted".to_owned(),
            ));
        }
    }
    let approved = approve(vault, owner, catalog.key)?;
    KeyView::new(catalog.key, approved)
}

/// Stages the resolved manifest under the suite, then runs the suite again
/// to activate the key: two full runs on the one surface the owner stamped.
fn probe(
    vault: &Vault,
    catalog: &Catalog,
    endpoint: &str,
    revision: &str,
    auth: Option<&HeaderValue>,
    kit: &QualificationKit,
) -> OwnerResult<()> {
    let client = host::client().map_err(engine)?;
    let discovery = host::discover(&client, endpoint, auth, Some(revision)).map_err(engine)?;
    let (_, slate) = slate_of(vault, &catalog.record)?;
    let resolved = host::resolve(&discovery.tools).map_err(|_| unresolvable())?;
    let classes = slate
        .manifest()
        .iter()
        .map(|tool| {
            (
                tool.name.clone(),
                ToolClass {
                    data_class: tool.data_class,
                    spends: tool.spends,
                },
            )
        })
        .collect();
    let listed = host::slate_manifest(&resolved, &discovery.tools, &classes);
    if by_name(&listed) != by_name(slate.manifest()) {
        return Err(OwnerError::Changed(
            "the connector's tools changed since it was registered".to_owned(),
        ));
    }
    let connector = host::HttpQualificationConnector::new(
        &client,
        endpoint,
        auth,
        revision,
        &kit.effect_state_uri,
    );
    let now = unix_seconds_now();
    let staged_plan = kit.plan_for_run();
    let suite = ProbeManifestQualifier {
        connector: &connector,
        plan: &staged_plan,
        oracle: kit,
    };
    vault
        .stage_connector_manifest(&catalog.key, resolved, revision, &suite, now)
        .map_err(engine)?;
    vault
        .qualify_connector_key(
            &catalog.key,
            revision,
            &connector,
            &kit.plan_for_run(),
            kit,
            now,
        )
        .map_err(|error| match error {
            ConnectorQualificationError::Probe(failure) => {
                OwnerError::Refused(format!("the connector failed qualification: {failure}"))
            }
            ConnectorQualificationError::Vault(error) => engine(error),
        })?;
    Ok(())
}

fn by_name(manifest: &[SlateToolManifest]) -> BTreeMap<&str, &SlateToolManifest> {
    manifest
        .iter()
        .map(|tool| (tool.name.as_str(), tool))
        .collect()
}

/// Approves the exact candidate qualification staged: the owner's qualify
/// act accepts the manifest the suite ran on.
fn approve(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    key: EntityId,
) -> OwnerResult<ConnectorKeyRecord> {
    let record = vault
        .get_connector_key(&key)?
        .ok_or_else(|| OwnerError::NotFound("connector key", key.to_hex()))?;
    let pending = record
        .pending_manifest
        .ok_or_else(|| OwnerError::Invalid("the connector has no staged manifest".to_owned()))?;
    let report = pending
        .qualification_report_hash
        .ok_or_else(|| OwnerError::Invalid("the staged manifest was never qualified".to_owned()))?;
    let manifest_hash = pending.manifest.hash().map_err(engine)?;
    vault
        .approve_connector_manifest(
            owner,
            &key,
            pending.candidate_id,
            manifest_hash,
            &report,
            unix_seconds_now(),
        )
        .map_err(engine)
}
