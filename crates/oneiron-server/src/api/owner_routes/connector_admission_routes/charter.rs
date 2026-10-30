//! `/charter`, `/charter/propose`, `/charter/approve` and `/charter/discard`:
//! the owner's GOV-10 charter on a catalog connector's key (FIX 11680). A
//! proposal compiles the text and stages it on the key; enforcement does
//! not change. Approve re-presents the hashes of the text and the compile
//! the owner reviewed, and stamps them as his act. Discard drops the
//! proposal. The gate enforces the compiled policy only, on the key and on
//! its per-grant keys.

use oneiron::connector_key::{CompiledConnectorPolicy, EffectorBudget, EffectorBudgetWindow};

use super::super::machine_routes::{parse_revision, revision_hex};
use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CharterQuery {
    connector: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CharterProposeRequest {
    pub(crate) connector: String,
    /// The charter text, one rule per line.
    pub(crate) text: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CharterApproveRequest {
    pub(crate) connector: String,
    /// The reviewed proposal's `text_hash`, as 64 lower-case hex.
    pub(crate) text_hash: String,
    /// The reviewed proposal's `compiled_hash`, as 64 lower-case hex.
    pub(crate) compiled_hash: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CharterDiscardRequest {
    pub(crate) connector: String,
}

/// A connector key's charter as the owner reviews it.
#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct CharterView {
    connector: String,
    key: String,
    /// The stamped charter the gate enforces; none: no charter.
    charter: Option<StampedCharterView>,
    /// The compiled proposal waiting for the owner's approve; none: nothing
    /// is staged.
    pending: Option<PendingCharterView>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct StampedCharterView {
    text: String,
    text_hash: String,
    compiled: CompiledCharterView,
    compiled_hash: String,
    stamped_by: String,
    stamped_at: u64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct PendingCharterView {
    text: String,
    /// Re-presented to `/charter/approve`, with `compiled_hash`.
    text_hash: String,
    compiled: CompiledCharterView,
    compiled_hash: String,
    proposed_at: u64,
}

/// What a compile enforces.
#[derive(Debug, Serialize, schemars::JsonSchema)]
struct CompiledCharterView {
    /// `channel:verb` pairs the connector never sends; `*` on either side
    /// matches any.
    never: Vec<String>,
    /// Budget rows enforced as the key's own.
    caps: Vec<CharterCapView>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct CharterCapView {
    dimension: &'static str,
    channel_class: Option<String>,
    limit: u64,
    unit: Option<String>,
    /// `rolling:<seconds>`, or `calendar:<period>` with `@<tz>` when set.
    window: String,
    on_exhaust: &'static str,
}

impl CharterView {
    fn new(connector: String, key: EntityId, record: &ConnectorKeyRecord) -> Self {
        Self {
            connector,
            key: key.to_hex(),
            charter: record.charter.as_ref().map(|charter| StampedCharterView {
                text: charter.text.clone(),
                text_hash: revision_hex(&charter.text_hash),
                compiled: CompiledCharterView::new(&charter.compiled),
                compiled_hash: revision_hex(&charter.compiled_hash),
                stamped_by: charter.stamped_by.clone(),
                stamped_at: charter.stamped_at,
            }),
            pending: record
                .pending_charter
                .as_ref()
                .map(|pending| PendingCharterView {
                    text: pending.text.clone(),
                    text_hash: revision_hex(&pending.text_hash),
                    compiled: CompiledCharterView::new(&pending.compiled),
                    compiled_hash: revision_hex(&pending.compiled_hash),
                    proposed_at: pending.proposed_at,
                }),
        }
    }
}

impl CompiledCharterView {
    fn new(compiled: &CompiledConnectorPolicy) -> Self {
        Self {
            never: compiled.never_list.clone(),
            caps: compiled
                .channel_caps
                .iter()
                .map(CharterCapView::new)
                .collect(),
        }
    }
}

impl CharterCapView {
    fn new(cap: &EffectorBudget) -> Self {
        let window = match &cap.window {
            EffectorBudgetWindow::Rolling { duration_s } => format!("rolling:{duration_s}"),
            EffectorBudgetWindow::Calendar { period, tz } => match tz {
                Some(tz) => format!("calendar:{}@{tz}", period.as_str()),
                None => format!("calendar:{}", period.as_str()),
            },
        };
        Self {
            dimension: cap.dimension.as_str(),
            channel_class: cap.channel_class.clone(),
            limit: cap.limit,
            unit: cap.unit.clone(),
            window,
            on_exhaust: cap.on_exhaust.as_str(),
        }
    }
}

/// A charter refusal as the owner reads it: a compile error names its line,
/// and a proposal that moved since review asks for a fresh read.
fn charter_error(error: oneiron::Error) -> OwnerError {
    match error.kind() {
        oneiron::ErrorKind::ConnectorCharterCompile => OwnerError::Invalid(error.to_string()),
        oneiron::ErrorKind::ConnectorCharterMissing => {
            OwnerError::Invalid("the connector has no staged charter".to_owned())
        }
        oneiron::ErrorKind::ConnectorCharterApprovalMismatch => OwnerError::Changed(
            "the charter proposal changed since review; read it again".to_owned(),
        ),
        _ => engine(error),
    }
}

/// `GET /v1/owner/connectors/charter?connector=`: the connector key's
/// stamped charter and its staged proposal.
pub(super) async fn charter(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<CharterQuery>, QueryRejection>,
) -> OwnerReply<CharterView> {
    let _owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let reply = blocking(move || -> OwnerResult<CharterView> {
        let name = normalize_name(&query.connector);
        let catalog = catalog(server.vault(), &name)?;
        Ok(CharterView::new(name, catalog.key, &catalog.record))
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/connectors/charter/propose`: compiles the text and
/// stages it on the connector's key, over any earlier proposal. What the
/// gate enforces does not change until the owner approves it.
pub(super) async fn propose_charter(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<CharterProposeRequest>,
) -> OwnerReply<CharterView> {
    let _owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<CharterView> {
        let vault = server.vault();
        let name = normalize_name(&request.connector);
        let catalog = catalog(vault, &name)?;
        vault
            .propose_connector_charter(&catalog.key, &request.text, unix_seconds_now())
            .map_err(charter_error)?;
        let record = vault
            .get_connector_key(&catalog.key)?
            .ok_or_else(|| OwnerError::NotFound("connector key", catalog.key.to_hex()))?;
        Ok(CharterView::new(name, catalog.key, &record))
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/connectors/charter/approve`: the owner's stamp on the
/// staged proposal whose text and compile hashes he reviewed. The gate
/// enforces the stamped compile from then on, with fresh usage on its caps.
pub(super) async fn approve_charter(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<CharterApproveRequest>,
) -> OwnerReply<CharterView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<CharterView> {
        let text_hash = parse_revision("text_hash", &request.text_hash)?;
        let compiled_hash = parse_revision("compiled_hash", &request.compiled_hash)?;
        let vault = server.vault();
        let name = normalize_name(&request.connector);
        let catalog = catalog(vault, &name)?;
        let record = vault
            .approve_connector_charter_as_owner(
                &owner,
                &catalog.key,
                text_hash,
                compiled_hash,
                unix_seconds_now(),
            )
            .map_err(charter_error)?;
        Ok(CharterView::new(name, catalog.key, &record))
    })
    .await?;
    Ok(Json(reply))
}

/// `POST /v1/owner/connectors/charter/discard`: drops the staged proposal.
/// The stamped charter, if any, stands.
pub(super) async fn discard_charter(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<CharterDiscardRequest>,
) -> OwnerReply<CharterView> {
    let _owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || -> OwnerResult<CharterView> {
        let vault = server.vault();
        let name = normalize_name(&request.connector);
        let catalog = catalog(vault, &name)?;
        let record = vault
            .discard_connector_charter(&catalog.key, unix_seconds_now())
            .map_err(charter_error)?;
        Ok(CharterView::new(name, catalog.key, &record))
    })
    .await?;
    Ok(Json(reply))
}
