//! `/refresh` and `/enabled`: the owner's doors on a connector already
//! admitted. [`super`] is past the file-size bar, so they live here.

use super::*;

/// `POST /v1/owner/connectors/refresh`: lists the connector's tools again,
/// at its pinned revision while it still answers that one. Unchanged:
/// nothing moves. Changed: a delta slate carries the unchanged and narrowed
/// rows with their settings and drafts the new and expanded ones, and the
/// key goes back to Pending with its per-grant keys held, for the owner's
/// stamp (when a row re-asks) and a fresh `/qualify`.
pub(super) async fn refresh(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<RefreshRequest>,
) -> OwnerReply<Refreshed> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || refresh_connector(&server, &owner, request)).await?;
    Ok(Json(reply))
}

fn refresh_connector(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: RefreshRequest,
) -> OwnerResult<Refreshed> {
    let vault = server.vault();
    let (name, endpoint) = installed(server, &request.connector)?;
    let catalog = catalog(vault, &name)?;
    match catalog.record.status {
        ConnectorKeyStatus::Active | ConnectorKeyStatus::Pending => {}
        ConnectorKeyStatus::Suspended => {
            return Err(OwnerError::Refused(
                "the connector is switched off; switch it on first".to_owned(),
            ));
        }
        ConnectorKeyStatus::Revoked => return Err(removed()),
    }
    let pinned =
        catalog.record.protocol_revision.clone().ok_or_else(|| {
            OwnerError::Invalid("the connector pins no protocol revision".to_owned())
        })?;
    // The pinned revision first: a connector that still answers it keeps it.
    let discovery =
        host::with_credential(vault, catalog.record.secret_ref.as_deref(), &name, |auth| {
            let client = host::client()?;
            host::discover(&client, &endpoint, auth, Some(&pinned))
                .or_else(|_| host::discover(&client, &endpoint, auth, None))
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
    let (slate_id, slate) = slate_of(vault, &catalog.record)?;
    let mut classes: BTreeMap<String, ToolClass> = slate
        .manifest()
        .iter()
        .map(|tool| {
            (
                tool.name.clone(),
                ToolClass {
                    data_class: tool.data_class,
                    spends: tool.spends,
                    price: tool.price.clone(),
                },
            )
        })
        .collect();
    classes.extend(request.tools);
    let resolved = host::resolve(&discovery.tools).map_err(|_| unresolvable())?;
    let listed = host::slate_manifest(&resolved, &discovery.tools, &classes);
    if discovery.revision == pinned && same_manifest(&listed, &slate) {
        return Ok(Refreshed {
            connector: name,
            changed: false,
            key: KeyView::new(catalog.key, catalog.record)?,
            slate: SlateView::new(vault, slate_id, &slate)?,
            reask: Vec::new(),
            carried: Vec::new(),
            dropped: Vec::new(),
        });
    }
    let delta = with_slate_drafter(server, owner, |drafter| {
        vault.draft_connector_delta_slate(slate_id, &listed, drafter)
    })
    .map_err(engine)?;
    let now = unix_seconds_now();
    let record = if discovery.revision == pinned {
        vault.revise_connector_slate(&catalog.key, delta.slate_id, now)
    } else {
        vault.revise_connector_protocol(&catalog.key, &discovery.revision, delta.slate_id, now)
    }
    .map_err(engine)?;
    let (_, next) = slate_of(vault, &record)?;
    Ok(Refreshed {
        connector: name,
        changed: true,
        key: KeyView::new(catalog.key, record)?,
        slate: SlateView::new(vault, delta.slate_id, &next)?,
        reask: delta.reask.into_iter().collect(),
        carried: delta.carried.into_iter().collect(),
        dropped: delta.dropped.into_iter().collect(),
    })
}

/// `POST /v1/owner/connectors/enabled`: the owner's on/off switch for an
/// admitted connector. Off suspends its key, and its per-grant keys are
/// held with it; on resumes it, and they carry or retire.
pub(super) async fn enabled(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<EnabledRequest>,
) -> OwnerReply<KeyView> {
    // The owner's proof rides into the switch's own transaction and is
    // revalidated there (FIX 8197).
    let proof = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || switch_connector(server.vault(), &request, &proof)).await?;
    Ok(Json(reply))
}

fn switch_connector(
    vault: &Vault,
    request: &EnabledRequest,
    owner: &oneiron::consent::AuthenticatedOwner,
) -> OwnerResult<KeyView> {
    let catalog = catalog(vault, &normalize_name(&request.connector))?;
    let record = match (catalog.record.status, request.enabled) {
        (ConnectorKeyStatus::Active, true) | (ConnectorKeyStatus::Suspended, false) => {
            catalog.record
        }
        (ConnectorKeyStatus::Active, false) => vault
            .suspend_connector_key_as_owner(
                &catalog.key,
                OWNER_OFF_REASON,
                unix_seconds_now(),
                owner,
            )
            .map_err(engine)?,
        (ConnectorKeyStatus::Suspended, true) => vault
            .resume_connector_key_as_owner(&catalog.key, unix_seconds_now(), owner)
            .map_err(engine)?,
        (ConnectorKeyStatus::Pending, _) => {
            return Err(OwnerError::Refused(
                "the connector is not admitted yet".to_owned(),
            ));
        }
        (ConnectorKeyStatus::Revoked, _) => return Err(removed()),
    };
    Ok(KeyView::new(catalog.key, record)?)
}
