//! `/qualify` and `/attest`: the suite or the owner's attestation that
//! activates a pending connector, or swaps in the slate a refresh staged
//! beside an admitted one (FIX 11677). [`super`] is past the file-size bar,
//! so they live here.

use oneiron::connector_key::{
    ConnectorQualificationError, OwnerAttestedManifestQualifier, ProbeManifestQualifier,
    ResolvedConnectorManifest,
};
use reqwest::header::HeaderValue;

use super::*;

/// `POST /v1/owner/connectors/qualify`: runs the probe suite through the
/// installed endpoint with the owner's kit, activates the key, and
/// approves the exact manifest the suite ran on. On an admitted key with a
/// staged slate the suite runs on that slate, and a pass swaps it in. A key
/// the suite already activated only has its staged manifest approved.
pub(super) async fn qualify(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<QualifyRequest>,
) -> OwnerReply<KeyView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || qualify_connector(&server, &owner, &request)).await?;
    Ok(Json(reply))
}

pub(crate) fn qualify_connector(
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
    let probes = match catalog.record.status {
        ConnectorKeyStatus::Pending => true,
        // The slate a refresh staged beside an admitted key's routing one.
        ConnectorKeyStatus::Active | ConnectorKeyStatus::Suspended
            if catalog.record.staged_slate_ref.is_some() =>
        {
            true
        }
        ConnectorKeyStatus::Active if catalog.record.retained_manifest.is_none() => false,
        _ => {
            return Err(OwnerError::Refused(
                "the connector is already admitted".to_owned(),
            ));
        }
    };
    if probes {
        host::with_credential(vault, catalog.record.secret_ref.as_deref(), &name, |auth| {
            probe(vault, &catalog, &endpoint, &revision, auth, &request.kit)
        })
        .map_err(engine)??;
    }
    let record = vault
        .get_connector_key(&catalog.key)?
        .ok_or_else(|| OwnerError::NotFound("connector key", catalog.key.to_hex()))?;
    // After a refresh the suite may find no manifest change, or apply a
    // proved narrow itself: nothing is left to approve.
    if record.pending_manifest.is_none() && record.retained_manifest.is_some() {
        return Ok(KeyView::new(catalog.key, record)?);
    }
    let approved = approve(vault, owner, catalog.key)?;
    Ok(KeyView::new(catalog.key, approved)?)
}

/// `POST /v1/owner/connectors/attest`: CONNECTOR-QUALIFY = A (owner ruling
/// 2026-10-30 05:52 JST). The owner attests a pending connector the probe
/// suite cannot grade (one that returns no `oneiron/probe` evidence). Its
/// tools are listed again and must match the slate he stamped; the manifest
/// stages under his attestation and the key activates with an
/// owner-attested receipt. On an admitted key with a staged slate, his
/// attestation swaps that slate in. Owner-only: no agent verb reaches it,
/// and `/qualify` stays the default.
pub(super) async fn attest(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<AttestRequest>,
) -> OwnerReply<KeyView> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || attest_connector(&server, &owner, &request)).await?;
    Ok(Json(reply))
}

fn attest_connector(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    request: &AttestRequest,
) -> OwnerResult<KeyView> {
    let vault = server.vault();
    let (name, endpoint) = installed(server, &request.connector)?;
    let catalog = catalog(vault, &name)?;
    let revision =
        catalog.record.protocol_revision.clone().ok_or_else(|| {
            OwnerError::Invalid("the connector pins no protocol revision".to_owned())
        })?;
    let staged = catalog.record.staged_slate_ref.is_some();
    if catalog.record.status != ConnectorKeyStatus::Pending && !staged {
        return Err(OwnerError::Refused(
            "the connector is already admitted".to_owned(),
        ));
    }
    let resolved =
        host::with_credential(vault, catalog.record.secret_ref.as_deref(), &name, |auth| {
            let client = host::client().map_err(engine)?;
            listed_as_stamped(vault, &catalog, &client, &endpoint, &revision, auth)
        })
        .map_err(engine)??;
    let now = unix_seconds_now();
    vault
        .stage_connector_manifest(
            &catalog.key,
            resolved,
            &revision,
            &OwnerAttestedManifestQualifier { owner },
            now,
        )
        .map_err(engine)?;
    let record = if staged {
        vault.attest_staged_connector_slate(owner, &catalog.key, &revision, now)
    } else {
        vault.attest_connector_key(owner, &catalog.key, &revision, now)
    }
    .map_err(engine)?;
    // The attested listing may change no manifest: nothing is left to approve.
    if record.pending_manifest.is_none() && record.retained_manifest.is_some() {
        return Ok(KeyView::new(catalog.key, record)?);
    }
    let approved = approve(vault, owner, catalog.key)?;
    Ok(KeyView::new(catalog.key, approved)?)
}

/// The connector's tools, listed again at `revision` and resolved, when
/// they are still the ones the owner stamped on the slate this run admits:
/// the one staged beside an admitted key's routing slate, if any.
fn listed_as_stamped(
    vault: &Vault,
    catalog: &Catalog,
    client: &reqwest::blocking::Client,
    endpoint: &str,
    revision: &str,
    auth: Option<&HeaderValue>,
) -> OwnerResult<ResolvedConnectorManifest> {
    let discovery = host::discover(client, endpoint, auth, Some(revision)).map_err(engine)?;
    let slate = match staged_slate_of(vault, &catalog.record)? {
        Some((_, staged)) => staged,
        None => slate_of(vault, &catalog.record)?.1,
    };
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
                    price: tool.price.clone(),
                },
            )
        })
        .collect();
    let listed = host::slate_manifest(&resolved, &discovery.tools, &classes);
    if !same_manifest(&listed, &slate) {
        return Err(OwnerError::Changed(
            "the connector's tools changed since it was registered".to_owned(),
        ));
    }
    Ok(resolved)
}

/// Stages the resolved manifest under the suite, then runs the suite again
/// to activate the key, or to swap in its staged slate: two full runs on
/// the one surface the owner stamped.
fn probe(
    vault: &Vault,
    catalog: &Catalog,
    endpoint: &str,
    revision: &str,
    auth: Option<&HeaderValue>,
    kit: &QualificationKit,
) -> OwnerResult<()> {
    let client = host::client().map_err(engine)?;
    let resolved = listed_as_stamped(vault, catalog, &client, endpoint, revision, auth)?;
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
    let qualified = if catalog.record.staged_slate_ref.is_some() {
        vault.qualify_staged_connector_slate(
            &catalog.key,
            revision,
            &connector,
            &kit.plan_for_run(),
            kit,
            now,
        )
    } else {
        vault.qualify_connector_key(
            &catalog.key,
            revision,
            &connector,
            &kit.plan_for_run(),
            kit,
            now,
        )
    };
    qualified.map_err(|error| match error {
        ConnectorQualificationError::Probe(failure) => {
            OwnerError::Refused(format!("the connector failed qualification: {failure}"))
        }
        ConnectorQualificationError::Vault(error) => engine(error),
    })?;
    // The kit that qualified the key is kept for an accepted issuer
    // revision's re-run (FIX 9304); the qualify stands without it.
    if let Err(error) = vault.keep_connector_qualification_kit(&catalog.key, kit) {
        tracing::warn!(%error, "connector qualification kit not kept");
    }
    Ok(())
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
