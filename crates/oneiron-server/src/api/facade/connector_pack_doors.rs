//! Source-bound connector packs over the existing owner, probe and slate doors.
use std::sync::Arc;

use oneiron::connector_key::{
    ConnectorCallClass, ConnectorCatalogEntry, ConnectorConsentTarget, ConnectorKeyRecord,
    ConnectorKeySpec, ConnectorKeyStatus, ConnectorToolConsent, ConnectorToolConsentRow,
    ProbeManifestQualifier, SlateManifest, SlatePackSource,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::skill_hub::pack_catalog::{PackKind, PackSource, ProbePackQualifier};
use oneiron::task_verb::sdk::*;
use oneiron::{EntityId, Vault};

use super::host_doors::support::Listed;
use super::legal_hold_doors::as_owner_naming;
use crate::api::owner_routes::connector_admission_routes as catalog;
use crate::api::unix_seconds_now;
use crate::auth::CoreAuth;
use crate::connector_admission_host::{self as host, ToolClass};
use crate::owner::OwnerError;
use crate::server::SyncServer;

fn invalid(message: &str) -> MemoryError {
    MemoryError::bad_request(message)
}

fn owner_error(error: OwnerError) -> MemoryError {
    match error {
        OwnerError::Engine(error) => MemoryError::from(*error),
        error => invalid(&error.to_string()),
    }
}

fn id(value: &str) -> MemoryResult<EntityId> {
    EntityId::from_hex(value).map_err(|_| invalid("invalid connector-pack record ref"))
}

fn hash(bytes: [u8; 32]) -> String {
    blake3::Hash::from(bytes).to_hex().to_string()
}

fn source(vault: &Vault, binding: &SlatePackSource) -> MemoryResult<PackSource> {
    let source = vault
        .get_pack_source(&id(&binding.source_ref)?)?
        .ok_or_else(|| invalid("connector pack source missing"))?;
    if source.manifest().kind != PackKind::Connector
        || source.content_hash().to_hex() != binding.content_hash
    {
        return Err(invalid("connector pack source hash or kind changed"));
    }
    Ok(source)
}

fn key(vault: &Vault, connector: &str) -> MemoryResult<(EntityId, ConnectorKeyRecord)> {
    let entry = vault
        .describe_connector(connector)?
        .ok_or_else(|| invalid("connector is not registered"))?;
    let record = vault
        .get_connector_key(&entry.key_ref)?
        .ok_or_else(|| invalid("connector key missing"))?;
    Ok((entry.key_ref, record))
}

fn view(server: &SyncServer, connector: &str) -> MemoryResult<ConnectorPackView> {
    let vault = server.vault();
    let (key_id, record) = key(vault, connector)?;
    let slate_id = record
        .slate_ref
        .ok_or_else(|| invalid("connector slate missing"))?;
    let slate = vault
        .connector_slate(slate_id)?
        .ok_or_else(|| invalid("connector slate missing"))?;
    let binding = slate
        .slate_manifest()
        .pack_source
        .clone()
        .ok_or_else(|| invalid("connector has no pack source binding"))?;
    let source = source(vault, &binding)?;
    let advisories = vault
        .skill_scan_verdicts_for_content_hash(source.content_hash())?
        .into_iter()
        .map(|body| {
            serde_json::from_value::<ConnectorPackAdvisory>(oneiron::msgpack_value_to_json(
                &body.value,
            ))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("connector advisory row is malformed"))?;
    let mut evidence = advisories
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("connector advisory encoding failed"))?;
    evidence.sort();
    let advisory_hash = blake3::hash(evidence.join("\n").as_bytes())
        .to_hex()
        .to_string();
    let pack = vault
        .installed_pack(&source.manifest().name)?
        .filter(|receipt| receipt.content_hash == binding.content_hash)
        .or(vault.candidate_pack(&source)?);
    Ok(ConnectorPackView {
        basis: ConnectorPackBasis {
            connector: record
                .catalog
                .as_ref()
                .ok_or_else(|| invalid("not a catalog key"))?
                .name
                .clone(),
            source: binding,
            key_ref: key_id.to_hex(),
            slate_ref: slate_id.to_hex(),
            slate_revision: slate.revision(),
            manifest_hash: hash(slate.manifest_hash()),
            grant_hash: hash(slate.grant_hash()),
            advisory_hash,
            protocol_revision: record
                .protocol_revision
                .clone()
                .ok_or_else(|| invalid("connector protocol revision missing"))?,
        },
        status: record.status.as_str().to_owned(),
        consent_required: record.consent_required,
        stamped: slate.owner_actor().is_some() && slate.stamp_holds(),
        manifest: slate.slate_manifest().clone(),
        rows: slate.rows().to_vec(),
        qualification: record.qualification_receipt,
        pack,
        advisories,
    })
}

fn reviewed(server: &SyncServer, basis: &ConnectorPackBasis) -> MemoryResult<ConnectorPackView> {
    let current = view(server, &basis.connector)?;
    if current.basis != *basis {
        return Err(invalid(
            "connector pack changed since review; read it again",
        ));
    }
    Ok(current)
}

/// Resolve the actual host-installed transport, then require the owner's exact
/// permission declaration. Neither an alias nor submitted tool metadata is proof.
fn observed(
    server: &SyncServer,
    connector: &str,
    secret_ref: Option<&str>,
    revision: &str,
    declared: &SlateManifest,
    binding: &SlatePackSource,
) -> MemoryResult<SlateManifest> {
    let (name, endpoint) = catalog::installed(server, connector).map_err(owner_error)?;
    let discovery = host::with_credential(server.vault(), secret_ref, &name, |auth| {
        host::discover(&host::client()?, &endpoint, auth, Some(revision))
    })??;
    if discovery.revision != revision {
        return Err(invalid(
            "connector protocol revision differs from declaration",
        ));
    }
    let screened = discovery
        .tools
        .iter()
        .map(host::ListedTool::screened)
        .collect::<Vec<_>>();
    if let Some(reason) = server.vault().screen_connector_tools(&screened, &name)? {
        return Err(invalid(&reason));
    }
    let resolved = host::resolve(&discovery.tools)?;
    let classes = declared
        .tools
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
    let mut listed = host::slate_manifest(&resolved, &discovery.tools, &classes);
    listed.pack_source = declared.pack_source.clone();
    if &listed != declared
        || declared
            .pack_source
            .as_ref()
            .is_some_and(|held| held != binding)
    {
        return Err(invalid(
            "observed connector manifest differs from reviewed declaration",
        ));
    }
    listed.pack_source = Some(binding.clone());
    Ok(listed)
}

fn rows(view: &ConnectorPackView) -> Vec<EntityId> {
    [
        &view.basis.source.source_ref,
        &view.basis.key_ref,
        &view.basis.slate_ref,
    ]
    .into_iter()
    .filter_map(|reference| EntityId::from_hex(reference).ok())
    .collect()
}

pub(crate) async fn vault_packs_connector_prepare(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorPackPrepareRequest,
) -> Listed<ConnectorPackView> {
    as_owner_naming(
        server,
        auth,
        "vault.packs.connector.prepare",
        move |server, owner| {
            let vault = server.vault();
            owner.revalidate(vault)?;
            source(vault, &input.source)?;
            let (name, _) = catalog::installed(server, &input.connector).map_err(owner_error)?;
            if vault.describe_connector(&name)?.is_some() {
                return Err(invalid(
                    "connector is already registered; use the pack update door",
                ));
            }
            let manifest = observed(
                server,
                &name,
                input.secret_ref.as_deref(),
                &input.protocol_revision,
                &input.manifest,
                &input.source,
            )?;
            owner.revalidate(vault)?;
            let slate_id = catalog::with_slate_drafter(server, owner, |drafter| {
                vault.draft_connector_admission_slate(&manifest, drafter)
            })?;
            let now = unix_seconds_now();
            vault.register_connector(
                ConnectorCatalogEntry {
                    name: name.clone(),
                    connector: name.clone(),
                    summary: input.summary,
                    verbs: manifest
                        .tools
                        .iter()
                        .map(|tool| tool.name.clone())
                        .collect(),
                    call_class: ConnectorCallClass::ScopedMcp,
                    registered_at: now,
                },
                ConnectorKeySpec {
                    connector: name.clone(),
                    actor_entity_ref: None,
                    budgets: Vec::new(),
                    secret_ref: input.secret_ref,
                    slate_ref: Some(slate_id),
                    protocol_revision: Some(input.protocol_revision),
                },
                now,
            )?;
            view(server, &name)
        },
        rows,
    )
    .await
}

pub(crate) async fn vault_packs_connector_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorPackGetRequest,
) -> Listed<ConnectorPackView> {
    as_owner_naming(
        server,
        auth,
        "vault.packs.connector.get",
        move |server, owner| {
            owner.revalidate(server.vault())?;
            view(server, &input.connector)
        },
        rows,
    )
    .await
}

pub(crate) async fn vault_packs_connector_update(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorPackUpdateRequest,
) -> Listed<ConnectorPackDelta> {
    as_owner_naming(
        server,
        auth,
        "vault.packs.connector.update",
        move |server, owner| {
            let vault = server.vault();
            owner.revalidate(vault)?;
            let prior = reviewed(server, &input.prior)?;
            let previous = source(vault, &input.prior.source)?;
            let next = source(vault, &input.source)?;
            if previous.manifest().name != next.manifest().name {
                return Err(invalid("a connector pack update must retain its pack name"));
            }
            let (key_id, record) = key(vault, &input.prior.connector)?;
            if !matches!(
                record.status,
                ConnectorKeyStatus::Active | ConnectorKeyStatus::Pending
            ) {
                return Err(invalid("connector must be active or pending to update"));
            }
            let manifest = observed(
                server,
                &input.prior.connector,
                record.secret_ref.as_deref(),
                &input.protocol_revision,
                &input.manifest,
                &input.source,
            )?;
            reviewed(server, &input.prior)?;
            if manifest == prior.manifest
                && input.protocol_revision == input.prior.protocol_revision
            {
                return Ok(ConnectorPackDelta {
                    prior: input.prior,
                    current: prior,
                    changed: false,
                    reask: Vec::new(),
                    carried: Vec::new(),
                    dropped: Vec::new(),
                });
            }
            let delta = catalog::with_slate_drafter(server, owner, |drafter| {
                vault
                    .draft_connector_delta_slate(id(&input.prior.slate_ref)?, &manifest, drafter)
                    .map_err(MemoryError::from)
            })?;
            owner.revalidate(vault)?;
            if input.protocol_revision == input.prior.protocol_revision {
                vault.revise_connector_slate(&key_id, delta.slate_id, unix_seconds_now())?;
            } else {
                vault.revise_connector_protocol(
                    &key_id,
                    &input.protocol_revision,
                    delta.slate_id,
                    unix_seconds_now(),
                )?;
            }
            Ok(ConnectorPackDelta {
                current: view(server, &input.prior.connector)?,
                prior: input.prior,
                changed: true,
                reask: delta.reask.into_iter().collect(),
                carried: delta.carried.into_iter().collect(),
                dropped: delta.dropped.into_iter().collect(),
            })
        },
        |delta| {
            let mut named = rows(&delta.current);
            named.extend(EntityId::from_hex(&delta.prior.source.source_ref).ok());
            named
        },
    )
    .await
}

pub(crate) async fn vault_packs_connector_accept(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorPackAcceptRequest,
) -> Listed<ConnectorPackView> {
    as_owner_naming(
        server,
        auth,
        "vault.packs.connector.accept",
        move |server, owner| {
            reviewed(server, &input.basis)?;
            catalog::accept_slate(
                server.vault(),
                owner,
                catalog::AcceptRequest {
                    connector: input.basis.connector.clone(),
                    revision: input.basis.slate_revision,
                    rows: input.rows,
                    facets: input.facets,
                    all_manual: input.all_manual,
                },
                Some(id(&input.basis.slate_ref)?),
            )
            .map_err(owner_error)?;
            view(server, &input.basis.connector)
        },
        rows,
    )
    .await
}

pub(crate) async fn vault_packs_connector_qualify(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorPackQualifyRequest,
) -> Listed<ConnectorPackView> {
    as_owner_naming(
        server,
        auth,
        "vault.packs.connector.qualify",
        move |server, owner| {
            let vault = server.vault();
            owner.revalidate(vault)?;
            let current = reviewed(server, &input.basis)?;
            let source = source(vault, &input.basis.source)?;
            let (_, record) = key(vault, &input.basis.connector)?;
            if record.status != ConnectorKeyStatus::Pending {
                return Err(invalid("connector pack is not pending qualification"));
            }
            let (name, endpoint) =
                catalog::installed(server, &input.basis.connector).map_err(owner_error)?;
            observed(
                server,
                &name,
                record.secret_ref.as_deref(),
                &input.basis.protocol_revision,
                &current.manifest,
                &input.basis.source,
            )?;
            host::with_credential(
                vault,
                record.secret_ref.as_deref(),
                &name,
                |auth| -> MemoryResult<()> {
                    let client = host::client()?;
                    let discovery = host::discover(
                        &client,
                        &endpoint,
                        auth,
                        Some(&input.basis.protocol_revision),
                    )?;
                    let manifest = host::resolve(&discovery.tools)?;
                    let connector = host::HttpQualificationConnector::new(
                        &client,
                        &endpoint,
                        auth,
                        &input.basis.protocol_revision,
                        &input.kit.effect_state_uri,
                    );
                    let plan = input.kit.plan_for_run();
                    let advisory = format!(
                        "Owner accepted source {} advisory evidence {}",
                        input.basis.source.content_hash, input.basis.advisory_hash
                    );
                    let qualifier = ProbePackQualifier {
                        source_hash: source.content_hash(),
                        manifest: &manifest,
                        protocol_revision: &input.basis.protocol_revision,
                        probes: ProbeManifestQualifier {
                            connector: &connector,
                            plan: &plan,
                            oracle: &input.kit,
                        },
                        runtime: input.runtime.clone(),
                        advisory_accepted: true,
                        advisory: &advisory,
                    };
                    // The existing put validates the engine-created qualification token and
                    // persists the source-bound receipt. A caller cannot submit a grade.
                    reviewed(server, &input.basis)?;
                    let installed =
                        vault.put_qualified_pack(owner, source.files().to_vec(), &qualifier)?;
                    if !matches!(
                        installed,
                        oneiron::skill_hub::pack_catalog::PackInstallDisposition::Installed(_)
                    ) {
                        return Err(invalid("connector pack install was held or blocked"));
                    }
                    Ok(())
                },
            )??;
            // Qualification can precede the stamp. It grants nothing by itself.
            if current.stamped || !current.consent_required {
                catalog::qualify_connector(
                    server,
                    owner,
                    &catalog::QualifyRequest {
                        connector: name.clone(),
                        kit: input.kit,
                    },
                )
                .map_err(owner_error)?;
            }
            view(server, &name)
        },
        rows,
    )
    .await
}

fn grants(
    server: &SyncServer,
    owner: &AuthenticatedOwner,
    basis: &ConnectorPackBasis,
    actor: Option<&str>,
) -> MemoryResult<ConnectorPackGrants> {
    reviewed(server, basis)?;
    let actor = actor.map(id).transpose()?;
    let authority = server
        .vault()
        .connector_consent_view(owner, &basis.connector, actor)?
        .ok_or_else(|| invalid("connector consent view missing"))?;
    let (_, endpoint) = catalog::installed(server, &basis.connector).map_err(owner_error)?;
    Ok(ConnectorPackGrants {
        basis: basis.clone(),
        endpoint: Some(endpoint),
        authority,
    })
}

fn grant_rows(grants: &ConnectorPackGrants) -> Vec<EntityId> {
    [
        &grants.basis.source.source_ref,
        &grants.basis.key_ref,
        &grants.basis.slate_ref,
        &grants.authority.actor,
    ]
    .into_iter()
    .filter_map(|reference| EntityId::from_hex(reference).ok())
    .collect()
}

pub(crate) async fn vault_packs_connector_grants_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorPackGrantsGetRequest,
) -> Listed<ConnectorPackGrants> {
    as_owner_naming(
        server,
        auth,
        "vault.packs.connector.grants.get",
        move |server, owner| grants(server, owner, &input.basis, input.actor.as_deref()),
        grant_rows,
    )
    .await
}

pub(crate) async fn vault_packs_connector_grants_put(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: ConnectorPackGrantsPutRequest,
) -> Listed<ConnectorPackGrants> {
    as_owner_naming(
        server,
        auth,
        "vault.packs.connector.grants.put",
        move |server, owner| {
            reviewed(server, &input.basis)?;
            let (_, endpoint) =
                catalog::installed(server, &input.basis.connector).map_err(owner_error)?;
            if endpoint != input.endpoint {
                return Err(invalid("connector endpoint changed since review"));
            }
            server.vault().consent_connector_tools(
                owner,
                &ConnectorToolConsent {
                    connector: input.basis.connector.clone(),
                    endpoint,
                    target: input
                        .actor
                        .as_deref()
                        .map(id)
                        .transpose()?
                        .map_or(ConnectorConsentTarget::Owner, ConnectorConsentTarget::Actor),
                    rows: input
                        .rows
                        .into_iter()
                        .map(|row| ConnectorToolConsentRow {
                            tool: row.tool,
                            data_class_ceiling: row.ceiling,
                            headers: row.headers,
                        })
                        .collect(),
                },
            )?;
            grants(server, owner, &input.basis, input.actor.as_deref())
        },
        grant_rows,
    )
    .await
}
