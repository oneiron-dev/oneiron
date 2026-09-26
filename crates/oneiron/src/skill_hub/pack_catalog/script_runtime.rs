//! Foreign pack scripts run only through the existing propose-only code-mode VM.
#[cfg(any(test, feature = "microvm-firecracker"))]
use serde::Deserialize;
#[cfg(any(test, feature = "microvm-firecracker"))]
use std::{collections::BTreeMap, fs, io::Read};
use std::{collections::BTreeSet, sync::Arc};

use super::{PackAdapter, PackSource, invalid};
use crate::{
    EntityId, Result, Vault,
    code_sandbox::microvm::{
        CredentialAllowlist, CredentialDestination, CredentialReadTransport, ExecutionBudget,
        GuestImage,
    },
    connector_key::{
        ConnectorKeyStatus,
        events::{ConnectorEventFilter, ConnectorWakeDecision},
    },
    consent::AuthenticatedOwner,
    outbound::OutboundIntent,
    surface_event::SurfaceEventAdmission,
};
#[cfg(any(test, feature = "microvm-firecracker"))]
use crate::{
    code_sandbox::microvm::{CredentialResolver, MicroVmBackend, MicroVmSandboxAdapter},
    code_sandbox::{SandboxGuestTier, SandboxMountTable, SandboxProposalWrite},
    connector_key::events::ConnectorEvent,
    outbound::{OutboundIntentDraft, OutboundIntentTrigger},
    surface_event::InboundSurfaceEventInput,
};

#[cfg(any(test, feature = "microvm-firecracker"))]
const OUTPUT_PATH: &str = "/mnt/workspace/adapter-output.json";
#[cfg(any(test, feature = "microvm-firecracker"))]
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// One owner-approved connector-key grant. The guest sees only the key's opaque
/// custody handle; resolution and destination checks remain on the host side.
#[derive(Debug, Clone)]
pub struct PackScriptGrant {
    pub requested: String,
    pub key_id: EntityId,
    pub destination: CredentialDestination,
}

/// Host-owned run inputs. The installed source and its pin are read from the
/// vault; the caller does not supply executable source bytes.
pub struct PackScriptRun<'a> {
    pub name: &'a str,
    pub agent: EntityId,
    pub grants: &'a [PackScriptGrant],
    pub image: &'a GuestImage,
    pub budget: ExecutionBudget,
    pub now: u64,
}

/// Typed output of a successful, validated foreign script. Verbs are intents,
/// not sends: the ordinary outbound effect dispatcher still gates each verb.
#[derive(Debug)]
pub struct PackScriptOutcome {
    pub inbound: Vec<SurfaceEventAdmission>,
    pub verbs: Vec<OutboundIntent>,
    pub wakes: Vec<ConnectorWakeDecision>,
}

#[cfg(any(test, feature = "microvm-firecracker"))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptOutput {
    #[serde(default)]
    inbound: Vec<InboundSurfaceEventInput>,
    #[serde(default)]
    verbs: Vec<ScriptVerb>,
    #[serde(default)]
    events: Vec<ConnectorEvent>,
}
#[cfg(any(test, feature = "microvm-firecracker"))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptVerb {
    channel: String,
    verb: String,
    target: String,
    content_ref: Option<String>,
}

impl Vault {
    /// Register this installed pack's declared event kinds as revocable OF-218
    /// subscriptions. Installation alone grants no wake authority.
    pub fn subscribe_pack_wakes(
        &self,
        name: &str,
        owner: &AuthenticatedOwner,
        agent: EntityId,
        grants: &[PackScriptGrant],
    ) -> Result<Vec<EntityId>> {
        let (source, _) = self.installed_script_pack(name)?;
        let _ = validate_grants(self, &source, agent, grants)?;
        let existing = self.connector_event_subscriptions(agent)?;
        let mut filters = Vec::new();
        for wake in &source.manifest().wake_subscriptions {
            let (grant, event_kind) = grants
                .iter()
                .find_map(|grant| {
                    wake.strip_prefix(&format!("{}.", grant.requested))
                        .map(|kind| (grant, kind))
                })
                .ok_or_else(|| invalid("wake outside granted connector"))?;
            if event_kind.is_empty() {
                return Err(invalid("empty connector wake kind"));
            }
            let filter = ConnectorEventFilter {
                connector: grant.requested.clone(),
                event_kind: Some(event_kind.to_owned()),
                predicate: None,
            };
            filters.push((grant.key_id, filter));
        }
        let mut ids = Vec::new();
        for (key_id, filter) in filters {
            if let Some((id, _)) = existing
                .iter()
                .find(|(_, row)| row.active && row.connector_key == key_id && row.filter == filter)
            {
                ids.push(*id);
            } else {
                ids.push(self.subscribe_connector_event(owner, agent, key_id, filter)?);
            }
        }
        Ok(ids)
    }

    /// Run the installed exact script in the configured foreign code-mode VM.
    /// No configured isolating backend means a refusal, not an in-process run.
    pub fn run_script_pack(
        self: &Arc<Self>,
        request: PackScriptRun<'_>,
        transport: Arc<dyn CredentialReadTransport>,
    ) -> Result<PackScriptOutcome> {
        #[cfg(feature = "microvm-firecracker")]
        {
            let backend = crate::code_sandbox::firecracker::FirecrackerBackend::detect()
                .ok_or_else(|| invalid("configured code-mode microVM unavailable"))?
                .with_read_transport(transport);
            self.run_script_pack_in_vm(request, Box::new(backend))
        }
        #[cfg(not(feature = "microvm-firecracker"))]
        {
            let _ = (self, request, transport);
            Err(invalid("foreign code-mode microVM not built"))
        }
    }

    fn installed_script_pack(&self, name: &str) -> Result<(PackSource, String)> {
        let receipt = self
            .installed_pack(name)?
            .ok_or_else(|| invalid("pack not installed"))?;
        let source_id = EntityId::from_hex(&receipt.source_id)?;
        let source = self
            .get_pack_source(&source_id)?
            .ok_or_else(|| invalid("installed source unavailable"))?;
        let Some(PackAdapter::Script(path)) = source.manifest().adapter.as_ref() else {
            return Err(invalid("pack has no script adapter"));
        };
        if receipt
            .runtime
            .as_ref()
            .is_none_or(|runtime| runtime.adapter != PackAdapter::Script(path.clone()))
        {
            return Err(invalid("installed runtime does not bind script"));
        }
        let path = path.clone();
        Ok((source, path))
    }

    #[cfg(any(test, feature = "microvm-firecracker"))]
    fn run_script_pack_in_vm(
        self: &Arc<Self>,
        request: PackScriptRun<'_>,
        backend: Box<dyn MicroVmBackend>,
    ) -> Result<PackScriptOutcome> {
        let PackScriptRun {
            name,
            agent,
            grants,
            image,
            budget,
            now,
        } = request;
        if backend.name() != "firecracker" {
            return Err(invalid("foreign pack requires isolating code-mode backend"));
        }
        let (source, path) = self.installed_script_pack(name)?;
        let allowlist = validate_grants(self, &source, agent, grants)?;
        let resolver: Arc<dyn CredentialResolver> = Arc::new(PackCredentialResolver {
            vault: Arc::clone(self),
            grants: grants
                .iter()
                .map(|grant| {
                    Ok((
                        validate_grant(self, &source, agent, grant)?
                            .as_str()
                            .to_owned(),
                        (
                            grant.key_id,
                            grant.requested.clone(),
                            grant.destination.clone(),
                            agent,
                        ),
                    ))
                })
                .collect::<Result<_>>()?,
        });
        let script = source
            .files()
            .iter()
            .find(|file| file.path == path)
            .ok_or_else(|| invalid("script source absent"))?;
        let script =
            std::str::from_utf8(&script.content).map_err(|_| invalid("script is not UTF-8"))?;
        let receipt = self
            .installed_pack(name)?
            .ok_or_else(|| invalid("pack not installed"))?;
        let runtime = receipt
            .runtime
            .as_ref()
            .ok_or_else(|| invalid("script runtime absent"))?;
        if runtime.runtime_id != crate::code_sandbox::SANDBOX_JS_COMPONENT_NAME {
            return Err(invalid(
                "script runtime is not the code-mode QuickJS component",
            ));
        }
        let mut component = Vec::new();
        fs::File::open(&image.component)
            .map_err(|_| invalid("guest component unavailable"))?
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut component)
            .map_err(|_| invalid("guest component read failed"))?;
        if component.len() > 64 * 1024 * 1024 {
            return Err(invalid("script component too large"));
        }
        if blake3::hash(&component).to_hex().as_str() != runtime.runtime_hash {
            return Err(invalid("installed script runtime pin mismatch"));
        }
        // This temporary tree is the entire guest source view. A pack can ask
        // for a path outside it, but the guest read import will refuse it.
        let workspace = tempfile::tempdir()?;
        for file in source.files() {
            let target = workspace.path().join(&file.path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(target, &file.content)?;
        }
        let mounts = SandboxMountTable::new(
            workspace.path(),
            workspace.path(),
            workspace.path(),
            workspace.path(),
        );
        let mut adapter = MicroVmSandboxAdapter::new(
            SandboxGuestTier::Foreign,
            mounts,
            backend,
            resolver,
            allowlist,
        )?;
        let guest = image.clone().with_source(script);
        let exit = adapter.run(&guest, budget)?;
        if exit.status != 0 {
            return Err(invalid("pack script failed in sandbox"));
        }
        let deltas = adapter.collect_overlay_proposals()?;
        if deltas.len() != 1 {
            return Err(invalid("pack script must emit one typed output"));
        }
        let SandboxProposalWrite::FileWrite(file) = deltas[0].write() else {
            return Err(invalid("pack script emitted non-output proposal"));
        };
        if file.path.as_str() != OUTPUT_PATH || file.bytes.len() > MAX_OUTPUT_BYTES {
            return Err(invalid("pack script output outside manifest"));
        }
        let output: ScriptOutput = serde_json::from_slice(&file.bytes)
            .map_err(|_| invalid("invalid typed pack script output"))?;
        if output.inbound.len() > 16 || output.verbs.len() > 16 || output.events.len() > 16 {
            return Err(invalid("pack script output count exceeded"));
        }
        for grant in grants {
            // Revocation or rotation during execution suppresses all output.
            let _ = validate_grant(self, &source, agent, grant)?;
        }
        if self.installed_pack(name)?.as_ref() != Some(&receipt) {
            return Err(invalid("installed pack changed during script execution"));
        }
        let permitted: BTreeSet<&str> = grants
            .iter()
            .map(|grant| grant.requested.as_str())
            .collect();
        if output
            .inbound
            .iter()
            .any(|event| !permitted.contains(event.channel.as_str()))
            || output.events.iter().any(|event| {
                !permitted.contains(event.connector.as_str())
                    || !source
                        .manifest()
                        .wake_subscriptions
                        .contains(&format!("{}.{}", event.connector, event.event_kind))
            })
        {
            return Err(invalid(
                "pack script output outside granted connector or wake slate",
            ));
        }
        let mut verbs = Vec::new();
        for verb in output.verbs {
            let grant = grants
                .iter()
                .find(|grant| grant.requested == verb.channel)
                .ok_or_else(|| invalid("pack script verb outside granted connector"))?;
            let route = self.route_connector_call(&verb.channel)?;
            if verb.verb.is_empty()
                || verb.target.is_empty()
                || !route.as_ref().is_some_and(|entry| {
                    entry.key_ref == grant.key_id
                        && entry.connector == verb.channel
                        && entry.verbs.contains(&verb.verb)
                })
            {
                return Err(invalid("pack script verb outside connector contract"));
            }
            let mut draft =
                OutboundIntentDraft::new(agent.to_hex(), verb.verb, verb.channel, verb.target);
            if let Some(content) = verb.content_ref {
                draft = draft.content_ref(content);
            }
            verbs.push(OutboundIntent::from_trigger(
                draft,
                OutboundIntentTrigger::agent_immediate(source.content_hash().to_hex()),
            ));
        }
        // Preflight EVERY identity route before enqueuing the first event. A
        // script with one valid and one cross-agent address cannot commit the
        // valid prefix and then discover the privilege violation.
        let mut checked = Vec::new();
        for mut event in output.inbound {
            event.foreign_inbound = true;
            event.received_at = now;
            let routed = self.route_inbound_surface_event(event.clone())?;
            if routed.agent_ref.as_deref() != Some(agent.to_hex().as_str()) {
                return Err(invalid("script inbound route outside granted agent"));
            }
            checked.push(event);
        }
        let mut inbound = Vec::new();
        for event in checked {
            inbound.push(self.enqueue_inbound_surface_event(event, now)?);
        }
        let mut wakes = Vec::new();
        for event in output.events {
            wakes.extend(self.ingest_connector_event(&event)?);
        }
        Ok(PackScriptOutcome {
            inbound,
            verbs,
            wakes,
        })
    }
}

fn validate_grants(
    vault: &Vault,
    source: &PackSource,
    agent: EntityId,
    grants: &[PackScriptGrant],
) -> Result<CredentialAllowlist> {
    let requested: BTreeSet<&str> = grants
        .iter()
        .map(|grant| grant.requested.as_str())
        .collect();
    if grants.is_empty()
        || requested.len() != grants.len()
        || requested
            != source
                .manifest()
                .requested_grants
                .iter()
                .map(String::as_str)
                .collect()
    {
        return Err(invalid("script grants differ from requested slate"));
    }
    let mut allowlist = CredentialAllowlist::new();
    let mut handles = BTreeSet::new();
    for grant in grants {
        let handle = validate_grant(vault, source, agent, grant)?;
        if !handles.insert(handle.as_str().to_owned()) {
            return Err(invalid(
                "script grants share an ambiguous credential handle",
            ));
        }
        allowlist.allow(&handle, grant.destination.clone());
    }
    Ok(allowlist)
}
fn validate_grant(
    vault: &Vault,
    source: &PackSource,
    agent: EntityId,
    grant: &PackScriptGrant,
) -> Result<crate::code_sandbox::SandboxCredentialHandle> {
    if !source
        .manifest()
        .requested_grants
        .contains(&grant.requested)
    {
        return Err(invalid("undeclared script grant"));
    }
    let key = vault
        .get_connector_key(&grant.key_id)?
        .ok_or_else(|| invalid("connector key absent"))?;
    if key.status != ConnectorKeyStatus::Active
        || key.connector != grant.requested
        || key.actor_entity_ref.is_some_and(|bound| bound != agent)
    {
        return Err(invalid("script connector key inactive or scope mismatch"));
    }
    let handle = key
        .secret_ref
        .ok_or_else(|| invalid("script grant has no credential handle"))?;
    let custody = vault
        .resolve_secret_ref(&handle)?
        .ok_or_else(|| invalid("script grant custody absent"))?;
    let metadata = vault
        .get_secret_metadata(&custody)?
        .ok_or_else(|| invalid("script grant custody unavailable"))?;
    if metadata.status != crate::secret_custody::SecretCustodyStatus::Active
        || !metadata.bindings.iter().any(|binding| {
            binding.effector == format!("connector:{}", grant.requested) && binding.grants_read()
        })
    {
        return Err(invalid("script grant custody inactive or unbound"));
    }
    crate::code_sandbox::SandboxCredentialHandle::new(handle)
}

/// Resolves an opaque handle only if its exact connector key and custody
/// binding are still live at the egress boundary (not only before VM boot).
#[cfg(any(test, feature = "microvm-firecracker"))]
struct PackCredentialResolver {
    vault: Arc<Vault>,
    grants: BTreeMap<String, (EntityId, String, CredentialDestination, EntityId)>,
}
#[cfg(any(test, feature = "microvm-firecracker"))]
impl CredentialResolver for PackCredentialResolver {
    fn resolve_for(
        &self,
        handle: &crate::code_sandbox::SandboxCredentialHandle,
        dest: &CredentialDestination,
    ) -> Result<Vec<u8>> {
        let (key_id, connector, bound_dest, agent) = self
            .grants
            .get(handle.as_str())
            .ok_or_else(|| invalid("unbound pack credential handle"))?;
        if dest != bound_dest {
            return Err(invalid("pack credential destination mismatch"));
        }
        let key = self
            .vault
            .get_connector_key(key_id)?
            .ok_or_else(|| invalid("connector key absent"))?;
        if key.status != ConnectorKeyStatus::Active
            || key.connector != *connector
            || key.secret_ref.as_deref() != Some(handle.as_str())
            || key.actor_entity_ref.is_some_and(|bound| bound != *agent)
        {
            return Err(invalid("pack credential key revoked or rotated"));
        }
        let custody = self
            .vault
            .resolve_secret_ref(handle.as_str())?
            .ok_or_else(|| invalid("pack credential custody absent"))?;
        let txn = self.vault.store.env.write_txn()?;
        let value = self
            .vault
            .get_secret_value_in_txn(&txn, &custody, &format!("connector:{connector}"))?
            .ok_or_else(|| invalid("pack credential custody unavailable"))?;
        drop(txn); // Never hold the vault writer while transport performs I/O.
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
