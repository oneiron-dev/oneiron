//! Where an organ call runs (OF-575, owner ruling MESH): on this machine
//! when it can start the organ, else on another node of the owner's that
//! offers it. With no node able to now, the call waits and says why; being
//! unable to reach compute is never an error to the caller.

use std::sync::Arc;
use std::time::Duration;

use oneiron::Vault;
use oneiron_mesh_transport::{MachineId, MeshTransport};
use tokio::runtime::Handle;

use crate::error::HostError;
use crate::handlers::{AskHandlers, in_handler};
#[cfg(unix)]
use crate::host::OrganHost;
use crate::mesh::{self, ORGAN_ALPN, PeerError};
use crate::outcome::OrganOutcome;
use crate::spec::{LentInput, OrganCall, OrganInput};

/// How long a node has to answer the dial and say what it offers.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
/// What a node's own deadline handling may add before the asking side
/// stops waiting for its reply.
const REPLY_GRACE: Duration = Duration::from_secs(10);

/// Whether this platform lets the engine start organ processes. Phones
/// cannot (each app is one sandboxed process), and neither can a browser.
#[must_use]
pub const fn can_start_organs() -> bool {
    cfg!(all(
        unix,
        not(any(
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos",
            target_os = "android"
        ))
    ))
}

/// The owner's other nodes a call may go to.
pub trait OrganNodes: Send + Sync {
    /// The machines to try, best first; never this one.
    ///
    /// # Errors
    /// The roster could not be read; the call waits and says so.
    fn nodes(&self) -> Result<Vec<MachineId>, String>;
}

/// The vault's MACHINE rows whose grant admits organ calls, without this
/// machine.
#[derive(Clone)]
pub struct VaultOrganNodes(pub Arc<Vault>);

impl std::fmt::Debug for VaultOrganNodes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultOrganNodes")
    }
}

impl OrganNodes for VaultOrganNodes {
    fn nodes(&self) -> Result<Vec<MachineId>, String> {
        let here = self
            .0
            .local_machine()
            .map_err(|err| err.to_string())?
            .map(|local| local.id);
        Ok(self
            .0
            .mesh_machines_granted(ORGAN_ALPN)
            .map_err(|err| err.to_string())?
            .into_iter()
            .filter(|machine| Some(*machine) != here)
            .collect())
    }
}

/// Where a call ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RanOn {
    Here,
    Node(MachineId),
}

/// A call no node can run now, and why, in the router's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeWait {
    pub organ: String,
    pub verb: String,
    /// Every place the call was tried and what each said.
    pub reason: String,
}

/// What became of a routed call.
#[derive(Debug)]
pub enum Routed {
    Done {
        outcome: OrganOutcome,
        ran_on: RanOn,
    },
    /// No node can run it now. [`OrganRouter::submit`] holds such a call
    /// in the vault until one can.
    Waiting(NodeWait),
}

struct MeshLeg {
    transport: Arc<dyn MeshTransport>,
    nodes: Arc<dyn OrganNodes>,
    runtime: Handle,
}

/// Routes organ calls: this machine's host first, then the owner's other
/// nodes over the mesh.
#[derive(Default)]
pub struct OrganRouter {
    #[cfg(unix)]
    local: Option<Arc<OrganHost>>,
    mesh: Option<MeshLeg>,
}

impl std::fmt::Debug for OrganRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("OrganRouter");
        #[cfg(unix)]
        debug.field("local", &self.local.is_some());
        debug.field("mesh", &self.mesh.is_some()).finish()
    }
}

impl OrganRouter {
    /// No host and no mesh: every call waits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs calls on this machine's host first. A host on a platform that
    /// cannot start organs ([`can_start_organs`]) is not used.
    #[cfg(unix)]
    #[must_use]
    pub fn with_local(mut self, host: Arc<OrganHost>) -> Self {
        if can_start_organs() {
            self.local = Some(host);
        }
        self
    }

    /// Sends calls this machine cannot run to the owner's other nodes.
    /// `runtime` drives the transport; a call blocks on it, so call from a
    /// blocking thread, never from inside that runtime.
    #[must_use]
    pub fn with_mesh(
        mut self,
        transport: Arc<dyn MeshTransport>,
        nodes: Arc<dyn OrganNodes>,
        runtime: Handle,
    ) -> Self {
        self.mesh = Some(MeshLeg {
            transport,
            nodes,
            runtime,
        });
        self
    }

    /// Runs one call where it can run: here, else on the first node that
    /// offers its organ and verb. When none can, the call waits, with every
    /// place tried and what each said.
    ///
    /// # Errors
    /// The call ran and failed (the organ's error, its deadline, a revoked
    /// grant, a reply that broke a rule), or an input could not be read
    /// here. Never that no node could run it.
    pub fn call_with(
        &self,
        vault: &Vault,
        call: OrganCall,
        lent: Vec<LentInput>,
        asks: &AskHandlers<'_>,
    ) -> Result<Routed, HostError> {
        if in_handler() {
            return Err(HostError::Reentrant);
        }
        let mut tried: Vec<String> = Vec::new();
        #[cfg(unix)]
        let lent = match &self.local {
            Some(host) => {
                let spare = self.mesh.is_some().then(|| lent.clone());
                match host.call_with(vault, call.clone(), lent, asks) {
                    Ok(outcome) => {
                        return Ok(Routed::Done {
                            outcome,
                            ran_on: RanOn::Here,
                        });
                    }
                    Err(err) if cannot_here(&err) => tried.push(format!("here: {err}")),
                    Err(err) => return Err(err),
                }
                spare.unwrap_or_default()
            }
            None => {
                tried.push("this device does not start organ processes".into());
                lent
            }
        };
        #[cfg(not(unix))]
        tried.push("this device does not start organ processes".into());
        let waiting = |tried: Vec<String>| {
            Ok(Routed::Waiting(NodeWait {
                organ: call.organ.clone(),
                verb: call.verb.clone(),
                reason: format!(
                    "waiting for a node that can run {}.{}: {}",
                    call.organ,
                    call.verb,
                    tried.join("; ")
                ),
            }))
        };
        let Some(mesh) = &self.mesh else {
            tried.push("no mesh to your other nodes".into());
            return waiting(tried);
        };
        let nodes = match mesh.nodes.nodes() {
            Ok(nodes) => nodes,
            Err(err) => {
                tried.push(format!("the node roster: {err}"));
                Vec::new()
            }
        };
        if nodes.is_empty() {
            tried.push("no other node of yours is granted organ calls".into());
            return waiting(tried);
        }
        let inputs = read_inputs(vault, &call, lent)?;
        for machine in nodes {
            let tried_node = mesh
                .runtime
                .block_on(mesh.try_node(machine, &call, &inputs, asks));
            match tried_node {
                Ok(outcome) => {
                    return Ok(Routed::Done {
                        outcome,
                        ran_on: RanOn::Node(machine),
                    });
                }
                Err(PeerError::Absent(why)) => {
                    tried.push(format!("node {}: {why}", machine.to_hex()));
                }
                Err(PeerError::Failed(err)) => return Err(err),
            }
        }
        waiting(tried)
    }
}

impl MeshLeg {
    async fn try_node(
        &self,
        machine: MachineId,
        call: &OrganCall,
        inputs: &[(Option<OrganInput>, LentInput)],
        asks: &AskHandlers<'_>,
    ) -> Result<OrganOutcome, PeerError> {
        let dialed = tokio::time::timeout(DIAL_TIMEOUT, self.transport.dial(machine, ORGAN_ALPN));
        let conn = match dialed.await {
            Ok(Ok(conn)) => conn,
            Ok(Err(err)) => return Err(PeerError::Absent(format!("unreachable: {err}"))),
            Err(_) => return Err(PeerError::Absent("did not answer".into())),
        };
        let ran = async {
            let offers = match tokio::time::timeout(DIAL_TIMEOUT, mesh::offers(&*conn)).await {
                Ok(Ok(offers)) => offers,
                Ok(Err(err)) => return Err(PeerError::Absent(format!("offers: {err}"))),
                Err(_) => return Err(PeerError::Absent("did not say what it offers".into())),
            };
            let offered = offers
                .iter()
                .any(|offer| offer.organ == call.organ && offer.verbs.contains(&call.verb));
            if !offered {
                return Err(PeerError::Absent(format!(
                    "does not offer {}.{}",
                    call.organ, call.verb
                )));
            }
            let longest = Duration::from_millis(u64::from(u32::MAX));
            let wait = call.deadline.min(longest) + REPLY_GRACE;
            match tokio::time::timeout(wait, mesh::call_on(&*conn, machine, call, inputs, asks))
                .await
            {
                Ok(ran) => ran,
                Err(_) => Err(PeerError::Failed(HostError::DeadlineExceeded)),
            }
        }
        .await;
        conn.close();
        ran
    }
}

/// Whether a local failure means this machine cannot run the call now,
/// so another node may: never the organ's own answer.
#[cfg(unix)]
fn cannot_here(err: &HostError) -> bool {
    matches!(
        err,
        HostError::NotInstalled(_)
            | HostError::Unavailable { .. }
            | HostError::Backoff { .. }
            | HostError::UnknownVerb { .. }
            | HostError::Handshake(_)
            | HostError::StartFailed { .. }
            | HostError::BudgetTimeout
            | HostError::OverBudget
            | HostError::MediaTypeNotGranted(_)
            | HostError::Io(_)
    )
}

/// Reads the call's vault inputs here, under the caller's own reach, so
/// the node that runs it needs nothing of this vault: vault inputs first,
/// each with the version it is, then the lent bytes.
fn read_inputs(
    vault: &Vault,
    call: &OrganCall,
    lent: Vec<LentInput>,
) -> Result<Vec<(Option<OrganInput>, LentInput)>, HostError> {
    let mut inputs = Vec::with_capacity(call.inputs.len() + lent.len());
    for input in &call.inputs {
        let read = vault.lend_blob_artifact_version(
            &input.artifact,
            input.version,
            |record, bytes| -> Result<LentInput, HostError> {
                Ok(LentInput {
                    media_type: record.export_media_type.clone(),
                    bytes: bytes.verified()?.into_owned(),
                })
            },
        )?;
        let read = read.unwrap_or_else(|| {
            Err(HostError::InputNotFound {
                artifact: input.artifact.to_hex(),
                version: input.version,
            })
        })?;
        inputs.push((Some(*input), read));
    }
    inputs.extend(lent.into_iter().map(|input| (None, input)));
    Ok(inputs)
}
