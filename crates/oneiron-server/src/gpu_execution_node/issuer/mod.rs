//! The issuer's `vault_machine` GPU job backend (pass 33 section 8): the connector that runs a
//! job's chunk on one of the vault's own machines over the job protocols, and what registers it.
//!
//! - [`connector`]: [`VaultMachineConnector`], the backend itself.
//! - [`node_client`]: the calls to a node, over the mesh or by script.
//! - [`billing`]: the bracket, the billed seconds and the typed terminal.
//! - [`reconcile`]: the reconcile of a node before the first dispatch to it.
//! - [`orphans`]: the keys a node holds that the issuer has no dispatch row for (row R4).
//! - [`guard`]: the issuer's half of the drain guard (row R4).
//! - [`view`]: the four status fields of door 8 (row R4).
//! - [`returns`]: the returned result, landed as a proposal, and the acknowledgement (row R4).
//! - [`clock`]: the wall and boot clocks the dispatch and the bracket read.
//! - [`register`]: where the backend may exist, and the one-issuer check of the start gate.
//! - [`machine_execution`]: the asks behind `vault.machines.execution.get`.
//!
//! The rows it writes are oneiron's `job_dispatch` tables. The quote names the machine
//! (`inputs.machine`), so the job row fixes the target before any network call.

pub mod billing;
pub mod clock;
pub mod connector;
pub mod guard;
pub mod machine_execution;
pub mod node_client;
pub mod node_status;
pub mod orphans;
pub mod reconcile;
pub mod register;
pub mod returns;
pub mod view;

use oneiron::EntityId;
use oneiron::gpu_job::GpuJobResultBinding;
use oneiron::job_workload::WorkloadStartRefusal;

pub use clock::{IssuerClock, SystemIssuerClock};
pub use connector::{VaultMachineConnector, VaultMachineParts};
pub use machine_execution::{MACHINE_EXECUTION_KEY_PAGES_MAX, read_machine_execution};
#[cfg(feature = "mesh")]
pub use node_client::MeshJobNodeClient;
pub use node_client::{JobNodeClient, NodeCallError};
pub use orphans::{JobOrphanKeys, LoggedUnattributedLedger, UnattributedLedger};
pub use reconcile::{LoggedOrphanKeys, OrphanKeys};
pub use register::{
    NotTheIssuer, VaultMachineNotRegistered, issuer_machine, not_the_issuer,
    register_vault_machine, register_vault_machine_at_start, vault_machine_backend,
};
pub use returns::ResultReturns;

use crate::gpu_execution_node::wire::{JobAnswer, JobRefusal, JobStatusAnswer, SlotSelector};

/// The backend registry's name for the connector, as an offer's `backend` names it.
pub const VAULT_MACHINE_BACKEND: &str = "vault_machine";

/// What a refusal of door 6 or 7 says to a caller who may not read
/// `vault.machines.execution.get`.
pub const NOT_AVAILABLE_TO_THIS_CALLER: &str = "not_available_to_this_caller";

/// A `vault_machine` quote's inputs: the machine that runs the job (required), the GPU it
/// may take, and where its returned result lands (EM-12 = A). Other fields (a lane's arm
/// binding) pass through untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultMachineInputs {
    pub machine: EntityId,
    pub device_id: Option<String>,
    pub model: Option<String>,
    /// `inputs.result { artifact, task }`: each returnable output becomes the artifact's next
    /// version, pending Keep, made by the task. Absent: the issuer fetches nothing.
    pub result: Option<GpuJobResultBinding>,
}

impl VaultMachineInputs {
    /// The GPU slot selectors a reserve and a submit carry.
    #[must_use]
    pub fn slot(&self) -> SlotSelector {
        SlotSelector {
            device_id: self.device_id.clone(),
            model: self.model.clone(),
        }
    }
}

/// Reads a `vault_machine` quote's inputs.
///
/// # Errors
///
/// `machine_missing` when `inputs.machine` is absent or not a MACHINE id in hex;
/// `device_id_invalid` or `model_invalid` when one is present and not a string;
/// `result_invalid` when `inputs.result` is present and not `{ artifact, task }` ids.
pub fn vault_machine_inputs(
    inputs: &serde_json::Value,
) -> Result<VaultMachineInputs, &'static str> {
    let machine = inputs
        .get("machine")
        .and_then(serde_json::Value::as_str)
        .and_then(|hex| EntityId::from_hex(hex).ok())
        .ok_or("machine_missing")?;
    let text = |name: &str, refusal: &'static str| match inputs.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(refusal),
    };
    let result = match inputs.get("result") {
        None | Some(serde_json::Value::Null) => None,
        Some(binding) => Some(
            serde_json::from_value::<GpuJobResultBinding>(binding.clone())
                .map_err(|_| "result_invalid")?,
        ),
    };
    Ok(VaultMachineInputs {
        machine,
        device_id: text("device_id", "device_id_invalid")?,
        model: text("model", "model_invalid")?,
        result,
    })
}

/// The code a start-gate refusal shows the caller (section 6: a refusal does not disclose). A
/// refusal that names the machine or what it said is shown only to a caller who may read
/// `vault.machines.execution.get`; any other caller gets [`NOT_AVAILABLE_TO_THIS_CALLER`].
#[must_use]
pub fn refusal_code_for_caller(
    refusal: &WorkloadStartRefusal,
    may_read_machines: bool,
) -> &'static str {
    if refusal.discloses_machine() && !may_read_machines {
        NOT_AVAILABLE_TO_THIS_CALLER
    } else {
        refusal.code()
    }
}

/// A node's refusal before any journal, by name.
#[must_use]
pub fn job_refusal_code(refusal: &JobRefusal) -> &'static str {
    match refusal {
        JobRefusal::NotEnabled => "not_enabled",
        JobRefusal::PeerNotProven => "peer_not_proven",
        JobRefusal::NotIssuer => "not_issuer",
        JobRefusal::OwnGrantEnded => "own_grant_ended",
        JobRefusal::IssuerStandingEnded => "issuer_standing_ended",
        JobRefusal::Paused { .. } => "paused",
        JobRefusal::Drained { .. } => "drained",
        JobRefusal::NotReleasable { .. } => "not_releasable",
        JobRefusal::HistoryLost => "history_lost",
        JobRefusal::KeyConflict => "key_conflict",
        JobRefusal::NotTheKeysIssuer => "not_the_keys_issuer",
        JobRefusal::SubmitSignatureInvalid => "submit_signature_invalid",
        JobRefusal::DevicesUnreadable { .. } => "devices_unreadable",
        JobRefusal::OutputNotFetchable { .. } => "output_not_fetchable",
        JobRefusal::NotAcknowledgeable { .. } => "not_acknowledgeable",
        JobRefusal::LogNotReadable { .. } => "log_not_readable",
    }
}

/// An answer on the new-work protocol, by kind: what a log names without its body.
#[must_use]
pub fn job_answer_kind(answer: &JobAnswer) -> &'static str {
    match answer {
        JobAnswer::Node(_) => "node",
        JobAnswer::Availability(_) => "availability",
        JobAnswer::Receipt(_) => "receipt",
        JobAnswer::Busy { .. } => "busy",
        JobAnswer::Refused(_) => "refused",
    }
}

/// An answer on the status protocol, by kind.
#[must_use]
pub fn status_answer_kind(answer: &JobStatusAnswer) -> &'static str {
    match answer {
        JobStatusAnswer::Known(_) => "known",
        JobStatusAnswer::Absent { .. } => "absent",
        JobStatusAnswer::HistoryLost => "history_lost",
        JobStatusAnswer::Busy { .. } => "busy",
        JobStatusAnswer::Keys(_) => "keys",
        JobStatusAnswer::Output { .. } => "output",
        JobStatusAnswer::Acknowledged => "acknowledged",
        JobStatusAnswer::Refused(_) => "refused",
        JobStatusAnswer::Tail(_) => "tail",
    }
}
