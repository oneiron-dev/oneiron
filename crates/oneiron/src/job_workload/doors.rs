//! The `vault.jobs.workloads.*` doors (pass 33, section 6 rows 2-5; EN-1 A:
//! the owner approves each exact workload).
//!
//! - `pin`: the owner, or an agent whose own live Grant names the verb, pins
//!   one exact workload. A pin approves nothing, and it is written once.
//! - `approve`: the owner's own act, with presence at `Important`, since it
//!   widens what runs on the owner's machines.
//! - `revoke`: the owner's own act; the issuer then stops the workload's
//!   running jobs (EN-4 A, the connector's step).
//! - `get`, `list`: reads for the owner, or an agent whose Grant names the
//!   verb. An agent reads only the workloads its Grant pinned or may start.
use crate::EdgeActorClass;
use crate::authority::{
    NoStanding, PACT_STANDING_LAPSED, VerifiedSlip, principal_standing_or_lapse_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL,
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use crate::world_keys::OwnerActImportance;
use crate::{EntityId, Vault};

use super::record::{
    JOB_WORKLOADS, JobWorkload, WorkloadApproval, WorkloadApprovedBy, WorkloadRevocation,
    digest_key,
};
use super::wire::{
    WorkloadApproveRequest, WorkloadChange, WorkloadList, WorkloadPinRequest, WorkloadRef,
    WorkloadView, parse_ids,
};
use super::{JOB_ALPN, PIN_ARG_BYTES_MAX, PIN_ARGS_MAX, PIN_OUTPUTS_MAX, WorkloadPin};

/// The `vault.jobs.workloads.*` verbs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadVerb {
    Pin,
    Approve,
    Revoke,
    Get,
    List,
}

impl WorkloadVerb {
    /// Every verb, in the order the verb table lists them.
    pub const ALL: [Self; 5] = [
        Self::Pin,
        Self::Approve,
        Self::Revoke,
        Self::Get,
        Self::List,
    ];

    /// The verb's registered name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Pin => "vault.jobs.workloads.pin",
            Self::Approve => "vault.jobs.workloads.approve",
            Self::Revoke => "vault.jobs.workloads.revoke",
            Self::Get => "vault.jobs.workloads.get",
            Self::List => "vault.jobs.workloads.list",
        }
    }

    /// The verb named `name`, if it is one of these.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|verb| verb.name() == name)
    }

    /// Whether only the owner's own proof admits it.
    #[must_use]
    pub const fn is_owner_act(self) -> bool {
        matches!(self, Self::Approve | Self::Revoke)
    }
}

/// Why a workload door refused.
#[derive(Debug, thiserror::Error)]
pub enum WorkloadError {
    #[error(transparent)]
    Vault(#[from] crate::Error),
    /// The caller may not do this act.
    #[error(transparent)]
    Caller(MemoryError),
    #[error("{field} must hold ids in hex")]
    BadId { field: &'static str },
    #[error("the pin is malformed: {why}")]
    BadPin { why: String },
    #[error("a workload with this digest is pinned with other content")]
    PinConflict,
    #[error("no workload is pinned under this digest")]
    NotFound,
    #[error("the owner revoked this workload")]
    Revoked,
    #[error("the approval's expiry is not in the future")]
    ExpiryPast,
    #[error("an approval names at least one machine")]
    NoMachines,
    #[error("the machine {machine} holds no live grant of the job protocol")]
    MachineNotGranted { machine: String },
    #[error("another approval of this workload stands until it expires or is revoked")]
    ApprovalStands,
}

impl From<WorkloadError> for MemoryError {
    fn from(error: WorkloadError) -> Self {
        let refusal = match error {
            WorkloadError::Vault(error) => return error.into(),
            WorkloadError::Caller(error) => return error,
            refusal => refusal,
        };
        let code = match &refusal {
            WorkloadError::Vault(_) | WorkloadError::Caller(_) => MEMORY_CODE_INTERNAL,
            WorkloadError::BadId { .. }
            | WorkloadError::BadPin { .. }
            | WorkloadError::ExpiryPast
            | WorkloadError::NoMachines => MEMORY_CODE_BAD_REQUEST,
            WorkloadError::PinConflict
            | WorkloadError::Revoked
            | WorkloadError::MachineNotGranted { .. }
            | WorkloadError::ApprovalStands => MEMORY_CODE_INVALID_STATE,
            WorkloadError::NotFound => MEMORY_CODE_NOT_FOUND,
        };
        MemoryError::new(code, refusal.to_string(), &[])
    }
}

/// The caller of a workload door: the owner under their own proof, or this
/// handle's agent under its own Grant.
#[derive(Debug, Clone, Copy)]
pub enum WorkloadCaller<'a> {
    Owner(&'a AuthenticatedOwner),
    Agent(&'a WorkloadAgent),
}

/// An agent caller of a workload door, as its own handle bound it. Only
/// [`Memory::workload_agent`] makes one; each door judges its Grant again in
/// its own read or write.
#[derive(Debug, Clone)]
pub struct WorkloadAgent {
    actor: EntityId,
    class: EdgeActorClass,
    credential: Option<VerifiedSlip>,
}

impl WorkloadAgent {
    /// The agent's actor id.
    #[must_use]
    pub fn actor(&self) -> EntityId {
        self.actor
    }

    /// The live Grant that admits this agent to `verb` now, as the standing
    /// rule picks it: its actor binding holds, its presented credential is
    /// still live, and one live Grant from a live owner names it and lists
    /// the verb.
    fn grant_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        verb: WorkloadVerb,
    ) -> MemoryResult<EntityId> {
        if verb.is_owner_act() {
            return Err(refused(verb, "it is the owner's own act"));
        }
        crate::memory::verify_actor_binding_in_txn(vault, txn, self.actor, self.class)?;
        if let Some(slip) = &self.credential
            && !vault.capability_slip_is_live_in_txn(txn, slip)?
        {
            return Err(refused(verb, "the caller's credential is no longer live"));
        }
        let standing = match self.class {
            EdgeActorClass::Agent | EdgeActorClass::System => {
                principal_standing_or_lapse_in_txn(vault, txn, self.actor, self.class, verb.name())?
            }
            EdgeActorClass::Human => Err(NoStanding::NotStanding),
        };
        match standing.map(|standing| standing.grant) {
            Ok(Some(grant)) => Ok(grant),
            Err(NoStanding::PactStandingLapsed) => Err(refused(verb, PACT_STANDING_LAPSED)),
            Ok(None) | Err(NoStanding::NotStanding) => Err(refused(
                verb,
                "no live Grant from a live owner names this agent and lists the verb",
            )),
        }
    }
}

impl Memory<'_> {
    /// This handle's caller as an agent of a workload door.
    #[must_use]
    pub fn workload_agent(&self) -> WorkloadAgent {
        WorkloadAgent {
            actor: self.actor(),
            class: self.actor_class(),
            credential: self.presented_credential().cloned(),
        }
    }

    /// Admits this handle's caller to `verb`. With `owner`, the caller's own
    /// proof decides: revalidated as a live owner of this vault and this
    /// handle's own human actor. Without one, `verb` must not be an owner
    /// act, and one live Grant a live owner gave this handle's agent must
    /// name it now.
    ///
    /// # Errors
    ///
    /// `forbidden` for a caller it does not admit; a store read failure.
    pub fn workload_admits(
        &self,
        owner: Option<&AuthenticatedOwner>,
        verb: WorkloadVerb,
    ) -> MemoryResult<()> {
        let vault = self.vault();
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        crate::memory::verify_actor_binding_in_txn(vault, &txn, self.actor(), self.actor_class())?;
        if let Some(owner) = owner {
            if owner.revalidate_in_txn(vault, &txn)? != self.actor()
                || self.actor_class() != EdgeActorClass::Human
            {
                return Err(refused(
                    verb,
                    "the owner proof does not belong to this caller",
                ));
            }
            return Ok(());
        }
        self.workload_agent()
            .grant_in_txn(vault, &txn, verb)
            .map(drop)
    }
}

/// The refusal of a caller `verb` does not admit.
fn refused(verb: WorkloadVerb, why: &str) -> MemoryError {
    let takes = if verb.is_owner_act() {
        "the vault owner's own proof"
    } else {
        "the vault owner's own proof or an agent's own Grant that names it"
    };
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{} takes {takes}: {why}", verb.name()),
        &["Call it as the vault owner, or name the verb in the agent's Grant."],
    )
}

/// Who the caller is in a read or write: the owner's id, or the agent's
/// Grant for `verb`.
enum Resolved {
    Owner(EntityId),
    Agent { actor: EntityId, grant: EntityId },
}

fn resolve_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: WorkloadCaller<'_>,
    verb: WorkloadVerb,
) -> crate::Result<Result<Resolved, WorkloadError>> {
    match caller {
        WorkloadCaller::Owner(owner) => {
            Ok(Ok(Resolved::Owner(owner.revalidate_in_txn(vault, txn)?)))
        }
        WorkloadCaller::Agent(agent) => Ok(match agent.grant_in_txn(vault, txn, verb) {
            Ok(grant) => Ok(Resolved::Agent {
                actor: agent.actor(),
                grant,
            }),
            Err(refusal) => Err(WorkloadError::Caller(refusal)),
        }),
    }
}

/// Whether an agent under `grant` may read `row`: its Grant pinned it, or
/// the approval names it as a starter.
fn agent_reads(row: &JobWorkload, grant: EntityId) -> bool {
    row.pinned_under == Some(grant)
        || row
            .approval
            .as_ref()
            .is_some_and(|approval| approval.starters.contains(&grant))
}

/// The ids in `ids`, sorted and without repeats.
fn id_set(mut ids: Vec<EntityId>) -> Vec<EntityId> {
    ids.sort_by_key(EntityId::to_hex);
    ids.dedup();
    ids
}

impl Vault {
    /// `caller` pins the exact workload `request.pin`. Pinning approves
    /// nothing. A pin is written once: pinning the same workload again
    /// answers the row that stands.
    ///
    /// # Errors
    ///
    /// [`WorkloadError::BadPin`] for a pin of the wrong shape;
    /// [`WorkloadError::PinConflict`] for a digest pinned with other content;
    /// [`WorkloadError::Caller`] for a caller the door does not admit.
    pub fn pin_job_workload(
        &self,
        caller: WorkloadCaller<'_>,
        request: &WorkloadPinRequest,
        now_ms: u64,
    ) -> Result<WorkloadChange, WorkloadError> {
        check_pin_shape(&request.pin).map_err(|why| WorkloadError::BadPin { why })?;
        let digest = request.pin.digest()?;
        let key = digest_key(&digest).ok_or(crate::Error::InvariantViolation(
            "a workload digest is 64 lower hex",
        ))?;
        if let WorkloadCaller::Owner(owner) = caller {
            owner.revalidate(self)?;
        }
        self.with_write_txn_grouped(
            |txn| -> crate::Result<Result<WorkloadChange, WorkloadError>> {
                let resolved = match resolve_in_txn(self, txn, caller, WorkloadVerb::Pin)? {
                    Ok(resolved) => resolved,
                    Err(refused) => return Ok(Err(refused)),
                };
                if let Some(row) = JOB_WORKLOADS.get(&self.store, txn, &key)? {
                    if row.pin != request.pin {
                        return Ok(Err(WorkloadError::PinConflict));
                    }
                    return Ok(Ok(WorkloadChange {
                        changed: false,
                        workload: WorkloadView::of(&row, now_ms),
                    }));
                }
                let (pinned_by, pinned_under) = match resolved {
                    Resolved::Owner(owner) => (owner, None),
                    Resolved::Agent { actor, grant } => (actor, Some(grant)),
                };
                let row = JobWorkload {
                    digest,
                    pin: request.pin.clone(),
                    pinned_by: Some(pinned_by),
                    pinned_under,
                    pinned_at_ms: now_ms,
                    approval: None,
                    revoked: None,
                };
                JOB_WORKLOADS.put(&self.store, txn, &key, &row)?;
                Ok(Ok(WorkloadChange {
                    changed: true,
                    workload: WorkloadView::of(&row, now_ms),
                }))
            },
        )?
    }

    /// The owner approves the workload `request.workload` on
    /// `request.machines`, for `request.starters`, until
    /// `request.expires_at_ms`. It widens what runs on the owner's machines,
    /// so the owner's presence is checked at `Important` first. The same
    /// approval again answers `changed: false`.
    ///
    /// # Errors
    ///
    /// [`WorkloadError::NotFound`], [`WorkloadError::Revoked`],
    /// [`WorkloadError::ExpiryPast`], [`WorkloadError::NoMachines`],
    /// [`WorkloadError::MachineNotGranted`] for a machine with no live grant
    /// of the job protocol, [`WorkloadError::ApprovalStands`] for a different
    /// approval while one stands; a refused presence check.
    pub fn approve_job_workload(
        &self,
        owner: &AuthenticatedOwner,
        request: &WorkloadApproveRequest,
        now_ms: u64,
    ) -> Result<WorkloadChange, WorkloadError> {
        let key = digest_key(&request.workload).ok_or(WorkloadError::NotFound)?;
        let machines = id_set(parse_ids("machines", &request.machines)?);
        let starters = id_set(parse_ids("starters", &request.starters)?);
        if machines.is_empty() {
            return Err(WorkloadError::NoMachines);
        }
        if request.expires_at_ms <= now_ms {
            return Err(WorkloadError::ExpiryPast);
        }
        owner.revalidate(self)?;
        let granted = self.mesh_machines_granted(JOB_ALPN)?;
        if let Some(machine) = machines.iter().find(|machine| !granted.contains(machine)) {
            return Err(WorkloadError::MachineNotGranted {
                machine: machine.to_hex(),
            });
        }
        let _witness =
            self.owner_presence(OwnerActImportance::Important, WorkloadVerb::Approve.name())?;
        self.with_write_txn_grouped(
            |txn| -> crate::Result<Result<WorkloadChange, WorkloadError>> {
                let by = owner.revalidate_in_txn(self, txn)?;
                let Some(mut row) = JOB_WORKLOADS.get(&self.store, txn, &key)? else {
                    return Ok(Err(WorkloadError::NotFound));
                };
                if row.revoked.is_some() {
                    return Ok(Err(WorkloadError::Revoked));
                }
                if let Some(standing) = row.approval.as_ref()
                    && standing.expires_at_ms > now_ms
                {
                    let same = standing.machines == machines
                        && standing.starters == starters
                        && standing.expires_at_ms == request.expires_at_ms;
                    if !same {
                        return Ok(Err(WorkloadError::ApprovalStands));
                    }
                    return Ok(Ok(WorkloadChange {
                        changed: false,
                        workload: WorkloadView::of(&row, now_ms),
                    }));
                }
                row.approval = Some(WorkloadApproval {
                    by: WorkloadApprovedBy::Owner { owner: Some(by) },
                    machines,
                    starters,
                    expires_at_ms: request.expires_at_ms,
                    at_ms: now_ms,
                });
                JOB_WORKLOADS.put(&self.store, txn, &key, &row)?;
                Ok(Ok(WorkloadChange {
                    changed: true,
                    workload: WorkloadView::of(&row, now_ms),
                }))
            },
        )?
    }

    /// The owner revokes the workload `request.workload`: no later start
    /// passes the gate, and the issuer stops its running jobs. A repeat
    /// answers `changed: false`.
    ///
    /// # Errors
    ///
    /// [`WorkloadError::NotFound`] for no such workload.
    pub fn revoke_job_workload(
        &self,
        owner: &AuthenticatedOwner,
        request: &WorkloadRef,
        now_ms: u64,
    ) -> Result<WorkloadChange, WorkloadError> {
        let key = digest_key(&request.workload).ok_or(WorkloadError::NotFound)?;
        owner.revalidate(self)?;
        self.with_write_txn_grouped(
            |txn| -> crate::Result<Result<WorkloadChange, WorkloadError>> {
                let by = owner.revalidate_in_txn(self, txn)?;
                let Some(mut row) = JOB_WORKLOADS.get(&self.store, txn, &key)? else {
                    return Ok(Err(WorkloadError::NotFound));
                };
                if row.revoked.is_some() {
                    return Ok(Ok(WorkloadChange {
                        changed: false,
                        workload: WorkloadView::of(&row, now_ms),
                    }));
                }
                row.revoked = Some(WorkloadRevocation {
                    by: Some(by),
                    at_ms: now_ms,
                });
                JOB_WORKLOADS.put(&self.store, txn, &key, &row)?;
                Ok(Ok(WorkloadChange {
                    changed: true,
                    workload: WorkloadView::of(&row, now_ms),
                }))
            },
        )?
    }

    /// The workload `request.workload`, as `caller` may read it. An agent
    /// reads only a workload its Grant pinned or may start; any other answers
    /// not found, so a read discloses nothing.
    ///
    /// # Errors
    ///
    /// [`WorkloadError::NotFound`]; [`WorkloadError::Caller`] for a caller
    /// the door does not admit.
    pub fn get_job_workload(
        &self,
        caller: WorkloadCaller<'_>,
        request: &WorkloadRef,
        now_ms: u64,
    ) -> Result<WorkloadView, WorkloadError> {
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let resolved = resolve_in_txn(self, &txn, caller, WorkloadVerb::Get)??;
        let row = self
            .job_workload_in_txn(&txn, &request.workload)?
            .ok_or(WorkloadError::NotFound)?;
        if let Resolved::Agent { grant, .. } = resolved
            && !agent_reads(&row, grant)
        {
            return Err(WorkloadError::NotFound);
        }
        Ok(WorkloadView::of(&row, now_ms))
    }

    /// Every workload `caller` may read, newest pin first.
    ///
    /// # Errors
    ///
    /// [`WorkloadError::Caller`] for a caller the door does not admit.
    pub fn list_job_workloads(
        &self,
        caller: WorkloadCaller<'_>,
        now_ms: u64,
    ) -> Result<WorkloadList, WorkloadError> {
        let resolved = {
            let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
            resolve_in_txn(self, &txn, caller, WorkloadVerb::List)??
        };
        let workloads = self
            .job_workloads()?
            .iter()
            .filter(|row| match resolved {
                Resolved::Owner(_) => true,
                Resolved::Agent { grant, .. } => agent_reads(row, grant),
            })
            .map(|row| WorkloadView::of(row, now_ms))
            .collect();
        Ok(WorkloadList { workloads })
    }
}

/// Whether `text` is `len` lower-hex characters.
fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether `path` is a plain relative path: not empty, not absolute, no
/// empty, `.` or `..` part, no backslash and no NUL.
fn is_relative_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Why `pin` has the wrong shape, if it does (door 2's refusals). The node
/// judges the rest against its own template: the allow-list, the ceilings,
/// the scope.
fn check_pin_shape(pin: &WorkloadPin) -> Result<(), String> {
    if pin.template.is_empty()
        || pin.template.len() > 64
        || !pin.template.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
        })
    {
        return Err("template is a name of 1-64 characters a-z, 0-9, '-', '_' or '.'".into());
    }
    if !is_lower_hex(&pin.template_digest, 64) {
        return Err("template_digest is a sha256 in 64 lower hex".into());
    }
    if !is_lower_hex(&pin.commit, 40) {
        return Err("commit is a revision in 40 lower hex".into());
    }
    if !is_lower_hex(&pin.contract_sha256, 64) {
        return Err("contract_sha256 is a sha256 in 64 lower hex".into());
    }
    if !is_relative_path(&pin.contract_path) {
        return Err("contract_path is a relative path inside the checkout".into());
    }
    if !is_relative_path(&pin.entry) {
        return Err("entry is a relative path inside the checkout".into());
    }
    if pin.args.len() > PIN_ARGS_MAX {
        return Err(format!("args carries at most {PIN_ARGS_MAX} strings"));
    }
    if pin.args.iter().map(String::len).sum::<usize>() > PIN_ARG_BYTES_MAX {
        return Err(format!(
            "args carries at most {PIN_ARG_BYTES_MAX} bytes together"
        ));
    }
    if pin.args.iter().any(|arg| arg.contains('\0')) {
        return Err("an argument holds no NUL".into());
    }
    if pin.request.maximum_secs == 0 {
        return Err("request.maximum_secs is above 0".into());
    }
    if let super::ScopeKind::Container { image } = &pin.scope {
        let pinned = image
            .split_once("@sha256:")
            .is_some_and(|(name, digest)| !name.is_empty() && is_lower_hex(digest, 64));
        if !pinned {
            return Err("a container image is pinned as name@sha256:<64 lower hex>".into());
        }
    }
    if pin.outputs.len() > PIN_OUTPUTS_MAX {
        return Err(format!("outputs declares at most {PIN_OUTPUTS_MAX}"));
    }
    let mut names: Vec<&str> = pin
        .outputs
        .iter()
        .map(|output| output.name.as_str())
        .collect();
    if names.iter().any(|name| !is_relative_path(name)) {
        return Err("an output name is a relative path".into());
    }
    names.sort_unstable();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("output names are distinct".into());
    }
    Ok(())
}
