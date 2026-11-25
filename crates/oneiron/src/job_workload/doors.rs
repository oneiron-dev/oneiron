//! The `vault.jobs.workloads.*` doors (pass 33, section 6 rows 2-5). The
//! owner approves each exact workload (card EN-1 A). Pass 34's check-in of
//! an agent's pin under a standing grant is R2's follow-up PR.
//!
//! - `pin`: the owner, or an agent whose own live Grant names the verb, pins
//!   one exact workload. A pin approves nothing, and it is written once. The
//!   pin is its own key, so no handle can stand in for a secret in it: the
//!   vault's secret scan refuses one before it is stored.
//! - `approve`: the owner's own act, with presence at `Important`, since it
//!   widens what runs on the owner's machines.
//! - `revoke`: the owner's own act; the issuer then stops the workload's
//!   running jobs (EN-4 A, the connector's step).
//! - `get`, `list`: reads for the owner, or an agent whose Grant names the
//!   verb. An agent reads the workloads its Grant pinned, and those whose
//!   approval, unexpired and not revoked, names its Grant to start.
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

use super::pin_shape::check_pin_shape;
use super::record::{
    JOB_WORKLOADS, JobWorkload, WorkloadApproval, WorkloadApprovedBy, WorkloadRevocation,
    digest_key,
};
use super::wire::{
    WorkloadApproveRequest, WorkloadChange, WorkloadList, WorkloadPinRequest, WorkloadRef,
    WorkloadView, parse_ids,
};
use super::{JOB_ALPN, WorkloadPin};

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

    /// Whether it approves or revokes: the vault owner's own act, which no
    /// agent's Grant admits.
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
    /// An agent's pin of a workload pinned before under a Grant that agent
    /// may not read it through.
    #[error("this exact workload is already pinned under another Grant")]
    PinnedElsewhere,
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
            | WorkloadError::ApprovalStands
            | WorkloadError::PinnedElsewhere => MEMORY_CODE_INVALID_STATE,
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
    /// rule picks it: never for the owner's own acts; its actor binding
    /// holds, its presented credential is still live, and one live Grant from
    /// a live owner names it and lists the verb.
    fn grant_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        verb: WorkloadVerb,
    ) -> MemoryResult<EntityId> {
        if verb.is_owner_act() {
            return Err(refused(verb, "it is the vault owner's own act"));
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
    /// handle's own human actor. Without one, one live Grant a live owner
    /// gave this handle's agent must name `verb` now, and an approve or a
    /// revoke admits no agent.
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
    let (takes, hint) = if verb.is_owner_act() {
        ("the vault owner's own proof", "Call it as the vault owner.")
    } else {
        (
            "the vault owner's own proof or an agent's own Grant that names it",
            "Call it as the vault owner, or name the verb in the agent's Grant.",
        )
    };
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{} takes {takes}: {why}", verb.name()),
        &[hint],
    )
}

/// Who the caller is in a read or write: the owner's id, or the agent and
/// its Grant for `verb`.
#[derive(Clone, Copy)]
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

/// Whether an agent under `grant` may read `row` at `now_ms`: its Grant
/// pinned it, or the workload is not revoked and its approval, unexpired,
/// names that Grant as a starter. A starter that may no longer start it
/// reads nothing of it.
fn agent_reads(row: &JobWorkload, grant: EntityId, now_ms: u64) -> bool {
    row.pinned_under == Some(grant)
        || (row.revoked.is_none()
            && row.approval.as_ref().is_some_and(|approval| {
                approval.expires_at_ms > now_ms && approval.starters.contains(&grant)
            }))
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
    /// the secret scan's refusal for a new pin that holds a secret;
    /// [`WorkloadError::PinnedElsewhere`] for an agent's pin of a workload
    /// that stands under a Grant it may not read it through, so the answer
    /// carries no approval it may not read;
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
                    if let Resolved::Agent { grant, .. } = resolved
                        && !agent_reads(&row, grant, now_ms)
                    {
                        return Ok(Err(WorkloadError::PinnedElsewhere));
                    }
                    return Ok(Ok(WorkloadChange {
                        changed: false,
                        workload: WorkloadView::of(&row, now_ms),
                    }));
                }
                // The pin is hashed into its own key and compared on a
                // repeat, so no custody handle can stand in for a secret in
                // it: the batch door's scan refuses one, under the owner's
                // switch, before the row is written.
                let pin_bytes = crate::llm::canonical_json_bytes(&request.pin)
                    .map_err(|_| crate::Error::InvariantViolation("workload pin encode"))?;
                crate::batch::secret_scan::scan_content_in_txn(&self.store, txn, &pin_bytes)?;
                let (pinned_by, pinned_under) = match resolved {
                    Resolved::Owner(owner) => (owner, None),
                    Resolved::Agent { actor, grant, .. } => (actor, Some(grant)),
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

    /// `caller` approves the workload `request.workload` on
    /// `request.machines`, for `request.starters`, until
    /// `request.expires_at_ms`. The owner's approval widens what runs on the
    /// owner's machines, so the owner's presence is checked at `Important`
    /// first. No agent approves. Each machine's job grant is judged again in
    /// the write. An approval stands until it expires: the same approval
    /// again answers `changed: false`, and another one is refused.
    ///
    /// # Errors
    ///
    /// [`WorkloadError::NotFound`], [`WorkloadError::Revoked`],
    /// [`WorkloadError::ExpiryPast`], [`WorkloadError::NoMachines`],
    /// [`WorkloadError::MachineNotGranted`] for a machine with no live grant
    /// of the job protocol, [`WorkloadError::ApprovalStands`] for a different
    /// approval while one stands, [`WorkloadError::Caller`] for a caller the
    /// door does not admit (every agent); a
    /// refused presence check.
    pub fn approve_job_workload(
        &self,
        caller: WorkloadCaller<'_>,
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
        let _witness = match caller {
            WorkloadCaller::Owner(owner) => {
                owner.revalidate(self)?;
                let granted = self.mesh_machines_granted(JOB_ALPN)?;
                if let Some(machine) = machines.iter().find(|machine| !granted.contains(machine)) {
                    return Err(WorkloadError::MachineNotGranted {
                        machine: machine.to_hex(),
                    });
                }
                Some(
                    self.owner_presence(
                        OwnerActImportance::Important,
                        WorkloadVerb::Approve.name(),
                    )?,
                )
            }
            WorkloadCaller::Agent(_) => None,
        };
        self.with_write_txn_grouped(
            |txn| -> crate::Result<Result<WorkloadChange, WorkloadError>> {
                let by = match resolve_in_txn(self, txn, caller, WorkloadVerb::Approve)? {
                    Ok(Resolved::Owner(owner)) => WorkloadApprovedBy::Owner { owner: Some(owner) },
                    Ok(Resolved::Agent { .. }) => {
                        return Ok(Err(WorkloadError::Caller(refused(
                            WorkloadVerb::Approve,
                            "it is the vault owner's own act",
                        ))));
                    }
                    Err(refused) => return Ok(Err(refused)),
                };
                let Some(mut row) = JOB_WORKLOADS.get(&self.store, txn, &key)? else {
                    return Ok(Err(WorkloadError::NotFound));
                };
                if row.revoked.is_some() {
                    return Ok(Err(WorkloadError::Revoked));
                }
                for machine in &machines {
                    if !self.mesh_machine_granted_in_txn(txn, *machine, JOB_ALPN)? {
                        return Ok(Err(WorkloadError::MachineNotGranted {
                            machine: machine.to_hex(),
                        }));
                    }
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
                    by,
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

    /// `caller` revokes the workload `request.workload`: no later start
    /// passes the gate, and the issuer stops its running jobs. The owner's
    /// own act: no agent revokes. A repeat answers `changed: false`.
    ///
    /// # Errors
    ///
    /// [`WorkloadError::NotFound`] for no such workload;
    /// [`WorkloadError::Caller`] for a caller the door does not admit (every
    /// agent).
    pub fn revoke_job_workload(
        &self,
        caller: WorkloadCaller<'_>,
        request: &WorkloadRef,
        now_ms: u64,
    ) -> Result<WorkloadChange, WorkloadError> {
        let key = digest_key(&request.workload).ok_or(WorkloadError::NotFound)?;
        if let WorkloadCaller::Owner(owner) = caller {
            owner.revalidate(self)?;
        }
        self.with_write_txn_grouped(
            |txn| -> crate::Result<Result<WorkloadChange, WorkloadError>> {
                let by = match resolve_in_txn(self, txn, caller, WorkloadVerb::Revoke)? {
                    Ok(Resolved::Owner(owner)) => owner,
                    Ok(Resolved::Agent { .. }) => {
                        return Ok(Err(WorkloadError::Caller(refused(
                            WorkloadVerb::Revoke,
                            "it is the vault owner's own act",
                        ))));
                    }
                    Err(refused) => return Ok(Err(refused)),
                };
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
    /// reads only a workload its Grant pinned or may start now; any other
    /// answers not found, so a read discloses nothing.
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
            && !agent_reads(&row, grant, now_ms)
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
        let txn = self.store.env.read_txn().map_err(crate::Error::from)?;
        let resolved = resolve_in_txn(self, &txn, caller, WorkloadVerb::List)??;
        let workloads = self
            .job_workloads_in_txn(&txn)?
            .iter()
            .filter(|row| match resolved {
                Resolved::Owner(_) => true,
                Resolved::Agent { grant, .. } => agent_reads(row, grant, now_ms),
            })
            .map(|row| WorkloadView::of(row, now_ms))
            .collect();
        Ok(WorkloadList { workloads })
    }
}
