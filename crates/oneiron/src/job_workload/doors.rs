//! The `vault.jobs.workloads.*` doors (pass 33, section 6 rows 2-5). Who
//! approves is the Setting `jobs.workloads.agent_may_approve`, whose default
//! is EN-1 A: the owner approves each exact workload.
//!
//! - `pin`: the owner, or an agent whose own live Grant names the verb, pins
//!   one exact workload. A pin approves nothing, and it is written once. The
//!   pin is its own key, so no handle can stand in for a secret in it: the
//!   vault's secret scan refuses one before it is stored.
//! - `approve`: the owner's act, with presence at `Important`, since it
//!   widens what runs on the owner's machines. While the key is on, also an
//!   agent's under its own Grant naming the verb, never on a workload that
//!   agent pinned or for a starter Grant that agent holds. The owner's
//!   approval replaces an agent's; an agent's never replaces one in force.
//! - `revoke`: the owner's act, and while the key is on an agent's under its
//!   own Grant naming the verb, on a workload it may read; the issuer then
//!   stops the workload's running jobs (EN-4 A, the connector's step).
//! - `get`, `list`: reads for the owner, or an agent whose Grant names the
//!   verb. An agent reads the workloads its Grant pinned, and those whose
//!   approval in force names its Grant to start or was the agent's own.
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
use super::setting_keys::agent_may_approve_in_txn;
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

    /// Whether it approves or revokes: the owner's act, and an agent's only
    /// while `jobs.workloads.agent_may_approve` is on.
    #[must_use]
    pub const fn is_approval_act(self) -> bool {
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
    /// An agent's approval of a workload it pinned, or one a Grant it holds
    /// would start: an agent never mints its own approval, whichever of its
    /// Grants it acts under.
    #[error("an agent does not approve a workload it pinned or one a Grant it holds would start")]
    SelfApproval,
    /// An agent's approval names a starter Grant this vault holds no live row
    /// of, so the approval cannot show it is another principal's.
    #[error("the starter Grant {starter} is not live in this vault")]
    StarterNotLive { starter: String },
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
            | WorkloadError::StarterNotLive { .. }
            | WorkloadError::PinnedElsewhere => MEMORY_CODE_INVALID_STATE,
            WorkloadError::SelfApproval => MEMORY_CODE_FORBIDDEN,
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
    /// rule picks it: an approval act only while
    /// `jobs.workloads.agent_may_approve` is on; its actor binding holds, its
    /// presented credential is still live, and one live Grant from a live
    /// owner names it and lists the verb.
    fn grant_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        verb: WorkloadVerb,
    ) -> MemoryResult<EntityId> {
        if verb.is_approval_act() && !agent_may_approve_in_txn(vault, txn)? {
            return Err(refused(
                verb,
                "it is the owner's own act while jobs.workloads.agent_may_approve is off",
            ));
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
    /// gave this handle's agent must name `verb` now, and an approval act
    /// needs `jobs.workloads.agent_may_approve` on.
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
    let (takes, hint) = if verb.is_approval_act() {
        (
            "the vault owner's own proof, or an agent's own Grant that names it while jobs.workloads.agent_may_approve is on",
            "Call it as the vault owner, or ask the owner to turn jobs.workloads.agent_may_approve on and name the verb in the agent's Grant.",
        )
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
    Agent {
        actor: EntityId,
        class: EdgeActorClass,
        grant: EntityId,
    },
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
                class: agent.class,
                grant,
            }),
            Err(refusal) => Err(WorkloadError::Caller(refusal)),
        }),
    }
}

/// Whether the agent `actor`, under `grant`, may read `row` now, in `txn`:
/// its Grant pinned it, or the workload is not revoked and an approval in
/// force that has not expired by `now_ms` names that Grant as a starter or
/// was given by that agent. A starter that may no longer start it, or an
/// approver whose approval no longer stands, reads nothing of it.
fn agent_reads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &JobWorkload,
    actor: EntityId,
    grant: EntityId,
    now_ms: u64,
) -> crate::Result<bool> {
    if row.pinned_under == Some(grant) {
        return Ok(true);
    }
    let Some(approval) = row.approval.as_ref() else {
        return Ok(false);
    };
    let gave_it = matches!(
        approval.by,
        WorkloadApprovedBy::Grant { actor: Some(by), .. } if by == actor
    );
    if row.revoked.is_some()
        || approval.expires_at_ms <= now_ms
        || !(gave_it || approval.starters.contains(&grant))
    {
        return Ok(false);
    }
    vault.approval_in_force_in_txn(txn, &approval.by)
}

/// The principal the Grant `grant` names, while its row is live in `txn`;
/// `None` for no live Grant row.
fn grant_holder_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    grant: EntityId,
) -> crate::Result<Option<EntityId>> {
    Ok(
        match crate::vault::live_entity_row_in_txn(&vault.store, txn, &grant)? {
            crate::vault::LiveEntityRow::Live {
                entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                body,
            } => crate::federation::decode_federation_grant_body(&body)
                .ok()
                .map(|grant| grant.member_ref),
            _ => None,
        },
    )
}

/// Whether the agent `actor`, approving under `grant`, would approve its own
/// work on `row` for `starters`: it pinned the workload, or it holds a Grant
/// that would start it (the named starters, or with none the Grant the
/// workload was pinned under). `Err` names a starter Grant with no live row.
fn self_approval_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &JobWorkload,
    actor: EntityId,
    grant: EntityId,
    starters: &[EntityId],
) -> crate::Result<Result<(), WorkloadError>> {
    if row.pinned_by == Some(actor) || row.pinned_under == Some(grant) {
        return Ok(Err(WorkloadError::SelfApproval));
    }
    let would_start: Vec<EntityId> = if starters.is_empty() {
        row.pinned_under.into_iter().collect()
    } else {
        starters.to_vec()
    };
    for starter in would_start {
        match grant_holder_in_txn(vault, txn, starter)? {
            _ if starter == grant => return Ok(Err(WorkloadError::SelfApproval)),
            Some(holder) if holder == actor => return Ok(Err(WorkloadError::SelfApproval)),
            Some(_) => {}
            None => {
                return Ok(Err(WorkloadError::StarterNotLive {
                    starter: starter.to_hex(),
                }));
            }
        }
    }
    Ok(Ok(()))
}

/// Whether `a` and `b` are the same approver: the owner, or one Grant.
fn same_approver(a: &WorkloadApprovedBy, b: &WorkloadApprovedBy) -> bool {
    match (a, b) {
        (WorkloadApprovedBy::Owner { .. }, WorkloadApprovedBy::Owner { .. }) => true,
        (
            WorkloadApprovedBy::Grant { grant: a, .. },
            WorkloadApprovedBy::Grant { grant: b, .. },
        ) => a == b,
        _ => false,
    }
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
                    if let Resolved::Agent { actor, grant, .. } = resolved
                        && !agent_reads_in_txn(self, txn, &row, actor, grant, now_ms)?
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
    /// first. An agent approves only while `jobs.workloads.agent_may_approve`
    /// is on, under its own Grant naming the verb, and never a workload it
    /// pinned or for a starter Grant it holds. Each machine's job grant is
    /// judged again in the write. An approval stands while it is unexpired
    /// and in force: the owner's replaces an agent's, and the same approver's
    /// same approval again answers `changed: false`.
    ///
    /// # Errors
    ///
    /// [`WorkloadError::NotFound`], [`WorkloadError::Revoked`],
    /// [`WorkloadError::ExpiryPast`], [`WorkloadError::NoMachines`],
    /// [`WorkloadError::MachineNotGranted`] for a machine with no live grant
    /// of the job protocol, [`WorkloadError::ApprovalStands`] for a different
    /// approval while one stands, [`WorkloadError::SelfApproval`],
    /// [`WorkloadError::StarterNotLive`] for an agent's starter Grant with no
    /// live row,
    /// [`WorkloadError::Caller`] for a caller the door does not admit; a
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
                    Ok(Resolved::Agent {
                        actor,
                        class,
                        grant,
                    }) => WorkloadApprovedBy::Grant {
                        actor: Some(actor),
                        class,
                        grant,
                    },
                    Err(refused) => return Ok(Err(refused)),
                };
                let Some(mut row) = JOB_WORKLOADS.get(&self.store, txn, &key)? else {
                    return Ok(Err(WorkloadError::NotFound));
                };
                if row.revoked.is_some() {
                    return Ok(Err(WorkloadError::Revoked));
                }
                if let WorkloadApprovedBy::Grant {
                    actor: Some(actor),
                    grant,
                    ..
                } = &by
                    && let Err(refused) =
                        self_approval_in_txn(self, txn, &row, *actor, *grant, &starters)?
                {
                    return Ok(Err(refused));
                }
                for machine in &machines {
                    if !self.mesh_machine_granted_in_txn(txn, *machine, JOB_ALPN)? {
                        return Ok(Err(WorkloadError::MachineNotGranted {
                            machine: machine.to_hex(),
                        }));
                    }
                }
                // An approval stands while the gate would admit it: unexpired
                // and in force. The owner's replaces an agent's; an agent's
                // never replaces one that stands.
                let owner_over_agent = matches!(by, WorkloadApprovedBy::Owner { .. })
                    && row.approval.as_ref().is_some_and(|standing| {
                        matches!(standing.by, WorkloadApprovedBy::Grant { .. })
                    });
                if let Some(standing) = row.approval.as_ref()
                    && !owner_over_agent
                    && standing.expires_at_ms > now_ms
                    && self.approval_in_force_in_txn(txn, &standing.by)?
                {
                    let same = same_approver(&standing.by, &by)
                        && standing.machines == machines
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
    /// passes the gate, and the issuer stops its running jobs. The owner
    /// revokes; an agent only while `jobs.workloads.agent_may_approve` is
    /// on, under its own Grant naming the verb, and only a workload it may
    /// read. A repeat answers `changed: false`.
    ///
    /// # Errors
    ///
    /// [`WorkloadError::NotFound`] for no such workload, or one an agent may
    /// not read;
    /// [`WorkloadError::Caller`] for a caller the door does not admit.
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
                let (by, under) = match resolve_in_txn(self, txn, caller, WorkloadVerb::Revoke)? {
                    Ok(Resolved::Owner(owner)) => (owner, None),
                    Ok(Resolved::Agent { actor, grant, .. }) => (actor, Some(grant)),
                    Err(refused) => return Ok(Err(refused)),
                };
                let Some(mut row) = JOB_WORKLOADS.get(&self.store, txn, &key)? else {
                    return Ok(Err(WorkloadError::NotFound));
                };
                // An agent revokes only what it may read, so a revoke answers
                // nothing a read would not.
                if let Some(grant) = under
                    && !agent_reads_in_txn(self, txn, &row, by, grant, now_ms)?
                {
                    return Ok(Err(WorkloadError::NotFound));
                }
                if row.revoked.is_some() {
                    return Ok(Ok(WorkloadChange {
                        changed: false,
                        workload: WorkloadView::of(&row, now_ms),
                    }));
                }
                row.revoked = Some(WorkloadRevocation {
                    by: Some(by),
                    under,
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
    /// reads only a workload its Grant pinned, may start now, or approved
    /// with an approval in force; any other answers not found, so a read
    /// discloses nothing.
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
        if let Resolved::Agent { actor, grant, .. } = resolved
            && !agent_reads_in_txn(self, &txn, &row, actor, grant, now_ms)?
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
        let mut workloads = Vec::new();
        for row in self.job_workloads_in_txn(&txn)? {
            let reads = match resolved {
                Resolved::Owner(_) => true,
                Resolved::Agent { actor, grant, .. } => {
                    agent_reads_in_txn(self, &txn, &row, actor, grant, now_ms)?
                }
            };
            if reads {
                workloads.push(WorkloadView::of(&row, now_ms));
            }
        }
        Ok(WorkloadList { workloads })
    }
}
