//! The browser program admission job (CUA E8b; DESIGN-2 "The Coach", row
//! E8): the Coach proposes a program it induced from a group's solved runs,
//! and this job admits it or says why not. The Coach never admits its own
//! work. Its write lands its Proposed finding, its seen marker and this job
//! in one commit ([`enqueue_program_admission_in_txn`]). The host's worker
//! claims the job, re-opens the pre-press page under the SOURCE caller,
//! revalidated at use, and proposes the program through the library's own
//! door, whose page check, fresh no-model replay and filing are the only
//! admission.
//!
//! A job runs once. One claimed again was cut off when its process stopped:
//! it is never run again, and its receipt names the program a filing in its
//! run filed, read from the association that filing wrote in its own write
//! ([`ProgramAdmissionFiling`]), never guessed from a lost answer.
//!
//! A receipt keeps references and typed outcomes only: no actor, no page
//! row, no replay operand and no credential. Once a job ends, the signed
//! binding each of its sources kept is dropped: a later job for the group
//! acts on a fresh capture's binding, or ends unavailable.

use oneiron_browser::{ProposeInput, SubgoalStatus, SupersedeOutcome, WorkflowCheck};
use serde::{Deserialize, Serialize};

use super::evidence::{SavedBrowserCaller, SolvedRunEvidence, SolvedRunScope};
use super::index::{drop_witness_in_txn, evidence_of, program_seen, saved_caller_in};
use crate::Vault;
use crate::WriteActor;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, EnqueueAttempt, EnqueueOutcome,
};
use crate::authority::InvocationSlipBinding;
use crate::claim::{CallerLocality, ScopedReadActorKey};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::runtime_hooks::verb::VerbAskCredentialRef;
use crate::side_table::{self, Named, SideTable};

/// The attempt kind the host's admission worker claims (CUA E8b).
pub const PROGRAM_ADMISSION_KIND: &str = "browser.program.admit";

/// Each admission job's receipt, and the association a filing in its run
/// wrote. Key: the job's id.
const RECEIPTS: SideTable<EntityId, ProgramAdmissionReceipt, Named> =
    SideTable::new(&side_table::BROWSER_PROGRAM_ADMISSION);

/// A program the Coach proposes for admission (CUA E8b): the payload of a
/// [`PROGRAM_ADMISSION_KIND`] attempt. It names its sources by their
/// evidence claims; the source authority each was captured under is kept
/// beside its claim, never here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramAdmissionJob {
    /// The Coach's Proposed finding this job admits.
    pub finding: EntityId,
    /// The candidate's input fingerprint, in
    /// [`super::CANDIDATE_DOMAIN`]: its seen marker's key.
    pub fingerprint: [u8; 32],
    /// The digest of the scoped group it was induced in.
    pub group: [u8; 32],
    /// The group's scope: the caller its sources were captured under.
    pub scope: SolvedRunScope,
    /// What the job proposes, as that caller.
    pub proposal: ProposeInput,
    /// The distinct source runs it was induced from.
    pub from_runs: Vec<EntityId>,
    /// Their evidence claims.
    pub source_evidence: Vec<EntityId>,
    /// The program it repairs, when induced from that program's failures.
    pub predecessor: Option<EntityId>,
    /// The failure generation it read, for a repair.
    pub failure_generation: u64,
    pub induction_version: u32,
}

impl ProgramAdmissionJob {
    /// Decodes a claimed attempt of [`PROGRAM_ADMISSION_KIND`].
    ///
    /// # Errors
    ///
    /// Another kind, or a payload that does not decode.
    pub fn decode(attempt: &AttemptRecord) -> Result<Self> {
        if attempt.kind != PROGRAM_ADMISSION_KIND {
            return Err(Error::InvariantViolation(
                "not a browser program admission attempt",
            ));
        }
        serde_json::from_slice(&attempt.payload)
            .map_err(|_| Error::CorruptedIndex("browser program admission payload"))
    }

    /// The filing context the job's run files under, as job `job`.
    #[must_use]
    pub const fn filing(&self, job: EntityId) -> ProgramAdmissionFiling {
        ProgramAdmissionFiling {
            job,
            finding: self.finding,
            fingerprint: self.fingerprint,
        }
    }
}

/// The source actor a [`PROGRAM_ADMISSION_KIND`] payload was captured
/// under (FIX 10718): its scope's actor, when the payload decodes. The
/// erase pass reads it to scrub an erased actor's payloads; a payload
/// that does not decode names no actor.
pub(crate) fn admission_payload_actor(payload: &[u8]) -> Option<EntityId> {
    serde_json::from_slice::<ProgramAdmissionJob>(payload)
        .map(|job| job.scope.actor)
        .ok()
}

/// The job a filing in an admission run files for (CUA E8b): the filing's
/// own write keeps the program it filed against the job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramAdmissionFiling {
    pub job: EntityId,
    pub finding: EntityId,
    pub fingerprint: [u8; 32],
}

/// What an admission job came to (CUA E8b).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramAdmissionOutcome {
    /// The library's own door filed the program as `workflow`.
    Admitted {
        workflow: EntityId,
        superseded: Option<SupersedeOutcome>,
    },
    /// The library's door refused it: its check, and the postcondition
    /// checks the page missed, by index.
    Refused {
        check: Option<WorkflowCheck>,
        unmet: Vec<usize>,
    },
    /// The page the proposal's steps reached is not its pre-press page:
    /// the no-model batch ended so, and nothing was proposed.
    ReconstructionStopped { status: SubgoalStatus },
    /// The proposal names parameters it gives no value.
    ArgsMissing { params: Vec<String> },
    /// The proposal's secret slots take secrets this run does not hold.
    SecretsUnbound { slots: Vec<String> },
    /// The source caller could not be established at use.
    CredentialUnavailable { cause: CallerUnavailable },
    /// The sources no longer stand as the job named them.
    SourceUnavailable { cause: SourceUnavailable },
    /// The browser's door refused a call, by its code.
    BrowserRefused { code: String },
    /// The job was cut off when its process stopped and was not run again:
    /// the program a filing in its run filed, if one did.
    Interrupted { filed: Option<EntityId> },
    /// An engine error stopped the job, by its kind alone.
    Failed { kind: String },
    /// The job's payload did not decode: its receipt keeps empty refs,
    /// and its sources' kept bindings are dropped, as every ended job's
    /// are.
    Undecodable,
}

/// Why the source caller could not be established (CUA E8b).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerUnavailable {
    /// The slip's mint, or the kept binding, is gone.
    CredentialMissing,
    /// The slip or an ancestor was revoked.
    CredentialRevoked,
    /// The slip's lifetime ended.
    CredentialExpired,
    /// The binding no longer verifies as the instrument the source used.
    CredentialChanged,
    /// The host could not establish it: a registration it does not hold.
    CredentialUnavailable,
    /// No binding is kept for the source: an earlier job used and dropped
    /// it, or the capture kept none.
    InstrumentNotHeld,
    /// The credential's scope, its connector's or the agent's grant no
    /// longer admits the call.
    ScopeRefused,
    /// No door rebuilds this caller: a person with no credential.
    ContextUnavailable,
    /// The managed vault's attested owner the source acted as is no longer
    /// its live owner (FIX 11690): his lapse, not the door's.
    OwnerNotLive,
}

/// Why a job's sources no longer stand (CUA E8b).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceUnavailable {
    /// The job names no source.
    NoSources,
    /// A source's claim or its source authority was erased.
    Erased { evidence: EntityId },
    /// A source's claim no longer reads as its caller.
    Withheld { evidence: EntityId },
    /// A source no longer stands in the job's scope, group or runs.
    Changed { evidence: EntityId },
    /// The Coach's finding is gone.
    FindingGone,
    /// The candidate's seen marker names another finding or job: a newer
    /// proposal took this one's place.
    ProposalMoved,
}

/// An admission job's receipt (CUA E8b): references and its typed outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramAdmissionReceipt {
    pub job: EntityId,
    pub finding: EntityId,
    pub fingerprint: [u8; 32],
    pub source_evidence: Vec<EntityId>,
    /// The admission run the job's calls were made in.
    pub run_id: Option<EntityId>,
    /// The program a filing in the job's run filed, written in that
    /// filing's own write.
    pub filed: Option<EntityId>,
    /// None while only the filing is written.
    pub outcome: Option<ProgramAdmissionOutcome>,
    pub settled_at: Option<u64>,
}

/// Who a job's sources were captured under, read again when it runs (CUA
/// E8b).
#[derive(Debug, Clone)]
pub enum AdmissionCaller {
    /// A native agent's own pumped runs: the job acts as that agent.
    Agent(WriteActor),
    /// A credential caller: its reference, and the binding its request was
    /// admitted on while one is kept, which the host verifies again.
    Credential {
        actor: WriteActor,
        reference: VerbAskCredentialRef,
        witness: Option<InvocationSlipBinding>,
    },
    /// A person with no credential: the host acts for them only while they
    /// are this vault's live recorded owner, proved afresh at each use.
    Person(WriteActor),
    /// No door rebuilds it: a caller with no credential that is no person
    /// and no agent's own run.
    Unsupported,
}

/// A job's sources as they stand now (CUA E8b): their caller and their
/// evidence, read as that caller.
#[derive(Debug, Clone)]
pub struct AdmissionSources {
    pub caller: AdmissionCaller,
    pub evidence: Vec<SolvedRunEvidence>,
}

/// The id of the admission job `attempt` is: its attempt id's bytes.
///
/// # Errors
///
/// Bytes that are no entity id.
pub fn program_admission_job_id(attempt: &AttemptRecord) -> Result<EntityId> {
    EntityId::from_bytes(*attempt.id.as_bytes())
}

/// Queues `job` in the caller's write `wtxn` (CUA E8b), beside the Coach's
/// finding and seen marker, and answers its job id for that marker. The
/// same candidate's job still queued for the same caller is answered again
/// (its fingerprint is the dedupe key, scoped to the caller). Call
/// [`program_admission_queued`] once the write commits.
///
/// # Errors
///
/// A payload that does not encode, and storage errors.
pub fn enqueue_program_admission_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    job: &ProgramAdmissionJob,
    now: u64,
) -> Result<EntityId> {
    let payload = serde_json::to_vec(job).map_err(|_| {
        Error::InvariantViolation("browser program admission payload encode failed")
    })?;
    let actor = job.scope.actor.to_hex();
    let input = EnqueueAttempt {
        kind: PROGRAM_ADMISSION_KIND.to_owned(),
        payload,
        dedupe_key: Some(crate::entity_id::bytes_to_hex_lower(&job.fingerprint)),
        run_id: None,
        now,
    };
    let outcome = AttemptQueue::new(vault).enqueue_with_task_ref_and_dedupe_actor_in_txn(
        wtxn,
        input,
        None,
        Some(actor.as_str()),
    )?;
    let (EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record)) = outcome;
    program_admission_job_id(&record)
}

/// Wakes the host's admission worker once the write that queued a job
/// committed (CUA E8b). Never before: the signal is no durability.
pub fn program_admission_queued(vault: &Vault) {
    vault.store.notify_attempt_observers();
}

/// The sources of job `job_id` as they stand now (CUA E8b): its seen marker
/// still names it, its finding stands, each source's authority row stands
/// in its scope, group and runs, and each claim reads as its caller. The
/// first source that does not stand is the answer.
///
/// # Errors
///
/// Storage errors, or the read's own refusal.
pub fn admission_sources(
    vault: &Vault,
    job_id: EntityId,
    job: &ProgramAdmissionJob,
) -> Result<std::result::Result<AdmissionSources, SourceUnavailable>> {
    let Some(first) = job.source_evidence.first().copied() else {
        return Ok(Err(SourceUnavailable::NoSources));
    };
    let proposed = program_seen(vault, &job.fingerprint)?.is_some_and(|seen| {
        seen.finding == job.finding && seen.job.is_none_or(|marked| marked == job_id)
    });
    if !proposed {
        return Ok(Err(SourceUnavailable::ProposalMoved));
    }
    let mut callers = Vec::with_capacity(job.source_evidence.len());
    {
        let rtxn = vault.store.env.read_txn()?;
        if vault.get_entity_type_in_txn(&rtxn, &job.finding)?.is_none() {
            return Ok(Err(SourceUnavailable::FindingGone));
        }
        for id in &job.source_evidence {
            let Some(caller) = saved_caller_in(vault, &rtxn, id)? else {
                return Ok(Err(SourceUnavailable::Erased { evidence: *id }));
            };
            if caller.scope != job.scope
                || caller.group != job.group
                || !job.from_runs.contains(&caller.run_id)
            {
                return Ok(Err(SourceUnavailable::Changed { evidence: *id }));
            }
            callers.push(caller);
        }
    }
    let Some(class) = EdgeActorClass::try_from_u8(job.scope.actor_class) else {
        return Ok(Err(SourceUnavailable::Changed { evidence: first }));
    };
    let actor = WriteActor::new(job.scope.actor, class);
    let key =
        ScopedReadActorKey::with_actor_class(job.scope.actor.to_hex(), class.gate_actor_class())
            .ok_or(Error::InvalidClaimBody("solved run scope"))?;
    let read = vault.scoped_read(key.at(CallerLocality::OnDevice));
    let rows = read.get_entities_parts_with_receipt(&job.source_evidence, None)?;
    let mut evidence = Vec::with_capacity(job.source_evidence.len());
    for (id, row) in job.source_evidence.iter().zip(rows.value) {
        let Some((entity_type, _, body)) = row else {
            return Ok(Err(SourceUnavailable::Withheld { evidence: *id }));
        };
        match evidence_of(entity_type, &body) {
            Some(found) if found.id == *id && found.group().digest() == job.group => {
                evidence.push(found);
            }
            _ => return Ok(Err(SourceUnavailable::Changed { evidence: *id })),
        }
    }
    let caller = source_caller(vault, actor, &callers)?;
    Ok(Ok(AdmissionSources { caller, evidence }))
}

/// Who `callers`, one job's sources' authority rows, were captured under
/// (CUA E8b, CALLS row "source kinds"): a credential caller by the
/// reference its rows keep, with the first binding still kept; a person
/// with no credential, whom the host proves its live owner at use or acts
/// for not at all; a native agent when every source run is that agent's
/// own pumped run; any other caller is none a door rebuilds.
fn source_caller(
    vault: &Vault,
    actor: WriteActor,
    callers: &[SavedBrowserCaller],
) -> Result<AdmissionCaller> {
    if let Some(reference) = callers.iter().find_map(|caller| caller.credential.clone()) {
        let witness = callers.iter().find_map(|caller| caller.witness.clone());
        return Ok(AdmissionCaller::Credential {
            actor,
            reference,
            witness,
        });
    }
    match actor.actor_class() {
        EdgeActorClass::Human => return Ok(AdmissionCaller::Person(actor)),
        EdgeActorClass::Agent => {}
        EdgeActorClass::System => return Ok(AdmissionCaller::Unsupported),
    }
    for caller in callers {
        if !native_agent_run(vault, caller.run_id, actor.entity_ref())? {
            return Ok(AdmissionCaller::Unsupported);
        }
    }
    Ok(AdmissionCaller::Agent(actor))
}

/// Whether run `run_id` is agent `agent`'s own pumped run: the agent
/// dispatch attempt whose id it is.
fn native_agent_run(vault: &Vault, run_id: EntityId, agent: EntityId) -> Result<bool> {
    let attempt = AttemptId::from_bytes(run_id.as_bytes())?;
    let Some(record) = AttemptQueue::new(vault).get(attempt)? else {
        return Ok(false);
    };
    Ok(crate::agent_dispatch::record_dispatch_input(&record)
        .and_then(|input| crate::agent_dispatch::agent_dispatch_actor(&input).ok())
        .is_some_and(|source| source.entity_ref() == agent))
}

/// What `job`'s proposal lacks before any act (CUA E8b, CALLS row
/// "readiness"): the parameters it gives no value, as the secret slots its
/// sources name when any of them is one. A fresh admission run holds no
/// secret its source found, and old handles are never a replay seed.
#[must_use]
pub fn admission_readiness(
    job: &ProgramAdmissionJob,
    evidence: &[SolvedRunEvidence],
) -> Option<ProgramAdmissionOutcome> {
    let missing: Vec<String> = job
        .proposal
        .params
        .iter()
        .filter(|param| !job.proposal.args.contains_key(*param))
        .cloned()
        .collect();
    if missing.is_empty() {
        return None;
    }
    let slots: Vec<String> = missing
        .iter()
        .filter(|param| {
            evidence
                .iter()
                .any(|source| source.secret_slots.iter().any(|slot| &slot.name == *param))
        })
        .cloned()
        .collect();
    Some(if slots.is_empty() {
        ProgramAdmissionOutcome::ArgsMissing { params: missing }
    } else {
        ProgramAdmissionOutcome::SecretsUnbound { slots }
    })
}

/// Keeps, in a filing's own write `wtxn`, the program `workflow` it filed
/// for the admission job `filing` names (CUA E8b).
///
/// # Errors
///
/// Storage errors.
pub(super) fn note_filed_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    filing: &ProgramAdmissionFiling,
    workflow: EntityId,
) -> Result<()> {
    let mut receipt = RECEIPTS
        .get(&vault.store, wtxn, &filing.job)?
        .unwrap_or_else(|| ProgramAdmissionReceipt {
            job: filing.job,
            finding: filing.finding,
            fingerprint: filing.fingerprint,
            source_evidence: Vec::new(),
            run_id: Some(filing.job),
            filed: None,
            outcome: None,
            settled_at: None,
        });
    receipt.filed = Some(workflow);
    RECEIPTS.put(vault, wtxn, &filing.job, &receipt)
}

/// Records what job `job_id` came to at `now` (CUA E8b), and in the same
/// write drops the binding each of its sources kept. An interruption names
/// the program a filing in its run filed, read in this write.
///
/// # Errors
///
/// Storage errors.
pub fn record_program_admission(
    vault: &Vault,
    job_id: EntityId,
    job: &ProgramAdmissionJob,
    outcome: &ProgramAdmissionOutcome,
    now: u64,
) -> Result<ProgramAdmissionReceipt> {
    vault.with_write_txn_grouped(|wtxn| {
        let filed = RECEIPTS
            .get(&vault.store, wtxn, &job_id)?
            .and_then(|receipt| receipt.filed);
        let mut outcome = outcome.clone();
        if let ProgramAdmissionOutcome::Interrupted { filed: seen } = &mut outcome {
            *seen = filed;
        }
        let receipt = ProgramAdmissionReceipt {
            job: job_id,
            finding: job.finding,
            fingerprint: job.fingerprint,
            source_evidence: job.source_evidence.clone(),
            run_id: Some(job_id),
            filed,
            outcome: Some(outcome),
            settled_at: Some(now),
        };
        RECEIPTS.put(vault, wtxn, &job_id, &receipt)?;
        for id in &job.source_evidence {
            drop_witness_in_txn(vault, wtxn, id)?;
        }
        Ok(receipt)
    })
}

/// Records an undecodable job `job_id`'s end at `now` (FIX 10716):
/// its payload never decoded, so its receipt keeps empty refs and the
/// [`ProgramAdmissionOutcome::Undecodable`] outcome, and in the same write
/// each leniently read source id's kept binding is dropped, as every
/// ended job's sources' are.
///
/// # Errors
///
/// Storage errors.
pub fn record_undecodable_program_admission(
    vault: &Vault,
    job_id: EntityId,
    source_evidence: &[EntityId],
    now: u64,
) -> Result<ProgramAdmissionReceipt> {
    vault.with_write_txn_grouped(|wtxn| {
        let filed = RECEIPTS
            .get(&vault.store, wtxn, &job_id)?
            .and_then(|receipt| receipt.filed);
        let receipt = ProgramAdmissionReceipt {
            job: job_id,
            // Unread: the payload did not decode. The job stands in for
            // its own finding ref; no finding is ever an attempt id.
            finding: job_id,
            fingerprint: [0; 32],
            source_evidence: source_evidence.to_vec(),
            run_id: Some(job_id),
            filed,
            outcome: Some(ProgramAdmissionOutcome::Undecodable),
            settled_at: Some(now),
        };
        RECEIPTS.put(vault, wtxn, &job_id, &receipt)?;
        for id in source_evidence {
            drop_witness_in_txn(vault, wtxn, id)?;
        }
        Ok(receipt)
    })
}

/// Job `job`'s receipt (CUA E8b), once a filing in its run or its end
/// wrote one.
///
/// # Errors
///
/// Storage errors.
pub fn program_admission_receipt(
    vault: &Vault,
    job: EntityId,
) -> Result<Option<ProgramAdmissionReceipt>> {
    let rtxn = vault.store.env.read_txn()?;
    RECEIPTS.get(&vault.store, &rtxn, &job)
}
