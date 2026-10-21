//! The checker's companion rows and their attempt lifecycle (FIX 6868).
//!
//! One configuration row per object store holds the plan frozen from the
//! approved baseline and the owner's queued approval. One work row per
//! request key holds an init, check or diagnosis request, its current
//! attempt and generation, its status and every receipt it produced. A work
//! row rides one ordinary AttemptQueue attempt of kind
//! [`QUEUE_CHECK_ATTEMPT_KIND`], whose payload is the work key alone: it is
//! no TASK, model run or second scheduler. A request the queue already
//! holds is answered from its row; a held, unconfigured or refreshed one is
//! queued again as a new generation, and its earlier receipts are kept.
//!
//! At most `queue_check_concurrency` checks of one repository run at once
//! (CALLS: one, by default). Past it a check waits Queued; it is never
//! refused.
use serde::{Deserialize, Serialize};

use super::check_inputs::{
    QueueCheckHold, QueueCheckHoldReason, QueueCheckNeed, QueueCheckReceipt,
};
use super::plan::FrozenCheckPlan;
use super::storage::{BATCHES, check_row_size};
use super::{CheckPhase, MergeBatch, MergeQueue, MergeQueuePointers, Quarantine};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt,
    EnqueueAttempt, EnqueueOutcome, FailAttempt,
};
use crate::consent::QueuedCheckApproval;
use crate::contract_oracle::invalid;
use crate::error::{Error, Result};
use crate::ports::JobQueue;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// The AttemptQueue kind a queue check's attempt carries.
pub const QUEUE_CHECK_ATTEMPT_KIND: &str = "merge_queue.check";

/// How many checks of one repository run at once unless the operator says
/// otherwise (CALLS "one active check per repo": the next one waits).
pub const DEFAULT_QUEUE_CHECK_CONCURRENCY: u32 = 1;

/// The checked configuration of one object store. Key: hex(repo identity).
pub(super) const CHECK_CONFIGS: SideTable<String, QueueCheckConfiguration, Named> =
    SideTable::new(&side_table::MERGE_QUEUE_CHECK_CONFIG);

/// Checker work rows. Key: hex(repo identity) ":" hex64(request digest).
pub(super) const CHECK_WORK: SideTable<String, QueueCheckWork, Named> =
    SideTable::new(&side_table::MERGE_QUEUE_CHECK_WORK);

/// Where a checked initialization stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueCheckInitStage {
    /// Approved and frozen; the baseline checks have not passed.
    Requested,
    /// Both baseline phases passed and the contract baseline is recorded;
    /// the queue is not initialized yet. A retry only attaches.
    Checked { baseline_id: String },
    /// The queue was initialized at the baseline.
    Initialized { baseline_id: String },
}

/// One object store's checked configuration: the owner-approved baseline,
/// the plan frozen from it and the owner's queued approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueCheckConfiguration {
    pub schema_version: u8,
    /// The object store's hex identity.
    pub store: String,
    /// The CODE_ARTIFACT the owner initialized.
    pub repo: EntityId,
    /// Its stored local folder pointer, canonical.
    pub repo_ref: String,
    pub baseline_commit: String,
    pub baseline_tree: String,
    pub plan: FrozenCheckPlan,
    /// An existing contract baseline the init cross-checks.
    pub contract_baseline_ref: Option<String>,
    pub(crate) approval: QueuedCheckApproval,
    /// The work key of the init request.
    pub init_work: String,
    pub stage: QueueCheckInitStage,
    /// The attached branch checked initialization proved, which enrolls
    /// this queue for automatic driving (G2 PR2); `None` drives nothing.
    pub driver_target: Option<super::QueueDriverTarget>,
}

/// What a work row asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueCheckRequest {
    Initialize {
        baseline_commit: String,
        contract_baseline_ref: Option<String>,
    },
    Check {
        batch: String,
        mask: u64,
        phase: CheckPhase,
        force_refresh: bool,
    },
    Diagnose {
        batch: String,
    },
}

impl QueueCheckRequest {
    /// The request's identity: the same init, check or diagnosis maps to
    /// the same work row. A refresh is the same request asked again.
    fn digest(&self) -> Result<String> {
        let identity = match self {
            Self::Initialize {
                baseline_commit,
                contract_baseline_ref,
            } => (
                "init",
                baseline_commit.as_str(),
                0,
                None,
                contract_baseline_ref.as_deref(),
            ),
            Self::Check {
                batch, mask, phase, ..
            } => ("check", batch.as_str(), *mask, Some(*phase), None),
            Self::Diagnose { batch } => ("diagnose", batch.as_str(), 0, None, None),
        };
        let bytes = rmp_serde::to_vec_named(&("oneiron:queue-check-request:v1", identity))
            .map_err(|_| invalid("queue check request encoding failed"))?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }

    fn force_refresh(&self) -> bool {
        matches!(
            self,
            Self::Check {
                force_refresh: true,
                ..
            }
        )
    }
}

/// Where a work row stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueueCheckStatus {
    Queued,
    Running,
    /// The work is kept; nothing went green.
    NeedsConfiguration(QueueCheckNeed),
    /// No verdict; the work and its exhaust are kept.
    Held(QueueCheckHold),
    /// The work ran to a verdict, or for an init to its pointers.
    Completed {
        passed: bool,
    },
    /// The path this check fills already held a verdict when it ran.
    Settled {
        verdict_ref: String,
    },
}

/// The attempt lease one running generation holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueCheckLease {
    pub owner: String,
    /// The attempt's own lease generation fence.
    pub attempt_count: u32,
}

/// One requested init, check or diagnosis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueCheckWork {
    pub schema_version: u8,
    /// hex(repo identity) ":" hex64(request digest).
    pub key: String,
    pub store: String,
    pub repo: EntityId,
    pub repo_ref: String,
    pub request: QueueCheckRequest,
    /// The frozen plan this work runs, once a configuration exists.
    pub plan_digest: Option<String>,
    pub attempt: Option<AttemptId>,
    pub lease: Option<QueueCheckLease>,
    /// How many times this request was queued.
    pub generation: u32,
    pub status: QueueCheckStatus,
    /// Every generation's receipts, oldest first.
    pub receipts: Vec<QueueCheckReceipt>,
    pub verdict_refs: Vec<String>,
    /// The queue pointers a completed init produced.
    pub pointers: Option<MergeQueuePointers>,
    /// The quarantine a completed diagnosis kept.
    pub quarantine: Option<Quarantine>,
    /// A checked init's baseline seal: pending from the checked stage,
    /// sealed once its tested revision is finalized (G2 PR3).
    pub baseline_seal: Option<super::QueueRevisionLink>,
}

impl QueueCheckWork {
    /// The public work reference: the request digest.
    #[must_use]
    pub fn work_ref(&self) -> &str {
        self.key
            .rsplit_once(':')
            .map_or(self.key.as_str(), |(_, digest)| digest)
    }
}

/// What one finished step writes with its work row, in one writer.
#[derive(Default)]
pub(super) struct WorkUpdate<'u> {
    /// `None` keeps the work running: an inline step of a longer work.
    pub(super) status: Option<QueueCheckStatus>,
    pub(super) receipts: Vec<QueueCheckReceipt>,
    pub(super) verdict_ref: Option<String>,
    pub(super) pointers: Option<MergeQueuePointers>,
    pub(super) quarantine: Option<Quarantine>,
    /// The current batch with its new verdict slot, under its key.
    pub(super) batch: Option<(String, &'u MergeBatch)>,
    pub(super) config: Option<&'u QueueCheckConfiguration>,
    /// The checked baseline's pending seal, kept once (G2 PR3).
    pub(super) baseline_seal: Option<super::QueueRevisionLink>,
}

impl WorkUpdate<'_> {
    /// The update that ends a work with `status` and `receipts`.
    pub(super) fn ending(status: QueueCheckStatus, receipts: Vec<QueueCheckReceipt>) -> Self {
        Self {
            status: Some(status),
            receipts,
            ..Self::default()
        }
    }
}

/// What a request writes beside its work row.
pub(super) enum ConfigWrite {
    /// No configuration: the work keeps a need.
    None,
    /// The existing configuration, its approval renewed.
    Renew,
    /// The existing configuration and its stored approval, unrenewed: the
    /// automatic driver's request, which no live owner makes (G2 PR2).
    Keep,
    /// A new configuration, approved now.
    Create(Box<QueueCheckConfigDraft>),
}

/// A new configuration before the owner's approval is minted in its writer.
pub(super) struct QueueCheckConfigDraft {
    pub(super) baseline_commit: String,
    pub(super) baseline_tree: String,
    pub(super) plan: FrozenCheckPlan,
    pub(super) contract_baseline_ref: Option<String>,
}

impl MergeQueue<'_> {
    /// This object store's checked configuration, if one was requested.
    pub(crate) fn checker_configuration(&self) -> Result<Option<QueueCheckConfiguration>> {
        let txn = self.vault.store.env.read_txn()?;
        CHECK_CONFIGS.get(&self.vault.store, &txn, &self.repo.identity().as_hex())
    }

    /// One work row of this object store by its public reference.
    pub(crate) fn check_work(&self, work_ref: &str) -> Result<Option<QueueCheckWork>> {
        if work_ref.len() != 64 || !work_ref.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("work_ref must be a digest"));
        }
        let txn = self.vault.store.env.read_txn()?;
        let key = format!("{}:{work_ref}", self.repo.identity().as_hex());
        CHECK_WORK.get(&self.vault.store, &txn, &key)
    }

    /// The work key `request` maps to on this object store.
    pub(super) fn work_key(&self, request: &QueueCheckRequest) -> Result<String> {
        Ok(format!(
            "{}:{}",
            self.repo.identity().as_hex(),
            request.digest()?
        ))
    }

    /// Writes one request's work row: an existing queued or running row is
    /// answered as it stands; a new, held, unconfigured or refreshed one is
    /// queued as a new generation. `approve` mints the owner's queued
    /// approval in this writer, for a configuration created or renewed.
    pub(super) fn submit_check_work(
        &self,
        repo: EntityId,
        request: QueueCheckRequest,
        config: ConfigWrite,
        need: Option<QueueCheckNeed>,
        approve: impl FnOnce(&heed::RoTxn<'_>, &str) -> Result<QueuedCheckApproval>,
    ) -> Result<QueueCheckWork> {
        let key = self.work_key(&request)?;
        let store = &self.vault.store;
        let mut txn = store.env.write_txn()?;
        let mut work = match CHECK_WORK.get(store, &txn, &key)? {
            Some(work) => work,
            None => QueueCheckWork {
                schema_version: 1,
                key: key.clone(),
                store: self.repo.identity().as_hex(),
                repo,
                repo_ref: self.repo.repo_ref().canonical(),
                request: request.clone(),
                plan_digest: None,
                attempt: None,
                lease: None,
                generation: 0,
                status: QueueCheckStatus::Queued,
                receipts: Vec::new(),
                verdict_refs: Vec::new(),
                pointers: None,
                quarantine: None,
                baseline_seal: None,
            },
        };
        match config {
            ConfigWrite::None => {}
            ConfigWrite::Renew => {
                let mut existing = CHECK_CONFIGS
                    .get(store, &txn, &work.store)?
                    .ok_or_else(|| invalid("merge queue has no checked configuration"))?;
                existing.approval = approve(&txn, &existing.plan.digest)?;
                work.plan_digest = Some(existing.plan.digest.clone());
                CHECK_CONFIGS.put(store, &mut txn, &existing.store, &existing)?;
            }
            ConfigWrite::Keep => {
                let existing = CHECK_CONFIGS
                    .get(store, &txn, &work.store)?
                    .ok_or_else(|| invalid("merge queue has no checked configuration"))?;
                work.plan_digest = Some(existing.plan.digest.clone());
            }
            ConfigWrite::Create(draft) => {
                let draft = *draft;
                let created = QueueCheckConfiguration {
                    schema_version: 1,
                    store: work.store.clone(),
                    repo,
                    repo_ref: work.repo_ref.clone(),
                    approval: approve(&txn, &draft.plan.digest)?,
                    baseline_commit: draft.baseline_commit,
                    baseline_tree: draft.baseline_tree,
                    plan: draft.plan,
                    contract_baseline_ref: draft.contract_baseline_ref,
                    init_work: key.clone(),
                    stage: QueueCheckInitStage::Requested,
                    driver_target: None,
                };
                work.plan_digest = Some(created.plan.digest.clone());
                check_row_size(&CHECK_CONFIGS.encode_value(&created)?)?;
                CHECK_CONFIGS.put(store, &mut txn, &created.store, &created)?;
            }
        }
        let active = matches!(
            work.status,
            QueueCheckStatus::Queued | QueueCheckStatus::Running
        ) && work.attempt.is_some();
        if let Some(need) = need {
            if !active {
                work.status = QueueCheckStatus::NeedsConfiguration(need);
            }
        } else {
            let again = match &work.status {
                _ if work.attempt.is_none() => true,
                QueueCheckStatus::Queued | QueueCheckStatus::Running => false,
                QueueCheckStatus::Completed { .. } | QueueCheckStatus::Settled { .. } => {
                    request.force_refresh()
                }
                QueueCheckStatus::NeedsConfiguration(_) | QueueCheckStatus::Held(_) => true,
            };
            if again {
                work.request = request;
                queue_attempt_in_txn(self.vault, &mut txn, &mut work)?;
            }
        }
        put_work(store, &mut txn, &work)?;
        txn.commit()?;
        store.notify_attempt_observers();
        Ok(work)
    }

    /// The configuration of this store, an initialized one, or the need a
    /// check names without it.
    pub(super) fn initialized_configuration(
        &self,
    ) -> Result<std::result::Result<QueueCheckConfiguration, QueueCheckNeed>> {
        Ok(match self.checker_configuration()? {
            Some(config) if matches!(config.stage, QueueCheckInitStage::Initialized { .. }) => {
                Ok(config)
            }
            Some(_) => Err(QueueCheckNeed::new(
                &[],
                "the checked initialization of this queue has not completed",
            )),
            None => Err(QueueCheckNeed::new(
                &[],
                "this queue has no checked configuration; request vault.code.merge_queue.init",
            )),
        })
    }

    /// The earlier passing receipt of this store whose inputs digest is
    /// `digest`, that a refresh-free check may stand on.
    pub(super) fn reusable_receipt(&self, digest: &str) -> Result<Option<QueueCheckReceipt>> {
        let txn = self.vault.store.env.read_txn()?;
        let prefix = format!("{}:", self.repo.identity().as_hex());
        Ok(CHECK_WORK
            .scan_from(&self.vault.store, &txn, prefix.as_bytes())?
            .into_iter()
            .flat_map(|(_, work)| work.receipts)
            .find(|receipt| {
                receipt.inputs_digest == digest
                    && receipt.run.is_some()
                    && receipt.tests_passed == Some(true)
                    && receipt.verdict_ref.is_some()
            }))
    }

    /// The stored receipt whose digest and verdict a bound verdict names.
    pub(super) fn bound_receipt(
        &self,
        digest: &str,
        verdict: &str,
    ) -> Result<Option<QueueCheckReceipt>> {
        let txn = self.vault.store.env.read_txn()?;
        let prefix = format!("{}:", self.repo.identity().as_hex());
        Ok(CHECK_WORK
            .scan_from(&self.vault.store, &txn, prefix.as_bytes())?
            .into_iter()
            .flat_map(|(_, work)| work.receipts)
            .find(|receipt| {
                receipt.inputs_digest == digest && receipt.verdict_ref.as_deref() == Some(verdict)
            }))
    }

    /// Whether `work` still runs under its lease and its owner's approval:
    /// read before an effect a stale or unapproved run must not take.
    pub(super) fn claimed_work_holds(&self, work: &QueueCheckWork) -> Result<bool> {
        let txn = self.vault.store.env.read_txn()?;
        let store = &self.vault.store;
        let Some(current) = CHECK_WORK.get(store, &txn, &work.key)? else {
            return Ok(false);
        };
        if current.status != QueueCheckStatus::Running
            || current.attempt != work.attempt
            || current.lease != work.lease
        {
            return Ok(false);
        }
        approval_holds_in_txn(self.vault, &txn, &current)
    }
}

impl Vault {
    /// The keys of every queued checker work row, in key order.
    ///
    /// # Errors
    /// A store failure.
    pub fn pending_queue_checks(&self) -> Result<Vec<String>> {
        let txn = self.store.env.read_txn()?;
        Ok(CHECK_WORK
            .scan(&self.store, &txn)?
            .into_iter()
            .filter(|(_, work)| work.status == QueueCheckStatus::Queued)
            .map(|(key, _)| key)
            .collect())
    }

    /// Queues again every work row left running by an executor that is no
    /// longer here: a checker pass starts with none of its own running.
    /// Its attempt is failed and a new generation queued; its receipts are
    /// kept. A check is declared-idempotent verify work, so it runs again.
    ///
    /// # Errors
    /// A store failure.
    pub fn requeue_interrupted_queue_checks(&self) -> Result<usize> {
        let store = &self.store;
        let mut txn = store.env.write_txn()?;
        let running: Vec<QueueCheckWork> = CHECK_WORK
            .scan(store, &txn)?
            .into_iter()
            .map(|(_, work)| work)
            .filter(|work| work.status == QueueCheckStatus::Running)
            .collect();
        for mut work in running.clone() {
            if let (Some(attempt), Some(lease)) = (work.attempt, &work.lease) {
                let leased = AttemptQueue::new(self)
                    .get_in_write_txn(&txn, attempt)?
                    .is_some_and(|row| {
                        row.state == AttemptState::Leased
                            && row.lease_owner.as_deref() == Some(lease.owner.as_str())
                            && row.attempt_count == lease.attempt_count
                    });
                if leased {
                    self.port_job_fail(
                        &mut txn,
                        FailAttempt {
                            id: attempt,
                            lease_owner: lease.owner.clone(),
                            attempt_count: lease.attempt_count,
                            reason: "queue checker interrupted".to_owned(),
                            now: self.now_recorded_at(),
                        },
                    )?;
                }
            }
            queue_attempt_in_txn(self, &mut txn, &mut work)?;
            put_work(store, &mut txn, &work)?;
        }
        txn.commit()?;
        Ok(running.len())
    }

    /// Claims queued work `key` for `lease_owner`, or `None` when it waits:
    /// its repository already runs `concurrency` checks, or it is not
    /// queued. Work whose owner's approval lapsed is held, not claimed.
    ///
    /// # Errors
    /// A store failure, an approval that cannot be read included.
    pub fn claim_queue_check(
        &self,
        key: &str,
        lease_owner: &str,
        concurrency: u32,
    ) -> Result<Option<QueueCheckWork>> {
        let store = &self.store;
        let mut txn = store.env.write_txn()?;
        let Some(mut work) = CHECK_WORK.get(store, &txn, &key.to_owned())? else {
            return Ok(None);
        };
        if work.status != QueueCheckStatus::Queued {
            return Ok(None);
        }
        let prefix = format!("{}:", work.store);
        let running = CHECK_WORK
            .scan_from(store, &txn, prefix.as_bytes())?
            .into_iter()
            .filter(|(_, other)| other.status == QueueCheckStatus::Running)
            .count();
        if running >= concurrency.max(1) as usize {
            return Ok(None);
        }
        if !approval_holds_in_txn(self, &txn, &work)? {
            work.status = QueueCheckStatus::Held(authority_lapsed());
            put_work(store, &mut txn, &work)?;
            txn.commit()?;
            return Ok(None);
        }
        let ready = match work.attempt {
            Some(attempt) => AttemptQueue::new(self)
                .get_in_write_txn(&txn, attempt)?
                .is_some_and(|row| {
                    matches!(row.state, AttemptState::Queued | AttemptState::Scheduled)
                }),
            None => false,
        };
        if !ready {
            queue_attempt_in_txn(self, &mut txn, &mut work)?;
        }
        let attempt = work
            .attempt
            .ok_or(Error::CorruptedIndex("queue check attempt missing"))?;
        let ClaimOutcome::Claimed(record) = self.port_job_claim_id(
            &mut txn,
            attempt,
            ClaimAttempt {
                lease_owner: lease_owner.to_owned(),
                now: self.now_recorded_at(),
            },
        )?
        else {
            return Ok(None);
        };
        work.lease = Some(QueueCheckLease {
            owner: lease_owner.to_owned(),
            attempt_count: record.attempt_count,
        });
        work.status = QueueCheckStatus::Running;
        put_work(store, &mut txn, &work)?;
        txn.commit()?;
        Ok(Some(work))
    }

    /// Ends one step of claimed work `ran`: rereads it, and attaches only if
    /// the same attempt and lease still hold it and its owner's approval
    /// still holds; a stale completion attaches nothing. The batch slot,
    /// configuration, work row and attempt completion commit together.
    pub(super) fn finish_queue_check(
        &self,
        ran: &QueueCheckWork,
        update: WorkUpdate<'_>,
    ) -> Result<QueueCheckWork> {
        let store = &self.store;
        let mut txn = store.env.write_txn()?;
        let mut current = CHECK_WORK
            .get(store, &txn, &ran.key)?
            .ok_or(Error::ConcurrentWrite("queue check work is gone"))?;
        if current.status != QueueCheckStatus::Running
            || current.attempt != ran.attempt
            || current.lease != ran.lease
        {
            return Err(Error::ConcurrentWrite(
                "a stale queue check completion attaches nothing",
            ));
        }
        let lease = current
            .lease
            .clone()
            .ok_or(Error::CorruptedIndex("running queue check has no lease"))?;
        let mut status = update.status;
        if approval_holds_in_txn(self, &txn, &current)? {
            if let Some((key, batch)) = update.batch {
                check_row_size(&BATCHES.encode_value(batch)?)?;
                BATCHES.put(store, &mut txn, &key, batch)?;
            }
            if let Some(config) = update.config {
                CHECK_CONFIGS.put(store, &mut txn, &config.store, config)?;
            }
            if update.pointers.is_some() {
                current.pointers = update.pointers;
            }
            if update.quarantine.is_some() {
                current.quarantine = update.quarantine;
            }
            if let Some(verdict) = update.verdict_ref
                && !current.verdict_refs.contains(&verdict)
            {
                current.verdict_refs.push(verdict);
            }
            if current.baseline_seal.is_none() {
                current.baseline_seal = update.baseline_seal;
            }
        } else {
            status = Some(QueueCheckStatus::Held(authority_lapsed()));
        }
        current.receipts.extend(update.receipts);
        if let Some(status) = status {
            let attempt = current
                .attempt
                .ok_or(Error::CorruptedIndex("queue check attempt missing"))?;
            self.port_job_complete(
                &mut txn,
                CompleteAttempt {
                    id: attempt,
                    lease_owner: lease.owner,
                    attempt_count: lease.attempt_count,
                    now: self.now_recorded_at(),
                },
            )?;
            current.status = status;
            current.lease = None;
        }
        put_work(store, &mut txn, &current)?;
        txn.commit()?;
        store.notify_attempt_observers();
        Ok(current)
    }
}

/// Whether the owner's queued approval holds for `work`'s repository and
/// plan in `txn`. Work with no plan has no configuration to run under. A
/// read failure is an error, never a pass.
fn approval_holds_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    work: &QueueCheckWork,
) -> Result<bool> {
    let Some(digest) = &work.plan_digest else {
        return Ok(false);
    };
    match CHECK_CONFIGS.get(&vault.store, txn, &work.store)? {
        Some(config) => config.approval.holds_in_txn(vault, txn, work.repo, digest),
        None => Ok(false),
    }
}

fn authority_lapsed() -> QueueCheckHold {
    QueueCheckHold::new(
        QueueCheckHoldReason::Authority,
        "the owner's queued approval no longer holds; ask again for the same plan",
    )
}

/// Queues `work` as a new generation on a new attempt.
fn queue_attempt_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    work: &mut QueueCheckWork,
) -> Result<()> {
    let outcome = vault.port_job_enqueue(
        txn,
        EnqueueAttempt {
            kind: QUEUE_CHECK_ATTEMPT_KIND.to_owned(),
            payload: work.key.as_bytes().to_vec(),
            dedupe_key: None,
            run_id: None,
            now: vault.now_recorded_at(),
        },
    )?;
    let record = match outcome {
        EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record) => record,
    };
    work.attempt = Some(record.id);
    work.lease = None;
    work.generation = work.generation.wrapping_add(1);
    work.status = QueueCheckStatus::Queued;
    Ok(())
}

pub(super) fn put_work(
    store: &crate::store::Store,
    txn: &mut heed::RwTxn<'_>,
    work: &QueueCheckWork,
) -> Result<()> {
    check_row_size(&CHECK_WORK.encode_value(work)?)?;
    CHECK_WORK.put(store, txn, &work.key, work)
}
