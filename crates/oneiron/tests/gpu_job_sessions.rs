//! Sessions on the host's GPU job step (pass 34, 9.3; row W1, issuer side): a job quoted on an
//! offer that renews at the maximum sends its next paid chunk before its chunk's end, admitted
//! under its own permit; a next chunk not admitted sends nothing, and the run ends at the end of
//! the chunk paid; each chunk settles its own slice of the one run once, with no termination at a
//! boundary the run passed; and a session takes none of C2's checkpoints, warning or stop. The
//! provider is a scripted fake that answers per resource and logs each call.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oneiron::consent::AuthenticatedOwner;
use oneiron::gpu_job::{
    AtMaximum, GpuConnectorError, GpuEndReason, GpuJob, GpuJobActor, GpuJobConnector,
    GpuJobPermits, GpuJobQuote, GpuJobRenewal, GpuJobRequest, GpuJobSignal, GpuJobSpec,
    GpuJobStart, GpuJobState, GpuJobStatus, GpuOffer, GpuResourceRef, GpuResourceStatus,
    GpuTermination, PriceShape,
};
use oneiron::llm::ModelLocality;
use oneiron::llm::run_admission::{
    BudgetLine, KeyCustody, LeaseUnit, MemoryReceipts, OfferRoute, PaidConnector, Payer,
    RunAdmission, RunDeclaration, RunEvent, RunReceiptSink,
};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};

const NOW: u64 = 1_800_000_000_000;
/// One chunk's maximum: with the default lead of 300 s, the step renews from 700 s of run time.
const CHUNK_SECS: u64 = 1_000;
/// The offer's startup, teardown and rounding, which the run's first chunk carries alone.
const OVERHEAD_SECS: u64 = 20;
/// The price of one second, in credit-micros.
const UNIT_COST: u64 = 2;
/// The host's floor for the renewal lead: a 30 s step, a 10 s send, the node's 35 s margin and
/// a second.
const LEAD_FLOOR_MS: u64 = 76_000;

/// What the fake provider holds and answers, per resource.
#[derive(Default)]
struct FakeState {
    calls: Vec<String>,
    created: HashMap<String, GpuResourceRef>,
    renewals: Vec<GpuJobSpec>,
    status: HashMap<GpuResourceRef, GpuResourceStatus>,
    termination: HashMap<GpuResourceRef, GpuTermination>,
    signals: Vec<GpuJobSignal>,
    /// Every renewal answers this refusal.
    renew_refusal: Option<String>,
    /// A resource whose status answers this refusal: its provider ended it unrun.
    status_refusal: HashMap<GpuResourceRef, String>,
}

#[derive(Default)]
struct FakeGpu(Mutex<FakeState>);

fn resource_of(key: &str) -> GpuResourceRef {
    GpuResourceRef(format!("resource-{key}"))
}

impl FakeGpu {
    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.0.lock().expect("fake provider lock")
    }

    fn reports(&self, key: &str, status: GpuResourceStatus) {
        self.state().status.insert(resource_of(key), status);
    }

    fn running(&self, key: &str, used_secs: u64) {
        self.reports(
            key,
            GpuResourceStatus::Running {
                used_secs,
                checkpoint: None,
            },
        );
    }

    fn terminates(&self, key: &str, termination: GpuTermination) {
        self.state()
            .termination
            .insert(resource_of(key), termination);
    }

    fn called(&self, prefix: &str) -> usize {
        self.state()
            .calls
            .iter()
            .filter(|call| call.starts_with(prefix))
            .count()
    }
}

impl GpuJobConnector for FakeGpu {
    fn create(&self, key: &str, _spec: &GpuJobSpec) -> Result<GpuResourceRef, GpuConnectorError> {
        let mut state = self.state();
        state.calls.push(format!("create {key}"));
        let resource = resource_of(key);
        state.created.insert(key.to_owned(), resource.clone());
        Ok(resource)
    }

    fn find(&self, key: &str) -> Result<Option<GpuResourceRef>, GpuConnectorError> {
        let mut state = self.state();
        state.calls.push(format!("find {key}"));
        Ok(state.created.get(key).cloned())
    }

    fn status(&self, resource: &GpuResourceRef) -> Result<GpuResourceStatus, GpuConnectorError> {
        let mut state = self.state();
        state.calls.push(format!("status {}", resource.0));
        if let Some(reason) = state.status_refusal.get(resource).cloned() {
            return Err(GpuConnectorError::Refused { reason });
        }
        Ok(state
            .status
            .get(resource)
            .cloned()
            .unwrap_or(GpuResourceStatus::Pending))
    }

    fn signal(
        &self,
        _resource: &GpuResourceRef,
        signal: GpuJobSignal,
    ) -> Result<(), GpuConnectorError> {
        self.state().signals.push(signal);
        Ok(())
    }

    fn terminate(&self, resource: &GpuResourceRef) -> Result<GpuTermination, GpuConnectorError> {
        let mut state = self.state();
        state.calls.push(format!("terminate {}", resource.0));
        Ok(state
            .termination
            .get(resource)
            .copied()
            .unwrap_or(GpuTermination::Pending))
    }

    fn renew(
        &self,
        key: &str,
        continues: &str,
        spec: &GpuJobSpec,
    ) -> Result<GpuResourceRef, GpuConnectorError> {
        let mut state = self.state();
        state.calls.push(format!("renew {key} {continues}"));
        if let Some(reason) = state.renew_refusal.clone() {
            return Err(GpuConnectorError::Refused { reason });
        }
        state.renewals.push(spec.clone());
        let resource = resource_of(key);
        state.created.insert(key.to_owned(), resource.clone());
        Ok(resource)
    }
}

/// A rooted vault, its owner, one offer that renews at the maximum and the fake provider.
struct Rig {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
    offer: GpuOffer,
    gpu: FakeGpu,
    permits: GpuJobPermits,
    /// Every chunk's admission reports here.
    receipts: Arc<MemoryReceipts>,
}

fn session_offer() -> GpuOffer {
    GpuOffer {
        name: "own-a6000".to_owned(),
        class: "a6000".to_owned(),
        provider: "own".to_owned(),
        region: "home".to_owned(),
        connector: PaidConnector {
            connector: "fixture-gpu".to_owned(),
            route: OfferRoute::new("fixture-gpu", "https://gpu.example.com").expect("route"),
            locality: ModelLocality::ThirdParty,
            payer: Payer::Local,
            credential_binding: None,
            catalog_revision: Some("own-prices-1".to_owned()),
            custody: KeyCustody::T0,
            unit_cost: UNIT_COST,
            cost_unit: LeaseUnit::new("credit-micros").expect("unit"),
            rates: Vec::new(),
        },
        price_shape: PriceShape::AtOneironList,
        list_cost_per_second: None,
        startup_secs: 10,
        teardown_secs: 5,
        rounding_secs: 5,
        at_maximum: AtMaximum::Renew,
    }
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("vault");
    let owner_actor = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(owner_actor, "principal:owner", true, GateDecisionId::now())
        .expect("owner proof");
    Rig {
        _dir: dir,
        vault,
        owner,
        offer: session_offer(),
        gpu: FakeGpu::default(),
        permits: GpuJobPermits::new(),
        receipts: Arc::new(MemoryReceipts::default()),
    }
}

impl Rig {
    /// The job's own run with one line of `limit` credit-micros, reporting to the rig's sink.
    fn admission(&self, job: &EntityId, limit: u64) -> RunAdmission {
        let declaration = RunDeclaration::declared(BudgetLine {
            limit_units: limit,
            reserve_units: limit,
            unit: LeaseUnit::new("credit-micros").expect("unit"),
        })
        .with_connector("fixture-gpu".to_owned());
        RunAdmission::new(
            GpuJob::admission_ref_of(job),
            declaration,
            None,
            Arc::clone(&self.receipts) as Arc<dyn RunReceiptSink>,
        )
    }

    fn start(&self) -> (GpuJob, RunAdmission) {
        self.start_for(CHUNK_SECS)
    }

    /// Starts a session whose chunks are `maximum_secs` long.
    fn start_for(&self, maximum_secs: u64) -> (GpuJob, RunAdmission) {
        let quote = self
            .offer
            .quote(
                &GpuJobRequest {
                    job_type: "session".to_owned(),
                    image: "open-models".to_owned(),
                    maximum_secs: Some(maximum_secs),
                    inputs: serde_json::json!({"machine": "fixture"}),
                },
                None,
                maximum_secs,
                NOW,
            )
            .expect("quote");
        assert_eq!(
            quote.at_maximum,
            AtMaximum::Renew,
            "the quote keeps the offer's mode"
        );
        let admission = self.admission(&quote.job, quote.units);
        let job = self
            .vault
            .start_gpu_job(
                GpuJobStart {
                    actor: GpuJobActor::Owner(&self.owner),
                    offer: &self.offer,
                    quote: &quote,
                    resume: None,
                    admission: &admission,
                },
                &self.permits,
                &self.gpu,
                NOW,
            )
            .expect("start");
        (job, admission)
    }

    /// One step, renewing with each chunk admitted under its own quote's line of `next_limit`
    /// credit-micros (`None`: the whole quote).
    fn step_renewing(
        &self,
        job: &EntityId,
        next_limit: Option<u64>,
    ) -> oneiron::gpu_job::GpuJobStepReport {
        let admission_of =
            |quote: &GpuJobQuote| self.admission(&quote.job, next_limit.unwrap_or(quote.units));
        let renewal = GpuJobRenewal {
            lead_floor_ms: LEAD_FLOOR_MS,
            admission: &admission_of,
        };
        self.vault
            .gpu_job_step_with_renewal(job, &self.offer, &self.permits, &self.gpu, &renewal, NOW)
            .expect("step")
    }

    fn step(&self, job: &EntityId) {
        let _ = self.step_renewing(job, None);
    }

    fn job(&self, id: &EntityId) -> GpuJob {
        self.vault.gpu_job(id).expect("job read").expect("job row")
    }

    /// The units each settled receipt charged, in order.
    fn settled(&self) -> Vec<u64> {
        self.receipts
            .rows()
            .into_iter()
            .filter_map(|row| match row.event {
                RunEvent::Settled { units, .. } => Some(units),
                _ => None,
            })
            .collect()
    }
}

fn key(job: &EntityId, index: usize) -> String {
    format!("{}:{index}", job.to_hex())
}

/// Starts a session, runs it to the renewal at 700 s and answers the job and the two chunk keys.
fn renewed(rig: &Rig) -> (GpuJob, String, String) {
    let (job, _admission) = rig.start();
    let (first, next) = (key(&job.id, 0), key(&job.id, 1));
    rig.gpu.running(&first, CHUNK_SECS - 300);
    rig.step(&job.id);
    (rig.job(&job.id), first, next)
}

#[test]
fn a_session_offer_sends_its_renewal_before_its_chunk_ends() {
    let rig = rig();
    let (job, _admission) = rig.start();
    let first = key(&job.id, 0);
    assert_eq!(rig.gpu.called("create"), 1);

    // 699 s of a 1,000 s chunk: one second short of the lead, nothing is sent. A job on any
    // other offer would have been told to checkpoint at 50 percent by now.
    rig.gpu.running(&first, CHUNK_SECS - 301);
    rig.step(&job.id);
    assert_eq!(rig.gpu.called("renew"), 0);
    assert!(rig.job(&job.id).renewal.is_none());

    rig.gpu.running(&first, CHUNK_SECS - 300);
    rig.step(&job.id);
    let stored = rig.job(&job.id);
    let next = stored.renewal.as_ref().expect("the next chunk is written");
    assert_eq!(
        rig.gpu
            .called(&format!("renew {} {first}", key(&job.id, 1))),
        1
    );
    assert_eq!(next.idempotency_key, key(&job.id, 1));
    assert_eq!(next.continues.as_deref(), Some(first.as_str()));
    assert_eq!(next.resource, Some(resource_of(&key(&job.id, 1))));
    assert!(rig.permits.holds(&job.id));
    assert_eq!(
        rig.gpu.state().renewals[0].maximum_secs,
        CHUNK_SECS,
        "the next chunk is quoted at the chunk's own maximum"
    );
    // The chunk sent so far still runs: one chunk, running, no second create.
    assert_eq!(stored.chunks.len(), 1);
    assert_eq!(stored.state, GpuJobState::Running);
    assert_eq!(rig.gpu.called("create"), 1);

    // Later steps send no second renewal, and C2 tells the session nothing at 95 percent.
    rig.gpu.running(&first, CHUNK_SECS - 50);
    rig.step(&job.id);
    assert_eq!(rig.gpu.called("renew"), 1);
    let signals = rig.gpu.state().signals.clone();
    assert!(signals.is_empty(), "{signals:?}");
    assert!(
        rig.settled().is_empty(),
        "nothing settles before a chunk ends"
    );
}

#[test]
fn a_session_whose_next_chunk_is_not_admitted_ends_at_its_chunk() {
    let rig = rig();
    let (job, _admission) = rig.start();
    let first = key(&job.id, 0);
    // The next chunk's line is one credit-micro: its whole quote does not fit.
    rig.gpu.running(&first, CHUNK_SECS - 300);
    let _ = rig.step_renewing(&job.id, Some(1));
    rig.gpu.running(&first, CHUNK_SECS - 100);
    let _ = rig.step_renewing(&job.id, Some(1));
    assert_eq!(rig.gpu.called("renew"), 0, "nothing is sent unpaid");
    assert!(rig.job(&job.id).renewal.is_none());

    // The node ends the run at the chunk's cutoff.
    rig.gpu.reports(
        &first,
        GpuResourceStatus::Exited {
            used_secs: CHUNK_SECS,
        },
    );
    rig.gpu.terminates(
        &first,
        GpuTermination::Confirmed {
            billed_secs: CHUNK_SECS,
        },
    );
    let _ = rig.step_renewing(&job.id, Some(1));
    let ended = rig.job(&job.id);
    assert_eq!(
        ended.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Exited
        }
    );
    assert_eq!(ended.chunks.len(), 1);
    assert_eq!(
        rig.settled(),
        vec![(CHUNK_SECS + OVERHEAD_SECS) * UNIT_COST],
        "only the first chunk's hold settles"
    );
    assert!(!rig.permits.holds(&job.id));
}

#[test]
fn a_session_whose_next_chunk_the_provider_refuses_sends_no_other() {
    let rig = rig();
    rig.gpu.state().renew_refusal = Some("template_not_a_session".to_owned());
    let (job, first, next) = renewed(&rig);
    let held = job
        .renewal
        .as_ref()
        .expect("the refused chunk stays on the job");
    assert_eq!(held.billed_secs, Some(0));
    assert_eq!(held.settled_units, Some(0));
    assert_eq!(
        rig.settled().iter().sum::<u64>(),
        0,
        "the refused chunk's hold settles at zero"
    );
    rig.gpu.running(&first, CHUNK_SECS - 100);
    rig.step(&job.id);
    assert_eq!(
        rig.gpu.called(&format!("renew {next}")),
        1,
        "no second renewal"
    );
}

#[test]
fn each_chunk_of_a_session_settles_its_own_slice_once() {
    let rig = rig();
    let (job, first, next) = renewed(&rig);
    assert!(job.renewal.is_some());

    // The node proves the run passed the first chunk's paid end: that slice is confirmed and
    // billed, and the run goes on in the next chunk.
    rig.gpu.reports(
        &first,
        GpuResourceStatus::Continued {
            used_secs: CHUNK_SECS,
            billed_secs: CHUNK_SECS,
        },
    );
    rig.gpu.running(&next, 10);
    rig.step(&job.id);
    let passed = rig.job(&job.id);
    assert_eq!(passed.state, GpuJobState::Running);
    assert_eq!(passed.chunks.len(), 2);
    assert!(passed.renewal.is_none());
    let current = &passed.chunks[1];
    assert_eq!(current.idempotency_key, next);
    assert_eq!(current.continues.as_deref(), Some(first.as_str()));
    assert_eq!(current.base_used_secs, CHUNK_SECS);
    assert_eq!(passed.maximum.maximum().units, 2 * CHUNK_SECS);
    assert_eq!(
        passed.chunks[0].settled_units,
        Some((CHUNK_SECS + OVERHEAD_SECS) * UNIT_COST)
    );
    assert_eq!(
        rig.gpu.called("terminate"),
        0,
        "a passed boundary stops nothing"
    );

    // The next step reads the chunk running now and settles nothing again.
    rig.gpu.running(&next, 300);
    rig.step(&job.id);
    assert_eq!(
        rig.settled(),
        vec![(CHUNK_SECS + OVERHEAD_SECS) * UNIT_COST]
    );
    assert_eq!(rig.job(&job.id).maximum.used_units(), CHUNK_SECS + 300);

    // The run's process exits 400 s into the second chunk: that slice bills its own seconds,
    // with no second overhead.
    rig.gpu
        .reports(&next, GpuResourceStatus::Exited { used_secs: 400 });
    rig.gpu
        .terminates(&next, GpuTermination::Confirmed { billed_secs: 400 });
    rig.step(&job.id);
    let ended = rig.job(&job.id);
    assert_eq!(
        ended.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Exited
        }
    );
    assert_eq!(ended.chunks[1].settled_units, Some(400 * UNIT_COST));
    rig.step(&job.id);
    assert_eq!(
        rig.settled(),
        vec![(CHUNK_SECS + OVERHEAD_SECS) * UNIT_COST, 400 * UNIT_COST],
        "each chunk settled once"
    );
    assert!(!rig.permits.holds(&job.id));
}

#[test]
fn a_session_that_ends_before_its_next_chunk_settles_that_chunk_at_zero() {
    let rig = rig();
    let (job, first, next) = renewed(&rig);
    rig.gpu
        .reports(&first, GpuResourceStatus::Exited { used_secs: 900 });
    rig.gpu
        .terminates(&first, GpuTermination::Confirmed { billed_secs: 900 });
    // The node withdraws the chunk the run never reached.
    rig.gpu
        .terminates(&next, GpuTermination::Confirmed { billed_secs: 0 });
    rig.step(&job.id);
    let ended = rig.job(&job.id);
    assert_eq!(
        ended.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Exited
        }
    );
    assert_eq!(ended.chunks.len(), 1);
    let drained = ended
        .renewal
        .as_ref()
        .expect("the next chunk stays on the job");
    assert_eq!(
        (drained.billed_secs, drained.settled_units),
        (Some(0), Some(0))
    );
    assert_eq!(
        rig.settled().iter().sum::<u64>(),
        (900 + OVERHEAD_SECS) * UNIT_COST,
        "the first chunk settles its slice and the next one nothing"
    );
    assert!(!rig.permits.holds(&job.id));
}

#[test]
fn a_cancel_that_meets_a_passed_boundary_ends_the_next_chunk() {
    let rig = rig();
    let (job, first, next) = renewed(&rig);
    // The run passed the first chunk's end before the stop reached it: the stop of the first
    // key stopped nothing.
    rig.gpu.terminates(
        &first,
        GpuTermination::Continued {
            used_secs: CHUNK_SECS,
            billed_secs: CHUNK_SECS,
        },
    );
    rig.gpu
        .terminates(&next, GpuTermination::Confirmed { billed_secs: 25 });
    let cancelled = rig
        .vault
        .cancel_gpu_job(
            GpuJobActor::Owner(&rig.owner),
            &job.id,
            &rig.permits,
            &rig.gpu,
            NOW,
        )
        .expect("cancel");
    assert_eq!(
        cancelled.state,
        GpuJobState::Ending {
            reason: GpuEndReason::Cancelled
        }
    );
    assert_eq!(cancelled.chunks.len(), 2, "the next chunk runs now");
    assert_eq!(
        cancelled.chunks[1].base_used_secs, CHUNK_SECS,
        "the passed slice counts the seconds it billed, not the last reading"
    );
    rig.step(&job.id);
    let ended = rig.job(&job.id);
    assert_eq!(
        ended.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Cancelled
        }
    );
    assert_eq!(
        rig.gpu
            .called(&format!("terminate {}", resource_of(&next).0)),
        1
    );
    assert_eq!(
        rig.settled(),
        vec![(CHUNK_SECS + OVERHEAD_SECS) * UNIT_COST, 25 * UNIT_COST]
    );
}

/// REVIEW-10521 r1 P1 (renew.rs:100): a chunk shorter than the lead sends no renewal before its
/// provider reports run time, since a renewal of a run that has not launched is refused for good.
#[test]
fn a_session_whose_run_has_not_launched_sends_no_renewal() {
    let rig = rig();
    // 120 s chunks under the default 300 s lead: every reading is inside the lead.
    let (job, _admission) = rig.start_for(120);
    let first = key(&job.id, 0);
    // Still staging: the provider answers pending, and no run time is known.
    rig.step(&job.id);
    rig.step(&job.id);
    assert_eq!(
        rig.gpu.called("renew"),
        0,
        "nothing is sent before the launch"
    );
    assert!(rig.job(&job.id).renewal.is_none());

    // Launched: the first reading sends the renewal.
    rig.gpu.running(&first, 5);
    rig.step(&job.id);
    assert_eq!(rig.gpu.called("renew"), 1);
    assert!(rig.job(&job.id).renewal.is_some());
}

/// REVIEW-10521 r1 P1 (renew.rs:78): a next chunk its provider ended before the run reached it,
/// seen on a later read (the renewal's refusal got no answer), settles zero at once, so its hold
/// returns before the current chunk ends; no other renewal follows it.
#[test]
fn a_next_chunk_its_provider_ended_unrun_releases_its_hold_at_once() {
    let rig = rig();
    let (job, first, next) = renewed(&rig);
    assert!(job.renewal.is_some());
    rig.gpu
        .state()
        .status_refusal
        .insert(resource_of(&next), "session_max_reached".to_owned());
    rig.gpu.running(&first, CHUNK_SECS - 200);
    rig.step(&job.id);
    let stored = rig.job(&job.id);
    let closed = stored
        .renewal
        .as_ref()
        .expect("the next chunk stays on the job");
    assert_eq!(
        (closed.billed_secs, closed.settled_units),
        (Some(0), Some(0))
    );
    assert_eq!(
        stored.state,
        GpuJobState::Running,
        "the current chunk runs on"
    );
    assert_eq!(
        rig.settled(),
        vec![0],
        "the next chunk's hold settles at zero now"
    );

    rig.gpu.running(&first, CHUNK_SECS - 100);
    rig.step(&job.id);
    assert_eq!(
        rig.gpu.called(&format!("renew {next}")),
        1,
        "no second renewal"
    );
}

/// REVIEW-10521 r1 P1 (step.rs:345): a cancel's stop that meets a passed slice billed below its
/// measure (the issuer's bracket clamped it) still counts the slice's measured run time as the
/// next chunk's base.
#[test]
fn a_passed_slice_billed_below_its_measure_keeps_its_measured_run_time() {
    let rig = rig();
    let (job, first, _next) = renewed(&rig);
    rig.gpu.terminates(
        &first,
        GpuTermination::Continued {
            used_secs: CHUNK_SECS,
            billed_secs: 0,
        },
    );
    let cancelled = rig
        .vault
        .cancel_gpu_job(
            GpuJobActor::Owner(&rig.owner),
            &job.id,
            &rig.permits,
            &rig.gpu,
            NOW,
        )
        .expect("cancel");
    assert_eq!(cancelled.chunks.len(), 2, "the next chunk runs now");
    assert_eq!(cancelled.chunks[0].billed_secs, Some(0));
    assert_eq!(
        cancelled.chunks[1].base_used_secs, CHUNK_SECS,
        "the base is the slice's measure, not its bill or the last reading"
    );
}

/// REVIEW-10521 r2 P1 (step.rs:402): a cancel whose stop met the run past a slice boundary ends
/// the next slice with no status read of it. That slice's confirmed seconds still count, in the
/// chunk and in the session's run time that door 8 shows.
#[test]
fn a_cancel_past_a_slice_boundary_counts_the_final_slice_in_the_run_time() {
    let rig = rig();
    let (job, first, next) = renewed(&rig);
    rig.gpu.terminates(
        &first,
        GpuTermination::Continued {
            used_secs: CHUNK_SECS,
            billed_secs: CHUNK_SECS,
        },
    );
    rig.gpu
        .terminates(&next, GpuTermination::Confirmed { billed_secs: 40 });
    let cancelled = rig
        .vault
        .cancel_gpu_job(
            GpuJobActor::Owner(&rig.owner),
            &job.id,
            &rig.permits,
            &rig.gpu,
            NOW,
        )
        .expect("cancel");
    assert_eq!(cancelled.chunks.len(), 2, "the next chunk runs now");
    rig.step(&job.id);
    let ended = rig.job(&job.id);
    assert_eq!(
        ended.state,
        GpuJobState::Ended {
            reason: GpuEndReason::Cancelled
        }
    );
    assert_eq!(
        ended.chunks[1].used_secs, 40,
        "the final slice ran what its provider confirmed"
    );
    assert_eq!(
        GpuJobStatus::from(&ended).used_secs,
        CHUNK_SECS + 40,
        "door 8 counts both slices"
    );
}
