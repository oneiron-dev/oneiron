//! Shared fixtures, helpers, and telemetry captures for the attempt-queue tests.

use super::*;

#[derive(Clone, Default)]
pub(super) struct TelemetryCapture {
    pub(super) records: Arc<Mutex<Vec<CapturedTelemetry>>>,
}

#[derive(Debug)]
pub(super) struct CapturedTelemetry {
    pub(super) kind: &'static str,
    pub(super) name: String,
    pub(super) fields: BTreeMap<String, String>,
}

impl tracing::Subscriber for TelemetryCapture {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn register_callsite(
        &self,
        _metadata: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::always()
    }

    fn max_level_hint(&self) -> Option<tracing::metadata::LevelFilter> {
        Some(tracing::metadata::LevelFilter::TRACE)
    }

    fn new_span(&self, attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut fields = BTreeMap::new();
        attrs.record(&mut TelemetryVisitor(&mut fields));
        self.records.lock().unwrap().push(CapturedTelemetry {
            kind: "span",
            name: attrs.metadata().name().to_owned(),
            fields,
        });
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = BTreeMap::new();
        event.record(&mut TelemetryVisitor(&mut fields));
        self.records.lock().unwrap().push(CapturedTelemetry {
            kind: "event",
            name: event.metadata().name().to_owned(),
            fields,
        });
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

pub(super) struct TelemetryVisitor<'a>(&'a mut BTreeMap<String, String>);

impl tracing::field::Visit for TelemetryVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

pub(super) fn open_queue() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

pub(super) fn enqueue(kind: &str, dedupe_key: Option<&str>, now: u64) -> EnqueueAttempt {
    EnqueueAttempt {
        kind: kind.to_owned(),
        payload: format!("payload-{now}").into_bytes(),
        dedupe_key: dedupe_key.map(str::to_owned),
        run_id: Some(format!("run-{now}")),
        now,
    }
}

pub(super) fn assert_invalid_transition(err: Error, action: &'static str, state: &'static str) {
    assert!(matches!(
        err,
        Error::InvalidAttemptQueueTransition {
            action: got_action,
            state: got_state,
        } if got_action == action && got_state == state
    ));
}

/// A stable id for rows written straight into storage below.
pub(super) fn synthetic_attempt_id(index: u32) -> AttemptId {
    let mut bytes = [0_u8; 16];
    bytes[..4].copy_from_slice(&index.to_be_bytes());
    // Never the all-zero key, which no minted id can be either.
    bytes[15] = 0x79;
    AttemptId::from_bytes(&bytes).expect("synthetic id")
}

/// Writes attempt rows past the state machine, in one transaction.
///
/// Nothing this queue offers can mint a cycle or a dangling `retry_of`, so a
/// test of what happens when storage carries one has to write the rows itself.
pub(super) fn put_raw_attempts(vault: &Vault, records: &[AttemptRecord]) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    for record in records {
        let encoded = encode_record(record)?;
        vault
            .store
            .attempt_records
            .put(&mut wtxn, record.id.as_bytes(), &encoded)?;
    }
    wtxn.commit()?;
    Ok(())
}

pub(super) fn skill_entry(reference: &str, version: &str, at: u64) -> ManifestEntry {
    ManifestEntry::new(ManifestKind::Skill, reference, version, at)
}

pub(super) fn enqueued(queue: &AttemptQueue<'_>, now: u64) -> Result<AttemptRecord> {
    match queue.enqueue(enqueue("pack", None, now))? {
        EnqueueOutcome::Enqueued(record) => Ok(record),
        EnqueueOutcome::Existing(record) => Ok(record),
    }
}

/// Runs one attempt with a two-kind pack manifest to the requested terminal
/// door, returning its stamped receipt (if any) and its receipt id.
pub(super) fn run_packed_attempt(
    vault: &Vault,
    terminal: fn(&AttemptQueue<'_>, AttemptId, u32) -> Result<()>,
) -> Result<(String, Option<crate::receipt::ReceiptRecord>)> {
    let queue = AttemptQueue::new(vault);
    let attempt = enqueued(&queue, 10)?;
    queue.append_manifest_entry(attempt.id, skill_entry("index", "1", 11))?;
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "worker".to_owned(),
        now: 12,
    })?
    else {
        panic!("expected claim");
    };
    queue.append_manifest_entry(attempt.id, skill_entry("pdf", "3", 13))?;
    queue.append_manifest_entry(
        attempt.id,
        ManifestEntry::new(ManifestKind::ActorClaim, "claim-a", "2", 13),
    )?;
    terminal(&queue, attempt.id, leased.attempt_count)?;

    let receipt_id = crate::receipt::attempt_pack_receipt_id(&attempt.id);
    let receipt = crate::receipt::attempt_pack_receipt(vault, &receipt_id)?;
    Ok((receipt_id, receipt))
}

pub(super) fn complete_at_14(
    queue: &AttemptQueue<'_>,
    id: AttemptId,
    attempt_count: u32,
) -> Result<()> {
    queue.complete(CompleteAttempt {
        id,
        lease_owner: "worker".to_owned(),
        attempt_count,
        now: 14,
    })?;
    Ok(())
}

pub(super) fn fail_at_14(
    queue: &AttemptQueue<'_>,
    id: AttemptId,
    attempt_count: u32,
) -> Result<()> {
    queue.fail(FailAttempt {
        id,
        lease_owner: "worker".to_owned(),
        attempt_count,
        reason: "boom".to_owned(),
        now: 14,
    })?;
    Ok(())
}

/// Enqueues, claims, and returns the leased row ready to be asked to stop.
pub(super) fn leased_attempt(queue: &AttemptQueue<'_>, dedupe_key: &str) -> Result<AttemptRecord> {
    queue.enqueue(enqueue("sync", Some(dedupe_key), 10))?;
    let ClaimOutcome::Claimed(leased) = queue.claim(ClaimAttempt {
        lease_owner: "worker-a".to_owned(),
        now: 11,
    })?
    else {
        panic!("expected claim");
    };
    Ok(leased)
}

pub(super) fn soft_request(
    id: AttemptId,
    actor: &str,
    standing: CancelStanding,
) -> RequestAttemptCancel {
    RequestAttemptCancel {
        id,
        actor: actor.to_owned(),
        standing,
        trigger: LandingTrigger::CancelRequest,
        reason: Some("owner asked for the machine back".to_owned()),
        now: 12,
    }
}

pub(super) fn accept_landing_at(
    queue: &AttemptQueue<'_>,
    leased: &AttemptRecord,
    trigger: LandingTrigger,
    now: u64,
) -> Result<AttemptRecord> {
    let LandingOutcome::Landing(landing) = queue.accept_landing(AcceptAttemptLanding {
        id: leased.id,
        lease_owner: "worker-a".to_owned(),
        attempt_count: leased.attempt_count,
        trigger,
        status: Some("green + pushed + packet-only".to_owned()),
        resume_point: None,
        request_sequence: None,
        now,
    })?
    else {
        panic!("expected a fresh landing");
    };
    Ok(landing)
}

/// Drives one attempt into LANDING with its append-only history at exactly the
/// non-terminal cap, so only the reserved terminal slot remains.
pub(super) fn landing_at_receipt_cap(
    queue: &AttemptQueue<'_>,
    dedupe_key: &str,
) -> Result<AttemptRecord> {
    let leased = leased_attempt(queue, dedupe_key)?;
    queue.request_cancel(soft_request(leased.id, "peer-1", CancelStanding::PeerAgent))?;
    let mut record = accept_landing_at(queue, &leased, LandingTrigger::CancelRequest, 13)?;
    let mut marker = 0_u64;
    while record.cancel_receipts().len() < MAX_NONTERMINAL_ATTEMPT_CANCEL_RECEIPTS {
        marker += 1;
        record = queue.record_resume_point(RecordAttemptResumePoint {
            id: leased.id,
            lease_owner: "worker-a".to_owned(),
            attempt_count: leased.attempt_count,
            resume_point: AttemptResumePoint::new(format!("step-{marker}"), 14),
            now: 14,
        })?;
    }
    assert_eq!(
        record.cancel_receipts().len(),
        MAX_NONTERMINAL_ATTEMPT_CANCEL_RECEIPTS
    );
    Ok(record)
}

pub(super) fn claimed(queue: &AttemptQueue<'_>, kind: &str, owner: &str) -> Result<AttemptRecord> {
    queue.enqueue(enqueue(kind, None, 10))?;
    let ClaimOutcome::Claimed(record) = queue.claim(ClaimAttempt {
        lease_owner: owner.to_owned(),
        now: 11,
    })?
    else {
        panic!("the enqueued row must be claimable");
    };
    Ok(record)
}

pub(super) fn result_ref(value: &str) -> AttemptResultRef {
    AttemptResultRef::new(value).expect("valid result reference")
}

/// A row written before `scheduled_at`/`retry_of` existed, at the unchanged
/// record version.
#[derive(serde::Serialize)]
pub(super) struct PreScheduledAttemptRecord {
    pub(super) id: AttemptId,
    pub(super) kind: String,
    pub(super) payload: Vec<u8>,
    pub(super) state: AttemptState,
    pub(super) lease_owner: Option<String>,
    pub(super) attempt_count: u32,
    pub(super) claimed_at: Option<u64>,
    pub(super) backoff_until: Option<u64>,
    pub(super) last_error: Option<String>,
    pub(super) task_ref: Option<String>,
    pub(super) run_id: Option<String>,
    pub(super) dedupe_key: Option<String>,
    pub(super) created_at: u64,
    pub(super) updated_at: u64,
    pub(super) events: Vec<AttemptEvent>,
}
