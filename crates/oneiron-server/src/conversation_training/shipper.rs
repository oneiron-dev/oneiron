//! The self-host training shipper (TL-6, FIX 5813): the loop that carries a
//! self-hosted vault's released offers and its withdrawals to the
//! publisher's intake through the anonymous training window, and applies
//! the intake's signed answers. It runs on plain serve only, with
//! `--publisher-training-self-host-shipper` and an outbox, beside the
//! outbox worker, and stops with it. Managed serve never starts it.
//!
//! Every 30 s (a missed tick waits) a pass runs on a blocking thread: the
//! withdrawals not yet acknowledged, then the uploads, then, at most once
//! every 15 minutes (CALLS TL6_STATUS_PACE), the receipts. A pass with no
//! upload or withdrawal due sends nothing. Each walks the vault's anonymous
//! custody a page at a time (`Vault::anonymous_*_page`), from where its
//! last walk stopped to the end (CALLS TL6_SHIPPER_FAIRNESS: one window per
//! piece a pass, every piece in turn). Pages, results and the
//! outbox's files are vault and file work, each done under the housekeeping
//! admission. No request is sent while an admission, a write transaction or
//! the outbox's lock is held, and each request's results are applied in the
//! vault's one writer before the next request. Only a signed receipt moves
//! a piece's cursor, so a request cut off moves nothing, and the next pass
//! sends the same window again.
//!
//! - Withdrawals: batches of codes, with no piece beside them, each sent
//!   until the intake signs it `removal_pending` (or `removed`); the
//!   receipts walk then polls it until it reads `removed`.
//! - Uploads: a window per piece (`window`), from the cursor the intake last
//!   signed, read from its released files (`stream`), packed into batches
//!   within the intake's bounds.
//! - Receipts: the codes whose next signed state is owed, each past the
//!   revision applied; an entry with `more` is asked again on the next
//!   receipts walk.
//!
//! Waits, all in memory: a restart begins afresh (CALLS TL6_RETRY_PACE). A
//! `429` or `503` stops its endpoint until the longer of its `Retry-After`
//! and its body's `retry_after_secs`. No reply, or one that does not
//! decode, waits the retry pace, 30 s doubling to 900 s, without end. An
//! entry the intake refused alone waits its own `retry_after_secs`, or the
//! next pass; `recipient_refresh_required` hands its piece to
//! `Vault::anonymous_refresh_required`, to be offered anew under a new C,
//! and asks the descriptor again. A `413` tightens the bounds and the
//! request goes again at once; a request whose time ran out halves the
//! request and part bytes and goes again next pass (CALLS
//! TL6_UPLOAD_TIMEOUT). Neither ever drops an item or a byte, and a request
//! no bound cuts smaller waits the retry pace.
//!
//! Logs carry counts and status classes only: never C, a scope, a code, a
//! body or a URL.

mod stream;
mod tally;
mod walks;
mod window;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::Vault;
use oneiron::feedback::{AnonymousApplied, IntakeReceiptKey, TrainingSubmissionId};
use oneiron_vault_contract::conversation_training::{
    OFFERS_DIR, PIECE_ERROR_RECIPIENT_REFRESH_REQUIRED, PIECE_RECEIPTS_PATH, PieceBatchResultV1,
    PieceCursorV1,
};
use tokio::time::MissedTickBehavior;

use self::stream::Piece;
use self::tally::Tally;
use self::window::{Bounds, START};
use super::descriptor::Descriptor;
use super::http::{Intake, Posted};
use super::retry::{Failure, Retry};
use super::{POLL, intake_receipt_key};
use crate::server::{HousekeepingAdmission, SyncServer};

/// Starts the shipper of the outbox at `dir`, beside its worker. It reaches
/// the intake through `intake`, and asks `descriptor` again when the intake
/// says a piece's recipient is gone.
pub(super) fn spawn(
    server: Arc<SyncServer>,
    admit: HousekeepingAdmission,
    dir: PathBuf,
    intake: Arc<Intake>,
    descriptor: Arc<Descriptor>,
) -> tokio::task::JoinHandle<()> {
    let weak = Arc::downgrade(&server);
    drop(server);
    let shipper = Arc::new(Shipper {
        offers: dir.join(OFFERS_DIR),
        dir,
        intake,
        descriptor,
        state: Mutex::new(State::new()),
    });
    tokio::spawn(async move {
        let stop = Arc::new(AtomicBool::new(false));
        let _stop_on_drop = StopOnDrop(Arc::clone(&stop));
        let mut every = tokio::time::interval(POLL);
        every.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            every.tick().await;
            let Some(server) = weak.upgrade() else {
                break;
            };
            let shipper = Arc::clone(&shipper);
            let admit = Arc::clone(&admit);
            let stop = Arc::clone(&stop);
            let ran =
                tokio::task::spawn_blocking(move || shipper.pass(&server, &admit, &stop)).await;
            match ran {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(
                    error = %format!("{error:#}"),
                    "a self-host training shipper pass failed; it runs again next tick"
                ),
                Err(error) => tracing::warn!(%error, "a self-host training shipper pass stopped"),
            }
        }
    })
}

/// Tells a pass in flight to stop at its next request once the shipper's
/// task ends, aborted at shutdown or not.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// One outbox's shipper.
struct Shipper {
    /// The outbox directory, whose receipt key ring verifies every answer.
    dir: PathBuf,
    /// Its `offers/`, where the released files are read.
    offers: PathBuf,
    /// The intake.
    intake: Arc<Intake>,
    /// The intake's descriptor, asked again on
    /// `recipient_refresh_required`.
    descriptor: Arc<Descriptor>,
    /// What passes keep.
    state: Mutex<State>,
}

/// What the shipper keeps between passes, in memory only: a restart begins
/// afresh (CALLS TL6_RETRY_PACE).
struct State {
    /// The intake's bounds as this process learned them.
    bounds: Bounds,
    /// The batches endpoint's waits.
    batches: Retry,
    /// The receipts endpoint's waits.
    receipts: Retry,
    /// The entries the intake refused alone, with when each may go again;
    /// `None` for a wait past what the clock counts.
    refused: BTreeMap<TrainingSubmissionId, Option<Instant>>,
    /// Where the withdrawals' walk resumes: past the last page it finished.
    withdrawals_after: Option<TrainingSubmissionId>,
    /// Where the uploads' walk resumes.
    uploads_after: Option<TrainingSubmissionId>,
    /// Where the receipts' walk resumes.
    receipts_after: Option<TrainingSubmissionId>,
    /// When the last receipts walk started; `None` before the first.
    receipts_at: Option<Instant>,
    /// Whether a request no bound cuts smaller was warned of.
    warned: bool,
}

impl State {
    /// A process's first state: the starting bounds, and nothing waiting.
    fn new() -> Self {
        Self {
            bounds: START,
            batches: Retry::default(),
            receipts: Retry::default(),
            refused: BTreeMap::new(),
            withdrawals_after: None,
            uploads_after: None,
            receipts_after: None,
            receipts_at: None,
            warned: false,
        }
    }

    /// Whether the entry of `id` may go at `now`.
    fn ready(&self, id: TrainingSubmissionId, now: Instant) -> bool {
        self.refused
            .get(&id)
            .copied()
            .is_none_or(|until| until.is_some_and(|until| now >= until))
    }
}

/// One piece to send a window of.
struct Shipment {
    /// Its C, 64 hex: its only handle at the intake. Never logged.
    code: String,
    /// Its facts and files, from its manifest.
    piece: Piece,
    /// Where the intake's last signed receipt says it resumes.
    cursor: PieceCursorV1,
}

impl Shipper {
    /// One pass, once the intake's receipt key ring reads: without it no
    /// answer could be applied, so nothing is sent.
    fn pass(
        &self,
        server: &SyncServer,
        admit: &HousekeepingAdmission,
        stop: &AtomicBool,
    ) -> anyhow::Result<()> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        state
            .refused
            .retain(|_, until| until.is_none_or(|until| until > now));
        let ring = {
            let Some(_admitted) = admit() else {
                return Ok(());
            };
            match intake_receipt_key(&self.dir) {
                Ok(ring) => ring,
                Err(reason) => {
                    tracing::debug!(
                        %reason,
                        "the self-host training shipper waits for the intake's receipt keys"
                    );
                    return Ok(());
                }
            }
        };
        let mut pass = Pass {
            shipper: self,
            vault: server.vault().as_ref(),
            admit,
            stop,
            ring,
            state: &mut state,
            tally: Tally::default(),
        };
        let ran = pass.run();
        pass.tally.log();
        ran
    }
}

/// One pass's working set.
struct Pass<'a> {
    /// The shipper.
    shipper: &'a Shipper,
    /// The vault whose anonymous custody the pass walks.
    vault: &'a Vault,
    /// The housekeeping admission vault and file work is done under.
    admit: &'a HousekeepingAdmission,
    /// Set once the shipper is stopping.
    stop: &'a AtomicBool,
    /// The intake's receipt key ring, read once a pass.
    ring: IntakeReceiptKey,
    /// What passes keep.
    state: &'a mut State,
    /// What this pass did.
    tally: Tally,
}

/// What became of one request.
enum Sent<T> {
    /// It was answered: the answer, decoded.
    Answered(T),
    /// The bounds tightened: the same work goes again at once, cut to them.
    Again,
    /// The walk stops for this pass: its endpoint waits, its time ran out,
    /// or the shipper is stopping.
    Stop,
}

impl Pass<'_> {
    /// The withdrawals, then the uploads, then the receipts.
    fn run(&mut self) -> anyhow::Result<()> {
        self.withdrawals()?;
        self.uploads()?;
        self.receipts()
    }

    /// Runs `work`, vault or file work, under the housekeeping admission,
    /// released once it returns; `None`, with nothing run, when the pass is
    /// not admitted.
    fn admitted<T>(&self, work: impl FnOnce() -> T) -> Option<T> {
        let _admitted = (self.admit)()?;
        Some(work())
    }

    /// Whether the shipper is stopping.
    fn stopping(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Sends one request to `route`, with no admission held, and reads its
    /// answer with `decode`. Failures, waits and tightened bounds are
    /// recorded here.
    fn send<T>(
        &mut self,
        route: &str,
        content_type: &str,
        body: Vec<u8>,
        decode: impl FnOnce(&[u8]) -> Option<T>,
    ) -> Sent<T> {
        let receipts = route == PIECE_RECEIPTS_PATH;
        if self.stopping() || !self.endpoint(receipts).ready(Instant::now()) {
            return Sent::Stop;
        }
        let timeout = window::post_timeout(body.len());
        let posted = self.shipper.intake.post(route, content_type, body, timeout);
        let failure = match posted {
            Ok(Posted::Body(answer)) => match decode(answer.as_slice()) {
                Some(decoded) => {
                    self.endpoint(receipts).succeeded();
                    self.tally.requests += 1;
                    return Sent::Answered(decoded);
                }
                None => Failure::Reply(None),
            },
            Ok(Posted::Split(refusal)) => {
                if self.state.bounds.split(refusal.as_ref()) {
                    self.tightened("split_required");
                    return Sent::Again;
                }
                self.at_floor(receipts);
                return Sent::Stop;
            }
            Ok(Posted::TimedOut) => {
                if self.state.bounds.slow() {
                    self.tightened("timed_out");
                    return Sent::Stop;
                }
                self.at_floor(receipts);
                return Sent::Stop;
            }
            Err(failure) => failure,
        };
        let endpoint = self.endpoint(receipts);
        endpoint.failed(Instant::now(), failure.retry_after());
        tracing::warn!(
            failure = failure.class(),
            status = ?failure.status(),
            failures = endpoint.failures(),
            "a self-host training shipper request failed; it goes again at the retry pace"
        );
        Sent::Stop
    }

    /// The retry state of the receipts endpoint, or of the batches one.
    fn endpoint(&mut self, receipts: bool) -> &mut Retry {
        if receipts {
            &mut self.state.receipts
        } else {
            &mut self.state.batches
        }
    }

    /// Logs the bounds a `413` or a request out of time (`cause`) left.
    fn tightened(&self, cause: &'static str) {
        let bounds = self.state.bounds;
        tracing::info!(
            cause,
            request_bytes = bounds.request_bytes,
            part_bytes = bounds.part_bytes,
            items_per_page = bounds.items_per_page,
            pieces_per_batch = bounds.pieces_per_batch,
            "the self-host training shipper cuts its requests smaller"
        );
    }

    /// The intake refused a request no bound cuts smaller: its endpoint
    /// waits the retry pace, never for good, and the first time is warned
    /// of.
    fn at_floor(&mut self, receipts: bool) {
        self.endpoint(receipts).failed(Instant::now(), None);
        if !self.state.warned {
            self.state.warned = true;
            tracing::warn!(
                "the intake's bounds refuse the smallest request the self-host training shipper \
                 can make; it goes again at the retry pace until they allow it"
            );
        }
    }

    /// Applies one batch's results in the vault's one writer, then settles
    /// what the intake refused alone. Whether the walk goes on.
    fn apply_results(&mut self, results: &PieceBatchResultV1) -> anyhow::Result<bool> {
        let applied = self.admitted(|| {
            self.vault
                .apply_anonymous_results(&results.results, &self.ring)
        });
        let Some(applied) = applied else {
            return Ok(false);
        };
        self.settle(applied?)
    }

    /// Counts what one application did, and schedules what the intake
    /// refused alone: `recipient_refresh_required` hands its piece to the
    /// vault, to be offered anew under a new C, and asks the descriptor
    /// again; any other refusal waits its `retry_after_secs`, or the next
    /// pass. Whether the walk goes on.
    fn settle(&mut self, applied: AnonymousApplied) -> anyhow::Result<bool> {
        self.tally.applied += applied.applied;
        self.tally.repeated += applied.repeated;
        self.tally.contradicted += applied.contradicted.len();
        self.tally.unverified += applied.unverified;
        let now = Instant::now();
        for refusal in applied.refused {
            if refusal.error == PIECE_ERROR_RECIPIENT_REFRESH_REQUIRED {
                let Some(dropped) =
                    self.admitted(|| self.vault.anonymous_refresh_required(refusal.id))
                else {
                    return Ok(false);
                };
                if dropped? {
                    self.tally.refreshed += 1;
                }
                self.shipper.descriptor.refresh();
                continue;
            }
            self.tally.refused += 1;
            if let Some(secs) = refusal.retry_after_secs {
                let until = now.checked_add(Duration::from_secs(secs));
                self.state.refused.insert(refusal.id, until);
            }
        }
        Ok(true)
    }
}
