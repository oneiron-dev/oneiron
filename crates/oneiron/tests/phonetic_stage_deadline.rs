//! The phonetic stage checks its deadline inside the stage (census L9-10;
//! the retrieval hub's follow-up "Two stages, phonetic and PPR, check the
//! deadline only at stage boundaries", ARCH-0042 #call-mode-budget-built).
//! A phonetic stage whose share of the stage time has run out stops at its
//! next checkpoint and drops its partial work, as the temporal stage does;
//! the stages that finished are fused without it.

use oneiron::retrieval_depth::{
    RetrievalDeadline, SlowRetrievalStage, still_deadline_clock_for_test,
};
use oneiron::store::RetrievalSignal;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use std::time::{Duration, Instant};

/// The one phonetic code the fixture row carries and the query asks for.
const CODE: &str = "LNTRN";
/// The call's whole budget. Its stages may run to three quarters of it (3 s),
/// and the phonetic stage, the query's only stage, takes all of that share.
const BUDGET: Duration = Duration::from_secs(4);
/// A stall before the phonetic stage's work: past the stage's share, and
/// short of the answer's time.
const STALL: Duration = Duration::from_millis(3_500);

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    matched: EntityId,
}

/// A vault holding one row that only the phonetic channel finds.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    let matched = EntityId::from_bytes([0x44; 16]).expect("entity id");
    vault
        .batch()
        .put(&matched, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
        .phonetic(&matched, &[CODE])
        .commit()
        .expect("commit the phonetic row");
    Fixture {
        _dir: dir,
        vault,
        matched,
    }
}

/// A hard deadline of [`BUDGET`] on the still clock, which moves only as a
/// slow test stage spends time, so the test does not depend on the host's
/// speed.
fn still_deadline() -> RetrievalDeadline {
    let replaced = still_deadline_clock_for_test(true);
    let deadline = RetrievalDeadline::hard(Instant::now(), BUDGET);
    still_deadline_clock_for_test(replaced);
    deadline
}

/// The ids a phonetic query for [`CODE`] returns under `deadline`.
fn phonetic_ids_under(vault: &Vault, deadline: &RetrievalDeadline) -> Vec<EntityId> {
    vault
        .query()
        .search_phonetic(&[CODE])
        .limit(10)
        .deadline(deadline)
        .run()
        .expect("phonetic query")
        .into_iter()
        .map(|row| row.id)
        .collect()
}

/// A phonetic stage that is past its share when its work begins stops at its
/// first checkpoint: its row is not returned, and the run says it was cut
/// short. Before the fix the stage read every posting to the end and
/// returned the row.
#[test]
fn a_phonetic_stage_past_its_share_stops_at_its_checkpoint() {
    let fixture = fixture();
    let deadline = still_deadline();
    fixture
        .vault
        .arm_slow_retrieval_stage_for_test(Some(SlowRetrievalStage {
            signal: RetrievalSignal::Phonetic,
            duration: STALL,
            yields: false,
        }));
    let ids = phonetic_ids_under(&fixture.vault, &deadline);
    fixture.vault.arm_slow_retrieval_stage_for_test(None);

    let used = deadline.used();
    assert!(
        used >= STALL,
        "FIXTURE: the stalled phonetic stage spent its stall before its work: used {used:?}"
    );
    assert!(
        used < BUDGET,
        "FIXTURE: the stall ends before the answer is due: used {used:?}"
    );
    assert!(
        ids.is_empty(),
        "a phonetic stage past its share stops at its first checkpoint and drops its rows: {ids:?}"
    );
    assert!(
        deadline.was_cut_short(),
        "a run whose phonetic stage was cut says it was cut short"
    );
}

/// Control: the same query under the same deadline, with no stall, returns
/// the row, and nothing is cut.
#[test]
fn an_unstalled_phonetic_stage_under_the_same_deadline_returns_its_row() {
    let fixture = fixture();
    let deadline = still_deadline();
    let ids = phonetic_ids_under(&fixture.vault, &deadline);

    assert_eq!(
        ids,
        [fixture.matched],
        "FIXTURE: the phonetic channel finds the row under the deadline"
    );
    assert!(
        !deadline.was_cut_short(),
        "a phonetic stage inside its share is not cut"
    );
}
