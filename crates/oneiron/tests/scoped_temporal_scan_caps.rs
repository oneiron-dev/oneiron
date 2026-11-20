//! [TEMPORAL-READER-SCAN-CAP-REFUSED-ROWS]: a scoped temporal call's scans
//! give no place under their caps to a row the call's reader refuses, for a
//! scope alone as for a `made_by` slice (REVIEW-9842 round 2). Before, the
//! scans asked only a slice's reader: a scope's refused rows nearer the
//! anchor filled an endpoint scan's cap or the spanner buffer, and a readable
//! row inside the bound was cut, so whether rows the reader may not read
//! exist moved what it got back (DEC-0005; ARCH-0004 #temporal-bound). A scan
//! asks the reader only once its cap would leave a row behind, so a window
//! its caps hold whole asks the reader no more than before.
//! The scope is a candidate filter set through a test door: run the file
//! with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron --all-features --test scoped_temporal_scan_caps`.
#![cfg(oneiron_test_support)]

use std::sync::atomic::{AtomicUsize, Ordering};

use oneiron::pipeline::RetrievalParams;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::test_doors::candidate_scope::run_reading_only;
use oneiron::test_doors::sound_match_birth::{put_born_at, put_born_over};
use oneiron::write_envelope::provenance::made_by::MadeByClass;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_retrieval::fusion::FUSION_LIST_LENGTH;

const DAY: u64 = 86_400;
const NOW: u64 = 1_700_000_000;
const ANCHOR: u64 = NOW - 10 * DAY;
/// What a one-row call's temporal channel fetches: the fusion floor. With a
/// widening multiple of 1 and no floor, a scoped call's window keeps at most
/// this many rows, and each of its scans places four times as many.
const CHANNEL_FETCH_FLOOR: usize = FUSION_LIST_LENGTH;
/// Rows the scope refuses: more than the places one scan holds under that
/// tight bound.
const REFUSED_ROWS: usize = 5 * CHANNEL_FETCH_FLOOR;
/// How far a spanner's interval reaches either side of its midpoint: past
/// the widest window, 12 days at a one-day sigma.
const SPAN: u64 = 60 * DAY;
/// When every spanner was learned: past the widest learned window too, and
/// the same for each, so the temporal score ties them all.
const SPANNER_LEARNED_AT: u64 = ANCHOR - 30 * DAY;
/// Rows within minutes of the anchor: under the shipped bound (the vault's
/// entity count, so each scan places four times as many), the scans' caps
/// hold them whole.
const WINDOW_ROWS: usize = 1_000;
/// Rows far outside every window, so the bound exceeds the window's rows.
const FAR_ROWS: usize = 10;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    Fixture { _dir: dir, vault }
}

fn person_body() -> Vec<u8> {
    rmp_serde::to_vec_named(&serde_json::json!({ "name": "row" })).expect("body")
}

fn ids(rows: oneiron::Result<Vec<oneiron::ScoredEntity>>) -> Vec<EntityId> {
    rows.expect("query").into_iter().map(|row| row.id).collect()
}

fn minutes(count: usize) -> u64 {
    60 * u64::try_from(count).expect("small count")
}

/// The scoped window's bound at the fusion floor: a widening multiple of 1
/// and no floor.
fn tight() -> RetrievalParams {
    RetrievalParams {
        temporal_widening_multiple: 1,
        temporal_widening_floor: 0,
        ..RetrievalParams::shipped()
    }
}

impl Fixture {
    /// One PERSON occurring and learned at `at`.
    fn point(&self, at: u64) -> EntityId {
        put_born_at(
            &self.vault,
            ENTITY_TYPE_PERSON,
            &person_body(),
            MadeByClass::Stated,
            &[],
            at,
        )
        .expect("FIXTURE: put the person")
    }

    /// One PERSON occurring over `SPAN` either side of `ANCHOR + offset` and
    /// learned at `SPANNER_LEARNED_AT`: neither end nor its learned time lies
    /// in any window, so only the temporal channel's spanner scan reads it.
    /// Its score ties every other spanner's; the tiebreak ranks it by its
    /// midpoint's distance from the anchor.
    fn spanner(&self, offset: u64) -> EntityId {
        put_born_over(
            &self.vault,
            ENTITY_TYPE_PERSON,
            &person_body(),
            MadeByClass::Stated,
            &[],
            TimeRange {
                start: ANCHOR + offset - SPAN,
                end: ANCHOR + offset + SPAN,
            },
            SPANNER_LEARNED_AT,
        )
        .expect("FIXTURE: put the spanning person")
    }

    /// The one-row temporal call at the anchor, with no scope.
    fn unscoped(&self, params: RetrievalParams) -> Vec<EntityId> {
        ids(self
            .vault
            .query()
            .with_temporal_now(NOW)
            .search_temporal(ANCHOR, ANCHOR, 1)
            .boost_recency(0.0)
            .retrieval_params(params)
            .limit(1)
            .run())
    }

    /// The same call under a scope that reads only `readable`, and how many
    /// times the scope was asked about a row.
    fn scoped(&self, readable: &[EntityId], params: RetrievalParams) -> (Vec<EntityId>, usize) {
        let asked = AtomicUsize::new(0);
        let rows = run_reading_only(&self.vault, readable, &asked, |query| {
            query
                .with_temporal_now(NOW)
                .search_temporal(ANCHOR, ANCHOR, 1)
                .boost_recency(0.0)
                .retrieval_params(params)
                .limit(1)
        });
        (ids(rows), asked.load(Ordering::Relaxed))
    }
}

/// An endpoint scan gives no place to a row the scope refuses:
/// `REFUSED_ROWS` refused points lie nearer the anchor than the one readable
/// point, more than one scan places under the tight bound, and the readable
/// point is the scope's nearest row, inside the bound. Before, each scan
/// placed its nearest rows up to its cap, all refused: no hit.
#[test]
fn a_readable_row_behind_refused_rows_that_fill_a_scan_is_found() {
    let fixture = fixture();
    for step in 1..=REFUSED_ROWS {
        fixture.point(ANCHOR - minutes(step));
    }
    let readable = fixture.point(ANCHOR - minutes(REFUSED_ROWS + 1));
    let unscoped = fixture.unscoped(tight());
    assert!(
        unscoped.len() == 1 && unscoped[0] != readable,
        "FIXTURE: a refused row ranks first, got {unscoped:?}"
    );
    assert_eq!(
        fixture.scoped(&[readable], tight()).0,
        [readable],
        "a scope finds its one readable row behind the refused rows"
    );
}

/// The spanner buffer gives no place to a spanner the scope refuses:
/// `REFUSED_ROWS` refused intervals centred at the anchor and one readable
/// interval centred a second later all span the window and tie on score, so
/// the midpoint tiebreak ranks the readable one last. Before, the buffer kept
/// its best spanners up to its cap, all refused: no hit.
#[test]
fn a_readable_spanner_behind_refused_spanners_that_fill_the_buffer_is_found() {
    let fixture = fixture();
    for _ in 0..REFUSED_ROWS {
        fixture.spanner(0);
    }
    let readable = fixture.spanner(1);
    let unscoped = fixture.unscoped(tight());
    assert!(
        unscoped.len() == 1 && unscoped[0] != readable,
        "FIXTURE: a refused spanner ranks first, got {unscoped:?}"
    );
    assert_eq!(
        fixture.scoped(&[readable], tight()).0,
        [readable],
        "a scope finds its one readable spanner behind the refused ones"
    );
}

/// A scan asks the reader only once its cap would leave a row behind: under
/// the shipped bound, a scope that reads every row is asked about the rows
/// the call takes, not about each of the `WINDOW_ROWS` rows its window holds.
/// A scan that asked about every row it placed would ask at least that many.
#[test]
fn a_window_its_scan_caps_hold_whole_asks_the_scope_only_about_rows_it_takes() {
    let fixture = fixture();
    let mut rows = Vec::new();
    for step in 1..=WINDOW_ROWS {
        rows.push(fixture.point(ANCHOR - minutes(step)));
    }
    for step in 1..=FAR_ROWS {
        rows.push(fixture.point(ANCHOR - 400 * DAY - minutes(step)));
    }
    let (found, asked) = fixture.scoped(&rows, RetrievalParams::shipped());
    assert_eq!(
        found,
        [rows[0]],
        "FIXTURE: the scope's nearest row ranks first"
    );
    assert!(
        asked < WINDOW_ROWS / 2,
        "the scope was asked {asked} times for a window of {WINDOW_ROWS} rows"
    );
}
