//! A pending access-request page walks the request keyspace from its cursor
//! and skips every decided request (FIX 14). It decoded each skipped row
//! whole first (its grant body, two ids and the row's checks), so the first
//! page over 100k decided requests cost seconds. It now reads a row's status
//! and addressee first, and decodes only a pending row it keeps.
//!
//! The test seeds 100,000 denied requests and then 100 pending ones (every
//! other one asking one person) through a test door in one write, pages the
//! owner's list and the asked person's list, checks each page's rows and
//! cursor, and prints the fastest of three reads of each first page: the
//! measurement main and the fix are compared by.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test access_request_pending_page`
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{Duration, Instant};

use oneiron::access_grant::AccessRequest;
use oneiron::test_doors::access_request_seed::seed_access_requests;
use oneiron::{EntityId, Vault, VaultConfig};

const DECIDED: usize = 100_000;
const PENDING: usize = 100;
const PAGE: usize = 50;

fn ids(page: &[AccessRequest]) -> Vec<EntityId> {
    page.iter().map(|request| request.id).collect()
}

/// The fastest of three runs of `read`, and its last answer.
fn fastest<T>(mut read: impl FnMut() -> T) -> (Duration, T) {
    let mut best = Duration::MAX;
    let mut answer = None;
    for _ in 0..3 {
        let started = Instant::now();
        let value = read();
        best = best.min(started.elapsed());
        answer = Some(value);
    }
    (best, answer.expect("three reads"))
}

fn millis(elapsed: Duration) -> f64 {
    elapsed.as_secs_f64() * 1000.0
}

#[test]
fn a_pending_page_over_many_decided_requests_keeps_its_rows_and_cursor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    let asked = EntityId::now();
    let addressees: Vec<Option<EntityId>> = (0..PENDING)
        .map(|index| (index % 2 == 0).then_some(asked))
        .collect();
    let seeding = Instant::now();
    let pending =
        seed_access_requests(&vault, owner, DECIDED, &addressees).expect("seeded requests");
    let seeded_ms = millis(seeding.elapsed());
    assert_eq!(pending.len(), PENDING);

    let (owner_elapsed, (first, next)) = fastest(|| {
        vault
            .pending_access_requests_page(None, PAGE)
            .expect("the owner's first page")
    });
    assert_eq!(
        ids(&first),
        pending[..PAGE],
        "the first page holds the first pending requests"
    );
    assert_eq!(next, Some(pending[PAGE - 1]), "its cursor is its last row");
    let (second, end) = vault
        .pending_access_requests_page(next.as_ref(), PAGE)
        .expect("the owner's second page");
    assert_eq!(
        ids(&second),
        pending[PAGE..],
        "the second page holds the rest"
    );
    assert_eq!(end, None, "nothing pending follows");

    let asked_ids: Vec<EntityId> = pending
        .iter()
        .zip(&addressees)
        .filter(|(_, addressee)| addressee.is_some())
        .map(|(id, _)| *id)
        .collect();
    let (asked_elapsed, (mine, mine_next)) = fastest(|| {
        vault
            .pending_access_requests_addressed_page(asked, None, PAGE)
            .expect("the asked person's page")
    });
    assert_eq!(
        ids(&mine),
        asked_ids,
        "the asked person's page holds the requests that ask them"
    );
    assert_eq!(mine_next, None);
    assert!(
        mine.iter()
            .all(|request| request.addressed_to == Some(asked) && request.decided_at.is_none()),
        "each is pending and asks them"
    );

    println!(
        "FIX14-PAGE decided={DECIDED} pending={PENDING} page={PAGE} seed_ms={seeded_ms:.0} \
         owner_first_page_ms={:.1} addressed_first_page_ms={:.1}",
        millis(owner_elapsed),
        millis(asked_elapsed)
    );
}
