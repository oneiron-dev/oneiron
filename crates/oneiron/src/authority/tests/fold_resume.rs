//! The resumed fold against the whole fold, its oracle: a chain the resumed
//! fold carries reaches the reference's fold exactly, and a row it cannot
//! carry falls back to the reference.
use std::cell::Cell;

use super::fold_scale::{confirm_op, owner_row, scale_log};
use super::support::*;
use super::*;
use crate::authority::fold_resume::{FoldBase, RESUMED_FOR_TEST, StoredLog, fold_stored_log};

fn observations(
    sequence_floors: BTreeMap<AuthorityEntryHash, u64>,
    policy: AuthorityObservationPolicy,
) -> AuthorityLocalObservations {
    AuthorityLocalObservations {
        sequence_floors,
        vouched: BTreeSet::new(),
        unvouched: false,
        policy,
    }
}

/// The stored-log fold of `entries` from `base`, the reference's fold, the
/// next base, and whether the fold resumed.
fn fold_both(
    entries: &[AuthorityLogEntry],
    observations: &AuthorityLocalObservations,
    base: Option<&FoldBase>,
) -> (AuthorityFold, AuthorityFold, Option<FoldBase>, bool) {
    let first_seen: BTreeMap<_, _> = entries
        .iter()
        .map(|entry| (authority_entry_hash(entry).unwrap(), 1))
        .collect();
    let peers = BTreeMap::new();
    let posture = crate::HostingPrivacyPosture::default();
    let before = RESUMED_FOR_TEST.with(Cell::get);
    let (fold, next) = fold_stored_log(
        StoredLog {
            entries,
            first_seen_at_secs: &first_seen,
            now_secs: 2,
            peer_consent_roots: &peers,
            observations,
            posture,
            pin: None,
        },
        base,
    );
    let resumed = RESUMED_FOR_TEST.with(Cell::get) > before;
    let reference = fold_authority_log_with_local_observations_and_posture(
        entries,
        &first_seen,
        2,
        &peers,
        observations,
        posture,
        None,
    );
    (fold, reference, next, resumed)
}

#[test]
fn a_resumed_fold_is_the_whole_fold_on_every_row_of_a_chain() {
    let observations = observations(BTreeMap::new(), AuthorityObservationPolicy::default());
    for shape in ["agents", "chain"] {
        let log = scale_log(shape, 24);
        let (mut base, mut resumed) = (None, 0);
        for len in 1..=log.len() {
            let (fold, reference, next, did) = fold_both(&log[..len], &observations, base.as_ref());
            assert_eq!(fold, reference, "{shape} at {len} rows");
            resumed += usize::from(did);
            base = next;
        }
        assert_eq!(resumed, log.len() - 1, "{shape}: each row after genesis");
        // Several rows at once.
        let (_, _, base, _) = fold_both(&log[..10], &observations, None);
        let (fold, reference, _, did) = fold_both(&log, &observations, base.as_ref());
        assert!(did, "{shape}: fourteen rows at once");
        assert_eq!(fold, reference, "{shape}: fourteen rows at once");
    }
}

#[test]
fn a_row_the_resumed_fold_cannot_carry_falls_back_to_the_whole_fold() {
    let plain = || observations(BTreeMap::new(), AuthorityObservationPolicy::default());
    let log = scale_log("chain", 8);
    let (_, _, base, _) = fold_both(&log, &plain(), None);
    let base = base.expect("a one-chain log leaves a base");
    let owner = ed_key(91);
    let vault_id = genesis_vault_id(&log[0]).unwrap();
    let root = authority_entry_hash(&log[0]).unwrap();
    let head = authority_entry_hash(log.last().unwrap()).unwrap();
    let row = |parents, op| owner_row(vault_id, &owner, 9, parents, op, None);
    let fresh = row(vec![head], confirm_op(100));
    let floored = observations(
        BTreeMap::from([(authority_entry_hash(&fresh).unwrap(), 10)]),
        AuthorityObservationPolicy::default(),
    );
    let other_policy = observations(
        BTreeMap::new(),
        AuthorityObservationPolicy {
            stale_roster_window_secs: 99,
            ..AuthorityObservationPolicy::default()
        },
    );
    let admin = AuthorityOp::EnrollDevice {
        device: device(
            authority_key_from_ed(&ed_key(7)),
            ROLE_ADMIN,
            AuthorityTier::Software,
        ),
    };
    let cases = [
        ("a second head", row(vec![root], confirm_op(100)), plain()),
        (
            "a confirm the log holds",
            row(vec![head], confirm_op(3)),
            plain(),
        ),
        ("an admin enrollment", row(vec![head], admin), plain()),
        ("a row below its floor", fresh.clone(), floored),
        ("another policy", fresh, other_policy),
    ];
    for (case, new_row, observations) in cases {
        let entries = [log.clone(), vec![new_row]].concat();
        let (fold, reference, _, resumed) = fold_both(&entries, &observations, Some(&base));
        assert!(!resumed, "{case} resumed");
        assert_eq!(fold, reference, "{case}");
    }
}
