#![cfg(all(oneiron_test_support, feature = "test-support"))]
//! L6-23 (ARCH-0057 membership-history scans: "cache per-slot membership
//! heads in the projector index"). Within one projector pass the
//! thread-membership fold walks a party's claims once. Each later read for
//! that party, by the same join or leave or by a later one, decodes only the
//! deciding slot's claims. Before, each join or leave decoded every claim
//! about the party twice: once for the active fold, then once for the
//! history or the retract sweep.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test comm_thread_member_claim_reads`.

use oneiron::comm::{
    count_active_thread_member_claims, record_comm_thread_event, resolve_or_create_comm_party,
    run_comm_projector,
};
use oneiron::test_doors::comm_thread_member_claim_reads::take_thread_member_claim_reads;
use oneiron::{Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PARTY: &str = "owen@example.com";
/// Threads the party joined in an earlier pass: the claims a join or leave
/// on another thread must not decode again and again.
const OTHER_THREADS: u64 = 24;

fn open_unseeded() -> TestResult<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_unseeded_for_test(dir.path(), config)?;
    Ok((dir, vault))
}

#[test]
fn a_join_and_leave_walk_the_partys_claims_once_then_read_their_slot() -> TestResult {
    let (_dir, vault) = open_unseeded()?;
    for n in 0..OTHER_THREADS {
        record_comm_thread_event(&vault, &format!("thread-{n}"), PARTY, true, 10 + n)?;
    }
    run_comm_projector(&vault)?;
    record_comm_thread_event(&vault, "target", PARTY, true, 100)?;
    record_comm_thread_event(&vault, "target", PARTY, false, 200)?;
    let party = resolve_or_create_comm_party(&vault, PARTY)?;
    let claims_about_party = vault.claims_for_subject(&party)?.len();
    assert!(
        claims_about_party >= usize::try_from(OTHER_THREADS)?,
        "each earlier join stands as a claim about the party: {claims_about_party}"
    );
    take_thread_member_claim_reads();
    run_comm_projector(&vault)?;
    let reads = take_thread_member_claim_reads();

    // The join walks the party's claims once and reads its still-empty slot
    // again for the history. The leave re-reads the one claim the join
    // minted, for its active fold and its retract sweep. A full walk per
    // read costs four walks, about 4 x claims_about_party.
    assert!(
        reads <= claims_about_party + 4,
        "{reads} claim reads for one join and one leave, {claims_about_party} claims about the party"
    );
    // The outcome is the full fold's: the target thread was left, and every
    // earlier thread still holds its member.
    assert_eq!(
        count_active_thread_member_claims(&vault, "target", PARTY)?,
        0
    );
    for n in [0, OTHER_THREADS - 1] {
        assert_eq!(
            count_active_thread_member_claims(&vault, &format!("thread-{n}"), PARTY)?,
            1,
            "thread-{n}"
        );
    }
    Ok(())
}
