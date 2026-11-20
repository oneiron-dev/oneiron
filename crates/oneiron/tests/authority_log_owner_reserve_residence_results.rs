//! Row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS, part 2e2: a residence
//! result carries the owner key's proof its machine holds when the directive
//! it answers is the owner's own signed word (LIMIT-1
//! RESULT-NEEDS-EXECUTOR-KEY), and never for the home's prediction. Past its
//! owner reserve, install B lands only the owner's work
//! (`authority/log_budget.rs` `owner_work`), and a result install A writes
//! reaches B signed by A's install key. Since #9892 the fold takes one owner
//! key's proof beside that signature on a residence result; here A's
//! residence upkeep signs one when an owner key A's fold holds live signed
//! the directive, the directive is no prediction, and A holds a key that
//! proves now.
//!
//! Each test admits a second machine of the owner's on A (the flooder), has
//! the owner issue a prune directive to A, takes A's history to a second
//! install B, floods B until its door holds a row at the reserve
//! (`owner_reserve/two_installs.rs`), then runs one round of A's residence
//! upkeep, and B imports every row A wrote since.
//!
//! Red at the base (#9934 head 32af3e91, owner work results carry their
//! proof, residence results none): A's result for the owner's directive
//! carries no cosign, and B's import refuses with `AuthorityLogFull`. The
//! controls, the result for the home's prediction and one from an A that
//! holds no owner key, wait at B.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_residence_results`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

use std::sync::Arc;

use oneiron::authority::{
    ActSurface, AuthorityEntryHash, AuthorityLogEntry, AuthorityOp, MachineOwnership, MachineRole,
    PredictedResidenceSet, ResidenceAct, ResidenceResultStatus, authority_entry_hash,
    decode_authority_log_entry_body,
};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::connection::{ConnectionConfig, SyncConnection};
use oneiron::sync::manager::WindowManager;
use oneiron::test_doors::predicted_residence::{append_prediction, apply_residence_directives};
use oneiron::{EntityId, ErrorKind, Vault};

#[path = "owner_reserve/two_installs.rs"]
mod two_installs;

use two_installs::{
    Rooted, Second, admit_flooder, hold_owner_key, rooted, second_install_at_its_reserve,
    stored_history,
};

/// A's own machine, which the owner marks his: its answered roster head
/// names A's install key, so A takes the owner's residence directives and
/// its results stand (FIX 8888).
fn a_is_yours(rooted: &Rooted) -> EntityId {
    let machine = rooted
        .vault
        .local_machine()
        .expect("FIXTURE: A's machine")
        .expect("FIXTURE: A has a machine")
        .id;
    rooted
        .vault
        .set_machine_role(
            &rooted.proof,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("FIXTURE: the owner marks A yours");
    machine
}

/// Runs one round of A's residence upkeep, as its own-device connection runs
/// one once the authority history is in; the tests' acts dial no home.
/// Answers how many directives it finished.
fn run_residence_upkeep(vault: Arc<Vault>) -> usize {
    let round = std::thread::Builder::new()
        .name("owner-reserve-residence-upkeep".to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(async move {
                    let manager = Arc::new(WindowManager::new(
                        vault,
                        Arc::new(Materializer::new()),
                        "owner-reserve-residence-results",
                    ));
                    let connection = SyncConnection::new(manager, ConnectionConfig::default())
                        .expect("A's own-device connection");
                    apply_residence_directives(&connection).await
                })
        })
        .expect("upkeep thread");
    match round.join() {
        Ok(finished) => finished.expect("A's residence upkeep runs"),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// The rows A stored since B took its history, and A's one result among them
/// for the directive `directive`, with its hash.
fn the_result_a_wrote(
    vault: &Vault,
    second: &Second,
    directive: EntityId,
) -> (Vec<Vec<u8>>, AuthorityLogEntry, AuthorityEntryHash) {
    let rows: Vec<Vec<u8>> = stored_history(vault)
        .into_iter()
        .filter(|row| !second.taken.contains(row))
        .collect();
    let mut results: Vec<AuthorityLogEntry> = rows
        .iter()
        .map(|row| decode_authority_log_entry_body(row).expect("A's row"))
        .filter(|entry| {
            matches!(&entry.op, AuthorityOp::ResidenceResult(result)
                if result.directive == directive)
        })
        .collect();
    assert_eq!(results.len(), 1, "A wrote one result for the directive");
    let result = results.remove(0);
    let hash = authority_entry_hash(&result).expect("hash");
    (rows, result, hash)
}

/// B imports `rows` and counts `result`, which A signed with one owner key's
/// proof beside its install key.
fn b_lands_the_proven_result(
    second: &Second,
    rows: &[Vec<u8>],
    result: &AuthorityLogEntry,
    hash: &AuthorityEntryHash,
) {
    assert_eq!(
        result.cosigns.len(),
        1,
        "A signed the result with one owner key's proof beside its install key"
    );
    assert_ne!(
        result.cosigns[0].public_key, result.signer.public_key,
        "the proof is not A's install key"
    );
    second
        .vault
        .import_signed_authority_history(rows)
        .expect("B lands the result A carries with the owner key's proof past its reserve");
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(hash),
        "B's fold counts the result"
    );
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "B's fold stays under its floor and its root stands"
    );
}

/// B's door holds `rows` at its reserve (`AuthorityLogFull`), and its fold
/// does not count the unproven `result`.
fn b_holds_the_unproven_result(
    second: &Second,
    rows: &[Vec<u8>],
    result: &AuthorityLogEntry,
    hash: &AuthorityEntryHash,
) {
    assert!(
        result.cosigns.is_empty(),
        "A carries the result unproven: {:?}",
        result.cosigns
    );
    let import = second.vault.import_signed_authority_history(rows);
    assert!(
        import
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::AuthorityLogFull),
        "B's door holds the unproven result at its reserve: {import:?}"
    );
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        !fold.valid_entries.contains(hash),
        "B does not count the result"
    );
}

/// The directive whose result a test reads.
enum Answered {
    /// The owner's prune directive to A, which A applies.
    OwnersPrune,
    /// The home's prediction for A under that directive, signed with the
    /// issuer the owner's directives carry, as the home pushes one
    /// (`test_doors::predicted_residence::append_prediction`). A is not at
    /// the predicted level, so A refuses it, a result its upkeep signs too.
    HomesPrediction,
}

/// The owner issues a prune directive to A, the owner's own machine, and,
/// for [`Answered::HomesPrediction`], the home pushes a prediction for A,
/// both before B takes A's history; B is flooded to its reserve; then one
/// round of A's residence upkeep answers what is pending. The rows A wrote
/// since, its result for `answered`, and the result's hash.
fn a_answers_a_residence_directive(
    answered: &Answered,
    a_holds_an_owner_key: bool,
) -> (Second, Vec<Vec<u8>>, AuthorityLogEntry, AuthorityEntryHash) {
    let rooted = rooted();
    if a_holds_an_owner_key {
        hold_owner_key(&rooted);
    }
    let machine_of_a = a_is_yours(&rooted);
    let flooder = admit_flooder(&rooted);
    let issuer = oneiron::test_support::test_host_issuer();
    let owners = rooted
        .vault
        .issue_residence_directive_as(
            &rooted.proof,
            &issuer,
            EntityId::now(),
            machine_of_a,
            ResidenceAct::Prune { before: 0 },
        )
        .expect("FIXTURE: the owner's prune directive to A")
        .directive
        .id;
    let (directive, pending, status) = match answered {
        Answered::OwnersPrune => (owners, 1, ResidenceResultStatus::Applied),
        Answered::HomesPrediction => (
            append_prediction(
                &rooted.vault,
                &issuer,
                machine_of_a,
                owners,
                &PredictedResidenceSet::default(),
            )
            .expect("FIXTURE: the home's prediction for A"),
            2,
            ResidenceResultStatus::Refused,
        ),
    };
    let second = second_install_at_its_reserve(&rooted, &flooder);
    // A connection takes the vault shared; B is set up, so A's handle moves.
    let vault_of_a = Arc::new(rooted.vault);
    assert_eq!(
        run_residence_upkeep(Arc::clone(&vault_of_a)),
        pending,
        "FIXTURE: A's upkeep answers every directive pending on A"
    );
    let (rows, result, hash) = the_result_a_wrote(&vault_of_a, &second, directive);
    assert!(
        matches!(&result.op, AuthorityOp::ResidenceResult(answer) if answer.status == status),
        "FIXTURE: A answers the directive {status:?}: {:?}",
        result.op
    );
    (second, rows, result, hash)
}

/// The owner's prune directive to A, answered by an A that holds an owner
/// key: the result carries that key's proof, and B, past its owner reserve,
/// lands it.
#[test]
fn the_owners_residence_result_another_install_proves_lands_past_this_installs_reserve() {
    let (second, rows, result, hash) =
        a_answers_a_residence_directive(&Answered::OwnersPrune, true);
    b_lands_the_proven_result(&second, &rows, &result, &hash);
}

/// The home's prediction for A, answered by an A that holds an owner key:
/// the home signs it as automatic upkeep with the issuer the owner's
/// directives carry, so its result is carried unproven (LIMIT-1) and waits
/// at B's door.
#[test]
fn a_result_for_the_homes_prediction_waits_past_this_installs_reserve() {
    let (second, rows, result, hash) =
        a_answers_a_residence_directive(&Answered::HomesPrediction, true);
    b_holds_the_unproven_result(&second, &rows, &result, &hash);
}

/// The owner's directive, answered by an A that holds no owner key: the
/// directive's signature does not carry to its answer (LIMIT-1
/// RESULT-NEEDS-EXECUTOR-KEY), so the result waits at B's door.
#[test]
fn a_residence_result_from_a_machine_without_an_owner_key_waits_past_this_installs_reserve() {
    let (second, rows, result, hash) =
        a_answers_a_residence_directive(&Answered::OwnersPrune, false);
    b_holds_the_unproven_result(&second, &rows, &result, &hash);
}
