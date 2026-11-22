//! Row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS, part 2e: an owner work
//! result carries the owner key's proof its executor holds when the request
//! it answers is the owner's own signed word (LIMIT-1
//! RESULT-NEEDS-EXECUTOR-KEY). Past its owner reserve, install B lands only
//! the owner's work (`authority/log_budget.rs` `owner_work`), and a result
//! install A writes reaches B signed by A's install key. Since #9892 the fold
//! takes one owner key's proof beside that signature on a result, and since
//! part 2d the owner's own requests carry one; here the result writer signs
//! one when an owner key A's fold holds live signed or cosigned the request,
//! and A holds a key that proves now.
//!
//! Each test admits a second machine of the owner's on A (the flooder),
//! takes A's history to a second install B, floods B until its door holds a
//! row at the reserve (`owner_reserve/two_installs.rs`), then A answers a
//! request naming A, and B imports every row A wrote since.
//!
//! Red at the base (#9926 head 273667bb, the requests carry their proof, the
//! results none): A's result carries no cosign, and B's import refuses with
//! `AuthorityLogFull`. The controls, a result for a request carried unproven
//! and one from an A that holds no owner key, wait at B.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_owner_work_results`.

use ed25519_dalek::Signer;
use oneiron::authority::{
    AUTHORITY_LOG_SCHEMA_VERSION, ActSurface, AuthorityEntryHash, AuthorityKey, AuthorityLogEntry,
    AuthorityOp, AuthoritySignature, MachineOwnership, MachineRole, OwnerAct, OwnerActKind,
    OwnerWorkBody, OwnerWorkRequest, WorldKeyMode, authority_entry_hash, authority_transcript,
};
use oneiron::secret_custody::{
    CustodyClass, CustodyPlan, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::test_doors::host_root_row_signature::cosign_authority_row_as_host_root;
use oneiron::world_keys::OwnerWorkStatus;
use oneiron::{EntityId, ErrorKind};

#[path = "owner_reserve/two_installs.rs"]
mod two_installs;

use two_installs::{
    AT, Flooder, Rooted, Second, admit_flooder, hold_owner_key, rooted,
    second_install_at_its_reserve, second_install_at_its_reserve_from, written_since,
};

/// When the owner's custody acts in these tests happen.
const CUSTODY_AT: u64 = 1_780_000_000;

/// The portable secret the custody test registers on A.
const SECRET: &str = "owner-reserve-result";

/// A's own machine, which the owner marks his: the executor of every
/// request here.
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

/// The rows A stored since B took its history, and the one owner work
/// result among them with its hash.
fn the_result_a_wrote(
    rooted: &Rooted,
    second: &Second,
) -> (Vec<Vec<u8>>, AuthorityLogEntry, AuthorityEntryHash) {
    let written = written_since(rooted, second);
    let rows = written.iter().map(|(row, _)| row.clone()).collect();
    let mut results = written
        .into_iter()
        .filter(|(_, entry)| matches!(entry.op, AuthorityOp::OwnerWorkResult(_)))
        .map(|(_, entry)| entry);
    let result = results.next().expect("A wrote an owner work result");
    assert!(results.next().is_none(), "A wrote one owner work result");
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
        .import_signed_authority_history(rows, &std::collections::BTreeMap::new())
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
    let import = second
        .vault
        .import_signed_authority_history(rows, &std::collections::BTreeMap::new());
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

/// The owner registered a portable secret on A, the owner's own machine,
/// before B took A's history. The owner then rewraps it with A as its
/// holder: A's custody door records the request with the owner's proof
/// (part 2d) and A enacts it in the same commit, its result carrying the
/// proof too, so B, past its owner reserve, lands both.
#[test]
fn the_owners_custody_result_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let machine_of_a = a_is_yours(&rooted);
    let flooder = admit_flooder(&rooted);
    // Registered after A is the owner's, so the value is portable.
    rooted
        .vault
        .register_secret_as_owner(
            &rooted.proof,
            &OwnerSecretRegistration {
                name: SECRET,
                class: CustodyClass::CustodyPortable,
                device_only: false,
                rung: CustodyTier::T1Leased,
                bindings: vec![RequestedBinding {
                    effector: "deploy".to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: b"owner-reserve-value",
            },
            CUSTODY_AT,
        )
        .expect("FIXTURE: the owner registers a portable secret on A");
    let second = second_install_at_its_reserve(&rooted, &flooder);
    let work = rooted
        .vault
        .rewrap_secret_as_owner(
            &rooted.proof,
            ActSurface::ThisInstall,
            SECRET,
            &CustodyPlan {
                holder: None,
                recipients: vec![machine_of_a],
            },
            CUSTODY_AT + 1,
        )
        .expect("the owner rewraps the secret with A as its holder");
    assert!(
        work.kept_here.is_none(),
        "FIXTURE: the rewrap was not kept on A"
    );
    let receipt = work.work.expect("FIXTURE: the rewrap recorded owner work");
    assert!(
        matches!(receipt.status, OwnerWorkStatus::Enacted),
        "FIXTURE: A enacted the rewrap in its commit: {receipt:?}"
    );
    assert_eq!(receipt.executor, Some(machine_of_a));
    let (rows, result, hash) = the_result_a_wrote(&rooted, &second);
    b_lands_the_proven_result(&second, &rows, &result, &hash);
}

/// What a test makes A answer: the flooder's request, cosigned by the owner
/// key or not, and whether A holds an owner key when it answers.
struct Answering {
    /// The flooder's request carries the owner key's proof.
    proven_request: bool,
    /// A holds the test host root, an owner key that proves now.
    a_holds_an_owner_key: bool,
}

/// The flooder, the owner's other machine, carries a request that A do key
/// work for a world that does not exist, on its admission, at its first
/// sequence: the owner key's proof beside the flooder's install key when
/// `proven`, as an owner device that holds that key carries the owner's own
/// request. The test signs it as setup; A signs the result under test.
fn the_flooders_request(
    rooted: &Rooted,
    flooder: &Flooder,
    executor: EntityId,
    proven: bool,
) -> AuthorityLogEntry {
    let world = EntityId::now();
    let op = AuthorityOp::OwnerWorkRequest(OwnerWorkRequest {
        carrier: flooder.machine,
        act: OwnerAct::by_owner(
            rooted.owner,
            OwnerActKind::WorldKeyRequest,
            world,
            ActSurface::ThisInstall,
            [0; 32],
        ),
        executor,
        work: OwnerWorkBody::WorldKey {
            mode: WorldKeyMode::Ensure,
        },
        privacy_basis: None,
    });
    let slot = |key: AuthorityKey| AuthoritySignature {
        suite: key.suite(),
        public_key: key,
        signature: vec![0; 64],
    };
    let owner_key = oneiron::test_support::test_host_issuer();
    let overlay_seed = oneiron_authority::authority::authority_overlay_seed_for(&op)
        .expect("authority overlay seed");
    let mut entry = AuthorityLogEntry {
        schema_version: AUTHORITY_LOG_SCHEMA_VERSION,
        vault_id: Some(rooted.vault_id),
        seq: 1,
        parent_hashes: vec![flooder.admission],
        op,
        overlay_seed,
        signer: slot(AuthorityKey::Ed25519(
            flooder.signing.verifying_key().to_bytes(),
        )),
        cosigns: if proven {
            vec![slot(owner_key.public_key())]
        } else {
            Vec::new()
        },
        ts: 2,
    };
    let transcript = authority_transcript(&entry).expect("transcript");
    entry.signer.signature = flooder.signing.sign(&transcript).to_bytes().to_vec();
    if proven {
        cosign_authority_row_as_host_root(&owner_key, &mut entry)
            .expect("FIXTURE: the owner key's proof");
    }
    entry
}

/// A, marked the owner's, lands the flooder's request naming A before B
/// takes A's history; B is flooded on it to its reserve; then A's pickup
/// answers the request refused (no such world) under A's install key. The
/// rows A wrote since, its result, and the result's hash.
fn a_answers_the_flooders_request(
    answering: &Answering,
) -> (Second, Vec<Vec<u8>>, AuthorityLogEntry, AuthorityEntryHash) {
    let rooted = rooted();
    if answering.a_holds_an_owner_key {
        hold_owner_key(&rooted);
    }
    let machine_of_a = a_is_yours(&rooted);
    let flooder = admit_flooder(&rooted);
    let request = the_flooders_request(&rooted, &flooder, machine_of_a, answering.proven_request);
    rooted
        .vault
        .put_authority_log_entry(&request, AT, 1)
        .expect("FIXTURE: A lands the flooder's request naming A");
    let request_hash = authority_entry_hash(&request).expect("hash");
    let second = second_install_at_its_reserve_from(&rooted, &flooder, (request_hash, 2));
    let drain = rooted
        .vault
        .run_pending_owner_work(|| true)
        .expect("A's pickup runs");
    assert_eq!(
        (drain.refused, drain.failed),
        (1, 0),
        "FIXTURE: A answers the request refused, no such world: {drain:?}"
    );
    let (rows, result, hash) = the_result_a_wrote(&rooted, &second);
    (second, rows, result, hash)
}

/// The owner's other machine carries the owner's request with the owner
/// key's proof, naming A. A's pickup answers it, and A holds an owner key:
/// the result carries that key's proof, and B, past its owner reserve,
/// lands it.
#[test]
fn a_result_for_the_owners_proven_request_another_install_proves_lands_past_this_installs_reserve()
{
    let (second, rows, result, hash) = a_answers_the_flooders_request(&Answering {
        proven_request: true,
        a_holds_an_owner_key: true,
    });
    b_lands_the_proven_result(&second, &rows, &result, &hash);
}

/// The same request carried unproven, which an agent's Grant, a holder or
/// an older install could have carried: A, which holds an owner key, answers
/// it unproven (LIMIT-1: the result never vouches for its request), and the
/// result waits at B's door.
#[test]
fn a_result_for_a_request_carried_unproven_waits_past_this_installs_reserve() {
    let (second, rows, result, hash) = a_answers_the_flooders_request(&Answering {
        proven_request: false,
        a_holds_an_owner_key: true,
    });
    b_holds_the_unproven_result(&second, &rows, &result, &hash);
}

/// The owner's proven request, answered by an A that holds no owner key:
/// the request's proof does not carry to its answer (LIMIT-1
/// RESULT-NEEDS-EXECUTOR-KEY), so the result waits at B's door.
#[test]
fn a_result_from_an_executor_without_an_owner_key_waits_past_this_installs_reserve() {
    let (second, rows, result, hash) = a_answers_the_flooders_request(&Answering {
        proven_request: true,
        a_holds_an_owner_key: false,
    });
    b_holds_the_unproven_result(&second, &rows, &result, &hash);
}
