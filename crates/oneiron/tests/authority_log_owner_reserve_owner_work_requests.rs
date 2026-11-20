//! Row OWNER-RESERVE-CROSS-INSTALL-COSIGN-REFUSALS, part 2d: the owner work
//! requests the vault owner's own acts write carry the owner key's proof.
//! Past its owner reserve, install B lands only the owner's work
//! (`authority/log_budget.rs` `owner_work`), and a request install A carries
//! reaches B signed by A's install key. Since #9892 the fold takes one owner
//! key's proof beside that signature on a request; here the request writer
//! signs it when the owner made the act in person: a world settings edit's
//! key work (the edit's own witness, part 2b), the owner's re-assertion of a
//! world for a holder, and the owner's custody change of a portable secret.
//!
//! Each test admits a second machine of the owner's on A (the flooder, an
//! eligible reader and custody holder), takes A's history to a second
//! install B, floods B until its door holds a row at the reserve
//! (`owner_reserve/two_installs.rs`), then the owner's act on A records work
//! for the other machine, and B imports every row A wrote since.
//!
//! Red at the base (#9919 head c31947c1, the edits and key records carry
//! their proof, the requests none): A's request carries no cosign, and B's
//! import refuses with `AuthorityLogFull`. The control, the same edit from an
//! A that holds no owner key, waits at B.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test authority_log_owner_reserve_owner_work_requests`.

use oneiron::authority::{
    ActSurface, AuthorityEntryHash, AuthorityLogEntry, AuthorityOp, KeyWork, MachineOwnership,
    MachineRole, ReadLocation, WorldPrivacy, authority_entry_hash,
};
use oneiron::policy_model::WorldPrivacyReceipt;
use oneiron::secret_custody::{
    CustodyClass, CustodyPlan, CustodyTier, OwnerSecretRegistration, RequestedBinding,
};
use oneiron::{EntityId, ErrorKind};

#[path = "owner_reserve/two_installs.rs"]
mod two_installs;

use two_installs::{
    Rooted, Second, admit_flooder, hold_owner_key, rooted, second_install_at_its_reserve,
    written_since,
};

/// When the owner's custody acts in these tests happen.
const CUSTODY_AT: u64 = 1_780_000_000;

/// The portable secret the custody test registers on A.
const SECRET: &str = "owner-reserve-deploy";

/// A world the owner creates on A, read everywhere until an edit narrows it.
fn world_on_a(rooted: &Rooted) -> EntityId {
    rooted
        .vault
        .create_world(
            &rooted.proof,
            "Owner reserve work world",
            rooted.vault.now_recorded_at(),
        )
        .expect("FIXTURE: the owner creates a world on A")
}

/// The settings that let only the owner's machines read a world.
fn my_machines() -> WorldPrivacy {
    WorldPrivacy {
        read: ReadLocation::MyMachines,
        ..WorldPrivacy::default()
    }
}

/// The owner narrows `world` to the owner's machines on A, at the owner's
/// own settings door. A is not yet the owner's own machine, so it reads no
/// such world: the key work awaits a holder, the flooder.
fn owner_narrows_on_a(rooted: &Rooted, world: EntityId) -> WorldPrivacyReceipt {
    let receipt = rooted
        .vault
        .set_world_privacy_as(
            &rooted.proof,
            ActSurface::ThisInstall,
            world,
            my_machines(),
            None,
        )
        .expect("the owner narrows the world on A");
    assert_eq!(
        receipt.key_work,
        KeyWork::AwaitingHolder,
        "FIXTURE: A reads no world of the owner's machines, so the key work awaits a holder"
    );
    receipt
}

/// The receipt names the request A recorded for `executor`.
fn records_work_for(receipt: Option<&oneiron::world_keys::OwnerWorkReceipt>, executor: EntityId) {
    let receipt = receipt.expect("FIXTURE: the act recorded owner work");
    assert!(
        receipt.request.is_some(),
        "FIXTURE: A recorded a request: {receipt:?}"
    );
    assert_eq!(
        receipt.executor,
        Some(executor),
        "FIXTURE: the request names the flooder"
    );
}

/// The rows A stored since B took its history, and the one owner work
/// request among them with its hash.
fn the_rows_a_wrote(
    rooted: &Rooted,
    second: &Second,
) -> (Vec<Vec<u8>>, AuthorityLogEntry, AuthorityEntryHash) {
    let written = written_since(rooted, second);
    let rows = written.iter().map(|(row, _)| row.clone()).collect();
    let mut requests = written
        .into_iter()
        .filter(|(_, entry)| matches!(entry.op, AuthorityOp::OwnerWorkRequest(_)))
        .map(|(_, entry)| entry);
    let request = requests.next().expect("A wrote an owner work request");
    assert!(requests.next().is_none(), "A wrote one owner work request");
    let hash = authority_entry_hash(&request).expect("hash");
    (rows, request, hash)
}

/// B imports `rows` and counts `request`, which A signed with one owner
/// key's proof beside its install key.
fn b_lands_the_proven_request(
    second: &Second,
    rows: &[Vec<u8>],
    request: &AuthorityLogEntry,
    hash: &AuthorityEntryHash,
) {
    assert_eq!(
        request.cosigns.len(),
        1,
        "A signed the request with one owner key's proof beside its install key"
    );
    assert_ne!(
        request.cosigns[0].public_key, request.signer.public_key,
        "the proof is not A's install key"
    );
    second
        .vault
        .import_signed_authority_history(rows)
        .expect("B lands the request A carries with the owner key's proof past its reserve");
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        fold.valid_entries.contains(hash),
        "B's fold counts the request"
    );
    assert!(
        !fold.authority_log_past_bound() && !fold.vault_root_is_conflicted(),
        "B's fold stays under its floor and its root stands"
    );
}

/// The owner narrows a world on A to the owner's machines, where A holds an
/// owner key and reads no such world: A records the key work for the
/// flooder in the edit's commit, the request carries the edit's proof, and
/// B, past its owner reserve, lands the edit and the request.
#[test]
fn the_owners_world_edit_key_work_request_another_install_proves_lands_past_this_installs_reserve()
{
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let world = world_on_a(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    let receipt = owner_narrows_on_a(&rooted, world);
    records_work_for(receipt.owner_work.as_ref(), flooder.machine);
    let (rows, request, hash) = the_rows_a_wrote(&rooted, &second);
    b_lands_the_proven_request(&second, &rows, &request, &hash);
}

/// The same edit from an A that holds no owner key: A carries the edit and
/// its key work request unproven, and they wait at B's door
/// (`AuthorityLogFull`), as before.
#[test]
fn the_owners_world_edit_key_work_request_carried_unproven_waits_past_this_installs_reserve() {
    let rooted = rooted();
    let flooder = admit_flooder(&rooted);
    let world = world_on_a(&rooted);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    let receipt = owner_narrows_on_a(&rooted, world);
    records_work_for(receipt.owner_work.as_ref(), flooder.machine);
    let (rows, request, hash) = the_rows_a_wrote(&rooted, &second);
    assert!(
        request.cosigns.is_empty(),
        "A holds no owner key, so it carries the request unproven"
    );
    let import = second.vault.import_signed_authority_history(&rows);
    assert!(
        import
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::AuthorityLogFull),
        "B's door holds the unproven rows at its reserve: {import:?}"
    );
    let fold = second.vault.authority_fold().expect("B's fold");
    assert!(
        !fold.valid_entries.contains(&hash),
        "B does not count the request"
    );
}

/// The owner narrowed a world on A to the owner's machines before B took
/// A's history. The owner then re-asserts the world's settings on A, which
/// holds no key of it: A records Reassert work for the flooder at the
/// owner's own door, the request carries the owner's proof, and B, past its
/// owner reserve, lands the re-assertion and the request.
#[test]
fn the_owners_reassert_request_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let flooder = admit_flooder(&rooted);
    let world = world_on_a(&rooted);
    owner_narrows_on_a(&rooted, world);
    let second = second_install_at_its_reserve(&rooted, &flooder);
    let expected = rooted
        .vault
        .world_privacy_revision(world)
        .expect("FIXTURE: the world's settings revision on A");
    let receipt = rooted
        .vault
        .reassert_world_privacy(
            &rooted.proof,
            ActSurface::ThisInstall,
            world,
            my_machines(),
            expected,
        )
        .expect("the owner re-asserts the world on A");
    records_work_for(receipt.owner_work.as_ref(), flooder.machine);
    let (rows, request, hash) = the_rows_a_wrote(&rooted, &second);
    b_lands_the_proven_request(&second, &rows, &request, &hash);
}

/// The owner registered a portable secret on A, the owner's own machine,
/// before B took A's history. The owner then asks the flooder to rewrap it:
/// A records the custody request for the flooder at the owner's own custody
/// door, the request carries the owner's proof, and B, past its owner
/// reserve, lands it.
#[test]
fn the_owners_custody_request_another_install_proves_lands_past_this_installs_reserve() {
    let rooted = rooted();
    hold_owner_key(&rooted);
    let machine_of_a = rooted
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
            machine_of_a,
            MachineRole::Owned(MachineOwnership::Yours),
            None,
        )
        .expect("FIXTURE: the owner marks A yours");
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
                holder: Some(flooder.machine),
                recipients: vec![flooder.machine],
            },
            CUSTODY_AT + 1,
        )
        .expect("the owner asks the flooder to rewrap the secret");
    assert!(
        work.kept_here.is_none(),
        "FIXTURE: the rewrap was not kept on A"
    );
    records_work_for(work.work.as_ref(), flooder.machine);
    let (rows, request, hash) = the_rows_a_wrote(&rooted, &second);
    b_lands_the_proven_request(&second, &rows, &request, &hash);
}
