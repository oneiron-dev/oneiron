//! Checkout receive-pack, catastrophe policy, closed scope, and pre-receive scan laws.

use std::net::{IpAddr, Ipv4Addr};

use super::*;
use crate::authority::{authority_first_seen_clock_sync_key, encode_authority_first_seen_secs};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::config::VaultConfig;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;

/// The custody name and value the door tests lease and inject. Benign bytes:
/// nothing detector-shaped ever goes into the vault.
const DOOR_SECRET: &str = "door.push.token";
const SECRET_VALUE: &[u8] = b"wave6-credential-door-test-value";

/// The door scope every test operation is bound to.
const EFFECTOR: &str = DOOR_RECEIVE_PACK_EFFECTOR;

/// How far AHEAD of the wall clock [`pin_vault_instant`] puts the vault's
/// authoritative instant.
///
/// Any value the wall clock cannot reach during a test run would do; a little
/// over a day is chosen so a stray `unix_seconds_now()` in an authorization
/// path is unmistakable in a failure message rather than a plausible-looking
/// off-by-a-few-seconds.
const PINNED_INSTANT_SKEW_SECS: u64 = 100_000;

/// The same known-fixture shape `batch::secret_scan`'s own tests use.
const DETECTED_LINE: &[u8] = b"token=ghp_0123456789abcdefghijklmnopqrstuvwxyz";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn temp_vault() -> (tempfile::TempDir, Arc<Vault>) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, Arc::new(vault))
}

/// Moves the vault's authoritative instant to `secs` and returns it.
///
/// This is NOT a test-only clock injection: it persists the SAME first-seen
/// clock-floor row [`Vault::authority_fold`] maintains, under the same sync
/// key and the same codec, and the door reads it back through the same
/// monotone observation the authority plane folds on. The floor only ever
/// RAISES the observation, which is exactly how a real elapsed interval
/// reaches this door.
///
/// Two consequences, both load-bearing for the tests below:
///
/// 1. the pinned instant is somewhere the wall clock cannot be, so a door that
///    had quietly gone back to reading `unix_seconds_now()` would see every
///    fixture credential as issued in the far future and deny it;
/// 2. raising the floor REBASES this vault's clock anchor at the next reading,
///    so a test's own reading and the readings its door calls take are the
///    same second unless a whole second of wall time passes between them —
///    which is what lets the boundary assertions stay exact now that no test
///    can choose the authorization clock by argument.
fn pin_vault_instant_at(vault: &Vault, secs: u64) -> u64 {
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    vault
        .store
        .sync_state
        .put(
            &mut wtxn,
            authority_first_seen_clock_sync_key(),
            &encode_authority_first_seen_secs(secs),
        )
        .expect("persist the authority clock floor");
    wtxn.commit().expect("commit clock floor");
    secs
}

/// [`pin_vault_instant_at`] a fixed distance ahead of the wall clock.
fn pin_vault_instant(vault: &Vault) -> u64 {
    pin_vault_instant_at(vault, crate::unix_seconds_now() + PINNED_INSTANT_SKEW_SECS)
}

/// A vault with the door's secret registered, a pinned authoritative instant,
/// and a door bound to it.
fn stored_policy(body: Vec<u8>) -> DoorResult<DoorPolicy> {
    let (_tmp, vault, door) = door_fixture();
    put_policy_manifest_body(&vault, 0x37, body);
    door.door_policy()
}

fn door_fixture() -> (tempfile::TempDir, Arc<Vault>, CredentialDoorService) {
    let (tmp, vault) = temp_vault();
    let door = CredentialDoorService::new(Arc::clone(&vault));
    (tmp, vault, door)
}

fn repo() -> RepoRef {
    RepoRef::GitHubAtCommit {
        owner: "oneiron".to_owned(),
        repo: "engine".to_owned(),
        commit: "a".repeat(40),
    }
}

fn loopback() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// The instant these tests authorize at — read from the DOOR'S OWN seam.
///
/// A test can no more choose the authorization clock than a caller can: every
/// door operation reads its [`VaultInstant`] from the vault and there is no
/// argument left to pass one in. So the fixtures ask the door what the vault
/// says the time is, and anchor the credential WINDOWS they build to that
/// reading.
///
/// Those windows are still external wire facts spelled as `u64` seconds — a
/// slip declares `issued_at` and `expires_at`, and it always did. What is gone
/// is any way to declare the instant they are COMPARED against.
fn witnessed(door: &CredentialDoorService) -> VaultInstant {
    door.door_instant().expect("the door reads its own instant")
}

/// A verified holder view good for pushing, injecting and leasing, issued at
/// `issued_at` and alive for `lifetime_secs` from there.
fn push_credential_from(issued_at: u64, lifetime_secs: u64) -> DoorCredential {
    let verbs = [DOOR_VERB_RECEIVE_PACK, "inject", "lease"];
    let records = [repo_record(&repo()), DOOR_SECRET.to_owned()];
    DoorCredential::verified(
        "slip-push-1",
        "holder:tester",
        issued_at,
        issued_at + lifetime_secs,
    )
    .with_verbs(verbs)
    .with_records(records)
    .with_channels([EFFECTOR])
}

/// The same, issued at the vault's witnessed instant.
fn push_credential_living(now: VaultInstant, lifetime_secs: u64) -> DoorCredential {
    push_credential_from(now.secs(), lifetime_secs)
}

/// The default push credential: 600s of validity left at `now`.
fn push_credential(now: VaultInstant) -> DoorCredential {
    push_credential_living(now, 600)
}

fn blob(path: &str, lines: &[&[u8]]) -> PushedBlob {
    PushedBlob {
        path: path.to_owned(),
        oid: "b".repeat(40),
        added_lines: lines.iter().map(|line| line.to_vec()).collect(),
    }
}

fn scan(door: &CredentialDoorService, blobs: &[PushedBlob]) -> DoorResult<DoorScanVerdict> {
    door.pre_receive_scan(&repo(), blobs)
}

/// Writes a POLICY_MANIFEST row carrying `rows` as its body, the way the
/// engine seeder does — the door dial resolves over exactly these bodies.
fn put_policy_manifest(vault: &Vault, seed: u8, rows: Vec<(Value, Value)>) {
    put_policy_manifest_body(vault, seed, encoded_map(rows));
}

/// The same row, with the body written VERBATIM — the seam a corrupt or
/// partially written manifest body arrives through.
fn put_policy_manifest_body(vault: &Vault, seed: u8, data: Vec<u8>) {
    let id = EntityId::from_bytes([seed; ENTITY_ID_LEN]).expect("manifest id");
    let learned_at = 2_u64;
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
    payload.push(ENTITY_TYPE_POLICY_MANIFEST);
    for _ in 0..3 {
        payload.extend_from_slice(&learned_at.to_be_bytes());
    }
    payload.extend_from_slice(&data);

    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    vault
        .store
        .entities
        .put(&mut wtxn, id.as_bytes(), &payload)
        .expect("put manifest");
    let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
    vault
        .store
        .type_index
        .put(&mut wtxn, &type_key, &[])
        .expect("type index row");
    wtxn.commit().expect("commit manifest");
}

/// Indexes `id` as a POLICY_MANIFEST while the entity plane says something
/// else: `payload: None` writes NO entity row (the dangling entry corruption
/// leaves behind), and `Some(bytes)` writes the row verbatim so a header the
/// door cannot parse — or one naming another entity type — can be staged.
fn put_manifest_index_over_entity(vault: &Vault, seed: u8, payload: Option<&[u8]>) {
    let id = EntityId::from_bytes([seed; ENTITY_ID_LEN]).expect("manifest id");
    let mut wtxn = vault.store.env.write_txn().expect("write txn");
    if let Some(bytes) = payload {
        vault
            .store
            .entities
            .put(&mut wtxn, id.as_bytes(), bytes)
            .expect("put entity");
    }
    let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
    vault
        .store
        .type_index
        .put(&mut wtxn, &type_key, &[])
        .expect("type index row");
    wtxn.commit().expect("commit manifest index");
}

/// An entity payload with a well-formed metadata header naming `entity_type`
/// and no body — enough to reach the door's type check.
fn entity_payload_of_type(entity_type: u8) -> Vec<u8> {
    let mut payload = vec![entity_type];
    for _ in 0..3 {
        payload.extend_from_slice(&2_u64.to_be_bytes());
    }
    payload
}

fn encoded_map(rows: Vec<(Value, Value)>) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &Value::Map(rows)).expect("encode body");
    body
}

fn ttl_row(secs: u64) -> (Value, Value) {
    let key = Value::from(door_policy_keys::MAX_LEASE_TTL_SECS);
    (key, Value::from(secs))
}

fn effector_row(names: Vec<Value>) -> (Value, Value) {
    let key = Value::from(door_policy_keys::ALLOWED_EFFECTORS);
    (key, Value::Array(names))
}

fn deny_reason(err: CredentialDoorError) -> DoorDenyReason {
    match err {
        CredentialDoorError::UnauthorizedPrincipal { reason }
        | CredentialDoorError::Ask { reason, .. } => reason,
        other => panic!("expected a default-deny refusal, got {other:?}"),
    }
}

fn is_scope_refusal(err: &CredentialDoorError) -> bool {
    matches!(err, CredentialDoorError::LeaseScopeRefused { .. })
}

fn is_invalid_policy(err: &CredentialDoorError) -> bool {
    matches!(err, CredentialDoorError::InvalidDoorPolicy { .. })
}

fn is_floor_named(err: &CredentialDoorError) -> bool {
    matches!(err, CredentialDoorError::FloorNamed { .. })
}

fn is_scan_failure(err: &CredentialDoorError) -> bool {
    matches!(err, CredentialDoorError::ScanFailure { .. })
}

fn is_binary_rejected(err: &CredentialDoorError) -> bool {
    matches!(err, CredentialDoorError::BinaryContentRejected { .. })
}

fn secret_text() -> &'static str {
    std::str::from_utf8(SECRET_VALUE).expect("benign fixture is text")
}

// ---------------------------------------------------------------------------
// Catastrophe floors, outside the lattice
// ---------------------------------------------------------------------------

#[test]
fn the_door_composes_over_the_vault_it_was_given() {
    let (_tmp, _vault, door) = door_fixture();
    let (_other_tmp, other_vault, other_door) = door_fixture();
    put_policy_manifest(&other_vault, 0x26, vec![effector_row(vec![])]);
    let credential = push_credential(witnessed(&door));
    door.authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .unwrap();
    let other_credential = push_credential(witnessed(&other_door));
    let err = other_door
        .authenticate_receive_pack(Some(&other_credential), &repo(), loopback())
        .expect_err("the other vault's closed dial must refuse");
    assert!(is_scope_refusal(&err));
}

#[test]
fn catastrophe_floors_are_constants_not_dials() {
    const {
        assert!(DOOR_SCAN_ALWAYS_ON);
    }
    assert_eq!(DOOR_MAX_LEASE_TTL_SECS, 3600);
    assert_eq!(DOOR_ONE_SHOT_MAX_LIFETIME_SECS, 300);
}

#[test]
fn a_row_naming_the_scan_floor_fails_closed_and_the_scan_still_runs() {
    // The lattice may not reach a floor at all: naming one is refused, and
    // the scan the row tried to name keeps rejecting.
    let (_tmp, vault, door) = door_fixture();
    let row = (Value::from("secret.door.scan.enabled"), Value::from(false));
    put_policy_manifest(&vault, 0x11, vec![row]);

    let err = door.door_policy().expect_err("floors are not dial space");
    assert!(is_floor_named(&err));

    let blobs = [blob("src/lib.rs", &[DETECTED_LINE])];
    let verdict = scan(&door, &blobs).expect("the scan reads no dial");
    assert!(matches!(verdict, DoorScanVerdict::Rejected { .. }));
}

#[test]
fn a_row_naming_the_ttl_floor_fails_closed() {
    let (_tmp, vault, door) = door_fixture();
    let key = "secret.door.floor.door_max_lease_ttl_secs";
    let row = (Value::from(key), Value::from(7200_u64));
    put_policy_manifest(&vault, 0x12, vec![row]);

    let err = door.door_policy().expect_err("floor naming fails closed");
    assert!(is_floor_named(&err));
}

#[test]
fn a_slip_may_not_name_a_floor_either() {
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door).secs();
    let credential = DoorCredential::verified("slip-floor", "holder:t", now, now + 60)
        .with_verbs(["DOOR_SCAN_ALWAYS_ON"])
        .with_records([repo_record(&repo())])
        .with_channels([EFFECTOR]);

    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect_err("a verb naming a floor is refused");
    assert!(is_floor_named(&err));
}

// ---------------------------------------------------------------------------
// T0 — remote at door
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Authenticated receive-pack — loopback is not an identity
// ---------------------------------------------------------------------------

#[test]
fn an_absent_credential_on_loopback_is_refused() {
    let (_tmp, _vault, door) = door_fixture();
    let err = door
        .authenticate_receive_pack(None, &repo(), loopback())
        .expect_err("127.0.0.1 is a route, not a principal");
    assert_eq!(deny_reason(err), DoorDenyReason::CredentialAbsent);
}

#[test]
fn a_live_credential_passes_the_one_evaluator_from_any_address() {
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = push_credential(now);
    let elsewhere = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    door.authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect("a live slip authenticates on loopback");
    door.authenticate_receive_pack(Some(&credential), &repo(), elsewhere)
        .expect("and off it: the address is not an authorization input");
}

#[test]
fn a_dial_with_no_allowed_effectors_shuts_the_receive_pack_door_itself() {
    // `door:receive-pack` is a door effector like any other. If the dial
    // narrowed leases and injections but not the push path, then the single
    // row an operator reaches for in a catastrophe — an empty effector set —
    // would close everything DOWNSTREAM of receive-pack while leaving
    // receive-pack itself open, which is the one door that matters.
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = push_credential(now);
    let elsewhere = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    door.authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect("the same push authenticates under the default dial");

    put_policy_manifest(&vault, 0x41, vec![effector_row(vec![])]);
    let policy = door.door_policy().expect("dial");
    assert!(!policy.admits_effector(EFFECTOR));

    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect_err("the catastrophe dial must be able to shut the push door");
    assert!(is_scope_refusal(&err));
    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), elsewhere)
        .expect_err("from any address, like every other door answer");
    assert!(is_scope_refusal(&err));
    // The dial NARROWS the one evaluator; it does not replace it. An absent
    // credential is still refused as an absent principal.
    let err = door
        .authenticate_receive_pack(None, &repo(), loopback())
        .expect_err("still default-deny");
    assert_eq!(deny_reason(err), DoorDenyReason::CredentialAbsent);
}

#[test]
fn a_dial_that_keeps_receive_pack_still_authenticates_it() {
    // The dial narrows; it does not deny by existing. A manifest that lowers
    // the TTL ceiling, or that names receive-pack explicitly, leaves the push
    // path exactly where it was.
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = push_credential(now);

    let named = vec![Value::from(DOOR_RECEIVE_PACK_EFFECTOR)];
    put_policy_manifest(&vault, 0x42, vec![ttl_row(60), effector_row(named)]);
    let policy = door.door_policy().expect("dial");

    assert!(policy.admits_effector(EFFECTOR));

    door.authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect("a narrowed dial that keeps the door open keeps it open");
}

#[test]
fn an_unreadable_dial_refuses_receive_pack_authentication() {
    // Fail-closed applies to the push path too: a dial the door cannot read
    // is never the permissive default that would let the push through.
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = push_credential(now);
    put_policy_manifest(&vault, 0x43, vec![ttl_row(DOOR_MAX_LEASE_TTL_SECS + 1)]);

    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect_err("an unreadable dial denies the push");
    assert!(is_invalid_policy(&err));
}

#[test]
fn expired_and_insufficient_slips_default_deny() {
    let (_tmp, _vault, door) = door_fixture();
    let instant = witnessed(&door);
    let now = instant.secs();
    let record = repo_record(&repo());

    let expired = DoorCredential::verified("slip-expired", "holder:t", now - 600, now - 1)
        .with_verbs([DOOR_VERB_RECEIVE_PACK])
        .with_records([record.clone()])
        .with_channels([EFFECTOR]);
    // Insufficient: a slip that may lease but never got the push verb.
    let insufficient = DoorCredential::verified("slip-lease-only", "holder:t", now, now + 60)
        .with_verbs(["lease"])
        .with_records([record.clone()])
        .with_channels([EFFECTOR]);
    let other_repo = DoorCredential::verified("slip-other-repo", "holder:t", now, now + 60)
        .with_verbs([DOOR_VERB_RECEIVE_PACK])
        .with_records(["github:oneiron/other"])
        .with_channels([EFFECTOR]);
    let other_channel = DoorCredential::verified("slip-other-chan", "holder:t", now, now + 60)
        .with_verbs([DOOR_VERB_RECEIVE_PACK])
        .with_records([record.clone()])
        .with_channels(["connector:gmail"]);
    // A blank holder view is not a verified holder.
    let blank = DoorCredential::verified("", "", now, now + 60)
        .with_verbs([DOOR_VERB_RECEIVE_PACK])
        .with_records([record])
        .with_channels([EFFECTOR]);

    let cases = vec![
        (expired, DoorDenyReason::Expired),
        (insufficient, DoorDenyReason::VerbNotInSlip),
        (other_repo, DoorDenyReason::RecordOutsideSlip),
        (other_channel, DoorDenyReason::ChannelOutsideSlip),
        (blank, DoorDenyReason::HolderUnverified),
    ];

    for (credential, expected) in cases {
        let refusal = door
            .authenticate_receive_pack(Some(&credential), &repo(), loopback())
            .expect_err("default deny, on loopback like anywhere else");
        assert_eq!(deny_reason(refusal), expected);
    }
}

// ---------------------------------------------------------------------------
// T1 — lease tickets
// ---------------------------------------------------------------------------

#[test]
fn a_door_operation_takes_its_instant_from_the_vault_clock_seam() {
    // The seam this replaces was a caller-supplied `now: u64`. Whoever passed
    // it decided, by itself, whether the presented slip was inside its own
    // window: `now = issued_at` revives a credential that died an hour ago,
    // and no default-deny arm further down the evaluator can refuse it,
    // because by then the lie has already been told. There is no such
    // argument any more, and `VaultInstant` has no `From<u64>`, so the door's
    // reading can only have come from the vault.
    //
    // The vault's authoritative instant is pinned somewhere the wall clock
    // cannot be, through the authority plane's own persisted clock floor.
    // Every assertion below distinguishes "the door read the vault" from "the
    // door read `unix_seconds_now()`".
    let (_tmp, vault, door) = door_fixture();
    let wall = crate::unix_seconds_now();
    let pinned = pin_vault_instant(&vault);

    let now = witnessed(&door);
    assert!(
        now.secs() >= pinned,
        "the door's instant {} is below the persisted authority floor {pinned}",
        now.secs()
    );
    assert!(
        now.secs() >= wall + PINNED_INSTANT_SKEW_SECS,
        "the door's instant {} is the wall clock, not the vault's clock",
        now.secs()
    );

    // A credential that is perfectly live BY THE WALL CLOCK is refused: the
    // window is compared against the vault's reading, and there is no longer
    // any argument that could tell the door otherwise.
    let wall_live = DoorCredential::verified("slip-wall", "holder:t", wall, wall + 600)
        .with_verbs([DOOR_VERB_RECEIVE_PACK])
        .with_records([repo_record(&repo())])
        .with_channels([EFFECTOR]);
    let err = door
        .authenticate_receive_pack(Some(&wall_live), &repo(), loopback())
        .expect_err("a wall-clock window is not the vault's window");
    assert_eq!(deny_reason(err), DoorDenyReason::Expired);

    let credential = push_credential(now);
    door.authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect("a slip live at the vault's instant authenticates");
}

#[test]
fn a_credential_dead_at_the_vault_instant_cannot_push() {
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door).secs();
    let credential = push_credential_from(now - 3600, 600);

    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect_err("a slip dead at the vault's instant is refused");
    assert_eq!(deny_reason(err), DoorDenyReason::Expired);
}

#[test]
fn two_dials_resolve_most_restrictive() {
    let (_tmp, vault, door) = door_fixture();
    put_policy_manifest(
        &vault,
        0x22,
        vec![ttl_row(1800), effector_row(vec![EFFECTOR.into()])],
    );
    put_policy_manifest(&vault, 0x23, vec![ttl_row(600), effector_row(vec![])]);

    let policy = door.door_policy().expect("dial");
    assert!(!policy.admits_effector(EFFECTOR));
}

#[test]
fn a_dial_may_narrow_the_effector_set_but_never_widen_it() {
    let (_tmp, vault, door) = door_fixture();
    put_policy_manifest(&vault, 0x24, vec![effector_row(vec![])]);
    let now = witnessed(&door);
    let credential = push_credential(now);

    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect_err("a dial allowing no effector denies every push");
    assert!(is_scope_refusal(&err));

    let foreign = vec![Value::from("connector:gmail")];
    let body = encoded_map(vec![effector_row(foreign)]);
    let widened = stored_policy(body).expect_err("widening fails");
    assert!(is_invalid_policy(&widened));
}

#[test]
fn a_dial_raising_the_ttl_ceiling_fails_closed() {
    let (_tmp, vault, door) = door_fixture();
    let raised = DOOR_MAX_LEASE_TTL_SECS + 1;
    put_policy_manifest(&vault, 0x25, vec![ttl_row(raised)]);

    let err = door.door_policy().expect_err("a raise is not a dial move");
    assert!(is_invalid_policy(&err));

    let now = witnessed(&door);
    let credential = push_credential(now);
    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect_err("an unreadable dial denies every push");
    assert!(is_invalid_policy(&err));
}

#[test]
fn malformed_and_duplicated_dial_rows_never_default_open() {
    let key = Value::from(door_policy_keys::MAX_LEASE_TTL_SECS);
    let body = encoded_map(vec![(key, Value::from("900"))]);
    let malformed = stored_policy(body).expect_err("unreadable row");
    assert!(is_invalid_policy(&malformed));

    let body = encoded_map(vec![ttl_row(900), ttl_row(600)]);
    let duplicated = stored_policy(body).expect_err("ambiguous row");
    assert!(is_invalid_policy(&duplicated));
}

#[test]
fn a_partially_decoded_dial_body_never_defaults_open() {
    // A body that announces a map and then cannot be read as one is a
    // declaration the door cannot SEE — never "a pack that declared nothing".
    let narrowing = encoded_map(vec![ttl_row(600)]);

    let mut truncated = narrowing.clone();
    truncated.pop();
    let err = stored_policy(truncated.clone()).expect_err("a truncated declaration");
    assert!(is_invalid_policy(&err));

    let mut trailing = narrowing;
    trailing.push(0x00);
    let err = stored_policy(trailing).expect_err("bytes left past the map");
    assert!(is_invalid_policy(&err));

    // And it denies at the door instead of resolving the permissive default
    // the narrowing row existed to replace.
    let (_tmp, vault, door) = door_fixture();
    put_policy_manifest_body(&vault, 0x27, truncated);
    let err = door
        .door_policy()
        .expect_err("an unreadable dial resolves to nothing");
    assert!(is_invalid_policy(&err));

    let now = witnessed(&door);
    let credential = push_credential(now);
    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect_err("no push is admitted against an unreadable dial");
    assert!(is_invalid_policy(&err));
}

#[test]
fn a_body_with_no_door_rows_takes_the_safe_default() {
    let (_tmp, vault, door) = door_fixture();
    let row = (Value::from("gate.unrelated.key"), Value::from(1_u64));
    put_policy_manifest(&vault, 0x26, vec![row]);

    let policy = door.door_policy().expect("dial");

    assert!(policy.admits_effector(EFFECTOR));
    assert!(!policy.admits_effector(""));
}

#[test]
fn a_dangling_manifest_index_entry_refuses_the_door_and_writes_nothing() {
    // The corruption this fails closed on is the cheapest one available: an
    // indexed POLICY_MANIFEST whose body is gone. If the resolver skipped it,
    // deleting exactly one entity row would restore the FULL effector set and
    // the FULL TTL ceiling the deleted manifest existed to narrow — a dial
    // that can be widened by damaging the store is not a dial.
    let (_tmp, vault, door) = door_fixture();
    put_manifest_index_over_entity(&vault, 0x32, None);

    let err = door
        .door_policy()
        .expect_err("a dangling manifest entry is not a manifest that declared nothing");
    assert!(is_invalid_policy(&err));

    let now = witnessed(&door);
    let credential = push_credential(now);
    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect_err("no push is admitted against a corrupt manifest plane");
    assert!(is_invalid_policy(&err));

    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect_err("nor does a push");
    assert!(is_invalid_policy(&err));
}

#[test]
fn every_broken_manifest_index_branch_fails_closed() {
    fn assert_fails_closed(door: &CredentialDoorService, case: &str, sentinels: &[&str]) {
        match door.door_policy() {
            Err(err) => {
                assert!(is_invalid_policy(&err), "case `{case}`: {err:?}");
                let rendered = format!("{err} / {err:?}");
                for sentinel in sentinels {
                    assert!(!rendered.contains(sentinel), "case `{case}`");
                }
            }
            Ok(policy) => panic!("case `{case}` resolved {policy:?}"),
        }
    }

    fn assert_default_admission(door: &CredentialDoorService) {
        let clean = door.door_policy().expect("clean dial");

        assert!(clean.admits_effector(EFFECTOR));
        assert!(!clean.admits_effector(""));
    }

    // 1. A type-index key with a sensitive suffix and an invalid length.
    let (_tmp, vault, door) = door_fixture();
    assert_default_admission(&door);
    let mut malformed_key = vec![ENTITY_TYPE_POLICY_MANIFEST];
    malformed_key.extend_from_slice(SECRET_VALUE);
    {
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        vault
            .store
            .type_index
            .put(&mut wtxn, &malformed_key, &[])
            .expect("malformed type key");
        wtxn.commit().expect("commit malformed key");
    }
    assert_fails_closed(
        &door,
        "unusable type-index key",
        &[
            secret_text(),
            "77617665362d63726564656e7469616c2d646f6f722d746573742d76616c7565",
        ],
    );

    // 2. An indexed entry whose entity row is gone.
    let (_tmp, vault, door) = door_fixture();
    assert_default_admission(&door);
    put_manifest_index_over_entity(&vault, 0x33, None);
    assert_fails_closed(
        &door,
        "dangling entity row",
        &[
            "33333333333333333333333333333333",
            "33333333-3333-3333-3333-333333333333",
        ],
    );

    // 3. An entity row too short to carry a metadata header.
    let (_tmp, vault, door) = door_fixture();
    assert_default_admission(&door);
    let mut stub = vec![ENTITY_TYPE_POLICY_MANIFEST];
    stub.extend_from_slice(b"private-header");
    put_manifest_index_over_entity(&vault, 0x34, Some(&stub));
    assert_fails_closed(
        &door,
        "unparseable metadata header",
        &["private-header", "707269766174652d686561646572"],
    );

    // 4. An entry naming an entity of some other type, with sensitive body bytes.
    let (_tmp, vault, door) = door_fixture();
    assert_default_admission(&door);
    let mut other = entity_payload_of_type(ENTITY_TYPE_POLICY_MANIFEST ^ 0x01);
    other.extend_from_slice(SECRET_VALUE);
    put_manifest_index_over_entity(&vault, 0x35, Some(other.as_slice()));
    assert_fails_closed(
        &door,
        "entity of another type",
        &[
            secret_text(),
            "77617665362d63726564656e7469616c2d646f6f722d746573742d76616c7565",
        ],
    );
}

#[test]
fn a_manifest_body_that_is_present_but_unreadable_refuses_the_door() {
    // The body half of the same audit: a POLICY_MANIFEST row whose body was
    // truncated to nothing is a declaration erased, not a pack that never
    // declared.
    let (_tmp, vault, door) = door_fixture();
    put_policy_manifest_body(&vault, 0x36, Vec::new());

    let err = door.door_policy().expect_err("an erased body");
    assert!(is_invalid_policy(&err));

    let now = witnessed(&door);
    let credential = push_credential(now);
    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect_err("and denies a push");
    assert!(is_invalid_policy(&err));
}

// ---------------------------------------------------------------------------
// The admission is atomic with the stamp
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The typed admission values are the only authority shape
// ---------------------------------------------------------------------------

#[test]
fn a_door_effector_is_a_member_of_the_constant_set_not_a_matching_string() {
    // The raw effector plumbing this replaces was a `BTreeSet<String>` that
    // could hold anything, checked for membership by whoever remembered to.
    // Now membership is decided once, on the way in, and a value that exists
    // IS a member.
    let known = DoorEffector::parse(DOOR_RECEIVE_PACK_EFFECTOR).expect("a known effector");
    assert_eq!(known.as_str(), DOOR_RECEIVE_PACK_EFFECTOR);
    // What came back is one of the door's own constants — a `&'static str`
    // drawn from `DOOR_EFFECTORS`, never the caller's bytes re-wrapped.
    assert!(DOOR_EFFECTORS.contains(&known.as_str()));

    for foreign in [
        "",
        "connector:gmail",
        "door:receive-pack ",
        " door:receive-pack",
        "DOOR:RECEIVE-PACK",
        "door:receive-pack\0",
    ] {
        assert!(
            DoorEffector::parse(foreign).is_none(),
            "{foreign:?} is not a door effector"
        );
    }
}

#[test]
fn the_dial_is_a_subset_of_the_door_effectors_by_construction() {
    let widest = EffectorDial::default();
    assert_eq!(widest.len(), DOOR_EFFECTORS.len());
    let known = DoorEffector::parse(EFFECTOR).expect("a known effector");
    assert!(widest.admits(known));

    // A body naming anything outside the constant set never becomes a dial at
    // all: the refusal happens at decode, so no widened set exists downstream
    // for anything to be checked against — or to forget to check.
    let foreign = vec![Value::from("connector:gmail")];
    let body = encoded_map(vec![effector_row(foreign)]);
    let widened = stored_policy(body).expect_err("a widen is not a dial move");
    assert!(is_invalid_policy(&widened));

    // A body naming the door's own effector narrows to exactly it.
    let named = vec![Value::from(DOOR_RECEIVE_PACK_EFFECTOR)];
    let body = encoded_map(vec![effector_row(named)]);
    let policy = stored_policy(body).expect("a narrowing declaration decodes");
    assert!(policy.admits_effector(EFFECTOR));

    // An empty declaration is a SHUT door, not a default one.
    let body = encoded_map(vec![effector_row(vec![])]);
    let policy = stored_policy(body).expect("an empty declaration decodes");
    assert!(!policy.admits_effector(EFFECTOR));
}

// ---------------------------------------------------------------------------
// Pre-receive verdict
// ---------------------------------------------------------------------------

#[test]
fn a_clean_push_is_clean() {
    let (_tmp, _vault, door) = door_fixture();
    let blobs = [
        blob("src/lib.rs", &[b"fn main() {}", b"// nothing to see"]),
        blob("README.md", &[b"# engine"]),
    ];

    let verdict = scan(&door, &blobs).expect("a clean push scans");
    assert_eq!(verdict, DoorScanVerdict::Clean);
}

#[test]
fn a_detector_hit_rejects_with_a_valueless_lift_proposal() {
    let (_tmp, _vault, door) = door_fixture();
    let blobs = [blob("src/config.rs", &[b"// fine", DETECTED_LINE])];

    let verdict = scan(&door, &blobs).expect("the scan produced a verdict");
    let DoorScanVerdict::Rejected { proposals } = verdict else {
        panic!("a detector hit must reject the push");
    };

    assert_eq!(proposals.len(), 1);
    let proposal = &proposals[0];
    assert_eq!(proposal.path, "src/config.rs");
    assert_eq!(proposal.reason, "gate.secret_scan.github_token");
    let suggested = "oneiron_engine.src_config_rs";
    assert_eq!(proposal.suggested_secret_name, suggested);

    // Nothing that travels back to the pusher carries the matched bytes.
    let printed = format!("{proposals:?}");
    assert!(!printed.contains("ghp_"));
}

#[test]
fn a_pushed_blob_debug_never_prints_added_bytes() {
    let printed = format!("{:?}", blob("src/config.rs", &[DETECTED_LINE]));
    assert!(!printed.contains("ghp_"));
}

#[test]
fn binary_lines_reject_typed_whatever_their_entropy_or_magic() {
    let (_tmp, _vault, door) = door_fixture();
    let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR".to_vec();
    let samples: Vec<(&str, Vec<u8>)> = vec![
        // Low entropy, NUL byte.
        ("low-entropy-nul", b"aaaaaaaa\0aaaaaaaa".to_vec()),
        // PNG magic (also NUL-bearing): no known-format allowlist exists.
        ("magic-png", png),
        // High-entropy invalid UTF-8, no NUL, no magic.
        ("high-entropy", vec![0xff, 0xfe, 0xc3, 0x28, 0x9a]),
        // Tiny, low entropy, one stray continuation byte: still binary.
        ("tiny-invalid-utf8", vec![b'a', 0x80]),
    ];

    for (name, bytes) in samples {
        let blobs = [blob("assets/blob.bin", &[&bytes])];
        let err = scan(&door, &blobs).expect_err("no pass path exists");
        assert!(is_binary_rejected(&err), "sample {name}");
        match err {
            CredentialDoorError::BinaryContentRejected { path } => {
                assert_eq!(path, "assets/blob.bin", "sample {name}");
            }
            other => panic!("sample {name} rejected wrongly: {other:?}"),
        }
    }
}

#[test]
fn binary_content_dominates_a_detector_hit_in_the_same_blob() {
    let (_tmp, _vault, door) = door_fixture();
    let lines: [&[u8]; 2] = [DETECTED_LINE, b"trailing\0binary"];
    let blobs = [blob("src/config.rs", &lines)];

    let err = scan(&door, &blobs).expect_err("never partially scanned");
    assert!(is_binary_rejected(&err));
}

#[test]
fn unusable_seam_input_is_a_fail_closed_scan_failure() {
    let (_tmp, _vault, door) = door_fixture();

    let mut nameless = blob("src/lib.rs", &[b"fn main() {}"]);
    nameless.path = String::new();
    let err = scan(&door, &[nameless]).expect_err("unnamed never passes");
    assert!(is_scan_failure(&err));

    let mut unaddressable = blob("src/lib.rs", &[b"fn main() {}"]);
    unaddressable.oid = "not-an-object-id".to_owned();
    let blobs = [unaddressable];
    let err = scan(&door, &blobs).expect_err("unaddressable never passes");
    assert!(is_scan_failure(&err));
}

#[test]
fn a_scanner_failure_is_a_rejection() {
    let (_tmp, _vault, door) = door_fixture();
    let blobs = [blob("src/lib.rs", &[b"fn main() {}"])];

    scan_fault_hook::arm_scanner_failure();
    let err = scan(&door, &blobs).expect_err("a scan that did not run");
    assert!(is_scan_failure(&err));
}

// ---------------------------------------------------------------------------
// One-shot hatch and the recorded mint stop
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Nothing printable carries a value
// ---------------------------------------------------------------------------

#[test]
fn door_refusals_and_credentials_print_no_secret_material() {
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = push_credential(now);
    let printed = format!("{credential:?}");
    assert_eq!(credential.slip_id(), "slip-push-1");
    assert_eq!(credential.holder_ref(), "holder:tester");
    assert!(printed.contains("slip-push-1"));
    assert!(!printed.contains(secret_text()));

    let errors = [
        CredentialDoorError::BinaryContentRejected {
            path: "assets/blob.bin".to_owned(),
        },
        CredentialDoorError::UnauthorizedPrincipal {
            reason: DoorDenyReason::Expired,
        },
        CredentialDoorError::AuthorityRejected,
        CredentialDoorError::LeaseScopeRefused {
            effector: DOOR_RECEIVE_PACK_EFFECTOR.to_owned(),
            reason: "scope refused",
        },
    ];
    for err in &errors {
        let rendered = format!("{err} / {err:?}");
        assert!(!rendered.contains(secret_text()));
        assert!(!rendered.contains("ghp_"));
    }
}

mod authority;

#[test]
fn all_scope_admits_only_the_live_door_preset_vocabulary() {
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door);
    let mut credential = push_credential(now);
    let super::door_credential::DoorGrant::Witnessed(scope) = &mut credential.grant else {
        panic!("witnessed fixture")
    };
    scope.verbs = crate::federation::ScopeAxis::All;
    for verb in ["receive-pack", "inject", "lease", "redeem"] {
        assert!(
            credential
                .evaluate(verb, &repo_record(&repo()), EFFECTOR, now)
                .is_ok()
        );
    }
    for verb in ["mint", "unknown"] {
        assert_eq!(
            deny_reason(
                credential
                    .evaluate(verb, &repo_record(&repo()), EFFECTOR, now)
                    .unwrap_err()
            ),
            DoorDenyReason::VerbNotInSlip
        );
    }
    let explicit = push_credential(now).with_verbs(["mint"]);
    assert_eq!(
        deny_reason(
            explicit
                .evaluate("mint", &repo_record(&repo()), EFFECTOR, now)
                .unwrap_err()
        ),
        DoorDenyReason::VerbNotInSlip
    );
    assert!(super::verb_class::preset("door.mint").is_none());
}
