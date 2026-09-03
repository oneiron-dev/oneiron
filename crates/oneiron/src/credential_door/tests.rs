//! CSTDY-02 unit tests: the T0 door composition (the egress gets bytes, the
//! caller gets a receipt), default-deny credential evaluation with no
//! loopback bypass, lease-ticket TTL/scope discipline against a narrow-only
//! dial, the catastrophe floors proving themselves independent of every row
//! and every slip, the pre-receive verdict (detector hit, clean push,
//! fail-closed scanner, binary reject-all), and the one-shot hatch with its
//! recorded mint stop.

use std::net::{IpAddr, Ipv4Addr};

use super::*;
use crate::authority::{authority_first_seen_clock_sync_key, encode_authority_first_seen_secs};
use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::config::VaultConfig;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::secret_custody::{
    CustodyClass, CustodyTier, SECRET_CUSTODY_SCHEMA_VERSION, SecretBinding, SecretCustodyFloor,
    SecretCustodyRecord, SecretCustodyStatus,
};
use crate::secret_lease::{SECRET_LEASE_KEY_PREFIX, SECRET_MATERIALIZATION_RECEIPT_PREFIX};

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

fn register_door_secret(vault: &Vault) {
    let binding = SecretBinding {
        effector: EFFECTOR.to_owned(),
        tier_ceiling: CustodyTier::T2LocalRegistered,
        scopes: vec!["read".to_owned()],
    };
    let rec = SecretCustodyRecord {
        schema_version: SECRET_CUSTODY_SCHEMA_VERSION,
        name: DOOR_SECRET.to_owned(),
        class: CustodyClass::CustodyPortable,
        device_only: false,
        value_bytes: SECRET_VALUE.to_vec(),
        status: SecretCustodyStatus::Active,
        registered_at: 1_700_000_000,
        rotated_at: None,
        rotation_generation: 0,
        bindings: vec![binding],
        manifest_ref: "secrets.toml".to_owned(),
        declared_paths: vec![".secrets/door.key".to_owned()],
        policy_floor_snapshot: SecretCustodyFloor::default(),
    };
    vault.register_secret(rec).expect("register secret");
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
/// 2. raising the floor REBASES the clock domain's anchor at the next reading,
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
fn door_fixture() -> (tempfile::TempDir, Arc<Vault>, CredentialDoorService) {
    let (tmp, vault) = temp_vault();
    register_door_secret(&vault);
    pin_vault_instant(&vault);
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
    let verbs = [DOOR_VERB_RECEIVE_PACK, DOOR_VERB_INJECT, DOOR_VERB_LEASE];
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

/// A push credential with more validity left than any floor or dial, so a TTL
/// test measures the ceiling under test and not the slip's own remaining life.
fn long_lived_push_credential(now: VaultInstant) -> DoorCredential {
    push_credential_living(now, 2 * DOOR_MAX_LEASE_TTL_SECS)
}

/// A verified one-shot: single-use caveat, one named secret, one named
/// effector, 120s of life from `issued_at`.
fn one_shot_credential_from(issued_at: u64) -> DoorCredential {
    DoorCredential::verified(
        "slip-one-shot-1",
        "holder:tester",
        issued_at,
        issued_at + 120,
    )
    .with_verbs([DOOR_VERB_REDEEM])
    .with_records([DOOR_SECRET])
    .with_channels([EFFECTOR])
    .with_single_use_caveat()
}

/// The same, issued at the vault's witnessed instant.
fn one_shot_credential(now: VaultInstant) -> DoorCredential {
    one_shot_credential_from(now.secs())
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

fn vault_meta_rows(vault: &Vault) -> u64 {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault.store.vault_meta.len(&rtxn).expect("vault_meta len")
}

fn entity_rows(vault: &Vault) -> u64 {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    vault.store.entities.len(&rtxn).expect("entities len")
}

fn prefix_rows(vault: &Vault, prefix: &str) -> usize {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let rows = vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, prefix.as_bytes())
        .expect("prefix iter");
    let mut count = 0;
    for row in rows {
        row.expect("row");
        count += 1;
    }
    count
}

fn has_receipt_row(vault: &Vault, receipt_id: &EntityId) -> bool {
    let hex = receipt_id.to_hex();
    let key = format!("{SECRET_MATERIALIZATION_RECEIPT_PREFIX}{hex}");
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let row = vault
        .store
        .vault_meta
        .get(&rtxn, key.as_bytes())
        .expect("read receipt row");
    row.is_some()
}

fn lease_rows(vault: &Vault) -> usize {
    prefix_rows(vault, SECRET_LEASE_KEY_PREFIX)
}

fn receipt_rows(vault: &Vault) -> usize {
    prefix_rows(vault, SECRET_MATERIALIZATION_RECEIPT_PREFIX)
}

fn deny_reason(err: CredentialDoorError) -> DoorDenyReason {
    match err {
        CredentialDoorError::UnauthorizedPrincipal { reason } => reason,
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

fn is_log_unreachable(err: &CredentialDoorError) -> bool {
    matches!(err, CredentialDoorError::AuthorityLogUnreachable)
}

fn secret_text() -> &'static str {
    std::str::from_utf8(SECRET_VALUE).expect("benign fixture is text")
}

// ---------------------------------------------------------------------------
// Catastrophe floors, outside the lattice
// ---------------------------------------------------------------------------

#[test]
fn the_door_composes_over_the_vault_it_was_given() {
    let (_tmp, vault, _door) = door_fixture();
    // The compatibility alias names the same one organ, never a second.
    let door: CredentialDoor = CredentialDoorService::new(Arc::clone(&vault));
    assert!(Arc::ptr_eq(door.vault(), &vault));
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

#[test]
fn a_slip_attenuation_cannot_raise_the_ttl_ceiling() {
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door);
    let greedy = long_lived_push_credential(now).attenuate_lease_ttl(7200);

    let policy = DoorPolicy::default();
    let ceiling = policy.effective_lease_ttl_ceiling(&greedy, now);
    assert_eq!(ceiling, DOOR_MAX_LEASE_TTL_SECS);

    let err = door
        .issue_lease_ticket(&greedy, DOOR_SECRET, EFFECTOR, 3601)
        .expect_err("the constant wins over the slip");
    assert!(matches!(
        err,
        CredentialDoorError::LeaseTtlDenied {
            ceiling_secs: DOOR_MAX_LEASE_TTL_SECS,
            ..
        }
    ));
}

#[test]
fn repeated_ttl_attenuation_is_a_minimum_in_both_orders() {
    // A verifier walks a slip chain and applies one TTL caveat per link, in
    // whatever order the chain is walked. Attenuation is documented as
    // narrowing-only, so it has to be narrowing with respect to ITSELF: a
    // later, looser caveat may not restore authority an earlier, tighter one
    // already gave up, or caveat ORDER becomes an authority dial.
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door);
    let policy = DoorPolicy::default();

    let tightening = long_lived_push_credential(now)
        .attenuate_lease_ttl(3600)
        .attenuate_lease_ttl(60);
    let loosening = long_lived_push_credential(now)
        .attenuate_lease_ttl(60)
        .attenuate_lease_ttl(3600);

    assert_eq!(policy.effective_lease_ttl_ceiling(&tightening, now), 60);
    assert_eq!(policy.effective_lease_ttl_ceiling(&loosening, now), 60);
    // Idempotent, not merely order-independent.
    let repeated = long_lived_push_credential(now)
        .attenuate_lease_ttl(60)
        .attenuate_lease_ttl(60);
    assert_eq!(policy.effective_lease_ttl_ceiling(&repeated, now), 60);

    // And the widening order cannot buy the time it asked for.
    let err = door
        .issue_lease_ticket(&loosening, DOOR_SECRET, EFFECTOR, 61)
        .expect_err("a later caveat may not restore an earlier one's authority");
    assert!(matches!(
        err,
        CredentialDoorError::LeaseTtlDenied {
            ceiling_secs: 60,
            ..
        }
    ));
    door.issue_lease_ticket(&loosening, DOOR_SECRET, EFFECTOR, 60)
        .expect("the narrowest caveat still mints exactly its own width");
}

#[test]
fn the_ttl_ceiling_is_a_meet_semilattice_that_cannot_leave_the_floor() {
    // The invariant lives in the TYPE, not in whoever remembers to `min`
    // last: there is no way to build a ceiling above the floor, and the only
    // combining operation is a meet.
    assert_eq!(TtlCeiling::FLOOR.secs(), DOOR_MAX_LEASE_TTL_SECS);
    assert_eq!(TtlCeiling::default(), TtlCeiling::FLOOR);
    // Every way in clamps: asking to widen buys the floor, never more.
    assert_eq!(TtlCeiling::at_most(u64::MAX), TtlCeiling::FLOOR);
    let raised = DOOR_MAX_LEASE_TTL_SECS + 1;
    assert_eq!(TtlCeiling::at_most(raised), TtlCeiling::FLOOR);
    assert_eq!(TtlCeiling::at_most(60).secs(), 60);

    let tight = TtlCeiling::at_most(60);
    let loose = TtlCeiling::at_most(600);
    // Commutative, idempotent, and never widening in either direction.
    assert_eq!(tight.meet(loose), tight);
    assert_eq!(loose.meet(tight), tight);
    assert_eq!(tight.meet(tight), tight);
    assert_eq!(tight.meet_secs(u64::MAX), tight);
    // Associative, so a chain of caveats has one answer whatever the walk.
    let mid = TtlCeiling::at_most(300);
    assert_eq!(tight.meet(loose).meet(mid), tight.meet(loose.meet(mid)));

    // Admission is "positive and at or below": zero is not a lease.
    assert!(!tight.admits(0));
    assert!(tight.admits(1));
    assert!(tight.admits(60));
    assert!(!tight.admits(61));
    assert!(!TtlCeiling::FLOOR.admits(DOOR_MAX_LEASE_TTL_SECS + 1));
}

#[test]
fn an_unattenuated_slip_sits_at_the_floor_rather_than_unbounded() {
    // The replaced `Option<u64>` spelled "nobody narrowed this" the same way
    // it spelled "no opinion". The typed cap has no such spelling: the safe
    // default IS the floor.
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door);
    let policy = DoorPolicy::default();
    let fresh = long_lived_push_credential(now);
    let ceiling = policy.effective_lease_ttl_ceiling(&fresh, now);
    assert_eq!(ceiling, DOOR_MAX_LEASE_TTL_SECS);
}

// ---------------------------------------------------------------------------
// T0 — remote at door
// ---------------------------------------------------------------------------

#[test]
fn t0_injection_hands_the_egress_bytes_and_the_caller_only_a_receipt() {
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = push_credential(now);

    let mut egress: Vec<Vec<u8>> = Vec::new();
    let mut apply = |value: &[u8]| -> crate::error::Result<()> {
        egress.push(value.to_vec());
        Ok(())
    };
    let receipt = door
        .inject_secret_at_door(&credential, DOOR_SECRET, EFFECTOR, &mut apply)
        .expect("door injection");

    assert_eq!(receipt.secret_ref, DOOR_SECRET);
    assert_eq!(receipt.effector, EFFECTOR);
    // The caller's only artefact carries no bytes, in any rendering.
    assert!(!format!("{receipt:?}").contains(secret_text()));
    // The mock egress, inside the door, did receive them.
    assert_eq!(egress, vec![SECRET_VALUE.to_vec()]);
}

#[test]
fn t0_injection_needs_a_live_credential_before_the_vault_is_touched() {
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door).secs();
    let expired = DoorCredential::verified("slip-old", "holder:t", now - 600, now - 1)
        .with_verbs([DOOR_VERB_INJECT])
        .with_records([DOOR_SECRET])
        .with_channels([EFFECTOR]);

    let mut egress: Vec<Vec<u8>> = Vec::new();
    let mut apply = |value: &[u8]| -> crate::error::Result<()> {
        egress.push(value.to_vec());
        Ok(())
    };
    let err = door
        .inject_secret_at_door(&expired, DOOR_SECRET, EFFECTOR, &mut apply)
        .expect_err("an expired slip buys no remote use");

    assert_eq!(deny_reason(err), DoorDenyReason::Expired);
    assert!(egress.is_empty());
}

#[test]
fn t0_injection_refuses_an_unscoped_effector() {
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = push_credential(now);
    let mut apply = |_: &[u8]| -> crate::error::Result<()> { Ok(()) };

    let err = door
        .inject_secret_at_door(&credential, DOOR_SECRET, "", &mut apply)
        .expect_err("there is no unscoped door use");
    assert!(is_scope_refusal(&err));
}

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
    assert_eq!(policy.lease_ttl_ceiling_secs(), 60);
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
fn expired_revoked_parent_revoked_and_insufficient_slips_default_deny() {
    let (_tmp, _vault, door) = door_fixture();
    let instant = witnessed(&door);
    let now = instant.secs();
    let record = repo_record(&repo());

    let expired = DoorCredential::verified("slip-expired", "holder:t", now - 600, now - 1)
        .with_verbs([DOOR_VERB_RECEIVE_PACK])
        .with_records([record.clone()])
        .with_channels([EFFECTOR]);
    let revoked = push_credential(instant).revoked();
    let cascaded = push_credential(instant).parent_revoked();
    // Insufficient: a slip that may lease but never got the push verb.
    let insufficient = DoorCredential::verified("slip-lease-only", "holder:t", now, now + 60)
        .with_verbs([DOOR_VERB_LEASE])
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
        (revoked, DoorDenyReason::Revoked),
        (cascaded, DoorDenyReason::ParentRevoked),
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

#[test]
fn revocation_is_terminal_and_no_order_of_transitions_revives_a_slip() {
    // The removed status setter could express `Revoked -> Active` simply by
    // being called with `Active`. The monotone transitions cannot: there is
    // no argument to pass, and every transition is a join UP the death order.
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door);

    // A live slip pushes. That is the control: the denials below are the
    // transitions talking, not a slip that was never good.
    door.authenticate_receive_pack(Some(&push_credential(now)), &repo(), loopback())
        .expect("the un-revoked control slip pushes");

    // Both orders, and repetition, all stay dead — and a direct revocation is
    // never downgraded to a mere cascade by a parent dying afterwards.
    let denied_revoked = DoorDenyReason::Revoked;
    let denied_cascade = DoorDenyReason::ParentRevoked;
    let cases = [
        (push_credential(now).revoked().revoked(), denied_revoked),
        (
            push_credential(now).revoked().parent_revoked(),
            denied_revoked,
        ),
        (
            push_credential(now).parent_revoked().revoked(),
            denied_revoked,
        ),
        (
            push_credential(now).parent_revoked().parent_revoked(),
            denied_cascade,
        ),
    ];
    for (credential, expected) in cases {
        let refusal = door
            .authenticate_receive_pack(Some(&credential), &repo(), loopback())
            .expect_err("a revoked slip stays revoked");
        assert_eq!(deny_reason(refusal), expected);
    }

    // The status lattice itself: `Revoked` is the top, so nothing joins back
    // down to `Active`, and `Active` is only ever where a slip STARTS.
    let revoked = DoorCredentialStatus::Revoked;
    let cascaded = DoorCredentialStatus::ParentRevoked;
    let active = DoorCredentialStatus::Active;
    assert_eq!(revoked.join(active), revoked);
    assert_eq!(active.join(revoked), revoked);
    assert_eq!(revoked.join(cascaded), revoked);
    assert_eq!(cascaded.join(revoked), revoked);
    assert_eq!(cascaded.join(active), cascaded);
    assert_eq!(active.join(active), active);
}

#[test]
fn a_single_use_slip_is_refused_when_the_log_cannot_be_read() {
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = push_credential(now).with_single_use_caveat();
    assert!(credential.is_single_use());

    authority_log_fault_hook::arm_log_unreachable();
    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect_err("an unwitnessable caveat is refused");
    assert!(is_log_unreachable(&err));
}

// ---------------------------------------------------------------------------
// T1 — lease tickets
// ---------------------------------------------------------------------------

#[test]
fn a_lease_ticket_rides_the_landed_receipt_before_value_path() {
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = push_credential(now);

    // Well inside the slip's 600s of remaining validity, so the ticket is
    // worth exactly what was asked for and the credential clamp is not what
    // this test is measuring.
    let ticket = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 300)
        .expect("lease ticket");

    assert_eq!(ticket.value.as_slice(), SECRET_VALUE);
    assert_eq!(ticket.lease.secret_ref, DOOR_SECRET);
    assert_eq!(ticket.lease.binding_effector, EFFECTOR);
    assert_eq!(ticket.lease.expires_at - ticket.lease.granted_at, 300);
    assert!(ticket.lease.expires_at <= now.secs() + 600);
    // The receipt the lease points at is already durable: the landed
    // materialization writes it before the value returns.
    let receipt_id = &ticket.lease.materialization_receipt;
    assert!(has_receipt_row(&vault, receipt_id));
    assert_eq!(lease_rows(&vault), 1);
    assert_eq!(receipt_rows(&vault), 1);
    // Every lease row names its scope; none is unscoped.
    assert!(!ticket.lease.binding_effector.is_empty());
}

#[test]
fn a_lease_above_the_hard_floor_is_denied() {
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = long_lived_push_credential(now);
    let asked = DOOR_MAX_LEASE_TTL_SECS + 1;

    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, asked)
        .expect_err("the hard ceiling holds");
    assert!(matches!(
        err,
        CredentialDoorError::LeaseTtlDenied {
            ceiling_secs: DOOR_MAX_LEASE_TTL_SECS,
            ..
        }
    ));
    assert_eq!(lease_rows(&vault), 0);
}

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

    // And the SAME authoritative reading that authorizes is the one that
    // stamps: a slip whose window is anchored at the vault's instant both
    // authenticates and buys a ticket granted at that instant.
    let credential = push_credential(now);
    door.authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect("a slip live at the vault's instant authenticates");
    let ticket = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 300)
        .expect("and buys a ticket");
    assert!(
        ticket.lease.granted_at >= wall + PINNED_INSTANT_SKEW_SECS,
        "the lease was stamped from the wall clock at {}",
        ticket.lease.granted_at
    );
    assert_eq!(ticket.lease.expires_at - ticket.lease.granted_at, 300);
    assert!(ticket.lease.expires_at <= now.secs() + 600);
    assert_eq!(lease_rows(&vault), 1);
    assert_eq!(receipt_rows(&vault), 1);
}

#[test]
fn a_lease_never_outlives_the_credential_that_bought_it() {
    // The slip has 600s left and the dial is at the 3600s floor, so the
    // credential's own remaining validity is the binding ceiling: a ticket
    // that outlived it would keep buying reads after the slip expired.
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = push_credential(now);

    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 1200)
        .expect_err("a slip may not sell more time than it has");
    assert!(matches!(
        err,
        CredentialDoorError::LeaseTtlDenied {
            requested_secs: 1200,
            ceiling_secs: 600,
        }
    ));
    assert_eq!(lease_rows(&vault), 0);

    // The remaining validity shrinks as the vault's own clock advances through
    // the slip's window, and the ceiling shrinks with it: a half-spent slip
    // buys a half-length ticket. The clock is moved the ONLY way anything can
    // move it — by raising the authority plane's persisted floor, exactly as
    // 300s of elapsed time would.
    pin_vault_instant_at(&vault, now.secs() + 300);
    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 301)
        .expect_err("half spent, half the ceiling");
    assert!(matches!(
        err,
        CredentialDoorError::LeaseTtlDenied {
            ceiling_secs: 300,
            ..
        }
    ));
    assert_eq!(lease_rows(&vault), 0);

    // Exactly the remaining validity still mints, and the ticket expires with
    // the credential rather than after it.
    let ticket = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 300)
        .expect("a ticket inside the slip's remaining life mints");
    assert_eq!(ticket.lease.expires_at - ticket.lease.granted_at, 300);
    assert!(ticket.lease.expires_at <= now.secs() + 600);
    assert_eq!(lease_rows(&vault), 1);
}

#[test]
fn a_lease_at_the_remaining_boundary_dies_with_the_credential() {
    // At the remaining boundary — where redemption and a maximal request both
    // land — a ticket sized by duration alone would outlive the slip by
    // however far the clock moved between authorizing and stamping. That gap
    // is now closed by construction rather than patched afterwards: the
    // instant that answers `remaining` IS the instant that stamps
    // `granted_at`, and the absolute expiry that clamps the row is derived
    // from that same instant.
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = push_credential(now);
    let credential_expiry = now.secs() + 600;

    // 600s is the whole of what is left, so the door admits it.
    let policy = DoorPolicy::default();
    assert_eq!(policy.effective_lease_ttl_ceiling(&credential, now), 600);

    let ticket = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 600)
        .expect("the boundary request is admitted");

    // The lease dies with the credential, to the second.
    assert_eq!(ticket.lease.expires_at, credential_expiry);
    assert!(ticket.lease.expires_at > ticket.lease.granted_at);
    assert!(ticket.lease.expires_at <= ticket.lease.granted_at + 600);
    assert_eq!(lease_rows(&vault), 1);
}

#[test]
fn a_credential_dead_at_the_vault_instant_mints_nothing() {
    // Past the far edge of the same seam. The slip's window closed before the
    // vault's reading, so the evaluator refuses it outright — the request
    // never reaches a write transaction, and a lease that would have been born
    // already dead is not written, receipted, or valued.
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door).secs();
    let credential = push_credential_from(now - 3600, 600);

    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 600)
        .expect_err("a slip dead at the vault's instant mints nothing");
    assert_eq!(deny_reason(err), DoorDenyReason::Expired);
    assert_eq!(lease_rows(&vault), 0);
    assert_eq!(receipt_rows(&vault), 0);
}

#[test]
fn a_one_shot_redeemed_after_the_vault_clock_advances_is_clamped_by_its_expiry() {
    // The redemption arm always asks for its whole remaining bound, so it is
    // the arm where an over-long ticket is guaranteed rather than incidental.
    // Here the VAULT'S OWN clock advances 60s between the one-shot being
    // written and its redemption — the only way anything can move this door's
    // clock — and the ticket still dies at the one-shot's absolute expiry
    // rather than 120s after the stamp.
    let (_tmp, vault, door) = door_fixture();
    let issued_at = witnessed(&door).secs();
    let one_shot = one_shot_credential_from(issued_at);

    pin_vault_instant_at(&vault, issued_at + 60);
    let ticket = door
        .redeem_one_shot(one_shot)
        .expect("a one-shot still inside its window redeems");
    assert_eq!(ticket.lease.granted_at, issued_at + 60);
    assert_eq!(ticket.lease.expires_at, issued_at + 120);
    assert_eq!(ticket.lease.expires_at - ticket.lease.granted_at, 60);
}

#[test]
fn an_unscoped_or_foreign_lease_scope_has_no_path() {
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = push_credential(now);

    for effector in ["", "connector:gmail"] {
        let err = door
            .issue_lease_ticket(&credential, DOOR_SECRET, effector, 60)
            .expect_err("only exact door scopes mint");
        assert!(is_scope_refusal(&err));
    }
}

#[test]
fn a_narrowing_dial_applies_to_lease_tickets() {
    let (_tmp, vault, door) = door_fixture();
    put_policy_manifest(&vault, 0x21, vec![ttl_row(900)]);
    let now = witnessed(&door);
    let credential = long_lived_push_credential(now);

    let policy = door.door_policy().expect("dial");
    assert_eq!(policy.lease_ttl_ceiling_secs(), 900);

    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 1800)
        .expect_err("the narrowed ceiling holds");
    assert!(matches!(
        err,
        CredentialDoorError::LeaseTtlDenied {
            ceiling_secs: 900,
            ..
        }
    ));
    door.issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 900)
        .expect("a lease at the narrowed ceiling mints");
}

#[test]
fn two_dials_resolve_most_restrictive() {
    let (_tmp, vault, door) = door_fixture();
    put_policy_manifest(&vault, 0x22, vec![ttl_row(1800)]);
    put_policy_manifest(&vault, 0x23, vec![ttl_row(600)]);

    let policy = door.door_policy().expect("dial");
    assert_eq!(policy.lease_ttl_ceiling_secs(), 600);
}

#[test]
fn a_dial_may_narrow_the_effector_set_but_never_widen_it() {
    let (_tmp, vault, door) = door_fixture();
    put_policy_manifest(&vault, 0x24, vec![effector_row(vec![])]);
    let now = witnessed(&door);
    let credential = push_credential(now);

    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 60)
        .expect_err("a dial allowing no effector denies every lease");
    assert!(is_scope_refusal(&err));

    let foreign = vec![Value::from("connector:gmail")];
    let body = encoded_map(vec![effector_row(foreign)]);
    let widened = decode_door_policy_keys(&body).expect_err("widening fails");
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
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 60)
        .expect_err("an unreadable dial denies every lease");
    assert!(is_invalid_policy(&err));
}

#[test]
fn malformed_and_duplicated_dial_rows_never_default_open() {
    let key = Value::from(door_policy_keys::MAX_LEASE_TTL_SECS);
    let body = encoded_map(vec![(key, Value::from("900"))]);
    let malformed = decode_door_policy_keys(&body).expect_err("unreadable row");
    assert!(is_invalid_policy(&malformed));

    let body = encoded_map(vec![ttl_row(900), ttl_row(600)]);
    let duplicated = decode_door_policy_keys(&body).expect_err("ambiguous row");
    assert!(is_invalid_policy(&duplicated));
}

#[test]
fn a_partially_decoded_dial_body_never_defaults_open() {
    // A body that announces a map and then cannot be read as one is a
    // declaration the door cannot SEE — never "a pack that declared nothing".
    let narrowing = encoded_map(vec![ttl_row(600)]);

    let mut truncated = narrowing.clone();
    truncated.pop();
    let err = decode_door_policy_keys(&truncated).expect_err("a truncated declaration");
    assert!(is_invalid_policy(&err));

    let mut trailing = narrowing;
    trailing.push(0x00);
    let err = decode_door_policy_keys(&trailing).expect_err("bytes left past the map");
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
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 60)
        .expect_err("no lease resolves against an unreadable dial");
    assert!(is_invalid_policy(&err));
    assert_eq!(lease_rows(&vault), 0);
}

#[test]
fn a_body_this_door_cannot_open_carries_no_door_rows() {
    // The manifest body schema belongs to the gate: a plane this door does not
    // read is not a malformed door declaration, and it denies nothing. The
    // dividing line is READABILITY, not shape — a body that decodes cleanly
    // into something other than a map simply carries no door rows.
    let mut array_body = Vec::new();
    let rows = vec![Value::from(1_u64)];
    rmpv::encode::write_value(&mut array_body, &Value::Array(rows)).expect("encode body");
    assert_eq!(
        decode_door_policy_keys(&array_body).expect("not a map"),
        None
    );

    // An EMPTY body is on the other side of that line. It is not another
    // plane's schema; it is a declaration whose bytes are gone, and the bytes
    // most worth erasing are the ones that narrowed the dial.
    let err = decode_door_policy_keys(&[]).expect_err("an empty body declares nothing readable");
    assert!(is_invalid_policy(&err));
    // Nor does "not a map" rescue a truncated value: a fixstr header promising
    // five bytes and carrying one is unreadable whatever it would have said.
    let err = decode_door_policy_keys(&[0xa5, b'a']).expect_err("an unreadable body");
    assert!(is_invalid_policy(&err));
}

#[test]
fn a_body_with_no_door_rows_takes_the_safe_default() {
    let (_tmp, vault, door) = door_fixture();
    let row = (Value::from("gate.unrelated.key"), Value::from(1_u64));
    put_policy_manifest(&vault, 0x26, vec![row]);

    let policy = door.door_policy().expect("dial");
    assert_eq!(policy, DoorPolicy::default());
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
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 60)
        .expect_err("no lease resolves against a corrupt manifest plane");
    assert!(is_invalid_policy(&err));
    assert_eq!(lease_rows(&vault), 0);
    assert_eq!(receipt_rows(&vault), 0);

    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback())
        .expect_err("nor does a push");
    assert!(is_invalid_policy(&err));
}

#[test]
fn every_broken_manifest_index_branch_fails_closed() {
    // Four ways the index plane can disagree with the entity plane. None of
    // them may quietly resolve the permissive default, and none of them may
    // put an id, a key byte, or a body byte into a refusal.
    fn assert_fails_closed(door: &CredentialDoorService, case: &str) {
        match door.door_policy() {
            Err(err) => {
                assert!(is_invalid_policy(&err), "case `{case}`: {err:?}");
                let rendered = format!("{err} / {err:?}");
                assert!(rendered.contains("policy_manifest"), "case `{case}`");
                assert!(!rendered.contains(secret_text()), "case `{case}`");
            }
            Ok(policy) => panic!("case `{case}` resolved {policy:?}"),
        }
    }

    // 1. A type-index key that is not `[type byte][entity id]` at all.
    let (_tmp, vault, door) = door_fixture();
    let clean = door.door_policy().expect("clean dial");
    assert_eq!(clean, DoorPolicy::default());
    {
        let mut wtxn = vault.store.env.write_txn().expect("write txn");
        let short_key: &[u8] = &[ENTITY_TYPE_POLICY_MANIFEST, 0x01, 0x02];
        vault
            .store
            .type_index
            .put(&mut wtxn, short_key, &[])
            .expect("short type key");
        wtxn.commit().expect("commit short key");
    }
    assert_fails_closed(&door, "unusable type-index key");

    // 2. An indexed entry whose entity row is gone.
    let (_tmp, vault, door) = door_fixture();
    let clean = door.door_policy().expect("clean dial");
    assert_eq!(clean, DoorPolicy::default());
    put_manifest_index_over_entity(&vault, 0x33, None);
    assert_fails_closed(&door, "dangling entity row");

    // 3. An entity row too short to carry a metadata header.
    let (_tmp, vault, door) = door_fixture();
    let clean = door.door_policy().expect("clean dial");
    assert_eq!(clean, DoorPolicy::default());
    let stub: &[u8] = &[ENTITY_TYPE_POLICY_MANIFEST, 0x00, 0x00];
    put_manifest_index_over_entity(&vault, 0x34, Some(stub));
    assert_fails_closed(&door, "unparseable metadata header");

    // 4. An entry naming an entity of some other type.
    let (_tmp, vault, door) = door_fixture();
    let clean = door.door_policy().expect("clean dial");
    assert_eq!(clean, DoorPolicy::default());
    let other = entity_payload_of_type(ENTITY_TYPE_POLICY_MANIFEST ^ 0x01);
    put_manifest_index_over_entity(&vault, 0x35, Some(other.as_slice()));
    assert_fails_closed(&door, "entity of another type");
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
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 60)
        .expect_err("and mints no lease");
    assert!(is_invalid_policy(&err));
    assert_eq!(lease_rows(&vault), 0);
    assert_eq!(receipt_rows(&vault), 0);
}

// ---------------------------------------------------------------------------
// The admission is atomic with the stamp
// ---------------------------------------------------------------------------

/// The door's read-side admission over the fixture secret, plus the ticket it
/// buys — held as a VALUE, so a test can move the manifest plane underneath it.
///
/// That is the whole reason the seam is testable without wall-clock or
/// thread-timing tricks: admission stopped being a moment that had already
/// passed and became something a stamp can re-examine.
fn admitted_ticket(
    door: &CredentialDoorService,
    now: VaultInstant,
    ttl_secs: u64,
) -> AdmittedLease {
    let credential = long_lived_push_credential(now);
    let admitted = door
        .admit_scope(EFFECTOR, now)
        .expect("the dial admits the door scope at the door's read");
    let not_after = now.after(credential.remaining_secs(now));
    admitted.into_lease(DOOR_SECRET, ttl_secs, not_after)
}

#[test]
fn a_dial_emptied_between_the_door_read_and_the_stamp_denies_instead_of_minting() {
    // The gap this closes is a TIME-OF-CHECK gap, not a type error. The door
    // resolves the dial in a READ transaction; the lease commits in a WRITE
    // transaction opened afterwards. A dial that narrowed in between used to
    // mint anyway, at the stale wide reading — so the single row an operator
    // reaches for in a catastrophe, an emptied effector set, lost every race it
    // was in.
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);
    let ticket = admitted_ticket(&door, now, 600);
    assert_eq!(ticket.effector(), EFFECTOR);

    // The dial is emptied AFTER the door read it and BEFORE the stamp.
    put_policy_manifest(&vault, 0x51, vec![effector_row(vec![])]);
    assert_eq!(door.door_policy().expect("dial").dial().len(), 0);

    let err = vault
        .materialize_admitted_lease(&ticket)
        .expect_err("a narrowed dial must deny, never mint under the stale reading");
    match err {
        CredentialDoorError::LeaseScopeRefused { reason, .. } => {
            // The STAMP's refusal, spelled differently from the door's on
            // purpose: this proves the check ran inside the write transaction
            // rather than at the read that already passed.
            assert_eq!(reason, STAMP_SCOPE_REFUSAL);
        }
        other => panic!("expected the in-transaction scope refusal, got {other:?}"),
    }
    // Fail-closed all the way down: the write txn was dropped uncommitted.
    assert_eq!(lease_rows(&vault), 0);
    assert_eq!(receipt_rows(&vault), 0);
}

#[test]
fn a_ttl_ceiling_narrowed_between_the_door_read_and_the_stamp_denies() {
    // The other half of the same window. The dial still admits the SCOPE, so
    // the scope arm passes; what moved is the CEILING, under a ticket already
    // sized against the wider one.
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);
    let ticket = admitted_ticket(&door, now, 600);
    assert_eq!(ticket.ttl_secs(), 600);

    put_policy_manifest(&vault, 0x52, vec![ttl_row(60)]);

    let err = vault
        .materialize_admitted_lease(&ticket)
        .expect_err("a ceiling narrowed under the ticket must deny");
    assert!(matches!(
        err,
        CredentialDoorError::LeaseTtlDenied {
            requested_secs: 600,
            ceiling_secs: 60,
        }
    ));
    assert_eq!(lease_rows(&vault), 0);
    assert_eq!(receipt_rows(&vault), 0);
}

#[test]
fn any_other_dial_movement_under_the_stamp_denies_and_an_unmoved_dial_mints() {
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);

    // A movement neither substantive arm names: the ceiling narrows to 900,
    // which still admits this 60s ticket, and the scope is untouched. Harmless
    // to mint under — and refused anyway, because the reading this admission
    // rests on is provably stale, and a stamp does not get to shrug at that.
    let ticket = admitted_ticket(&door, now, 60);
    put_policy_manifest(&vault, 0x53, vec![ttl_row(900)]);
    let err = vault
        .materialize_admitted_lease(&ticket)
        .expect_err("a stale dial reading is not a dial reading");
    assert!(matches!(
        err,
        CredentialDoorError::DialMovedUnderStamp { effector } if effector == EFFECTOR
    ));
    assert_eq!(lease_rows(&vault), 0);
    assert_eq!(receipt_rows(&vault), 0);

    // The control, and it is load-bearing: the seam denies MOVEMENT, not every
    // stamp. An admission taken against the dial that is actually live
    // reaffirms inside the write transaction and mints exactly its own width.
    let now = witnessed(&door);
    let ticket = admitted_ticket(&door, now, 60);
    let materialized = vault
        .materialize_admitted_lease(&ticket)
        .expect("an admission the stamping transaction agrees with mints");
    assert_eq!(materialized.lease.binding_effector, EFFECTOR);
    assert_eq!(materialized.lease.secret_ref, DOOR_SECRET);
    assert_eq!(materialized.value.as_slice(), SECRET_VALUE);
    assert_eq!(
        materialized.lease.expires_at - materialized.lease.granted_at,
        60
    );
    assert_eq!(materialized.lease.granted_at, now.secs());
    assert_eq!(lease_rows(&vault), 1);
    assert_eq!(receipt_rows(&vault), 1);
}

#[test]
fn the_whole_lease_path_still_denies_when_the_dial_shuts_under_it() {
    // The same seam through the PUBLIC arm, so the atomicity is a property of
    // `issue_lease_ticket` and not only of the value it happens to build. The
    // door's own read already refuses an emptied dial, so this asserts the
    // outcome that matters — no ticket, no rows — rather than which of the two
    // fail-closed arms answered first.
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);
    let credential = long_lived_push_credential(now);
    put_policy_manifest(&vault, 0x55, vec![effector_row(vec![])]);

    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 60)
        .expect_err("a shut dial mints nothing through any arm");
    assert!(is_scope_refusal(&err));
    assert_eq!(lease_rows(&vault), 0);
    assert_eq!(receipt_rows(&vault), 0);
}

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
    let widened = decode_door_policy_keys(&body).expect_err("a widen is not a dial move");
    assert!(is_invalid_policy(&widened));

    // A body naming the door's own effector narrows to exactly it.
    let named = vec![Value::from(DOOR_RECEIVE_PACK_EFFECTOR)];
    let body = encoded_map(vec![effector_row(named)]);
    let policy = decode_door_policy_keys(&body)
        .expect("a narrowing declaration decodes")
        .expect("and carries door rows");
    assert!(policy.admits_effector(EFFECTOR));
    assert_eq!(policy.dial().len(), 1);

    // An empty declaration is a SHUT door, not a default one.
    let body = encoded_map(vec![effector_row(vec![])]);
    let policy = decode_door_policy_keys(&body)
        .expect("an empty declaration decodes")
        .expect("and carries door rows");
    assert_eq!(policy.dial().len(), 0);
    assert!(!policy.admits_effector(EFFECTOR));
}

#[test]
fn the_resolved_floors_are_lattice_values_not_assignable_numbers() {
    // `max_lease_ttl_secs: u64` could hold a ceiling above the catastrophe
    // floor and could be assigned from anywhere. `PolicyFloors` holds the
    // lattice value, so the floor is applied on the way in.
    let floors = PolicyFloors::default();
    assert_eq!(floors.lease_ttl(), TtlCeiling::FLOOR);
    assert_eq!(floors.lease_ttl().secs(), DOOR_MAX_LEASE_TTL_SECS);
    assert_eq!(
        PolicyFloors::at_most_lease_ttl(u64::MAX).lease_ttl(),
        TtlCeiling::FLOOR
    );
    assert_eq!(PolicyFloors::at_most_lease_ttl(60).lease_ttl().secs(), 60);
    // Meets only, in either order.
    let tight = PolicyFloors::at_most_lease_ttl(60);
    let loose = PolicyFloors::at_most_lease_ttl(600);
    assert_eq!(tight.meet(loose), tight);
    assert_eq!(loose.meet(tight), tight);
    assert_eq!(floors.meet(tight), tight);
}

#[test]
fn no_admission_value_exists_for_an_effector_outside_the_resolved_dial() {
    // The proof is the authority. An effector the dial does not admit produces
    // no `AdmittedScope`, so there is nothing to hand a stamp — the refusal is
    // an absence of a value rather than a check somewhere downstream.
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);

    for foreign in ["", "connector:gmail"] {
        let err = door
            .admit_scope(foreign, now)
            .expect_err("only exact door scopes are admitted");
        assert!(is_scope_refusal(&err));
    }
    // The known effector IS admitted under the default dial, so the refusals
    // above are the dial talking and not a broken fixture.
    let admitted = door
        .admit_scope(EFFECTOR, now)
        .expect("the default dial admits the door's own effector");
    assert_eq!(admitted.effector().as_str(), EFFECTOR);
    assert_eq!(admitted.instant(), now);
    assert_eq!(admitted.floors().lease_ttl(), TtlCeiling::FLOOR);

    // And once the dial shuts, the door's own effector stops producing one too.
    put_policy_manifest(&vault, 0x56, vec![effector_row(vec![])]);
    let err = door
        .admit_scope(EFFECTOR, now)
        .expect_err("an emptied dial admits no scope at all");
    assert!(is_scope_refusal(&err));
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
    assert!(printed.contains("src/config.rs"));
    assert!(printed.contains("redacted"));
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

#[test]
fn a_one_shot_redeems_once_by_move_and_writes_no_ledger() {
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);
    let meta_before = vault_meta_rows(&vault);
    let entities_before = entity_rows(&vault);

    let ticket = door
        .redeem_one_shot(one_shot_credential(now))
        .expect("a live one-shot redeems");

    assert_eq!(ticket.lease.secret_ref, DOOR_SECRET);
    assert_eq!(ticket.lease.binding_effector, EFFECTOR);
    assert_eq!(ticket.value.as_slice(), SECRET_VALUE);
    // Exactly two new rows — the landed lease and its landed receipt. No burn
    // ledger, no token registry, no hash-at-rest store, and no new entity (so
    // no authority-log append) appeared behind the redemption.
    assert_eq!(vault_meta_rows(&vault) - meta_before, 2);
    assert_eq!(entity_rows(&vault), entities_before);
    assert_eq!(lease_rows(&vault), 1);
    assert_eq!(receipt_rows(&vault), 1);
    // The credential was moved into the call and dropped there, so a second
    // redemption of it cannot even be written: that IS the single-use
    // guarantee this ticket ships.
}

#[test]
fn a_one_shot_lease_never_outlives_the_one_shot_cap() {
    let (_tmp, _vault, door) = door_fixture();
    let instant = witnessed(&door);
    let now = instant.secs();

    let ticket = door
        .redeem_one_shot(one_shot_credential(instant))
        .expect("redeem");
    // The one-shot's own absolute expiry is the ticket's, exactly: the
    // redemption asks for its whole remaining bound and the vault's instant
    // clamps it there. (The DURATION is that bound minus however far the
    // vault's clock has moved since `now`, so the absolute instant is the
    // honest assertion.)
    assert_eq!(ticket.lease.expires_at, now + 120);
    let ttl = ticket.lease.expires_at - ticket.lease.granted_at;
    assert!(ttl <= 120);
    assert!(ttl <= DOOR_ONE_SHOT_MAX_LIFETIME_SECS);

    let too_long = DoorCredential::verified("slip-long", "holder:t", now, now + 301)
        .with_verbs([DOOR_VERB_REDEEM])
        .with_records([DOOR_SECRET])
        .with_channels([EFFECTOR])
        .with_single_use_caveat();
    let err = door
        .redeem_one_shot(too_long)
        .expect_err("301s is past the one-shot cap");
    assert!(matches!(
        err,
        CredentialDoorError::OneShotLifetimeDenied {
            lifetime_secs: 301,
            ceiling_secs: DOOR_ONE_SHOT_MAX_LIFETIME_SECS,
        }
    ));
}

#[test]
fn a_redeemed_one_shot_ticket_dies_with_its_one_shot() {
    // Redeemed 90s into a 120s one-shot: 30s of authority remain, so the
    // ticket is worth 30s — not the 120s the credential was declared with.
    // The 90s are spent by the one-shot's OWN window sitting that far behind
    // the vault's instant; there is no caller clock left to fake them with.
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door).secs();
    let issued_at = now - 90;

    let ticket = door
        .redeem_one_shot(one_shot_credential_from(issued_at))
        .expect("a live one-shot redeems late");
    assert_eq!(ticket.lease.expires_at, issued_at + 120);
    assert!(ticket.lease.expires_at - ticket.lease.granted_at <= 30);
    assert!(ticket.lease.expires_at > ticket.lease.granted_at);
}

#[test]
fn a_one_shot_needs_the_caveat_the_verb_and_one_named_scope() {
    let (_tmp, _vault, door) = door_fixture();
    let now = witnessed(&door).secs();

    let no_caveat = DoorCredential::verified("slip-plain", "holder:t", now, now + 120)
        .with_verbs([DOOR_VERB_REDEEM])
        .with_records([DOOR_SECRET])
        .with_channels([EFFECTOR]);
    let err = door
        .redeem_one_shot(no_caveat)
        .expect_err("no caveat, no redemption");
    assert_eq!(deny_reason(err), DoorDenyReason::SingleUseCaveatAbsent);

    let two_secrets = DoorCredential::verified("slip-wide", "holder:t", now, now + 120)
        .with_verbs([DOOR_VERB_REDEEM])
        .with_records([DOOR_SECRET, "door.other.token"])
        .with_channels([EFFECTOR])
        .with_single_use_caveat();
    let err = door
        .redeem_one_shot(two_secrets)
        .expect_err("a one-shot names exactly one secret");
    assert!(is_scope_refusal(&err));

    let wrong_verb = DoorCredential::verified("slip-verb", "holder:t", now, now + 120)
        .with_verbs([DOOR_VERB_LEASE])
        .with_records([DOOR_SECRET])
        .with_channels([EFFECTOR])
        .with_single_use_caveat();
    let err = door
        .redeem_one_shot(wrong_verb)
        .expect_err("redemption needs the redeem verb");
    assert_eq!(deny_reason(err), DoorDenyReason::VerbNotInSlip);
}

#[test]
fn a_verifier_that_cannot_reach_the_log_refuses_the_caveat() {
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door);
    let meta_before = vault_meta_rows(&vault);

    authority_log_fault_hook::arm_log_unreachable();
    let err = door
        .redeem_one_shot(one_shot_credential(now))
        .expect_err("an unwitnessable single-use caveat is refused");
    assert!(is_log_unreachable(&err));
    assert_eq!(vault_meta_rows(&vault), meta_before);
}

#[test]
fn the_one_shot_mint_arm_stops_closed() {
    let (_tmp, vault, door) = door_fixture();
    let now = witnessed(&door).secs();
    let meta_before = vault_meta_rows(&vault);
    let entities_before = entity_rows(&vault);

    let err = door
        .mint_one_shot(DOOR_SECRET, EFFECTOR, 120, now)
        .expect_err("no landed surface admits slip-mint bodies");
    assert!(matches!(err, CredentialDoorError::MintUnavailable));
    // The stop is a stop: nothing was persisted in its place.
    assert_eq!(vault_meta_rows(&vault), meta_before);
    assert_eq!(entity_rows(&vault), entities_before);
}

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
            reason: DoorDenyReason::Revoked,
        },
        CredentialDoorError::MintUnavailable,
        // The in-transaction re-admission's refusal carries the door's own
        // effector CONSTANT, so it is safe to print by construction.
        CredentialDoorError::DialMovedUnderStamp {
            effector: DOOR_RECEIVE_PACK_EFFECTOR,
        },
        CredentialDoorError::LeaseScopeRefused {
            effector: DOOR_RECEIVE_PACK_EFFECTOR.to_owned(),
            reason: STAMP_SCOPE_REFUSAL,
        },
    ];
    for err in &errors {
        let rendered = format!("{err} / {err:?}");
        assert!(!rendered.contains(secret_text()));
        assert!(!rendered.contains("ghp_"));
    }
}
