//! CSTDY-02 unit tests: the T0 door composition (the egress gets bytes, the
//! caller gets a receipt), default-deny credential evaluation with no
//! loopback bypass, lease-ticket TTL/scope discipline against a narrow-only
//! dial, the catastrophe floors proving themselves independent of every row
//! and every slip, the pre-receive verdict (detector hit, clean push,
//! fail-closed scanner, binary reject-all), and the one-shot hatch with its
//! recorded mint stop.

use std::net::{IpAddr, Ipv4Addr};

use super::*;
use crate::config::VaultConfig;
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

/// A vault with the door's secret registered, and a door bound to it.
fn door_fixture() -> (tempfile::TempDir, Arc<Vault>, CredentialDoorService) {
    let (tmp, vault) = temp_vault();
    register_door_secret(&vault);
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

/// The instant these tests authorize at.
///
/// It is the ENGINE clock, not a fictional constant, and that is a fixture
/// invariant rather than a convenience: a door-issued lease is clamped against
/// the credential's absolute expiry by the transaction that stamps it, so a
/// test that authorizes at some year-2023 literal while the vault stamps today
/// is not exercising the door, it is exercising a credential that expired
/// years ago. Tests that WANT that gap open it explicitly, by subtracting from
/// this reading (see the skew regressions).
fn door_now() -> u64 {
    crate::unix_seconds_now()
}

/// A verified holder view good for pushing, injecting and leasing, alive for
/// `lifetime_secs` from `now`.
fn push_credential_living(now: u64, lifetime_secs: u64) -> DoorCredential {
    let verbs = [DOOR_VERB_RECEIVE_PACK, DOOR_VERB_INJECT, DOOR_VERB_LEASE];
    let records = [repo_record(&repo()), DOOR_SECRET.to_owned()];
    DoorCredential::verified("slip-push-1", "holder:tester", now, now + lifetime_secs)
        .with_verbs(verbs)
        .with_records(records)
        .with_channels([EFFECTOR])
}

/// The default push credential: 600s of validity left at `now`.
fn push_credential(now: u64) -> DoorCredential {
    push_credential_living(now, 600)
}

/// A push credential with more validity left than any floor or dial, so a TTL
/// test measures the ceiling under test and not the slip's own remaining life.
fn long_lived_push_credential(now: u64) -> DoorCredential {
    push_credential_living(now, 2 * DOOR_MAX_LEASE_TTL_SECS)
}

/// A verified one-shot: single-use caveat, one named secret, one named
/// effector, 120s of life.
fn one_shot_credential(now: u64) -> DoorCredential {
    DoorCredential::verified("slip-one-shot-1", "holder:tester", now, now + 120)
        .with_verbs([DOOR_VERB_REDEEM])
        .with_records([DOOR_SECRET])
        .with_channels([EFFECTOR])
        .with_single_use_caveat()
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
    let now = door_now();
    let credential = DoorCredential::verified("slip-floor", "holder:t", now, now + 60)
        .with_verbs(["DOOR_SCAN_ALWAYS_ON"])
        .with_records([repo_record(&repo())])
        .with_channels([EFFECTOR]);

    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback(), now)
        .expect_err("a verb naming a floor is refused");
    assert!(is_floor_named(&err));
}

#[test]
fn a_slip_attenuation_cannot_raise_the_ttl_ceiling() {
    let (_tmp, _vault, door) = door_fixture();
    let now = door_now();
    let greedy = long_lived_push_credential(now).attenuate_lease_ttl(7200);

    let policy = DoorPolicy::default();
    let ceiling = policy.effective_lease_ttl_ceiling(&greedy, now);
    assert_eq!(ceiling, DOOR_MAX_LEASE_TTL_SECS);

    let err = door
        .issue_lease_ticket(&greedy, DOOR_SECRET, EFFECTOR, 3601, now)
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
    let now = door_now();
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
        .issue_lease_ticket(&loosening, DOOR_SECRET, EFFECTOR, 61, now)
        .expect_err("a later caveat may not restore an earlier one's authority");
    assert!(matches!(
        err,
        CredentialDoorError::LeaseTtlDenied {
            ceiling_secs: 60,
            ..
        }
    ));
    door.issue_lease_ticket(&loosening, DOOR_SECRET, EFFECTOR, 60, now)
        .expect("the narrowest caveat still mints exactly its own width");
}

// ---------------------------------------------------------------------------
// T0 — remote at door
// ---------------------------------------------------------------------------

#[test]
fn t0_injection_hands_the_egress_bytes_and_the_caller_only_a_receipt() {
    let (_tmp, _vault, door) = door_fixture();
    let now = door_now();
    let credential = push_credential(now);

    let mut egress: Vec<Vec<u8>> = Vec::new();
    let mut apply = |value: &[u8]| -> crate::error::Result<()> {
        egress.push(value.to_vec());
        Ok(())
    };
    let receipt = door
        .inject_secret_at_door(&credential, DOOR_SECRET, EFFECTOR, now, &mut apply)
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
    let now = door_now();
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
        .inject_secret_at_door(&expired, DOOR_SECRET, EFFECTOR, now, &mut apply)
        .expect_err("an expired slip buys no remote use");

    assert_eq!(deny_reason(err), DoorDenyReason::Expired);
    assert!(egress.is_empty());
}

#[test]
fn t0_injection_refuses_an_unscoped_effector() {
    let (_tmp, _vault, door) = door_fixture();
    let now = door_now();
    let credential = push_credential(now);
    let mut apply = |_: &[u8]| -> crate::error::Result<()> { Ok(()) };

    let err = door
        .inject_secret_at_door(&credential, DOOR_SECRET, "", now, &mut apply)
        .expect_err("there is no unscoped door use");
    assert!(is_scope_refusal(&err));
}

// ---------------------------------------------------------------------------
// Authenticated receive-pack — loopback is not an identity
// ---------------------------------------------------------------------------

#[test]
fn an_absent_credential_on_loopback_is_refused() {
    let (_tmp, _vault, door) = door_fixture();
    let now = door_now();
    let err = door
        .authenticate_receive_pack(None, &repo(), loopback(), now)
        .expect_err("127.0.0.1 is a route, not a principal");
    assert_eq!(deny_reason(err), DoorDenyReason::CredentialAbsent);
}

#[test]
fn a_live_credential_passes_the_one_evaluator_from_any_address() {
    let (_tmp, _vault, door) = door_fixture();
    let now = door_now();
    let credential = push_credential(now);
    let elsewhere = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    door.authenticate_receive_pack(Some(&credential), &repo(), loopback(), now)
        .expect("a live slip authenticates on loopback");
    door.authenticate_receive_pack(Some(&credential), &repo(), elsewhere, now)
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
    let now = door_now();
    let credential = push_credential(now);
    let elsewhere = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    door.authenticate_receive_pack(Some(&credential), &repo(), loopback(), now)
        .expect("the same push authenticates under the default dial");

    put_policy_manifest(&vault, 0x41, vec![effector_row(vec![])]);
    let policy = door.door_policy().expect("dial");
    assert!(!policy.admits_effector(EFFECTOR));

    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback(), now)
        .expect_err("the catastrophe dial must be able to shut the push door");
    assert!(is_scope_refusal(&err));
    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), elsewhere, now)
        .expect_err("from any address, like every other door answer");
    assert!(is_scope_refusal(&err));
    // The dial NARROWS the one evaluator; it does not replace it. An absent
    // credential is still refused as an absent principal.
    let err = door
        .authenticate_receive_pack(None, &repo(), loopback(), now)
        .expect_err("still default-deny");
    assert_eq!(deny_reason(err), DoorDenyReason::CredentialAbsent);
}

#[test]
fn a_dial_that_keeps_receive_pack_still_authenticates_it() {
    // The dial narrows; it does not deny by existing. A manifest that lowers
    // the TTL ceiling, or that names receive-pack explicitly, leaves the push
    // path exactly where it was.
    let (_tmp, vault, door) = door_fixture();
    let now = door_now();
    let credential = push_credential(now);

    let named = vec![Value::from(DOOR_RECEIVE_PACK_EFFECTOR)];
    put_policy_manifest(&vault, 0x42, vec![ttl_row(60), effector_row(named)]);
    let policy = door.door_policy().expect("dial");
    assert_eq!(policy.max_lease_ttl_secs, 60);
    assert!(policy.admits_effector(EFFECTOR));

    door.authenticate_receive_pack(Some(&credential), &repo(), loopback(), now)
        .expect("a narrowed dial that keeps the door open keeps it open");
}

#[test]
fn an_unreadable_dial_refuses_receive_pack_authentication() {
    // Fail-closed applies to the push path too: a dial the door cannot read
    // is never the permissive default that would let the push through.
    let (_tmp, vault, door) = door_fixture();
    let now = door_now();
    let credential = push_credential(now);
    put_policy_manifest(&vault, 0x43, vec![ttl_row(DOOR_MAX_LEASE_TTL_SECS + 1)]);

    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback(), now)
        .expect_err("an unreadable dial denies the push");
    assert!(is_invalid_policy(&err));
}

#[test]
fn expired_revoked_parent_revoked_and_insufficient_slips_default_deny() {
    let (_tmp, _vault, door) = door_fixture();
    let now = door_now();
    let record = repo_record(&repo());
    let revoked_status = DoorCredentialStatus::Revoked;
    let cascade_status = DoorCredentialStatus::ParentRevoked;

    let expired = DoorCredential::verified("slip-expired", "holder:t", now - 600, now - 1)
        .with_verbs([DOOR_VERB_RECEIVE_PACK])
        .with_records([record.clone()])
        .with_channels([EFFECTOR]);
    let revoked = push_credential(now).with_status(revoked_status);
    let cascaded = push_credential(now).with_status(cascade_status);
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
            .authenticate_receive_pack(Some(&credential), &repo(), loopback(), now)
            .expect_err("default deny, on loopback like anywhere else");
        assert_eq!(deny_reason(refusal), expected);
    }
}

#[test]
fn a_single_use_slip_is_refused_when_the_log_cannot_be_read() {
    let (_tmp, _vault, door) = door_fixture();
    let now = door_now();
    let credential = push_credential(now).with_single_use_caveat();
    assert!(credential.is_single_use());

    authority_log_fault_hook::arm_log_unreachable();
    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback(), now)
        .expect_err("an unwitnessable caveat is refused");
    assert!(is_log_unreachable(&err));
}

// ---------------------------------------------------------------------------
// T1 — lease tickets
// ---------------------------------------------------------------------------

#[test]
fn a_lease_ticket_rides_the_landed_receipt_before_value_path() {
    let (_tmp, vault, door) = door_fixture();
    let now = door_now();
    let credential = push_credential(now);

    // Well inside the slip's 600s of remaining validity, so the ticket is
    // worth exactly what was asked for and the credential clamp is not what
    // this test is measuring.
    let ticket = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 300, now)
        .expect("lease ticket");

    assert_eq!(ticket.value.as_slice(), SECRET_VALUE);
    assert_eq!(ticket.lease.secret_ref, DOOR_SECRET);
    assert_eq!(ticket.lease.binding_effector, EFFECTOR);
    assert_eq!(ticket.lease.expires_at - ticket.lease.granted_at, 300);
    assert!(ticket.lease.expires_at <= now + 600);
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
    let now = door_now();
    let credential = long_lived_push_credential(now);
    let asked = DOOR_MAX_LEASE_TTL_SECS + 1;

    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, asked, now)
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
fn a_lease_never_outlives_the_credential_that_bought_it() {
    // The slip has 600s left and the dial is at the 3600s floor, so the
    // credential's own remaining validity is the binding ceiling: a ticket
    // that outlived it would keep buying reads after the slip expired.
    let (_tmp, vault, door) = door_fixture();
    let now = door_now();
    let credential = push_credential(now);

    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 1200, now)
        .expect_err("a slip may not sell more time than it has");
    assert!(matches!(
        err,
        CredentialDoorError::LeaseTtlDenied {
            requested_secs: 1200,
            ceiling_secs: 600,
        }
    ));
    assert_eq!(lease_rows(&vault), 0);

    // The remaining validity shrinks with the witnessed clock, and the
    // ceiling shrinks with it: a half-spent slip buys a half-length ticket.
    let later = now + 300;
    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 301, later)
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
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 300, later)
        .expect("a ticket inside the slip's remaining life mints");
    assert_eq!(ticket.lease.expires_at - ticket.lease.granted_at, 300);
    assert!(ticket.lease.expires_at <= now + 600);
    assert_eq!(lease_rows(&vault), 1);
}

#[test]
fn a_lease_at_the_remaining_boundary_is_clamped_by_the_stamping_clock() {
    // The root this test exists for: the door authorizes against the caller's
    // witnessed `now`, but the landed materialization stamps `granted_at`
    // from its OWN reading inside the write transaction. At the remaining
    // boundary — where redemption and a maximal request both land — every
    // second between the two would otherwise be a second of lease the
    // credential never sold.
    //
    // The gap is opened honestly: the caller witnessed `now` five minutes ago
    // and the request only reaches persistence now, which is exactly the
    // "delayed request widens the gap" shape.
    let (_tmp, vault, door) = door_fixture();
    let engine_clock = door_now();
    let now = engine_clock - 300;
    let credential = push_credential(now);
    let credential_expiry = now + 600;

    // 600s is the whole of what is left at `now`, so the door admits it.
    let policy = DoorPolicy::default();
    assert_eq!(policy.effective_lease_ttl_ceiling(&credential, now), 600);

    let ticket = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 600, now)
        .expect("the boundary request is admitted");

    // The lease dies with the credential, not 600s after a later stamp.
    assert!(
        ticket.lease.expires_at <= credential_expiry,
        "lease expiry {} outlived the credential expiry {credential_expiry}",
        ticket.lease.expires_at
    );
    // And the clamp actually bit: a naive `granted_at + ttl` would have run
    // to `credential_expiry + 300`.
    assert!(ticket.lease.granted_at >= engine_clock);
    assert!(ticket.lease.expires_at < ticket.lease.granted_at + 600);
    assert!(ticket.lease.expires_at > ticket.lease.granted_at);
    assert_eq!(lease_rows(&vault), 1);
}

#[test]
fn a_credential_that_expires_before_the_stamp_mints_nothing() {
    // Same seam, past the far edge: the credential's window closed between
    // the witnessed authorization and the write transaction. A clamped lease
    // would be born already dead, so nothing is written and no value returns
    // — the receipt-before-value transaction never commits.
    let (_tmp, vault, door) = door_fixture();
    let now = door_now() - 3600;
    let credential = push_credential(now);

    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 600, now)
        .expect_err("a stamp past the credential's expiry mints nothing");
    assert!(matches!(err, CredentialDoorError::Custody(_)));
    assert_eq!(lease_rows(&vault), 0);
    assert_eq!(receipt_rows(&vault), 0);
}

#[test]
fn a_late_one_shot_redemption_is_clamped_by_the_stamping_clock_too() {
    // The redemption arm always asks for its whole remaining bound, so it is
    // the arm where the clock gap is guaranteed rather than incidental.
    let (_tmp, _vault, door) = door_fixture();
    let engine_clock = door_now();
    let now = engine_clock - 60;
    let one_shot_expiry = now + 120;

    let ticket = door
        .redeem_one_shot(one_shot_credential(now), now)
        .expect("a one-shot still inside its window redeems");
    assert!(
        ticket.lease.expires_at <= one_shot_expiry,
        "redeemed lease expiry {} outlived the one-shot expiry {one_shot_expiry}",
        ticket.lease.expires_at
    );
    assert!(ticket.lease.expires_at < ticket.lease.granted_at + 120);
}

#[test]
fn an_unscoped_or_foreign_lease_scope_has_no_path() {
    let (_tmp, _vault, door) = door_fixture();
    let now = door_now();
    let credential = push_credential(now);

    for effector in ["", "connector:gmail"] {
        let err = door
            .issue_lease_ticket(&credential, DOOR_SECRET, effector, 60, now)
            .expect_err("only exact door scopes mint");
        assert!(is_scope_refusal(&err));
    }
}

#[test]
fn a_narrowing_dial_applies_to_lease_tickets() {
    let (_tmp, vault, door) = door_fixture();
    put_policy_manifest(&vault, 0x21, vec![ttl_row(900)]);
    let now = door_now();
    let credential = long_lived_push_credential(now);

    let policy = door.door_policy().expect("dial");
    assert_eq!(policy.max_lease_ttl_secs, 900);

    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 1800, now)
        .expect_err("the narrowed ceiling holds");
    assert!(matches!(
        err,
        CredentialDoorError::LeaseTtlDenied {
            ceiling_secs: 900,
            ..
        }
    ));
    door.issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 900, now)
        .expect("a lease at the narrowed ceiling mints");
}

#[test]
fn two_dials_resolve_most_restrictive() {
    let (_tmp, vault, door) = door_fixture();
    put_policy_manifest(&vault, 0x22, vec![ttl_row(1800)]);
    put_policy_manifest(&vault, 0x23, vec![ttl_row(600)]);

    let policy = door.door_policy().expect("dial");
    assert_eq!(policy.max_lease_ttl_secs, 600);
}

#[test]
fn a_dial_may_narrow_the_effector_set_but_never_widen_it() {
    let (_tmp, vault, door) = door_fixture();
    put_policy_manifest(&vault, 0x24, vec![effector_row(vec![])]);
    let now = door_now();
    let credential = push_credential(now);

    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 60, now)
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

    let now = door_now();
    let credential = push_credential(now);
    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 60, now)
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

    let now = door_now();
    let credential = push_credential(now);
    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 60, now)
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

    let now = door_now();
    let credential = push_credential(now);
    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 60, now)
        .expect_err("no lease resolves against a corrupt manifest plane");
    assert!(is_invalid_policy(&err));
    assert_eq!(lease_rows(&vault), 0);
    assert_eq!(receipt_rows(&vault), 0);

    let err = door
        .authenticate_receive_pack(Some(&credential), &repo(), loopback(), now)
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

    let now = door_now();
    let credential = push_credential(now);
    let err = door
        .issue_lease_ticket(&credential, DOOR_SECRET, EFFECTOR, 60, now)
        .expect_err("and mints no lease");
    assert!(is_invalid_policy(&err));
    assert_eq!(lease_rows(&vault), 0);
    assert_eq!(receipt_rows(&vault), 0);
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
    let now = door_now();
    let meta_before = vault_meta_rows(&vault);
    let entities_before = entity_rows(&vault);

    let ticket = door
        .redeem_one_shot(one_shot_credential(now), now)
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
    let now = door_now();

    let ticket = door
        .redeem_one_shot(one_shot_credential(now), now)
        .expect("redeem");
    // The one-shot's own absolute expiry is the ticket's, exactly: the
    // redemption asks for its whole remaining bound and the stamping clock
    // clamps it there. (The DURATION is that bound minus however far the
    // engine clock has moved since `now`, so the absolute instant is the
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
        .redeem_one_shot(too_long, now)
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
    let (_tmp, _vault, door) = door_fixture();
    let now = door_now();

    let ticket = door
        .redeem_one_shot(one_shot_credential(now), now + 90)
        .expect("a live one-shot redeems late");
    assert_eq!(ticket.lease.expires_at - ticket.lease.granted_at, 30);
    assert!(ticket.lease.expires_at <= now + 120);
}

#[test]
fn a_one_shot_needs_the_caveat_the_verb_and_one_named_scope() {
    let (_tmp, _vault, door) = door_fixture();
    let now = door_now();

    let no_caveat = DoorCredential::verified("slip-plain", "holder:t", now, now + 120)
        .with_verbs([DOOR_VERB_REDEEM])
        .with_records([DOOR_SECRET])
        .with_channels([EFFECTOR]);
    let err = door
        .redeem_one_shot(no_caveat, now)
        .expect_err("no caveat, no redemption");
    assert_eq!(deny_reason(err), DoorDenyReason::SingleUseCaveatAbsent);

    let two_secrets = DoorCredential::verified("slip-wide", "holder:t", now, now + 120)
        .with_verbs([DOOR_VERB_REDEEM])
        .with_records([DOOR_SECRET, "door.other.token"])
        .with_channels([EFFECTOR])
        .with_single_use_caveat();
    let err = door
        .redeem_one_shot(two_secrets, now)
        .expect_err("a one-shot names exactly one secret");
    assert!(is_scope_refusal(&err));

    let wrong_verb = DoorCredential::verified("slip-verb", "holder:t", now, now + 120)
        .with_verbs([DOOR_VERB_LEASE])
        .with_records([DOOR_SECRET])
        .with_channels([EFFECTOR])
        .with_single_use_caveat();
    let err = door
        .redeem_one_shot(wrong_verb, now)
        .expect_err("redemption needs the redeem verb");
    assert_eq!(deny_reason(err), DoorDenyReason::VerbNotInSlip);
}

#[test]
fn a_verifier_that_cannot_reach_the_log_refuses_the_caveat() {
    let (_tmp, vault, door) = door_fixture();
    let now = door_now();
    let meta_before = vault_meta_rows(&vault);

    authority_log_fault_hook::arm_log_unreachable();
    let err = door
        .redeem_one_shot(one_shot_credential(now), now)
        .expect_err("an unwitnessable single-use caveat is refused");
    assert!(is_log_unreachable(&err));
    assert_eq!(vault_meta_rows(&vault), meta_before);
}

#[test]
fn the_one_shot_mint_arm_stops_closed() {
    let (_tmp, vault, door) = door_fixture();
    let now = door_now();
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
    let now = door_now();
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
    ];
    for err in &errors {
        let rendered = format!("{err} / {err:?}");
        assert!(!rendered.contains(secret_text()));
        assert!(!rendered.contains("ghp_"));
    }
}
