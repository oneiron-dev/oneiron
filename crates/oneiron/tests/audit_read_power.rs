//! [AUDIT-READ-POWER] (RULING AUDIT-READ-POWER-LIST = B, the lead 15 Nov
//! 21:1x; Engine RULINGs AUDITREAD-GRANT-HOME = A and AUDITREAD-DOOR-LIST = A,
//! 15 Nov 22:00): the 7 Nov ROLES ruling retired `auditor` as a role, and what
//! it granted (audit and receipt reads) became ONE power, audit_read, that any
//! person or agent can hold.
//!
//! - The owner alone grants and revokes it, as his own act
//!   (`vault.audit_read.grant`, `vault.audit_read.revoke`). No other caller
//!   can, the holder included, and every generic AccessGrant door refuses its
//!   scope.
//! - Each covered door reads for its old reader (the owner, or a receipt's own
//!   actor) or for a live holder. The power is checked at each read, so a
//!   revoke or an expiry refuses at the very next one.
//! - The owner's grant and revoke land a receipt that the authority audit
//!   lists, so an auditor sees who else audits, and both owner verbs list the
//!   live holders.
//!
//! PR 1 covers `vault.authority.audit` and `vault.receipts.get`.
//!
//! Every call goes through the generated verb dispatch
//! (`task_verb::sdk::invoke`), JSON in and out, as a transport calls it. A
//! holder is a PERSON bound to its own live credential, minted from the host
//! root's claims and verified as a transport verifies the slip a request
//! presents. Public paths only.
//!
//! `cargo test --locked -p oneiron --all-features --test audit_read_power`

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::access_grant::{AccessGrant, decode_access_grant_body, encode_access_grant_body};
use oneiron::authority::{HostSlipIssuer, VerifiedSlip};
use oneiron::booking::DisclosureRung;
use oneiron::deletion::DeleteEntityOptions;
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError};
use oneiron::receipt::{CallOutcome, CallReceiptInput, CallTransport};
use oneiron::task_verb::sdk::invoke;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_store::ports::manual_clock::ManualClock;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const CHALLENGE: &[u8] = b"oneiron-request:audit-read-power";
const HOUR: u64 = 60 * 60;

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    clock: Arc<ManualClock>,
    issuer: HostSlipIssuer,
    owner: EntityId,
    start: u64,
}

/// A device vault on a manual clock set to the wall clock, with its host root
/// and embedded owner.
fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let clock = ManualClock::new(start);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let issuer = HostSlipIssuer::from_secret(b"oneiron-test-audit-read-power")?;
    vault.ensure_host_root_slip(&issuer)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    Ok(Fixture {
        _dir: dir,
        vault,
        clock,
        issuer,
        owner,
        start,
    })
}

fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// A live PERSON, not the owner, with no power.
fn person(fixture: &Fixture, name: &str) -> Result<EntityId, Box<dyn std::error::Error>> {
    let person = EntityId::now();
    fixture.vault.put_entity(
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        name.as_bytes(),
    )?;
    Ok(person)
}

/// The live `human` credential this host mints `holder`, with the host root's
/// whole reach, verified as a transport verifies it.
fn credential(
    fixture: &Fixture,
    holder: EntityId,
) -> Result<VerifiedSlip, Box<dyn std::error::Error>> {
    let root = fixture.vault.ensure_host_root_slip(&fixture.issuer)?;
    let mut claims = root.claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.records = BTreeSet::new();
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)?;
    let binding = fixture.issuer.binding_proof(&slip, CHALLENGE)?;
    Ok(fixture.vault.verify_capability_slip(
        &fixture.issuer.public_key(),
        &slip,
        CHALLENGE,
        &binding,
    )?)
}

/// The owner's own embedded handle.
fn owner(fixture: &Fixture) -> Memory<'_> {
    fixture.vault.memory(fixture.owner, EdgeActorClass::Human)
}

/// `person`'s handle, bound to its own live credential.
fn bound<'v>(fixture: &'v Fixture, person: EntityId, proof: &VerifiedSlip) -> Memory<'v> {
    fixture
        .vault
        .memory(person, EdgeActorClass::Human)
        .with_read_proof(proof)
}

fn call(memory: &Memory<'_>, verb: &str, input: Value) -> Value {
    invoke(memory, verb, input).unwrap_or_else(|error| panic!("{verb} answers: {error:?}"))
}

fn refused(memory: &Memory<'_>, verb: &str, input: Value) -> MemoryError {
    match invoke(memory, verb, input) {
        Ok(answer) => panic!("{verb} is refused, but answered {answer}"),
        Err(error) => error,
    }
}

fn assert_forbidden(error: &MemoryError, what: &str) {
    assert_eq!(
        error.code, MEMORY_CODE_FORBIDDEN,
        "{what} is refused as forbidden: {error:?}"
    );
}

/// The owner grants `holder` the audit_read power, with no end unless
/// `expires_at` names one; answers the grant's answer.
fn grant(fixture: &Fixture, holder: EntityId, expires_at: Option<u64>) -> Value {
    let mut input = json!({ "holder": holder.to_hex() });
    if let Some(end) = expires_at {
        input["expires_at"] = json!(end);
    }
    call(&owner(fixture), "vault.audit_read.grant", input)
}

/// The owner revokes `holder`'s audit_read power; answers the revoke's answer.
fn revoke(fixture: &Fixture, holder: EntityId) -> Value {
    call(
        &owner(fixture),
        "vault.audit_read.revoke",
        json!({ "holder": holder.to_hex() }),
    )
}

/// The holders an owner verb's answer lists, by their hex.
fn listed_holders(answer: &Value) -> Vec<String> {
    answer["holders"]
        .as_array()
        .unwrap_or_else(|| panic!("the answer lists its holders: {answer}"))
        .iter()
        .map(|row| row["holder"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// One call receipt of the owner's own, as a transport records it.
fn owner_call_receipt(fixture: &Fixture) -> Result<String, Box<dyn std::error::Error>> {
    Ok(fixture.vault.record_call_receipt(CallReceiptInput {
        transport: CallTransport::HttpFacade,
        verb: "vault.claims.list".to_owned(),
        actor_ref: fixture.owner.to_hex(),
        actor_class: "human".to_owned(),
        credential_ref: None,
        carrier_machine: None,
        outcome: CallOutcome::Ok,
        request_digest: "ab".repeat(32),
        result_digest: Some("cd".repeat(32)),
        inputs: None,
        attempt: None,
        served: Vec::new(),
    })?)
}

/// `reader`'s `vault.receipts.get` answer for `receipt_ref`.
fn receipt(reader: &Memory<'_>, receipt_ref: &str) -> Value {
    call(
        reader,
        "vault.receipts.get",
        json!({ "receipt_ref": receipt_ref }),
    )
}

/// `vault.authority.audit`: the owner's dated authority log reads for a live
/// audit_read holder too, and for no one else.
#[test]
fn the_authority_audit_reads_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);

    call(&owner(&fixture), "vault.authority.audit", json!({}));
    assert_forbidden(
        &refused(&as_holder, "vault.authority.audit", json!({})),
        "the audit before any grant",
    );

    let granted = grant(&fixture, holder, None);
    assert_eq!(
        granted["changed"],
        json!(true),
        "the grant lands: {granted}"
    );
    assert_eq!(listed_holders(&granted), vec![holder.to_hex()]);
    let page = call(&as_holder, "vault.authority.audit", json!({}));
    assert!(page["rows"].is_array(), "the holder reads a page: {page}");
    assert_forbidden(
        &refused(&as_stranger, "vault.authority.audit", json!({})),
        "the audit for a person without the power",
    );

    let revoked = revoke(&fixture, holder);
    assert_eq!(
        revoked["changed"],
        json!(true),
        "the revoke lands: {revoked}"
    );
    assert!(
        listed_holders(&revoked).is_empty(),
        "no holder is left: {revoked}"
    );
    assert_forbidden(
        &refused(&as_holder, "vault.authority.audit", json!({})),
        "the audit at the next read after the revoke",
    );
    Ok(())
}

/// `vault.receipts.get`: a call receipt reads for its own actor, the owner and
/// a live audit_read holder; to anyone else it reads as none.
#[test]
fn a_call_receipt_reads_for_a_live_audit_read_holder_only() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let receipt_ref = owner_call_receipt(&fixture)?;

    let own = receipt(&owner(&fixture), &receipt_ref);
    assert_eq!(own["receipt_ref"], json!(receipt_ref), "the owner reads it");
    assert_eq!(
        receipt(&as_holder, &receipt_ref),
        Value::Null,
        "before any grant the receipt reads as none"
    );

    grant(&fixture, holder, None);
    let read = receipt(&as_holder, &receipt_ref);
    assert_eq!(
        read["receipt_ref"],
        json!(receipt_ref),
        "the holder reads the owner's receipt: {read}"
    );
    assert_eq!(read["verb"], json!("vault.claims.list"));
    assert_eq!(
        receipt(&as_stranger, &receipt_ref),
        Value::Null,
        "a person without the power reads none"
    );

    revoke(&fixture, holder);
    assert_eq!(
        receipt(&as_holder, &receipt_ref),
        Value::Null,
        "after the revoke the receipt reads as none at the next read"
    );
    Ok(())
}

/// An audit_read grant with an end stops reading at the first read past it,
/// with no write: the power is checked live, at the vault's clock.
#[test]
fn an_expired_audit_read_refuses_at_the_next_read() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let holder_proof = credential(&fixture, holder)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let receipt_ref = owner_call_receipt(&fixture)?;

    let end = fixture.start + HOUR;
    let granted = grant(&fixture, holder, Some(end));
    assert_eq!(granted["expires_at"], json!(end), "the grant keeps its end");
    call(&as_holder, "vault.authority.audit", json!({}));
    assert_eq!(
        receipt(&as_holder, &receipt_ref)["receipt_ref"],
        json!(receipt_ref)
    );

    fixture.clock.set(end + 1);
    assert_forbidden(
        &refused(&as_holder, "vault.authority.audit", json!({})),
        "the audit past the grant's end",
    );
    // Not the credential's end: the same handle still reads, and reads none.
    assert_eq!(receipt(&as_holder, &receipt_ref), Value::Null);
    let listed = grant(&fixture, holder, None);
    assert_eq!(listed["changed"], json!(true), "the owner grants it anew");
    assert_eq!(
        receipt(&as_holder, &receipt_ref)["receipt_ref"],
        json!(receipt_ref),
        "the new grant reads again"
    );
    Ok(())
}

/// The owner's grants and revokes of audit_read are themselves listed on the
/// authority audit, in order, so a holder sees who else audits; each owner
/// verb answers the live holders, and a repeat changes nothing.
#[test]
fn the_owners_audit_read_acts_list_on_the_authority_audit() -> TestResult {
    let fixture = fixture()?;
    let first = person(&fixture, "the first auditor")?;
    let second = person(&fixture, "the second auditor")?;
    let second_proof = credential(&fixture, second)?;
    let as_second = bound(&fixture, second, &second_proof);

    grant(&fixture, first, None);
    let both = grant(&fixture, second, None);
    let mut expected = vec![first.to_hex(), second.to_hex()];
    expected.sort();
    let mut listed = listed_holders(&both);
    listed.sort();
    assert_eq!(listed, expected, "both holders are listed: {both}");
    let repeat = grant(&fixture, second, None);
    assert_eq!(repeat["changed"], json!(false), "a repeat changes nothing");
    let revoked = revoke(&fixture, first);
    assert_eq!(listed_holders(&revoked), vec![second.to_hex()]);
    let again = revoke(&fixture, first);
    assert_eq!(
        again["changed"],
        json!(false),
        "a repeat revoke changes nothing"
    );

    let acts = |page: &Value| -> Vec<(String, String, String)> {
        page["audit_read_acts"]
            .as_array()
            .unwrap_or_else(|| panic!("the page lists the audit_read acts: {page}"))
            .iter()
            .map(|row| {
                (
                    row["holder"].as_str().unwrap_or_default().to_owned(),
                    row["change"].as_str().unwrap_or_default().to_owned(),
                    row["owner"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect()
    };
    let owner_hex = fixture.owner.to_hex();
    let expected_acts = vec![
        (first.to_hex(), "grant".to_owned(), owner_hex.clone()),
        (second.to_hex(), "grant".to_owned(), owner_hex.clone()),
        (first.to_hex(), "revoke".to_owned(), owner_hex),
    ];
    let owner_page = call(&owner(&fixture), "vault.authority.audit", json!({}));
    assert_eq!(acts(&owner_page), expected_acts, "{owner_page}");
    let holder_page = call(&as_second, "vault.authority.audit", json!({}));
    assert_eq!(
        acts(&holder_page),
        expected_acts,
        "the holder sees who else audits: {holder_page}"
    );
    Ok(())
}

/// Only the owner grants or revokes audit_read: a holder can neither widen it
/// to another person nor revoke it, and a person without it cannot grant it
/// to itself.
#[test]
fn only_the_owner_grants_or_revokes_audit_read() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    grant(&fixture, holder, None);

    for (memory, verb, target, what) in [
        (
            &as_stranger,
            "vault.audit_read.grant",
            stranger,
            "a self-grant",
        ),
        (
            &as_holder,
            "vault.audit_read.grant",
            stranger,
            "a holder's grant",
        ),
        (
            &as_holder,
            "vault.audit_read.revoke",
            holder,
            "a holder's revoke",
        ),
    ] {
        assert_forbidden(
            &refused(memory, verb, json!({ "holder": target.to_hex() })),
            what,
        );
    }
    assert_forbidden(
        &refused(&as_stranger, "vault.authority.audit", json!({})),
        "the audit after a refused self-grant",
    );
    call(&as_holder, "vault.authority.audit", json!({}));
    Ok(())
}

/// No generic AccessGrant door writes, overwrites or revokes an audit_read
/// grant: only the owner's verbs do, with their receipt.
#[test]
fn every_generic_access_grant_door_refuses_the_audit_read_scope() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let stranger = person(&fixture, "a person with no power")?;
    let holder_proof = credential(&fixture, holder)?;
    let stranger_proof = credential(&fixture, stranger)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let as_stranger = bound(&fixture, stranger, &stranger_proof);
    let granted = grant(&fixture, holder, None);
    let grant_ref = EntityId::from_hex(
        granted["grant_ref"]
            .as_str()
            .ok_or("the grant names its row")?,
    )?;
    let now = fixture.start;

    assert!(
        fixture.vault.revoke_access_grant(&grant_ref, now).is_err(),
        "the generic revoke refuses an audit_read grant"
    );
    call(&as_holder, "vault.authority.audit", json!({}));

    // An audit_read grant for the stranger, built as a caller of the generic
    // doors would build one.
    let forged = audit_read_body(stranger, now)?;
    assert!(
        fixture
            .vault
            .create_access_grant(&EntityId::now(), &forged)
            .is_err(),
        "the generic create refuses the audit_read scope"
    );
    assert!(
        fixture.vault.put_access_grant(&grant_ref, &forged).is_err(),
        "the generic put refuses to overwrite an audit_read grant"
    );
    let other =
        AccessGrant::calendar_disclosure(holder, EntityId::now(), DisclosureRung::Busy, now);
    assert!(
        fixture.vault.put_access_grant(&grant_ref, &other).is_err(),
        "the generic put refuses to write another scope over an audit_read grant"
    );
    call(&as_holder, "vault.authority.audit", json!({}));
    assert_forbidden(
        &refused(&as_stranger, "vault.authority.audit", json!({})),
        "the audit for a forged grant's principal",
    );
    Ok(())
}

/// No generic delete removes an audit_read grant (Astra review
/// auditread-8435-pr1 T1): only the owner's revoke verb ends one, and it
/// records his act. `vault.delete` refuses it, soft or hard, the owner's own
/// call included, and so do the vault's record and batch delete doors, while
/// it stands and once revoked. The grant stands through every attempt, and
/// its history stays listed.
#[test]
fn no_generic_delete_removes_an_audit_read_grant() -> TestResult {
    let fixture = fixture()?;
    let holder = person(&fixture, "an auditor")?;
    let holder_proof = credential(&fixture, holder)?;
    let as_holder = bound(&fixture, holder, &holder_proof);
    let granted = grant(&fixture, holder, None);
    let grant_hex = granted["grant_ref"]
        .as_str()
        .ok_or("the grant names its row")?
        .to_owned();
    let grant_ref = EntityId::from_hex(&grant_hex)?;
    let names_the_revoke = |text: String| text.contains("vault.audit_read.revoke");

    let assert_deletes_refused = |when: &str| {
        let soft = refused(
            &owner(&fixture),
            "vault.delete",
            json!({ "entity_ref": grant_hex, "reason": "user_delete" }),
        );
        assert_forbidden(&soft, &format!("the owner's vault.delete {when}"));
        assert!(
            names_the_revoke(soft.message.clone()),
            "the refusal names the owner's revoke verb {when}: {soft:?}"
        );
        refused(
            &owner(&fixture),
            "vault.delete",
            json!({ "entity_ref": grant_hex, "reason": "user_hard_delete" }),
        );
        let plain = fixture.vault.delete_entity(&grant_ref);
        assert!(
            plain
                .as_ref()
                .is_err_and(|error| names_the_revoke(error.to_string())),
            "the record delete refuses an audit_read grant {when}: {plain:?}"
        );
        let purge = fixture
            .vault
            .delete_entity_with_options(&grant_ref, DeleteEntityOptions { purge: true });
        assert!(
            purge.is_err(),
            "the record purge refuses an audit_read grant {when}: {purge:?}"
        );
        let batch = fixture.vault.batch().delete(&grant_ref).commit();
        assert!(
            batch
                .as_ref()
                .is_err_and(|error| names_the_revoke(error.to_string())),
            "the batch delete refuses an audit_read grant {when}: {batch:?}"
        );
    };

    assert_deletes_refused("while it stands");
    call(&as_holder, "vault.authority.audit", json!({}));
    let revoked = revoke(&fixture, holder);
    assert_eq!(
        revoked["changed"],
        json!(true),
        "the owner's revoke still finds the grant standing: {revoked}"
    );
    assert_deletes_refused("once revoked");
    let page = call(&owner(&fixture), "vault.authority.audit", json!({}));
    let changes: Vec<&str> = page["audit_read_acts"]
        .as_array()
        .ok_or("the page lists the audit_read acts")?
        .iter()
        .map(|row| row["change"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(
        changes,
        vec!["grant", "revoke"],
        "the grant's history stays listed: {page}"
    );
    Ok(())
}

/// An active audit_read grant body naming `principal`, made from a calendar
/// grant's pinned body with its scope and capability swapped.
fn audit_read_body(
    principal: EntityId,
    created_at: u64,
) -> Result<AccessGrant, Box<dyn std::error::Error>> {
    let calendar = AccessGrant::calendar_disclosure(
        principal,
        EntityId::now(),
        DisclosureRung::Busy,
        created_at,
    );
    let bytes = encode_access_grant_body(&calendar)?;
    let mut value = rmpv::decode::read_value(&mut bytes.as_slice())?;
    let rmpv::Value::Map(entries) = &mut value else {
        return Err("a grant body is a map".into());
    };
    for (key, field) in entries.iter_mut() {
        match key.as_str() {
            Some("scope") => {
                *field = rmpv::Value::Map(vec![(
                    rmpv::Value::from("kind"),
                    rmpv::Value::from("vault_audit"),
                )]);
            }
            Some("capability") => *field = rmpv::Value::from("audit.read"),
            _ => {}
        }
    }
    let mut forged = Vec::new();
    rmpv::encode::write_value(&mut forged, &value)?;
    Ok(decode_access_grant_body(&forged)?)
}
