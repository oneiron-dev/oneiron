//! UC-03 PR 0 guard (fable/21 DESIGN §5): one Gate receipt writer from each of six stage-1
//! families, driven on a fresh vault, with each row's 15 fields other than its id and its time
//! pinned. Stage 1 moves each literal onto the one draft and mint and must change none of these
//! fields, so this file is green on main and stays green on every head through stage 3.
//!
//! - 1a secret custody: the owner's payment mark (`secret_custody/payment_credential.rs`).
//! - 1b consent, kept words: the owner revokes a contact's clearance (`consent/contact_clearance.rs`).
//! - 1c the gate's own doors: the owner grants a foreign principal (`gate/foreign_agent.rs`).
//! - 1d settlements: the owner's direct correction of their own claim (`claim/deferred.rs`;
//!   added by UC-03 PR 1d).
//! - 1e Dreamer: the facet admission receipt of an enqueued attempt (`dreamer_runner/authority.rs`).
//! - 1g the rest: the booking guard parks a borderline submission (`booking/anti_abuse/quarantine.rs`;
//!   added by UC-03 PR 1g, the one row here with a bound id and a bound time).
//! - 1h the rest: the owner approves an agent's plan-doc (`note/plan_doc.rs`), and a connector
//!   key's register receipt (`connector_key/txn.rs`; added by UC-03 PR 1h, a row whose time its
//!   caller binds), and the owner's delete of a NOTE (`deletion/gate.rs`; added by UC-03 PR
//!   1h-ii, a row built before its write transaction opens).
//!
//! The foreign grant and the owner's correction are owner yeses that D2 (UC-03 PR 5) respells from
//! `allow` to `approved`, so their pins read `approved`. The plan-doc approval (n52) keeps `allow`
//! until its literal moves after #8178, and its pin moves with it.
//! Fields are copied out of the row rather than compared against a built record, because UC-03
//! PR 3 seals the record so that only the mint can build one.

#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, AgentTier, MachineRole};
use oneiron::booking::EventTypeKey;
use oneiron::booking::anti_abuse::{
    BookingRequestFacts, booking_ip_hash, quarantine_borderline_submission,
};
use oneiron::claim::base_world_id;
use oneiron::connector_key::{ConnectorKeyRecord, encode_connector_key_body};
use oneiron::consent::AuthenticatedOwner;
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::deletion::TombstoneReason;
use oneiron::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
};
use oneiron::federation::{Scope, ScopeId};
use oneiron::memory::{ClaimInput, SafeDeleteReason, resolve_entity_ref};
use oneiron::note::{
    PlanDocProposeRequest, PlanDocVerdictRequest, TakeTarget, approve_plan_doc_as,
};
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_PERSON};
use oneiron::store::{
    GateDecisionContext, GateDecisionId, GateDecisionReadContext, GateDecisionRecord, GateLoopLink,
    GateLoopSource, GateSystemNoticeRecord,
};
use oneiron::test_doors::derive_verbs::define_agent;
use oneiron::test_doors::gate_receipt_rows as door;
use oneiron::test_doors::payment_credential::register_bound_secret;
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::verbs::{AgentGrantMintRequest, mint_agent_grant_as};
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, EdgeActorClass, EntityId, TimeRange, Vault,
    VaultConfig,
};
use serde_json::json;
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The policy schema version every one of these rows names.
const POLICY_VERSION: &str = "1.2";

/// A row's fields other than `decision_id` and `created_at`.
#[derive(Debug, PartialEq)]
struct Fields {
    version: u8,
    outcome: String,
    reason_codes: Vec<String>,
    receipt_reasons: Vec<String>,
    system_notices: Vec<GateSystemNoticeRecord>,
    actor_class: String,
    actor_ref: Option<String>,
    content_kind: String,
    policy_manifest_version: String,
    claim_id: Option<[u8; 16]>,
    grant_ref: Option<String>,
    diff_handle: Vec<u8>,
    read_frontier_hash: [u8; 32],
    context: GateDecisionContext,
    redacted_at: Option<u64>,
}

fn fields(row: &GateDecisionRecord) -> Fields {
    Fields {
        version: row.version,
        outcome: row.outcome.clone(),
        reason_codes: row.reason_codes.clone(),
        receipt_reasons: row.receipt_reasons.clone(),
        system_notices: row.system_notices.clone(),
        actor_class: row.actor_class.clone(),
        actor_ref: row.actor_ref.clone(),
        content_kind: row.content_kind.clone(),
        policy_manifest_version: row.policy_manifest_version.clone(),
        claim_id: row.claim_id,
        grant_ref: row.grant_ref.clone(),
        diff_handle: row.diff_handle.clone(),
        read_frontier_hash: row.read_frontier_hash,
        context: row.context.clone(),
        redacted_at: row.redacted_at,
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("lowercase hex"))
        .collect()
}

/// The decision a `gate:<hex>` receipt names.
fn decision_of(receipt: &str) -> GateDecisionId {
    let bytes = unhex(receipt.strip_prefix("gate:").expect("a gate receipt"));
    GateDecisionId::from_bytes(bytes.try_into().expect("16 id bytes"))
}

fn row(vault: &Vault, decision: GateDecisionId) -> GateDecisionRecord {
    door::gate_row(vault, decision)
        .expect("ledger read")
        .expect("the writer appended its row")
}

/// A vault with install signing, its embedded owner and the owner's proof.
fn signing_vault() -> (tempfile::TempDir, Vault, EntityId, AuthenticatedOwner) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    (dir, vault, owner, proof)
}

/// Family 1a: the owner marks a credential as a payment credential.
#[test]
fn a_payment_mark_row_keeps_its_fields() -> TestResult {
    let (_dir, vault, owner, proof) = signing_vault();
    let secret = register_bound_secret(&vault, "shop", b"uc03-guard-value", "connector:shop")?;

    let set = vault.set_secret_payment_mark(&proof, &secret, Some(true))?;

    let row = row(&vault, decision_of(&set.receipt));
    assert_eq!(
        fields(&row),
        Fields {
            version: 0,
            outcome: "approved".to_owned(),
            reason_codes: strings(&["gate.secret.payment_mark.set"]),
            receipt_reasons: Vec::new(),
            system_notices: GateSystemNoticeRecord::receipt_details(
                "secret_payment_mark",
                vec![
                    format!("custody:{}", secret.to_hex()),
                    "action:payment".to_owned()
                ],
            ),
            actor_class: "human".to_owned(),
            actor_ref: Some(owner.to_hex()),
            content_kind: "secret_payment_mark".to_owned(),
            policy_manifest_version: POLICY_VERSION.to_owned(),
            claim_id: None,
            grant_ref: None,
            diff_handle: secret.as_bytes().to_vec(),
            read_frontier_hash: [0; 32],
            context: GateDecisionContext::default(),
            redacted_at: None,
        }
    );
    Ok(())
}

/// Family 1b: the owner revokes the clearance of a contact he cleared.
#[test]
fn a_contact_clearance_revoke_row_keeps_its_fields() -> TestResult {
    let (_dir, vault, owner, proof) = signing_vault();
    let person = EntityId::now();
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 5, end: 5 },
        5,
        b"owen",
    )?;
    let contact = EntityId::now();
    vault.create_counterparty_contact(
        &contact,
        &CounterpartyContactRecord::public(person, "owen@example.com", vault.now_recorded_at())?,
    )?;
    vault.preclear_contact_disclosure(&proof, "owen", &[contact], Scope::top())?;

    let receipt = vault.revoke_contact_disclosure(&proof, &contact)?;

    let row = row(&vault, receipt.decision_id);
    assert_eq!(
        fields(&row),
        Fields {
            version: 0,
            outcome: "revoked".to_owned(),
            reason_codes: strings(&["gate.consent.contact_disclosure.revoked"]),
            receipt_reasons: Vec::new(),
            system_notices: GateSystemNoticeRecord::receipt_details(
                "consent_grant",
                vec![
                    format!("contact:{}", contact.to_hex()),
                    format!("before:{}", hex(&receipt.before_digest)),
                    format!("after:{}", hex(&receipt.after_digest)),
                ],
            ),
            actor_class: "human".to_owned(),
            actor_ref: Some(owner.to_hex()),
            content_kind: "consent_grant".to_owned(),
            policy_manifest_version: POLICY_VERSION.to_owned(),
            claim_id: None,
            grant_ref: Some(format!("contact_clearance:{}", contact.to_hex())),
            diff_handle: receipt.after_digest.to_vec(),
            read_frontier_hash: [0; 32],
            context: GateDecisionContext::default(),
            redacted_at: None,
        }
    );
    Ok(())
}

/// Family 1c: the owner grants a foreign principal read reach.
#[test]
fn a_foreign_grant_row_keeps_its_fields() -> TestResult {
    const PRINCIPAL: &str = "oauth-relay:uc03-guard";
    let (_dir, vault, owner, proof) = signing_vault();

    let receipt = vault.grant_foreign_principal(&proof, PRINCIPAL)?;

    let row = row(&vault, receipt.decision_id);
    let frontier = door::policy_frontier(&vault)?;
    assert_ne!(frontier, [0; 32], "the grant is judged on a read policy");
    assert_eq!(
        row.diff_handle.len(),
        32,
        "a digest of the granted manifest"
    );
    assert_eq!(
        fields(&row),
        Fields {
            version: 0,
            outcome: "approved".to_owned(),
            reason_codes: strings(&["gate.allow.owner_foreign_grant"]),
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "human".to_owned(),
            actor_ref: Some(owner.to_hex()),
            content_kind: "policy_manifest".to_owned(),
            policy_manifest_version: POLICY_VERSION.to_owned(),
            claim_id: None,
            grant_ref: Some(format!("foreign:{PRINCIPAL}")),
            diff_handle: receipt.diff_handle.clone(),
            read_frontier_hash: frontier,
            context: GateDecisionContext::default(),
            redacted_at: None,
        }
    );
    Ok(())
}

/// Family 1e: a Dreamer attempt's facet admission receipt.
#[test]
fn a_dreamer_facet_admission_row_keeps_its_fields() -> TestResult {
    const RUN: &str = "uc03-guard-run";
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    let outcome = DreamerRunnerStore::new(&vault).enqueue(EnqueueDreamerAttempt {
        attempt_type: "uc03-guard-probe".to_owned(),
        input: rmpv::Value::Nil,
        parent_attempt: None,
        dedupe_key: None,
        run_id: Some(RUN.to_owned()),
        now: 1_700_000_000,
    })?;
    let EnqueueDreamerAttemptOutcome::Enqueued(status) = outcome else {
        panic!("a fresh Dreamer attempt is enqueued");
    };
    let attempt = status.attempt.id;
    let stamp = vault
        .dreamer_attempt_authority(attempt)?
        .expect("the attempt holds its authority stamp");

    let row = row(&vault, GateDecisionId::from_bytes(stamp.receipt_id));
    let frontier = door::policy_frontier(&vault)?;
    assert_ne!(
        frontier, [0; 32],
        "the admission is judged on a read policy"
    );
    assert_eq!(
        fields(&row),
        Fields {
            version: 0,
            outcome: "allow".to_owned(),
            reason_codes: strings(&["gate.dreamer.facet_admitted"]),
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "system".to_owned(),
            actor_ref: Some(stamp.actor.to_hex()),
            content_kind: "dreamer_authority".to_owned(),
            policy_manifest_version: POLICY_VERSION.to_owned(),
            claim_id: None,
            grant_ref: None,
            diff_handle: attempt.as_bytes().to_vec(),
            read_frontier_hash: frontier,
            context: GateDecisionContext::linked(
                GateLoopLink::admission(
                    GateLoopSource::Dreamer,
                    Some(RUN.to_owned()),
                    Some(*attempt.as_bytes()),
                ),
                Vec::<GateDecisionReadContext>::new(),
            ),
            redacted_at: None,
        }
    );
    Ok(())
}

/// Family 1g: the booking guard parks a borderline submission for the owner's review. The
/// fixture is `tests/claim_facet_birth.rs`'s: a vault with the engine machines and a host-bound
/// owner, and the booking page stored as an EVENT. The row takes the parked claim's id and the
/// guard's time, so this pin also holds `decision_id` and `created_at`.
#[test]
fn a_booking_quarantine_row_keeps_its_fields() -> TestResult {
    const SUBMITTED_AT: u64 = 1;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault");
    provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor()?;
    bind_host_owner(&vault, &test_host_issuer(), owner).expect("owner host binding");
    let page = EntityId::now();
    vault.put_entity(
        &page,
        ENTITY_TYPE_EVENT,
        TimeRange { start: 5, end: 5 },
        5,
        b"booking page",
    )?;
    let facts = BookingRequestFacts {
        page_ref: page,
        event_type: Some(EventTypeKey("intro-call".to_owned())),
        ip_hash: booking_ip_hash("203.0.113.10"),
        email_hash: None,
        session_hash: None,
        started_at_millis: 1_000_000,
        submitted_at_millis: 1_005_000,
        submission_fingerprint: [1; 32],
        selected_slot_hash: [2; 32],
        intake_content_hash: [3; 32],
        honeypot_nonempty: false,
        intake_chars: 40,
        active_future_bookings_for_email: 0,
        active_holds_for_session: 0,
        email: None,
    };

    let receipt = quarantine_borderline_submission(&vault, &facts, "borderline", SUBMITTED_AT)
        .expect("a borderline submission is quarantined");

    let decision = GateDecisionId::from_bytes(receipt.decision_id);
    assert_eq!(
        decision,
        GateDecisionId::from_bytes(receipt.claim_id),
        "the row takes the parked claim's id"
    );
    let row = row(&vault, decision);
    assert_eq!(row.decision_id, decision);
    assert_eq!(
        row.created_at, SUBMITTED_AT,
        "the row keeps the guard's time"
    );
    let pending = vault
        .pending_gate_consents(16)?
        .into_iter()
        .find(|pending| pending.claim_id == receipt.claim_id)
        .expect("the guard parked the claim");
    assert_eq!(pending.decision_id, decision);
    assert_eq!(
        pending.diff_handle.len(),
        32,
        "a digest of the parked claim"
    );
    let frontier = door::policy_frontier(&vault)?;
    assert_eq!(pending.read_frontier_hash, frontier);
    assert_eq!(
        fields(&row),
        Fields {
            version: 0,
            outcome: "pending".to_owned(),
            reason_codes: strings(&["gate.pending.booking.anti_abuse.borderline"]),
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "booking.http_guard".to_owned(),
            actor_ref: None,
            content_kind: "booking.submission".to_owned(),
            policy_manifest_version: "booking.anti_abuse.v1".to_owned(),
            claim_id: Some(receipt.claim_id),
            grant_ref: None,
            diff_handle: pending.diff_handle.clone(),
            read_frontier_hash: frontier,
            context: GateDecisionContext::default(),
            redacted_at: None,
        }
    );
    Ok(())
}

/// Family 1h: a connector key's register receipt. The fixture is
/// `tests/connector_key_suspend_admission.rs`'s: an owned vault with install signing, its embedded
/// owner, and the person the key acts for.
#[test]
fn a_connector_key_register_row_keeps_its_fields() -> TestResult {
    const REGISTERED_AT: u64 = 10;
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    vault.ensure_embedded_owner_actor()?;
    let person = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({ "name": "connector person" }))?;
    vault.put_entity(
        &person,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        &body,
    )?;
    let key = EntityId::now();

    let record = vault.register_connector_key(
        &key,
        ConnectorKeyRecord::active("email", Some(person), Vec::new(), REGISTERED_AT),
    )?;

    let grant_ref = format!("ckey:{}", key.to_hex());
    let rows: Vec<GateDecisionRecord> = vault
        .gate_decisions(64)?
        .into_iter()
        .filter(|row| {
            row.content_kind == "connector_key_op"
                && row.grant_ref.as_deref() == Some(grant_ref.as_str())
        })
        .collect();
    assert_eq!(rows.len(), 1, "a registration writes one receipt");
    let row = &rows[0];
    assert_eq!(
        row.created_at, REGISTERED_AT,
        "the row keeps the registration's time"
    );
    let mut handle = Sha256::new();
    handle.update(b"oneiron.connector_key.op.v0");
    handle.update(encode_connector_key_body(&record)?);
    let frontier = door::policy_frontier(&vault)?;
    assert_eq!(
        fields(row),
        Fields {
            version: 0,
            outcome: "allow".to_owned(),
            reason_codes: strings(&["gate.connector_key.register"]),
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "first_party".to_owned(),
            actor_ref: None,
            content_kind: "connector_key_op".to_owned(),
            policy_manifest_version: POLICY_VERSION.to_owned(),
            claim_id: None,
            grant_ref: Some(grant_ref),
            diff_handle: handle.finalize().to_vec(),
            read_frontier_hash: frontier,
            context: GateDecisionContext::default(),
            redacted_at: None,
        }
    );
    Ok(())
}

/// Family 1h: the owner deletes a NOTE through `vault.delete`'s call, `Memory::safe_delete`. The
/// deletion's plan builds this row before any write transaction opens, with the request's id and
/// time bound, and a later transaction appends it. The fixture is G41's
/// (`tests/gate_pins_authority_rechecks.rs`): a seeded vault, its embedded owner and a keystore.
#[test]
fn an_owner_delete_row_keeps_its_fields() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: 1_780_000_000,
            end: 1_780_000_000,
        },
        1_780_000_000,
        &rmp_serde::to_vec_named(&json!({ "name": "delete guard subject" }))?,
    )?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let note = memory
        .author_take(TakeTarget::Subject(subject), "a take the owner deletes")?
        .id_hex;
    let note_id = EntityId::from_hex(&note)?;

    let receipt = memory.safe_delete(&note, SafeDeleteReason::UserDelete)?;

    assert!(receipt.existed);
    let mut handle = Sha256::new();
    handle.update(b"oneiron.gate.deletion.v0");
    handle.update(owner.as_bytes());
    handle.update(note_id.as_bytes());
    handle.update([TombstoneReason::UserDelete.wire_byte()]);
    let handle = handle.finalize().to_vec();
    let rows: Vec<GateDecisionRecord> = vault
        .gate_decisions(64)?
        .into_iter()
        .filter(|row| row.content_kind == "deletion" && row.diff_handle == handle)
        .collect();
    assert_eq!(rows.len(), 1, "the delete of the NOTE writes one row");
    let frontier = door::policy_frontier(&vault)?;
    assert_eq!(
        fields(&rows[0]),
        Fields {
            version: 0,
            outcome: "allow".to_owned(),
            reason_codes: strings(&["gate.allow.owner_delete"]),
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "human".to_owned(),
            actor_ref: Some(owner.to_hex()),
            content_kind: "deletion".to_owned(),
            policy_manifest_version: POLICY_VERSION.to_owned(),
            claim_id: None,
            grant_ref: None,
            diff_handle: handle,
            read_frontier_hash: frontier,
            context: GateDecisionContext::default(),
            redacted_at: None,
        }
    );
    Ok(())
}

/// Family 1d: the owner's direct correction of their own landed claim (FIX 22041). The
/// replacement lands at once and closes the prior in the same write, with this row. The fixture
/// is `tests/claim_settle_supersession.rs`'s: an unrooted vault and its embedded owner.
#[test]
fn an_owner_correction_row_keeps_its_fields() -> TestResult {
    let (_dir, vault, owner, _proof) = signing_vault();
    let subject = EntityId::now();
    vault.put_entity(
        &subject,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 5, end: 5 },
        5,
        b"correction guard subject",
    )?;
    let facet = vault.default_facet()?;
    let input = |value: &str| ClaimInput {
        id: None,
        // The shipped manifest declares `profile.` normal, so no confirmation holds the write.
        predicate: "profile.name".to_owned(),
        subject_ref: subject.to_hex(),
        value: json!(value),
        confidence: 1.0,
        confidence_details: None,
        source: "user_stated".to_owned(),
        world_ref: None,
        relationship_ref: None,
        scope: Some(json!({ "facet": facet.to_hex() })),
        valid_from: Some(100),
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
    };
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let first = memory.claim_upsert(&input("Owen"))?;
    assert_eq!(first.approval, "auto", "the owner's claim lands");
    let prior = resolve_entity_ref(&vault, &first.claim_short_id)?;

    let second = memory.claim_upsert(&input("Owen, corrected"))?;

    assert_eq!(
        second.approval, "auto",
        "the owner's correction lands at once"
    );
    let replacement = resolve_entity_ref(&vault, &second.claim_short_id)?;
    assert_eq!(
        vault.get_claim(&prior)?.expect("the prior reads").lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the correction closes the prior in the same write",
    );
    let rows: Vec<GateDecisionRecord> = vault
        .gate_decisions(64)?
        .into_iter()
        .filter(|row| row.reason_codes == ["gate.supersede.owner_correction"])
        .collect();
    assert_eq!(rows.len(), 1, "the correction writes one row");
    // The handle binds the replacement's body as a proposal would carry it.
    let mut body = vault
        .get_claim(&replacement)?
        .expect("the replacement reads");
    body.approval = ClaimApprovalStatus::Proposed;
    let mut handle = Sha256::new();
    handle.update(b"oneiron.gate.claim_diff.v0");
    handle.update(encode_claim_body(&body)?);
    let frontier = door::policy_frontier(&vault)?;
    assert_eq!(
        fields(&rows[0]),
        Fields {
            version: 0,
            outcome: "approved".to_owned(),
            reason_codes: strings(&["gate.supersede.owner_correction"]),
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "human".to_owned(),
            actor_ref: Some(owner.to_hex()),
            content_kind: "claim".to_owned(),
            policy_manifest_version: POLICY_VERSION.to_owned(),
            claim_id: Some(*replacement.as_bytes()),
            grant_ref: None,
            diff_handle: handle.finalize().to_vec(),
            read_frontier_hash: frontier,
            context: GateDecisionContext::default(),
            redacted_at: None,
        }
    );
    Ok(())
}

/// Family 1h: the owner approves the plan-doc an agent proposed. The fixture is
/// `tests/plan_mode_setting.rs`'s: a rooted vault, its owner, and an agent with an owner Grant
/// of base reach.
#[test]
fn a_plan_doc_approval_row_keeps_its_fields() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing()?;
    let issuer = vault.bootstrap_host_slip_issuer()?;
    vault.ensure_host_root_slip(&issuer)?;
    vault.provision_engine_machine_identities(&issuer)?;
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let agent = define_agent(&vault, "uc03-guard-planner")?;
    let proof = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    let mut authority_scope = Scope::top();
    authority_scope.worlds = [ScopeId(base_world_id())].into_iter().collect();
    authority_scope.verbs = AgentTier::FullAccess
        .grant_verbs()
        .iter()
        .map(|verb| (*verb).to_owned())
        .collect();
    mint_agent_grant_as(
        &vault,
        &proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("the owner grants the agent base reach");
    let request: PlanDocProposeRequest = serde_json::from_value(json!({
        "plan": {
            "title": "Tidy the tide log",
            "steps": ["Merge the duplicate dawn readings"],
            "scope_asked": ["notes tagged tide"],
            "budget": 400,
        },
    }))?;
    let plan = vault
        .memory(agent, EdgeActorClass::Agent)
        .propose_plan_doc(&request)
        .expect("the agent proposes a plan");

    let settled = approve_plan_doc_as(
        &vault,
        &proof,
        PlanDocVerdictRequest {
            plan_ref: plan.plan_ref,
            expected_revision: plan.revision.clone(),
            approving_turn_ref: None,
            approving_thread_ref: None,
        },
    )
    .expect("the owner approves the plan");

    let row = row(&vault, decision_of(&settled.receipt_ref));
    let frontier = door::policy_frontier(&vault)?;
    assert_ne!(frontier, [0; 32], "the verdict is judged on a read policy");
    assert_eq!(
        fields(&row),
        Fields {
            version: 0,
            outcome: "allow".to_owned(),
            reason_codes: strings(&["gate.allow.owner_plan_doc"]),
            receipt_reasons: Vec::new(),
            system_notices: GateSystemNoticeRecord::receipt_details(
                "plan_doc_verdict",
                vec![
                    format!("plan:{}", plan.plan_ref.to_hex()),
                    format!("revision:{}", plan.revision),
                    format!("proposed_by:{}", agent.to_hex()),
                ],
            ),
            actor_class: "human".to_owned(),
            actor_ref: Some(owner.to_hex()),
            content_kind: "plan_doc_verdict".to_owned(),
            policy_manifest_version: POLICY_VERSION.to_owned(),
            claim_id: None,
            grant_ref: Some(format!("note:{}", plan.plan_ref.to_hex())),
            diff_handle: unhex(&plan.revision),
            read_frontier_hash: frontier,
            context: GateDecisionContext::default(),
            redacted_at: None,
        }
    );
    Ok(())
}
