//! UC-02 B1a: the engine owns the input rules the bindings used to own.
//!
//! Each verb is called by name through the generic invoke
//! (`oneiron::task_verb::sdk::invoke`), as every door calls it: JSON in, JSON
//! out. So a rule proven here holds over napi, Python, Swift, HTTP and MCP
//! alike, with one refusal.
//!
//! - An omitted `is_visible` reads as `true` (napi, uniffi and Python filled
//!   it; HTTP refused the message).
//! - A message whose `metadata` is not a JSON object is refused (napi alone
//!   refused it; the other doors stored it).
//! - The outbound schedule context's offset and timezone rules, which napi
//!   also checked by hand, are already the engine's
//!   (`OutboundScheduleContext::validate`, run in the schedule's admission):
//!   nothing moves, and this guard keeps them.
//! - The three expression-preference rows, the doors only napi's
//!   `ActorScopedVault` had, run through the generic invoke; an omitted
//!   `occurred_at` on the write is the vault's recording clock.
//! - The read row answers only what the caller's own read lane reads
//!   (REVIEW-8147 P1): a preference claim a verified credential withholds
//!   shows no value and no ref, and a subject it withholds is NOT_FOUND, as a
//!   missing one is.
//! - The retrieval quality report writes `confidence_adjustment`; a body
//!   with the old `confidenceAdjustment` key still reads.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test engine_owned_input_rules`
#![cfg(feature = "test-support")]

use std::sync::atomic::{AtomicU8, Ordering};

use oneiron::authority::VerifiedSlip;
use oneiron::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_NOT_FOUND, Memory, MemoryError, OutboundScheduleContext,
    WitnessMessage,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_support::{
    bind_host_owner, provision_engine_machines, put_policy_manifest_bytes, test_host_issuer,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use rmpv::Value as Msgpack;
use serde_json::{Value, json};

fn fresh_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    bind_host_owner(&vault, &test_host_issuer(), owner).expect("owner host binding");
    (directory, vault)
}

fn owner_memory(vault: &Vault) -> Memory<'_> {
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    vault.memory(owner, EdgeActorClass::Human)
}

/// One user message, as JSON, with the given extra members.
fn message(extra: &Value) -> Value {
    let mut message = json!({
        "id": EntityId::now().to_hex(),
        "author": "user",
        "message_type": "dialogue",
        "content": "hello",
        "metadata": null,
        "order": 0
    });
    for (key, value) in extra.as_object().expect("extra members") {
        message[key] = value.clone();
    }
    message
}

/// A witness input for one fresh turn holding `message`.
fn witness(vault: &Vault, message: Value) -> Value {
    json!({
        "conversation_ref": EntityId::now().to_hex(),
        "turn_ref": EntityId::now().to_hex(),
        "messages": [message],
        "occurred_at": vault.now_recorded_at()
    })
}

fn refused(result: Result<Value, MemoryError>, what: &str) -> MemoryError {
    match result {
        Ok(output) => panic!("{what}: accepted, answered {output}"),
        Err(error) => error,
    }
}

/// (b) An omitted `is_visible` is `true`: in the engine DTO's serde, and so
/// through the generic invoke.
#[test]
fn an_omitted_is_visible_reads_as_visible() {
    let decoded: WitnessMessage =
        serde_json::from_value(message(&json!({}))).expect("a message without is_visible");
    assert!(decoded.is_visible);
    let hidden: WitnessMessage =
        serde_json::from_value(message(&json!({"is_visible": false}))).expect("a hidden message");
    assert!(!hidden.is_visible, "a stated false stays false");

    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    let receipt = invoke(
        &memory,
        "vault.witness",
        witness(&vault, message(&json!({}))),
    )
    .expect("a message without is_visible is witnessed");
    assert!(receipt.is_object(), "{receipt}");
}

/// (c) A message's metadata is a JSON object or absent: an array or a scalar
/// is refused by the engine, naming the message; an object is witnessed.
#[test]
fn a_message_whose_metadata_is_not_an_object_is_refused() {
    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    for (metadata, kind) in [(json!([1, 2]), "an array"), (json!("note"), "a string")] {
        let error = refused(
            invoke(
                &memory,
                "vault.witness",
                witness(&vault, message(&json!({ "metadata": metadata }))),
            ),
            kind,
        );
        assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST, "{kind}: {error:?}");
        assert!(
            error.message.contains("metadata must be a JSON object")
                && error.message.contains("order 0")
                && error.message.contains(kind),
            "{kind}: {error:?}"
        );
    }
    invoke(
        &memory,
        "vault.witness",
        witness(&vault, message(&json!({"metadata": {"source": "test"}}))),
    )
    .expect("object metadata is witnessed");
}

/// (d) The schedule context's three rules that napi checked by hand are the
/// engine's own, run in the schedule's admission: an offset outside
/// -840..=840, a timezone label without an offset, and a blank label.
#[test]
fn the_schedule_context_rules_are_the_engines() {
    let refused = |context: OutboundScheduleContext, what: &str| {
        let error = context.validate().expect_err(what);
        assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST, "{what}: {error:?}");
    };
    refused(
        OutboundScheduleContext {
            utc_offset_minutes: Some(900),
            ..OutboundScheduleContext::default()
        },
        "offset 900",
    );
    refused(
        OutboundScheduleContext {
            iana_timezone: Some("Asia/Tokyo".to_owned()),
            ..OutboundScheduleContext::default()
        },
        "a label without an offset",
    );
    refused(
        OutboundScheduleContext {
            utc_offset_minutes: Some(540),
            iana_timezone: Some("  ".to_owned()),
            ..OutboundScheduleContext::default()
        },
        "a blank label",
    );
    OutboundScheduleContext {
        utc_offset_minutes: Some(540),
        iana_timezone: Some("Asia/Tokyo".to_owned()),
        ..OutboundScheduleContext::default()
    }
    .validate()
    .expect("a current offset with its label");
}

/// The auto-band manifest the expression-preference family needs: a human
/// (and the lifecycle's first-party puts) write `companion.expression.*` at
/// `auto`, as the engine's own family tests install it.
fn install_expression_policy(vault: &Vault) {
    let axes = || {
        Msgpack::Map(vec![
            (Msgpack::from("criticality"), Msgpack::from("normal")),
            (Msgpack::from("sensitivity"), Msgpack::from("normal")),
        ])
    };
    let ceiling = |class: &str| {
        Msgpack::Map(vec![
            (Msgpack::from("actor_class"), Msgpack::from(class)),
            (Msgpack::from("ceiling"), Msgpack::from("auto")),
        ])
    };
    let manifest = Msgpack::Map(vec![
        (
            Msgpack::from("schema_version"),
            Msgpack::from(oneiron_store::policy_record::POLICY_SCHEMA_VERSION),
        ),
        (
            Msgpack::from("pack_id"),
            Msgpack::from("uc02-b1a-expression-preference"),
        ),
        (Msgpack::from("pack_version"), Msgpack::from("v1")),
        (
            Msgpack::from("min_engine_version"),
            Msgpack::from(env!("CARGO_PKG_VERSION")),
        ),
        (Msgpack::from("defaults"), axes()),
        (
            Msgpack::from("rules"),
            Msgpack::Array(vec![Msgpack::Map(vec![
                (
                    Msgpack::from("prefix"),
                    Msgpack::from("companion.expression."),
                ),
                (Msgpack::from("axes"), axes()),
            ])]),
        ),
        (
            Msgpack::from("actor_ceilings"),
            Msgpack::Array(vec![ceiling("human"), ceiling("first_party")]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest).expect("encode manifest");
    put_policy_manifest_bytes(vault, EntityId::now(), &data).expect("install the manifest");
}

/// (e) The three expression-preference rows run through the generic invoke:
/// set (its omitted `occurred_at` is the recording clock), get, retract.
#[test]
fn the_expression_preference_rows_run_through_the_generic_invoke() {
    let (_directory, vault) = fresh_vault();
    install_expression_policy(&vault);
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"subject",
        )
        .expect("the preference's subject");
    let memory = owner_memory(&vault);
    let now = vault.now_recorded_at();
    let set = |valid_from: u64, occurred_at: Option<u64>| {
        let mut input = json!({
            "subject_ref": subject.to_hex(),
            "value": {"kind": "language", "value": "en-US"},
            "origin": "explicit_user",
            "valid_from": valid_from
        });
        if let Some(at) = occurred_at {
            input["occurred_at"] = json!(at);
        }
        invoke(&memory, "vault.expression_preferences.set", input)
    };

    // The omitted time is now, on the recording clock: a valid_from an hour
    // ahead of it is refused (this family does not schedule), and one a
    // minute behind it is written.
    let ahead = refused(set(now + 3_600, None), "a valid_from an hour ahead");
    assert!(
        ahead
            .message
            .contains("valid_from cannot be later than learned_at"),
        "{ahead:?}"
    );
    // A stated time is used as given, never replaced by the clock.
    let stated = refused(
        set(now - 60, Some(now - 7_200)),
        "a valid_from after the stated occurred_at",
    );
    assert!(
        stated
            .message
            .contains("valid_from cannot be later than learned_at"),
        "{stated:?}"
    );
    let receipt = set(now - 60, None).expect("a preference with occurred_at omitted");
    let claim_ref = receipt["claim_short_id"]
        .as_str()
        .unwrap_or_else(|| panic!("a claim ref in {receipt}"))
        .to_owned();
    assert!(receipt["superseded_short_ids"].is_array(), "{receipt}");

    let view = invoke(
        &memory,
        "vault.expression_preferences.get",
        json!({ "subject_ref": subject.to_hex() }),
    )
    .expect("the preferences in force");
    assert_eq!(view["language"], json!("en-US"), "{view}");
    assert_eq!(view["winning_refs"]["language"], json!(claim_ref), "{view}");

    let retracted = invoke(
        &memory,
        "vault.expression_preferences.retract",
        json!({ "claim_ref": claim_ref }),
    )
    .expect("the retraction");
    assert_eq!(retracted, Value::Null);
    let after = invoke(
        &memory,
        "vault.expression_preferences.get",
        json!({ "subject_ref": subject.to_hex(), "at": vault.now_recorded_at() }),
    )
    .expect("the preferences after the retraction");
    assert_eq!(after["language"], Value::Null, "{after}");
}

const CHALLENGE: &[u8] = b"oneiron-request:engine-owned-input-rules";

fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// A fresh PERSON row.
fn person(vault: &Vault, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            body,
        )
        .expect("a PERSON row");
    id
}

/// The live `human` credential the test host mints `holder`, held by a
/// records caveat to `records`, verified as a transport verifies the slip a
/// request presents.
fn held_credential(vault: &Vault, holder: EntityId, records: &[EntityId]) -> VerifiedSlip {
    let issuer = test_host_issuer();
    let mut claims = vault
        .ensure_host_root_slip(&issuer)
        .expect("the host root slip")
        .claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.records = records.iter().map(EntityId::to_hex).collect();
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("mint the credential");
    let binding = issuer
        .binding_proof(&slip, CHALLENGE)
        .expect("the binding proof");
    vault
        .verify_capability_slip(&issuer.public_key(), &slip, CHALLENGE, &binding)
        .expect("verify the credential")
}

/// One owner-stated `language` preference in force on a fresh subject:
/// the subject and the preference claim.
fn owner_preference(vault: &Vault) -> (EntityId, EntityId) {
    install_expression_policy(vault);
    let subject = person(vault, b"subject");
    invoke(
        &owner_memory(vault),
        "vault.expression_preferences.set",
        json!({
            "subject_ref": subject.to_hex(),
            "value": {"kind": "language", "value": "en-US"},
            "origin": "explicit_user",
            "valid_from": vault.now_recorded_at() - 60
        }),
    )
    .expect("the owner's preference");
    let in_force = vault
        .expression_preferences(&subject, vault.now_recorded_at())
        .expect("the preferences in force")
        .winning_claim_ids;
    assert_eq!(in_force.len(), 1, "one preference in force: {in_force:?}");
    let claim = in_force.into_values().next().expect("the preference claim");
    (subject, claim)
}

fn preferences_of(memory: &Memory<'_>, subject: EntityId) -> Result<Value, MemoryError> {
    invoke(
        memory,
        "vault.expression_preferences.get",
        json!({ "subject_ref": subject.to_hex() }),
    )
}

/// (f) A credential that reads the subject but not the preference claim
/// reads no value and no ref for it (REVIEW-8147 P1: the read took no lane).
#[test]
fn a_credential_that_withholds_the_preference_reads_no_value() {
    let (_directory, vault) = fresh_vault();
    let (subject, _claim) = owner_preference(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    let proof = held_credential(&vault, owner, &[owner, subject]);
    let reader = vault
        .memory(owner, EdgeActorClass::Human)
        .with_read_proof(&proof);
    let view = preferences_of(&reader, subject).expect("the held credential reads the subject");
    assert_eq!(view["language"], Value::Null, "{view}");
    assert_eq!(view["winning_refs"], json!({}), "{view}");
}

/// (f) Guard: a credential that reads the preference claim reads its value
/// and the same ref the owner reads.
#[test]
fn a_credential_that_reads_the_preference_reads_its_value_and_ref() {
    let (_directory, vault) = fresh_vault();
    let (subject, claim) = owner_preference(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    let unbound = preferences_of(&owner_memory(&vault), subject).expect("the owner's read");
    let proof = held_credential(&vault, owner, &[owner, subject, claim]);
    let reader = vault
        .memory(owner, EdgeActorClass::Human)
        .with_read_proof(&proof);
    let view = preferences_of(&reader, subject).expect("the held credential reads the subject");
    assert_eq!(view["language"], json!("en-US"), "{view}");
    assert_eq!(
        view["winning_refs"]["language"], unbound["winning_refs"]["language"],
        "{view} / {unbound}"
    );
    assert!(view["winning_refs"]["language"].is_string(), "{view}");
}

/// (f) A subject the caller's credential withholds is NOT_FOUND, exactly as
/// a subject that does not exist, so the door is no existence oracle.
#[test]
fn a_subject_the_credential_withholds_reads_as_missing() {
    let (_directory, vault) = fresh_vault();
    let (subject, _claim) = owner_preference(&vault);
    let stranger = person(&vault, b"a person with no grant");
    let proof = held_credential(&vault, stranger, &[stranger]);
    let reader = vault
        .memory(stranger, EdgeActorClass::Human)
        .with_read_proof(&proof);
    let withheld = refused(
        preferences_of(&reader, subject),
        "a subject the credential withholds",
    );
    let missing = refused(
        preferences_of(&reader, EntityId::now()),
        "a subject that does not exist",
    );
    assert_eq!(missing.code, MEMORY_CODE_NOT_FOUND, "{missing:?}");
    assert_eq!(
        (withheld.code.as_str(), withheld.message.as_str()),
        (missing.code.as_str(), missing.message.as_str()),
        "{withheld:?} / {missing:?}"
    );
}

/// The retrieval quality report writes `confidence_adjustment`, as every
/// other field of it does, and a body written with the old camelCase key
/// still reads the same (UC02-B1-SPLIT = A, note 2: the stored-change path
/// is keep).
#[test]
fn the_confidence_adjustment_key_is_snake_case_and_the_old_key_still_reads() {
    use oneiron::retrieval_quality::{RetrievalQuality, RetrievalQualityReport};
    let report = RetrievalQualityReport {
        quality: RetrievalQuality::Degraded,
        degradation: Vec::new(),
        confidence_adjustment: RetrievalQuality::Degraded.confidence_adjustment(),
    };
    let written = serde_json::to_value(&report).expect("the report writes");
    let Value::Object(mut members) = written.clone() else {
        panic!("the report is an object: {written}");
    };
    assert!(
        members.contains_key("confidence_adjustment")
            && !members.contains_key("confidenceAdjustment"),
        "{written}"
    );
    let reread: RetrievalQualityReport =
        serde_json::from_value(written.clone()).expect("the new body reads");
    assert_eq!(reread, report);
    let adjustment = members
        .remove("confidence_adjustment")
        .expect("the adjustment member");
    members.insert("confidenceAdjustment".to_owned(), adjustment);
    let old: RetrievalQualityReport =
        serde_json::from_value(Value::Object(members)).expect("a body with the old key reads");
    assert_eq!(old, report);
}
