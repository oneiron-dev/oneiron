//! The short ref `vault.get` issues for a row whose body became a document
//! resolves through `vault.refs.resolve` and reads back through `vault.get`
//! (FIX SUMMARY-SHORT-REF-INDEX). A live read issues the ref with the
//! content hash of the body it serves: a document-backed row's document
//! projection. The short-id index kept the hash of the body the row was put
//! with, so the issued ref answered NOT_FOUND whenever the projection's bytes
//! differ from it: a map whose text field the projection moves after the
//! other fields (a scope SUMMARY's body), or a text an edit changed.
//! The text migration, atomic MESSAGE commit and streamed MESSAGE cases keep
//! bodies the projection reproduces byte for byte; they guard that a fix
//! keeps those refs resolving. The verbs are called by name through the
//! embedded door, and their output is read as JSON.
//!
//! Fleet: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test short_ref_after_document_pointer`
#![cfg(feature = "test-support")]

use oneiron::consent::AuthenticatedOwner;
use oneiron::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb, TextField};
use oneiron::memory::{
    Memory, MessageWriteMode, WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn,
};
use oneiron::registry::ENTITY_TYPE_ASSET;
use oneiron::store::GateDecisionId;
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::{Value, json};

fn fresh_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    bind_host_owner(&vault, &test_host_issuer(), owner).expect("owner host binding");
    (directory, vault)
}

fn authenticated_owner(vault: &Vault) -> (WriteActor, AuthenticatedOwner) {
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    (WriteActor::new(owner, EdgeActorClass::Human), proof)
}

fn owner_memory(vault: &Vault) -> Memory<'_> {
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    vault.memory(owner, EdgeActorClass::Human)
}

fn witness_turn(vault: &Vault, content: &str) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: Some(EntityId::now().to_hex()),
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: Some(EntityId::now().to_hex()),
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: content.to_owned(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: vault.now_recorded_at(),
        assertions: WitnessAssertions::default(),
    }
}

fn message_id(turn: &WitnessTurn) -> EntityId {
    let hex = turn.messages[0].id.as_deref().expect("message id");
    EntityId::from_hex(hex).expect("message id hex")
}

fn field<'a>(output: &'a Value, pointer: &str, what: &str) -> &'a Value {
    output
        .pointer(pointer)
        .unwrap_or_else(|| panic!("{what}: no {pointer} in {output}"))
}

/// The ref `vault.get` issues for `entity` must name it at
/// `vault.refs.resolve` and read it back at `vault.get`.
fn assert_issued_short_ref_resolves(memory: &Memory<'_>, entity: &EntityId) {
    let read = oneiron::task_verb::sdk::invoke(
        memory,
        "vault.get",
        json!({ "entity_ref": entity.to_hex() }),
    )
    .expect("the owner reads the row by its id");
    let reference = field(&read, "/value/short_ref", "vault.get by id")
        .as_str()
        .unwrap_or_else(|| panic!("vault.get issued no short ref: {read}"))
        .to_owned();

    let resolved = oneiron::task_verb::sdk::invoke(
        memory,
        "vault.refs.resolve",
        json!({ "reference": reference }),
    )
    .unwrap_or_else(|error| {
        panic!("the short ref {reference} that vault.get issued does not resolve: {error:?}")
    });
    assert_eq!(
        field(&resolved, "/value/record/id", "vault.refs.resolve")
            .as_str()
            .map(str::to_ascii_lowercase),
        Some(entity.to_hex().to_ascii_lowercase()),
        "the issued short ref {reference} resolves to its own row: {resolved}"
    );

    let reread =
        oneiron::task_verb::sdk::invoke(memory, "vault.get", json!({ "entity_ref": reference }))
            .unwrap_or_else(|error| {
                panic!("vault.get by the issued ref {reference} fails: {error:?}")
            });
    assert!(
        !field(&reread, "/value", "vault.get by short ref").is_null(),
        "vault.get reads the row back by the ref it issued ({reference}): {reread}"
    );
}

#[test]
fn a_migrated_text_row_resolves_by_its_issued_short_ref() {
    let (_directory, vault) = fresh_vault();
    let (owner, proof) = authenticated_owner(&vault);
    let entity = EntityId::now();
    vault
        .put_entity(
            &entity,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 7, end: 7 },
            9,
            b"short ref fixture text",
        )
        .expect("text asset");
    // The migration rewrites the indexed text body to a document pointer.
    vault
        .migrate_entity_text(
            &entity,
            &TextField::Utf8Body,
            owner,
            &DocAuthorization::Owner(&proof),
        )
        .expect("the owner migrates the text to a document");

    assert_issued_short_ref_resolves(&owner_memory(&vault), &entity);
}

#[test]
fn a_map_row_whose_text_field_moves_resolves_by_its_issued_short_ref() {
    let (_directory, vault) = fresh_vault();
    let (owner, proof) = authenticated_owner(&vault);
    let entity = EntityId::now();
    // The text field comes first, as a scope SUMMARY's body has it before
    // its actor, covers and minting time. The document projection writes
    // the other fields first and the text after them.
    let body = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("text"),
            rmpv::Value::from("the scope summary text of this fixture"),
        ),
        (rmpv::Value::from("lang"), rmpv::Value::from("en")),
    ]);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &body).expect("encode the map body");
    vault
        .put_entity(
            &entity,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 7, end: 7 },
            9,
            &encoded,
        )
        .expect("map asset");
    vault
        .migrate_entity_text(
            &entity,
            &TextField::MapField("text".to_owned()),
            owner,
            &DocAuthorization::Owner(&proof),
        )
        .expect("the owner migrates the text field to a document");

    assert_issued_short_ref_resolves(&owner_memory(&vault), &entity);
}

#[test]
fn an_edited_document_row_resolves_by_its_issued_short_ref() {
    let (_directory, vault) = fresh_vault();
    let (owner, proof) = authenticated_owner(&vault);
    let entity = EntityId::now();
    vault
        .put_entity(
            &entity,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 7, end: 7 },
            9,
            b"short ref fixture text before the edit",
        )
        .expect("text asset");
    vault
        .migrate_entity_text(
            &entity,
            &TextField::Utf8Body,
            owner,
            &DocAuthorization::Owner(&proof),
        )
        .expect("the owner migrates the text to a document");
    let end = vault
        .entity_text(&entity)
        .expect("the migrated text")
        .chars()
        .count();
    vault
        .edit_entity_text(
            &entity,
            &[AnchoredEdit {
                actor: Some(owner),
                verb: EditVerb::ReplaceQuotedSpan {
                    span: vault
                        .entity_text_anchor(&entity, 0, end)
                        .expect("the whole text"),
                    text: "the edited short ref fixture text".to_owned(),
                },
            }],
            &DocAuthorization::Owner(&proof),
            2_000,
        )
        .expect("the owner edits the document text");

    assert_issued_short_ref_resolves(&owner_memory(&vault), &entity);
}

#[test]
fn an_atomically_committed_message_resolves_by_its_issued_short_ref() {
    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    let turn = witness_turn(&vault, "a committed message body");
    // The commit indexes the MESSAGE, then its document birth rewrites the
    // body to a pointer in the same transaction.
    memory
        .commit_message(&turn)
        .expect("the owner commits one MESSAGE");

    assert_issued_short_ref_resolves(&memory, &message_id(&turn));
}

#[test]
fn a_streamed_message_resolves_by_its_issued_short_ref() {
    let (_directory, vault) = fresh_vault();
    let memory = owner_memory(&vault);
    let turn = witness_turn(&vault, "");
    let handle = memory
        .begin_message_stream(&turn, Some(MessageWriteMode::Atomic))
        .expect("the owner opens a MESSAGE stream");
    memory
        .append_to_stream(handle, "a streamed message body")
        .expect("the stream takes text");
    // Finalizing lands the MESSAGE, its document birth and its parts.
    memory
        .finalize_stream(handle)
        .expect("the stream finalizes");

    assert_issued_short_ref_resolves(&memory, &handle.message_id());
}
