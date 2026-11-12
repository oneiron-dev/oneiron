use oneiron::claim::{base_world_id, default_project_id, substrate_facet_id};
use oneiron::memory::{ClaimListFilter, Memory};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::{Value, json};

fn fresh_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("create a fresh vault directory");
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = None;
    let vault = Vault::open_owned(directory.path(), config).expect("open a fresh owned vault");
    (directory, vault)
}

fn claim_input(memory: &Memory<'_>, subject_ref: &str) -> Value {
    json!({
        "predicate": "inventory.crate_contents",
        "subject_ref": subject_ref,
        "value": "The copied crate contains a sapphire prism.",
        "confidence": 0.9,
        "source": "user_stated",
        "scope": {
            "world_id": base_world_id().to_hex(),
            "scope_facet_id": substrate_facet_id(memory.actor())
                .expect("derive the writer's substrate facet")
                .to_hex(),
            "scope_relationship_id": "all",
            "scope_project_id": default_project_id().to_hex()
        }
    })
}

fn assert_invented_subject(memory: &Memory<'_>, subject_ref: &str) {
    let error = oneiron::verbs::invoke(
        memory,
        "vault.claims.upsert",
        claim_input(memory, subject_ref),
    )
    .expect_err("an unknown or unreadable subject must refuse the claim write");
    assert_eq!(error.code, "INVENTED_REFERENCE", "subject {subject_ref}");
    assert_eq!(
        error.message,
        "the record named at `/subject_ref` does not resolve for this writer; the write was refused and the refusal receipted",
        "subject {subject_ref}"
    );
}

#[test]
fn a_claim_names_the_owners_fresh_research_note_as_its_subject() {
    let (_directory, vault) = fresh_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("ensure the vault owner");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let markdown = "The copied crate contains a sapphire prism.";
    let note = memory
        .create_note("research", markdown)
        .expect("create the owner's research NOTE through the public facade path");

    let written = oneiron::verbs::invoke(
        &memory,
        "vault.claims.upsert",
        claim_input(&memory, &note.id_hex),
    )
    .unwrap_or_else(|error| {
        panic!(
            "owner's fresh research NOTE must resolve as /subject_ref; got {}: {}",
            error.code, error.message
        )
    });

    let claims = memory
        .claim_list(&ClaimListFilter {
            predicate: Some("inventory.crate_contents".to_owned()),
            limit: 10,
            ..Default::default()
        })
        .expect("read back the written claim")
        .value;
    assert_eq!(claims.len(), 1, "the NOTE-subject claim must be stored");
    assert_eq!(claims[0].subject_ref, note.id_hex);
    assert_eq!(claims[0].value, json!(markdown));
    assert_eq!(claims[0].source.as_deref(), Some("user_stated"));
    assert_eq!(
        written["claim_short_id"],
        json!(claims[0].short_ref.as_deref().expect("claim short ref"))
    );

    let read_note = memory
        .get_entity(&note.id_hex)
        .expect("read the admitted NOTE's live projection")
        .value
        .expect("the owner's NOTE must remain readable");
    assert_eq!(read_note.id_hex, note.id_hex);
    assert_eq!(read_note.kind, "NOTE");
    assert_eq!(
        read_note.body.expect("the NOTE must have a live body")["markdown"],
        json!(markdown)
    );
}

#[test]
fn a_claim_naming_an_unknown_id_is_still_refused_as_invented() {
    let (_directory, vault) = fresh_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("ensure the vault owner");
    let memory = vault.memory(owner, EdgeActorClass::Human);
    // A fresh id: [0xA1; 16]..[0xA6; 16] hold the seeded system agents.
    let unknown_id = EntityId::now().to_hex();
    assert_eq!(
        memory
            .get_entity(&unknown_id)
            .expect("a well-formed unknown id must read as absent")
            .value
            .map(|entity| entity.kind),
        None
    );
    assert_invented_subject(&memory, &unknown_id);
}

#[test]
fn a_claim_naming_another_actors_private_note_is_still_refused_as_invented() {
    let (_directory, vault) = fresh_vault();
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("ensure the vault owner");
    let owner_memory = vault.memory(owner, EdgeActorClass::Human);
    let note = owner_memory
        .create_note("diary", "A private entry that the owner did not share.")
        .expect("create the owner's private diary NOTE");
    let reader = vault
        .ensure_agent_principal("note-subject-reader")
        .expect("ensure a different live reader");
    assert_ne!(reader, owner);
    let reader_memory = vault.memory(reader, EdgeActorClass::Agent);
    assert_eq!(
        reader_memory
            .get_entity(&note.id_hex)
            .expect("an unreadable NOTE must read as absent")
            .value
            .map(|entity| entity.kind),
        None
    );
    assert_invented_subject(&reader_memory, &note.id_hex);
}
