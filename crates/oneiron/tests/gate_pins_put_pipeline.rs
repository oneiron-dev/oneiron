//! OPUS-T0-F gate pins, PR 3 (Engine task 12 Nov 19:38): green pins for six
//! put-pipeline write gates of OPUS-GATECENSUS's DEEP list
//! (census/GATE-CENSUS.md, class GAP-PASSES: real callers pass the gate
//! today, and no running test drove it from a door). Each test drives the
//! door a real caller uses, with that caller's input, through the gate, and
//! reads the write back. A pin that goes red is a live refusal of a real
//! caller (GAP-BROKEN).
//!
//! Each test name starts with its census ids, so `-- g429_` runs the pin of
//! G429 alone.
//!
//! - G17 `SavedRoomBirth::land` and G441 `put_saved_claim_in_txn`: the
//!   owner saves a claim staged in an off-record room
//!   (`vault.off_record.artifacts.save`); the claim lands with its birth.
//! - G427 `validate_facet_of_edge_at`: a scoped claim takes the FacetOf edge
//!   to the facet it was born in.
//! - G429 `admit_put` (use restriction): a record under the owner's legal
//!   hold is written again; a hold refuses deletes, not writes.
//! - G433 `validate_connector_manifest_put`: a fresh connector key
//!   registers (the previous-row arm has no public door).
//! - G435 `validate_note_birth_put`: a fresh NOTE is born (the
//!   identical-bytes re-put arm has no public door).
//!
//! `cargo test --locked -p oneiron --all-features --test gate_pins_put_pipeline`
//! (the lane's runner also sets `RUSTFLAGS="--cfg oneiron_test_support"`).
#![cfg(feature = "test-support")]

use std::sync::Arc;

use oneiron::claim::base_world_id;
use oneiron::connector_key::{ConnectorKeyRecord, ConnectorKeyStatus};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::LegalHoldTarget;
use oneiron::memory::{AllRelationships, ClaimRelationships, ClaimScope, ScopedClaimInput};
use oneiron::off_record::OffRecordBackendClass;
use oneiron::registry::{ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed, so a red
/// pin names its door and the refusal's own words.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

const fn range(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// An owned vault with a device keystore and install signing, its embedded
/// owner PERSON and that owner's proof, as the owner-verb fixtures open one
/// (`tests/agent_definition_proposed_change.rs`), and a legal hold store
/// outside the vault directory, where an owner's hold writes its sealed copy.
struct Owned {
    _dir: tempfile::TempDir,
    _holds: tempfile::TempDir,
    vault: Vault,
    actor: EntityId,
    owner: AuthenticatedOwner,
}

fn owned() -> TestResult<Owned> {
    let dir = tempfile::tempdir()?;
    let holds = tempfile::tempdir()?;
    let config = VaultConfig::device().with_legal_hold_store(holds.path().to_path_buf());
    let vault = Vault::open_owned(dir.path(), config).map_err(at("open owned"))?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .map_err(at("install signing"))?;
    let actor = vault
        .ensure_embedded_owner_actor()
        .map_err(at("embedded owner"))?;
    let owner = vault
        .authenticate_owner(actor, &actor.to_hex(), true, GateDecisionId::now())
        .map_err(at("owner proof"))?;
    Ok(Owned {
        _dir: dir,
        _holds: holds,
        vault,
        actor,
        owner,
    })
}

/// A row of `kind` named `name` at a fresh id.
fn named_row(vault: &Vault, kind: u8, name: &str) -> TestResult<EntityId> {
    let id = EntityId::now();
    let body = rmp_serde::to_vec_named(&json!({ "name": name }))?;
    vault
        .put_entity(&id, kind, range(1), 1, &body)
        .map_err(at("put a fixture row"))?;
    Ok(id)
}

/// The scoped claim the claim upsert door admits about `subject`, in
/// `facet` and `project`, as the facade facet fixture writes one
/// (`tests/consolidation_facade_facet.rs`).
fn scoped_claim(
    id: EntityId,
    subject: EntityId,
    facet: EntityId,
    project: EntityId,
) -> ScopedClaimInput {
    ScopedClaimInput {
        id: Some(id.to_hex()),
        predicate: "profile.hobby".to_owned(),
        subject_ref: subject.to_hex(),
        value: json!("gardening"),
        confidence: 1.0,
        source: "user_stated".to_owned(),
        scope: ClaimScope {
            world_id: base_world_id().to_hex(),
            scope_facet_id: facet.to_hex(),
            scope_relationship_id: ClaimRelationships::All(AllRelationships::All),
            scope_project_id: project.to_hex(),
        },
        sensitivity: None,
        evidence_turn_refs: Vec::new(),
        valid_from: None,
        valid_to: None,
        occurred_at: Some(1),
        learned_at: Some(1),
        salience: None,
    }
}

/// G17 and G441: the owner stages a claim in an off-record room and saves
/// it (`OffRecordSession::save_artifact_as`, the door of
/// `vault.off_record.artifacts.save`). The save puts the claim
/// (`put_saved_claim_in_txn`, G441) and then lands the birth the room staged
/// beside it (`SavedRoomBirth::land`, G17).
#[test]
fn g17_g441_the_owners_room_save_lands_a_claim_with_its_birth() -> TestResult {
    let fixture = owned()?;
    let vault = &fixture.vault;
    let facet = named_row(vault, ENTITY_TYPE_FACET, "gate pin facet")?;
    let project = named_row(vault, ENTITY_TYPE_EVENT, "gate pin project")?;
    let room = vault
        .off_record_session_vault()
        .enter("gate-pin-room", OffRecordBackendClass::Local)
        .map_err(at("enter the room"))?;
    let claim = EntityId::now();
    vault
        .memory(fixture.actor, EdgeActorClass::Human)
        .claim_upsert_in_session(&room, &scoped_claim(claim, fixture.actor, facet, project))
        .map_err(at("stage the room claim"))?;

    let outcome = room
        .save_artifact_as(&fixture.owner, &claim.to_hex())
        .map_err(at("the owner's room save"))?;
    assert!(
        outcome.replayed.contains(&claim),
        "the save names the claim: {:?}",
        outcome.replayed
    );
    let saved = vault
        .get_claim(&claim)
        .map_err(at("read the saved claim"))?
        .ok_or("the saved claim reads nothing")?;
    assert_eq!(saved.predicate, "profile.hobby");
    assert!(
        vault
            .row_birth(&claim)
            .map_err(at("read the saved birth"))?
            .is_some(),
        "the room's birth landed beside the claim"
    );
    Ok(())
}

/// G427: a claim admitted in a facet takes the FacetOf edge to that facet
/// through the public edge door (`Vault::put_edge`), the edge every born
/// row's producer writes. Only a FacetOf to a different facet is refused.
#[test]
fn g427_a_scoped_claim_takes_the_facet_of_edge_to_its_facet() -> TestResult {
    let fixture = owned()?;
    let vault = &fixture.vault;
    let facet = named_row(vault, ENTITY_TYPE_FACET, "gate pin facet")?;
    let project = named_row(vault, ENTITY_TYPE_EVENT, "gate pin project")?;
    let claim = EntityId::now();
    vault
        .memory(fixture.actor, EdgeActorClass::Human)
        .claim_upsert_scoped(&scoped_claim(claim, fixture.actor, facet, project))
        .map_err(at("admit the scoped claim"))?;
    assert_eq!(
        vault
            .get_claim(&claim)
            .map_err(at("read the claim"))?
            .ok_or("the claim reads nothing")?
            .scope_facet,
        facet
    );

    vault
        .put_edge(&claim, EdgeKind::FacetOf, &facet, 1.0)
        .map_err(at("the FacetOf edge put"))?;
    let edges = vault.edges_out(&claim).map_err(at("read the edges"))?;
    assert!(
        edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::FacetOf && edge.target == facet),
        "the claim's FacetOf edge names its facet: {edges:?}"
    );
    Ok(())
}

/// G429: the owner places a legal hold on a PERSON (`place_legal_hold`,
/// the door of the owner's legal-hold route), then the record is written
/// again. Every put meets the use-restriction check; a hold keeps the
/// record from deletion and leaves its writes alone.
#[test]
fn g429_a_record_under_legal_hold_is_written_again() -> TestResult {
    let fixture = owned()?;
    let vault = &fixture.vault;
    let id = named_row(vault, ENTITY_TYPE_PERSON, "held person")?;
    vault
        .place_legal_hold(
            &fixture.owner,
            vec![LegalHoldTarget::Record(id)],
            None,
            None,
        )
        .map_err(at("the owner's legal hold"))?;
    assert!(
        !vault
            .legal_holds(&fixture.owner)
            .map_err(at("read the holds"))?
            .is_empty(),
        "the hold stands"
    );

    let rewritten = rmp_serde::to_vec_named(&json!({ "name": "held person, renamed" }))?;
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, range(2), 2, &rewritten)
        .map_err(at("the held record's put"))?;
    assert_eq!(
        vault.get(&id).map_err(at("read the held record"))?,
        Some(rewritten)
    );
    Ok(())
}

/// G433: a host registers a fresh connector key for a person
/// (`Vault::register_connector_key`, as the counterparty shipping oracle
/// does). Its put meets the connector manifest check before it lands.
#[test]
fn g433_a_fresh_connector_key_registers() -> TestResult {
    let fixture = owned()?;
    let vault = &fixture.vault;
    let actor = named_row(vault, ENTITY_TYPE_PERSON, "connector person")?;
    let id = EntityId::now();
    vault
        .register_connector_key(
            &id,
            ConnectorKeyRecord::active("email", Some(actor), Vec::new(), 10),
        )
        .map_err(at("register the connector key"))?;
    let stored = vault
        .get_connector_key(&id)
        .map_err(at("read the connector key"))?
        .ok_or("the connector key reads nothing")?;
    assert_eq!(stored.connector, "email");
    assert_eq!(stored.actor_entity_ref, Some(actor));
    assert_eq!(stored.status, ConnectorKeyStatus::Active);
    Ok(())
}

/// G435: the owner writes a research NOTE (`Vault::create_note`, the door
/// of `vault.notes.create`). Its birth put meets the NOTE birth check before
/// it lands.
#[test]
fn g435_a_fresh_note_is_born() -> TestResult {
    let fixture = owned()?;
    let vault = &fixture.vault;
    let id = vault
        .create_note(
            "research",
            "an ordinary afternoon entry",
            WriteActor::new(fixture.actor, EdgeActorClass::Human),
        )
        .map_err(at("create the note"))?;
    let note = vault
        .read_note(&id)
        .map_err(at("read the note"))?
        .ok_or("the note reads nothing")?;
    assert_eq!(note.markdown, "an ordinary afternoon entry");
    Ok(())
}
