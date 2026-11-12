//! Engine doors whose CLAIM subject has no FACET of its own put that claim in
//! a stored FACET ([CLAIM-FACET-BIRTH-GATE-CENSUS]). `ClaimBody::new` stamps
//! the subject's derived substrate id, which is a stored FACET only for a
//! PERSON, so the CLAIM birth gate (#4389) refused every other subject with
//! `InvalidFacet`. A born claim now takes the vault default facet, or the
//! facet its subject record was born under; a PERSON subject keeps its own
//! substrate.
#![cfg(feature = "test-support")]

use oneiron::channel_identity_provider::{LineChat, LineChatKind};
use oneiron::code_revision::CodeSessionRun;
use oneiron::registry::{
    ENTITY_TYPE_ASSET, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN,
};
use oneiron::test_support::{bind_host_owner, provision_engine_machines, test_host_issuer};
use oneiron::{
    ClaimBody, EntityId, TimeRange, Vad, VadAnnotation, VadAnnotationSource, Vault, VaultConfig,
};
use rmpv::Value;

fn fresh_vault() -> (tempfile::TempDir, Vault) {
    let directory = tempfile::tempdir().expect("temporary vault");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("fresh vault");
    provision_engine_machines(&vault);
    let owner = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    bind_host_owner(&vault, &test_host_issuer(), owner).expect("owner host binding");
    (directory, vault)
}

fn stored_row(vault: &Vault, entity_type: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, entity_type, TimeRange { start: 5, end: 5 }, 5, body)
        .expect("fixture row");
    id
}

/// The claim stored at `claim`, after checking its scope facet is a stored
/// FACET.
fn claim_in_stored_facet(vault: &Vault, claim: &EntityId) -> ClaimBody {
    let body = vault
        .get_claim(claim)
        .expect("claim read")
        .expect("stored claim");
    assert_eq!(
        vault
            .get_entity_type(&body.scope_facet)
            .expect("facet read"),
        Some(ENTITY_TYPE_FACET),
        "the {} claim's scope facet is a stored FACET",
        body.predicate
    );
    body
}

fn default_facet(vault: &Vault) -> EntityId {
    vault.default_facet().expect("vault default facet")
}

#[test]
fn code_session_run_provenance_is_born_in_the_default_facet() {
    let (_directory, vault) = fresh_vault();
    let session = stored_row(&vault, ENTITY_TYPE_SESSION, b"code session");
    let actor = vault.ensure_embedded_owner_actor().expect("owner PERSON");
    let run = CodeSessionRun {
        session,
        actor,
        model: "model-a".to_owned(),
        prompt_hash: [1; 32],
        content_hash: [2; 32],
        params_hash: [3; 32],
        version: "1".to_owned(),
        diff_lineage_receipt: Value::Map(vec![(Value::from("diff"), Value::from("lineage"))]),
    };
    let claim = vault
        .record_code_session_run(&run, 11)
        .expect("a SESSION's run provenance is recorded");
    let body = claim_in_stored_facet(&vault, &claim);
    assert_eq!(body.scope_facet, default_facet(&vault));
}

#[test]
fn turn_vad_annotation_is_born_in_a_stored_facet() {
    let (_directory, vault) = fresh_vault();
    let turn = stored_row(&vault, ENTITY_TYPE_TURN, b"turn");
    let annotation = VadAnnotation::new(
        Vad {
            valence: 0.5,
            arousal: 0.6,
            dominance: 0.9,
        },
        VadAnnotationSource::UserSelfReport,
        12,
    )
    .expect("annotation");
    vault
        .annotate_turn_vad(&turn, annotation)
        .expect("a TURN is annotated");
    let annotations: Vec<EntityId> = vault
        .claims_for_subject(&turn)
        .expect("turn claim ids")
        .into_iter()
        .filter(|id| {
            vault
                .get_claim(id)
                .expect("claim read")
                .is_some_and(|body| body.predicate == "affect.vad")
        })
        .collect();
    assert_eq!(annotations.len(), 1, "one affect.vad claim on the TURN");
    claim_in_stored_facet(&vault, &annotations[0]);
}

#[test]
fn member_binding_on_a_non_person_member_is_born_in_the_default_facet() {
    let (_directory, vault) = fresh_vault();
    let member = stored_row(&vault, ENTITY_TYPE_ASSET, b"member");
    let person = stored_row(&vault, ENTITY_TYPE_PERSON, b"person");
    let claim = oneiron::federation::bind_member_person(
        &vault,
        member,
        person,
        TimeRange { start: 13, end: 13 },
        13,
    )
    .expect("a non-PERSON member is bound");
    let body = claim_in_stored_facet(&vault, &claim);
    assert_eq!(body.scope_facet, default_facet(&vault));
}

#[test]
fn member_binding_on_a_person_member_keeps_its_substrate() {
    let (_directory, vault) = fresh_vault();
    let member = stored_row(&vault, ENTITY_TYPE_PERSON, b"member");
    let person = stored_row(&vault, ENTITY_TYPE_PERSON, b"person");
    let claim = oneiron::federation::bind_member_person(
        &vault,
        member,
        person,
        TimeRange { start: 13, end: 13 },
        13,
    )
    .expect("a PERSON member is bound");
    let body = claim_in_stored_facet(&vault, &claim);
    assert_eq!(
        body.scope_facet,
        oneiron::claim::substrate_facet_id(member).expect("substrate id")
    );
}

#[test]
fn line_chat_observation_is_born_in_a_stored_facet() {
    let (_directory, vault) = fresh_vault();
    let chat = LineChat::new(LineChatKind::Group, format!("C{}", "1".repeat(32)));
    let claim = vault
        .observe_line_chat(
            &format!("U{}", "2".repeat(32)),
            &chat,
            "blob:line-event",
            14,
        )
        .expect("a LINE chat is observed");
    claim_in_stored_facet(&vault, &claim);
}

#[test]
fn dreamer_peer_binding_is_born_in_a_stored_facet() {
    let (_directory, vault) = fresh_vault();
    let dreamer = vault.dreamer_authority().expect("Dreamer authority");
    let claim = oneiron::edit_distance::register_peer_actor(&vault, 7, &dreamer)
        .expect("the Dreamer MACHINE is registered as a peer actor");
    claim_in_stored_facet(&vault, &claim);
}
