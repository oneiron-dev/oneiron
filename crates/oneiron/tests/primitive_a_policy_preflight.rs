//! Primitive A, slice 6.4e (SLICE6-MAP row A; ENGINE CALL S64-5):
//! `vault.policy.preflight` with the act `read` says, per ref, whether the
//! caller's own read serves it. A readable ref carries its version and the
//! source-audience policies it reads under; a withheld ref carries nothing
//! but its id, no reason and no audience, and an absent id answers the same.
//!
//! Public paths only: the generated engine fn `oneiron::verbs::vault_policy_preflight`.

use oneiron::memory::{Memory, WitnessAssertions};
use oneiron::snapshot_read::{
    EvidenceSpansRequest, PolicyPreflight, PolicyPreflightAct, PolicyPreflightRef,
    PolicyPreflightRequest,
};
use oneiron::{
    EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WitnessAuthor, WitnessMessage,
    WitnessTurn,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn open() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

/// The owner witnesses one TURN of one MESSAGE row.
fn witnessed_turn(memory: &Memory<'_>) -> Result<EntityId, Box<dyn std::error::Error>> {
    let receipt = memory.witness(&WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: None,
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: None,
            author: WitnessAuthor::User,
            message_type: "dialogue".to_owned(),
            content: "a private line".to_owned(),
            parts: None,
            metadata: None,
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: 900,
        assertions: WitnessAssertions::default(),
    })?;
    Ok(receipt.turn_id)
}

fn preflight(
    memory: &Memory<'_>,
    refs: Vec<EntityId>,
) -> Result<PolicyPreflight, Box<dyn std::error::Error>> {
    Ok(oneiron::verbs::vault_policy_preflight(
        memory,
        PolicyPreflightRequest {
            refs,
            act: PolicyPreflightAct::Read,
        },
    )?
    .value)
}

#[test]
fn a_caller_learns_a_ref_it_may_not_read_is_withheld_and_nothing_more() -> TestResult {
    let (_dir, vault) = open()?;
    let owner_actor = vault.ensure_embedded_owner_actor()?;
    let owner = vault.memory(owner_actor, EdgeActorClass::Human);
    let turn = witnessed_turn(&owner)?;
    let absent = EntityId::now();
    let stranger = EntityId::now();
    vault.put_entity(
        &stranger,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a person with no grant",
    )?;

    // The owner reads the TURN: its version is the one a span read serves.
    let own = preflight(&owner, vec![turn, absent])?;
    assert_eq!(own.act, PolicyPreflightAct::Read);
    let PolicyPreflightRef::Readable {
        entity, version, ..
    } = &own.refs[0]
    else {
        return Err("the owner reads its own TURN".into());
    };
    assert_eq!(*entity, turn);
    let spans = oneiron::verbs::vault_evidence_spans(
        &owner,
        EvidenceSpansRequest {
            source: turn,
            version: None,
            ranges: Vec::new(),
        },
    )?
    .value;
    assert_eq!(spans.version.as_ref(), Some(version));
    assert_eq!(own.refs[1], PolicyPreflightRef::Withheld { entity: absent });

    // The stranger learns only that both refs are withheld: the TURN it may
    // not read answers as the id that does not exist, with no reason and no
    // audience.
    let theirs = preflight(
        &vault.memory(stranger, EdgeActorClass::Human),
        vec![turn, absent],
    )?;
    assert_eq!(
        theirs.refs,
        vec![
            PolicyPreflightRef::Withheld { entity: turn },
            PolicyPreflightRef::Withheld { entity: absent },
        ]
    );
    let json = serde_json::to_value(&theirs.refs[0])?;
    let mut keys: Vec<&str> = json
        .as_object()
        .ok_or("a ref answer is an object")?
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["entity", "status"]);
    Ok(())
}

#[test]
fn a_preflight_names_between_one_and_a_hundred_refs() -> TestResult {
    let (_dir, vault) = open()?;
    let owner = vault.memory(vault.ensure_embedded_owner_actor()?, EdgeActorClass::Human);
    assert!(preflight(&owner, Vec::new()).is_err());
    assert!(preflight(&owner, (0..101).map(|_| EntityId::now()).collect()).is_err());
    assert_eq!(
        preflight(&owner, (0..100).map(|_| EntityId::now()).collect())?
            .refs
            .len(),
        100
    );
    Ok(())
}
