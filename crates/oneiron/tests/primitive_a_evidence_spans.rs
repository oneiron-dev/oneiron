//! Primitive A, slice 6.4a (SLICE6-MAP row A): `vault.evidence.spans` serves
//! the exact bytes of a TURN's text through the caller's own scoped read,
//! with the MESSAGE-local slices each range covers and the source's version;
//! a source that moved since the version named serves no bytes, and a source
//! the caller does not read says nothing.
//!
//! Public paths only: the generated engine fn `oneiron::verbs::vault_evidence_spans`.

use oneiron::memory::{Memory, MemoryResult, WitnessAssertions};
use oneiron::snapshot_read::{
    EvidenceRange, EvidenceSourceStatus, EvidenceSpans, EvidenceSpansRequest, SourceVersion,
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

fn said(content: &str, order: u32) -> WitnessMessage {
    WitnessMessage {
        id: None,
        author: WitnessAuthor::User,
        message_type: "dialogue".to_owned(),
        content: content.to_owned(),
        parts: None,
        metadata: None,
        is_visible: true,
        order,
        quote: None,
    }
}

/// The owner witnesses one TURN of two MESSAGE rows, whose projected text is
/// `"hello there\nsecond line"`.
fn witnessed_turn(memory: &Memory<'_>) -> Result<EntityId, Box<dyn std::error::Error>> {
    let receipt = memory.witness(&WitnessTurn {
        conversation_ref: EntityId::now().to_hex(),
        turn_ref: None,
        thread_audience: None,
        messages: vec![said("hello there", 0), said("second line", 1)],
        occurred_at: 900,
        assertions: WitnessAssertions::default(),
    })?;
    Ok(receipt.turn_id)
}

fn spans(
    memory: &Memory<'_>,
    source: EntityId,
    version: Option<SourceVersion>,
    ranges: &[(u64, u64)],
) -> MemoryResult<EvidenceSpans> {
    let ranges = ranges
        .iter()
        .map(|&(start, end)| EvidenceRange { start, end })
        .collect();
    Ok(oneiron::verbs::vault_evidence_spans(
        memory,
        EvidenceSpansRequest {
            source,
            version,
            ranges,
        },
    )?
    .value)
}

#[test]
fn a_turn_serves_exact_spans_with_the_message_slices_they_cover() -> TestResult {
    let (_dir, vault) = open()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let turn = witnessed_turn(&memory)?;

    let answer = spans(&memory, turn, None, &[(6, 11), (12, 18)])?;
    assert_eq!(answer.status, EvidenceSourceStatus::Current);
    let version = answer.version.clone().expect("a read source has a version");
    assert_eq!(version.entity, turn);
    assert!(
        version.projection.is_some(),
        "a TURN's version pins the rows its text was projected from"
    );
    let texts: Vec<&str> = answer.spans.iter().map(|span| span.text.as_str()).collect();
    assert_eq!(texts, ["there", "second"]);
    let (first, second) = (&answer.spans[0].messages, &answer.spans[1].messages);
    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert_eq!((first[0].start, first[0].end), (6, 11));
    assert_eq!((second[0].start, second[0].end), (0, 6));
    assert_ne!(first[0].message, second[0].message);

    // No range reads the whole text; a range across the line break covers
    // both MESSAGE rows.
    let whole = spans(&memory, turn, None, &[])?;
    assert_eq!(whole.spans.len(), 1);
    assert_eq!(whole.spans[0].text, "hello there\nsecond line");
    let across = spans(&memory, turn, Some(version), &[(6, 18)])?;
    assert_eq!(across.status, EvidenceSourceStatus::Current);
    assert_eq!(across.spans[0].text, "there\nsecond");
    assert_eq!(across.spans[0].messages.len(), 2);

    // A range of only the line break names no words; one past the end and an
    // empty one are refused.
    assert!(spans(&memory, turn, None, &[(11, 12)]).is_err());
    assert!(spans(&memory, turn, None, &[(20, 40)]).is_err());
    assert!(spans(&memory, turn, None, &[(3, 3)]).is_err());
    Ok(())
}

#[test]
fn a_source_that_moved_since_its_version_serves_no_bytes() -> TestResult {
    let (_dir, vault) = open()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let person = EntityId::now();
    let at = TimeRange { start: 1, end: 1 };
    vault.put_entity(
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        at,
        1,
        b"first body",
    )?;

    let first = spans(&memory, person, None, &[])?;
    assert_eq!(first.status, EvidenceSourceStatus::Current);
    assert!(
        first.spans.is_empty(),
        "a row that is no TURN serves its version only"
    );
    let version = first.version.expect("a read source has a version");
    assert_eq!(version.projection, None);
    let again = spans(&memory, person, Some(version.clone()), &[])?;
    assert_eq!(again.status, EvidenceSourceStatus::Current);

    vault.put_entity(
        &person,
        oneiron::registry::ENTITY_TYPE_PERSON,
        at,
        2,
        b"second body",
    )?;
    let moved = spans(&memory, person, Some(version.clone()), &[])?;
    assert_eq!(moved.status, EvidenceSourceStatus::Moved);
    assert!(moved.spans.is_empty());
    assert_ne!(moved.version.as_ref(), Some(&version));

    // Byte ranges are served over a TURN's text only.
    assert!(spans(&memory, person, None, &[(0, 1)]).is_err());
    Ok(())
}

#[test]
fn a_caller_that_does_not_read_the_turn_learns_nothing_of_it() -> TestResult {
    let (_dir, vault) = open()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let turn = witnessed_turn(&vault.memory(owner, EdgeActorClass::Human))?;
    let stranger = EntityId::now();
    vault.put_entity(
        &stranger,
        oneiron::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a person with no grant",
    )?;

    let answer = spans(
        &vault.memory(stranger, EdgeActorClass::Human),
        turn,
        None,
        &[(0, 5)],
    )?;
    assert_eq!(answer.status, EvidenceSourceStatus::Withheld);
    assert_eq!(answer.version, None);
    assert!(answer.spans.is_empty());
    Ok(())
}
