//! Primitive A, slice 6.4a (SLICE6-MAP row A): `vault.evidence.spans` serves
//! the exact bytes of a TURN's text through the caller's own scoped read,
//! with the MESSAGE-local slices each range covers and the source's version;
//! a source that moved since the version named serves no bytes, and a source
//! the caller does not read says nothing.
//!
//! Public paths only: the generated engine fn `oneiron::verbs::vault_evidence_spans`.
//! The masked-spans test also seeds a lifted key through the test door
//! `oneiron::test_doors::lifted_text` (FIX-LIST
//! EVIDENCE-SPANS-MASKED-COORDINATES), so it runs only under
//! `--cfg oneiron_test_support`.

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

#[test]
fn a_bound_read_filter_narrows_the_words_a_turn_serves() -> TestResult {
    let (_dir, vault) = open()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let turn = witnessed_turn(&memory)?;

    // A filter that admits TURN rows only reads the TURN, but not the MESSAGE
    // rows its words come from: the source is withheld, never served.
    let turns_only = oneiron::memory::ReadFilterInput {
        entity_types: Some(std::collections::BTreeSet::from([
            oneiron::registry::ENTITY_TYPE_TURN,
        ])),
        ..oneiron::memory::ReadFilterInput::default()
    };
    let answer = spans(&memory.with_read_filter(Some(&turns_only)), turn, None, &[])?;
    assert_eq!(answer.status, EvidenceSourceStatus::Withheld);
    assert_eq!(answer.version, None);
    assert!(answer.spans.is_empty());
    Ok(())
}

/// A reader other than the owner whose secret sight is masked (lead 12:4x,
/// FIX-LIST EVIDENCE-SPANS-MASKED-COORDINATES): its spans over a TURN whose
/// text holds a lifted key are cut from the text as it reads it.
#[cfg(oneiron_test_support)]
mod masked {
    use super::{TestResult, open, said, spans};
    use oneiron::access_grant::{
        AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
    };
    use oneiron::federation::{Scope, ScopeAxis};
    use oneiron::memory::WitnessAssertions;
    use oneiron::snapshot_read::{
        EvidenceSourceStatus, SnapshotKind, SnapshotOpenRequest, SnapshotPageRequest,
    };
    use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, WitnessTurn, WriteActor};

    /// A PERSON who is not the owner, with the read-policy permit and one
    /// live grant over the messages of `conversation`.
    fn granted_reader(
        vault: &Vault,
        conversation: EntityId,
    ) -> Result<EntityId, Box<dyn std::error::Error>> {
        let reader = EntityId::now();
        vault.put_entity(
            &reader,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"a reader of one conversation",
        )?;
        vault.install_read_permit_for_test(WriteActor::new(reader, EdgeActorClass::Human))?;
        let mut authority_scope = Scope::top();
        authority_scope.verbs =
            ScopeAxis::Some(std::collections::BTreeSet::from(["read".to_owned()]));
        vault.create_access_grant(
            &EntityId::now(),
            &AccessGrant {
                authority_scope,
                principal_ref: reader,
                scope: AccessGrantScope::ConversationMessages {
                    conversation_ref: conversation,
                },
                capability: AccessGrantCapability::MessagesRead,
                status: AccessGrantStatus::Active,
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
                revoked_at: None,
                expires_at: None,
                companion_bounds: None,
            },
        )?;
        Ok(reader)
    }

    #[test]
    fn a_reader_other_than_the_owner_gets_spans_over_the_masked_text_it_reads() -> TestResult {
        let (_dir, vault) = open()?;
        let owner = vault.ensure_embedded_owner_actor()?;
        let conversation = EntityId::now();
        let secret = "locker-4471-quartz";
        let second = format!("the code is {secret} today");
        let turn = vault
            .memory(owner, EdgeActorClass::Human)
            .witness(&WitnessTurn {
                conversation_ref: conversation.to_hex(),
                turn_ref: None,
                thread_audience: None,
                messages: vec![said("hello there", 0), said(&second, 1)],
                occurred_at: 900,
                assertions: WitnessAssertions::default(),
            })?
            .turn_id;
        // The second MESSAGE's stored words keep the value; its mark makes
        // it a lifted key, read as `handle` by every reader but the owner.
        let handle =
            oneiron::test_doors::lifted_text::mark_lifted_key(&vault, turn, &second, secret)?;
        let reader = granted_reader(&vault, conversation)?;
        let theirs = vault.memory(reader, EdgeActorClass::Human);

        // The text this reader reads: `vault.snapshot.page`'s.
        let shown = format!("hello there\nthe code is {handle} today");
        let opened = oneiron::verbs::vault_snapshot_open(
            &theirs,
            SnapshotOpenRequest {
                kinds: vec![SnapshotKind::Turn],
                filter: None,
                lifetime_secs: None,
            },
        )?;
        let page = oneiron::verbs::vault_snapshot_page(
            &theirs,
            SnapshotPageRequest {
                handle: opened.handle,
                cursor: None,
                limit: None,
            },
        )?
        .value;
        let paged = page
            .rows
            .iter()
            .find(|row| row.version.entity == turn)
            .expect("the granted reader pages the TURN");
        assert_eq!(paged.text.as_deref(), Some(shown.as_str()));

        // A handle whose filter admits TURN rows only (review of #6983): the
        // TURN's words come from MESSAGE rows that filter withholds, so the
        // TURN is not served at all, and no row serves the value. Its spans
        // under the same filter are withheld.
        let turns_only = oneiron::memory::ReadFilterInput {
            entity_types: Some(std::collections::BTreeSet::from([
                oneiron::registry::ENTITY_TYPE_TURN,
            ])),
            ..oneiron::memory::ReadFilterInput::default()
        };
        let narrowed = oneiron::verbs::vault_snapshot_open(
            &theirs,
            SnapshotOpenRequest {
                kinds: vec![SnapshotKind::Turn],
                filter: Some(turns_only.clone()),
                lifetime_secs: None,
            },
        )?;
        let narrowed = oneiron::verbs::vault_snapshot_page(
            &theirs,
            SnapshotPageRequest {
                handle: narrowed.handle,
                cursor: None,
                limit: None,
            },
        )?
        .value;
        assert!(narrowed.rows.iter().all(|row| row.version.entity != turn));
        assert!(
            !narrowed
                .rows
                .iter()
                .any(|row| row.text.as_deref().is_some_and(|text| text.contains(secret)))
        );
        let withheld = spans(&theirs.with_read_filter(Some(&turns_only)), turn, None, &[])?;
        assert_eq!(withheld.status, EvidenceSourceStatus::Withheld);
        assert!(withheld.spans.is_empty());

        // The whole text: the masked one, never the value.
        let whole = spans(&theirs, turn, None, &[])?;
        assert_eq!(whole.status, EvidenceSourceStatus::Current);
        assert!(whole.masked);
        assert_eq!(whole.spans.len(), 1);
        assert_eq!(whole.spans[0].text, shown);
        assert!(!whole.spans[0].text.contains(secret));

        // A range indexes into that text, and its MESSAGE slice into the
        // MESSAGE's masked words.
        let at = u64::try_from(shown.find(&handle).expect("the handle is shown"))?;
        let end = at + u64::try_from(handle.len())?;
        let exact = spans(&theirs, turn, None, &[(at, end)])?;
        assert!(exact.masked);
        assert_eq!(exact.spans[0].text, handle);
        let slices = &exact.spans[0].messages;
        assert_eq!(slices.len(), 1);
        let in_message = u64::try_from("the code is ".len())?;
        assert_eq!(
            (slices[0].start, slices[0].end),
            (in_message, in_message + u64::try_from(handle.len())?)
        );
        let after = spans(&theirs, turn, None, &[(end + 1, end + 6)])?;
        assert_eq!(after.spans[0].text, "today");

        // A range with its ends inside the handle widens to the handle.
        let inside = spans(&theirs, turn, None, &[(at + 2, end - 1)])?;
        assert_eq!((inside.spans[0].start, inside.spans[0].end), (at, end));
        assert_eq!(inside.spans[0].text, handle);

        // The owner's spans are the stored text's.
        let owners = spans(&vault.memory(owner, EdgeActorClass::Human), turn, None, &[])?;
        assert!(!owners.masked);
        assert_eq!(owners.spans[0].text, format!("hello there\n{second}"));
        let stored_at = u64::try_from("hello there\nthe code is ".len())?;
        let stored_end = stored_at + u64::try_from(secret.len())?;
        let value = spans(
            &vault.memory(owner, EdgeActorClass::Human),
            turn,
            None,
            &[(stored_at, stored_end)],
        )?;
        assert!(!value.masked);
        assert_eq!(value.spans[0].text, secret);
        Ok(())
    }
}
