//! Rerank blocks, Hyde recall, session staging, and stale-world federation.

use super::*;

// ===== RET-010 (ONE-1292) host-injected rerank hook =====

/// Scores candidates ascending by engine rank, so the rerank order is the
/// exact reversal of the engine block order.
pub(super) struct ReversingReranker;

impl Reranker for ReversingReranker {
    fn id(&self) -> &str {
        "test/reranker-reversing@v1"
    }

    fn rerank(&self, _query: &str, candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        Ok((0..candidates.len()).map(|index| index as f32).collect())
    }
}

// ===== EMB-2 (ONE-1334) funnel fork-hash segments =====

#[derive(Default)]
struct CountingErroringReranker {
    calls: std::sync::Mutex<usize>,
}

impl Reranker for CountingErroringReranker {
    fn id(&self) -> &str {
        "test/reranker-counting-erroring@v1"
    }

    fn rerank(&self, _query: &str, _candidates: &[RerankCandidate<'_>]) -> Result<Vec<f32>> {
        *self.calls.lock().unwrap() += 1;
        Err(Error::InvalidConfig(
            "reranker must not run on an empty block".to_owned(),
        ))
    }
}

/// Qodo #472-F3: an empty rerank block is a semantic no-op — the host impl
/// must never be invoked, so an otherwise-empty retrieval cannot fail
/// solely on reranker behavior.
#[test]
fn rerank_skips_empty_block_without_invoking_reranker() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_text(&vault, entity_id(0xE8), "indexed but unrelated")?;

    let reranker = CountingErroringReranker::default();
    let results = vault
        .query()
        .search_text("zeromatch query tokens", 10)
        .limit(10)
        .rerank(&reranker, RerankOptions::default())
        .run()?;

    assert!(results.is_empty(), "the retrieval itself is empty");
    assert_eq!(
        *reranker.calls.lock().unwrap(),
        0,
        "the reranker must never be invoked on an empty block"
    );
    Ok(())
}

/// K10: a session pipeline run's telemetry row lands IN THE ROOM.
///
/// The session arm STAGES its row through the room's registration door, and
/// overlay staging refuses without an active txn segment — so an arm that
/// opens only a base write txn fails on every call. This asserts the ROW
/// exists rather than that the run succeeded: with no row, the K8 pre-close
/// census counts zero context receipts and an in-room caller cannot see its
/// own runs.
#[test]
fn a_session_pipeline_run_stages_its_telemetry_row_in_the_room() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    put_text(&vault, entity_id(0x9A), "sessiontelemetryneedle")?;

    let session = vault.off_record_session_vault().enter(
        "sess-pipeline-telemetry",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    let base_runs_before = vault.retrieval_runs(16)?.len();

    let route = session.write_route()?;
    let door = session.retrieval_telemetry(&route)?;
    let telemetry = vault
        .query()
        .search_text("sessiontelemetryneedle", 10)
        .in_session(&door)
        .run_with_telemetry()?;
    let run_id = telemetry
        .run_id
        .expect("a session run registers its telemetry row");

    {
        let view = session.read_view()?;
        let rtxn = vault.store.env.read_txn()?;
        let rows = view.retrieval_runs_in_txn(&rtxn, 16)?;
        assert!(
            rows.iter().any(|row| row.run_id == run_id),
            "the run row is readable through the room's composed view"
        );
    }
    assert_eq!(
        vault.retrieval_runs(16)?.len(),
        base_runs_before,
        "a session run adds ZERO base telemetry rows"
    );

    drop(door);
    session.close()?;
    Ok(())
}

fn person_name_body(name: &str) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
    )
    .expect("encode person name");
    body
}

fn put_indexed_person(vault: &Vault, id: EntityId, name: &str) -> Result<()> {
    vault
        .batch()
        .put(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &person_name_body(name),
        )
        .text(&id, &[("name", name)])
        .commit()
}

fn restage_room_person(
    session: &crate::off_record::OffRecordSession<'_>,
    id: EntityId,
    name: &str,
) -> Result<()> {
    use crate::session_overlay::{JournalEntry, JournalRole, JournalScope};

    let route = session.write_route()?;
    let conversation = session.overlay_conversation_shell()?;
    let occurred = TimeRange { start: 2, end: 2 };
    let entry = JournalEntry {
        scope: JournalScope::new(conversation, id),
        role: JournalRole::TurnOwnedArtifact,
        occurred,
        learned_at: 2,
        source_run: None,
        op: crate::batch::BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_PERSON,
            occurred,
            learned_at: 2,
            row_version: None,
            data: person_name_body(name),
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        },
    };
    session.overlay_write_routed(&route, |wtxn, apply| apply(wtxn, entry))
}

#[test]
fn a_room_put_only_restage_publishes_its_revision_at_once() -> Result<()> {
    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x9B);
    put_indexed_person(&vault, id, "Owen Marsh")?;
    let old_codes = crate::batch::generate_phonetic_codes("Owen Marsh");
    let new_codes = crate::batch::generate_phonetic_codes("Yuki Tanaka");
    let old_refs: Vec<_> = old_codes.iter().map(String::as_str).collect();
    let new_refs: Vec<_> = new_codes.iter().map(String::as_str).collect();
    assert!(
        vault
            .query()
            .search_phonetic(&old_refs)
            .run()?
            .iter()
            .any(|row| row.id == id),
        "base holds the old name codes"
    );
    assert!(
        vault
            .query()
            .search_text("Marsh", 10)
            .run()?
            .iter()
            .any(|row| row.id == id),
        "base holds the old name text"
    );

    let session = vault.off_record_session_vault().enter(
        "sess-put-only-restage",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    restage_room_person(&session, id, "Yuki Tanaka")?;
    {
        let view = session.read_view()?;
        let rtxn = vault.store.env.read_txn()?;
        let record = crate::ports::EntityStoreRead::port_entity_record(&view, &rtxn, &id)?
            .expect("room holds the restaged person");
        let body = rmpv::decode::read_value(&mut std::io::Cursor::new(record.body))
            .expect("decode room person");
        let name = body
            .as_map()
            .expect("person body is a map")
            .iter()
            .find(|(key, _)| key.as_str() == Some("name"))
            .and_then(|(_, value)| value.as_str());
        assert_eq!(name, Some("Yuki Tanaka"));
        drop(rtxn);
        assert!(
            !vault
                .query()
                .reading(view.read())
                .search_phonetic(&old_refs)
                .run()?
                .iter()
                .any(|row| row.id == id),
            "the old name codes stop answering as soon as the Put lands"
        );
        assert!(
            vault
                .query()
                .reading(view.read())
                .search_phonetic(&new_refs)
                .run()?
                .iter()
                .any(|row| row.id == id),
            "the new name codes answer without a Text apply"
        );
        assert!(
            !vault
                .query()
                .reading(view.read())
                .search_text("Marsh", 10)
                .run()?
                .iter()
                .any(|row| row.id == id),
            "the old name text stops answering"
        );
        assert!(
            vault
                .query()
                .reading(view.read())
                .search_text("Tanaka", 10)
                .run()?
                .iter()
                .any(|row| row.id == id),
            "the live body's name text answers at once"
        );
    }
    session.close()?;
    Ok(())
}

#[test]
fn a_room_restage_with_its_text_keeps_the_text_it_sent() -> Result<()> {
    use crate::session_overlay::{JournalEntry, JournalRole, JournalScope};

    let (_dir, vault) = open_test_vault();
    let id = entity_id(0x9C);
    put_indexed_person(&vault, id, "Owen Marsh")?;
    let session = vault.off_record_session_vault().enter(
        "sess-restage-with-text",
        crate::off_record::OffRecordBackendClass::Local,
    )?;
    restage_room_person(&session, id, "Yuki Tanaka")?;
    let route = session.write_route()?;
    let entry = JournalEntry {
        scope: JournalScope::new(session.overlay_conversation_shell()?, id),
        role: JournalRole::TurnOwnedArtifact,
        occurred: TimeRange { start: 2, end: 2 },
        learned_at: 2,
        source_run: None,
        op: crate::batch::BatchOp::Text {
            id,
            fields: vec![("name".to_owned(), "Yuki Tanaka".to_owned())],
        },
    };
    session.overlay_write_routed(&route, |wtxn, apply| apply(wtxn, entry))?;
    {
        let view = session.read_view()?;
        assert!(
            vault
                .query()
                .reading(view.read())
                .search_text("Tanaka", 10)
                .run()?
                .iter()
                .any(|row| row.id == id),
            "the following Text apply keeps its own name postings"
        );
        assert!(
            !vault
                .query()
                .reading(view.read())
                .search_text("Marsh", 10)
                .run()?
                .iter()
                .any(|row| row.id == id),
            "the following Text apply removes the old name postings"
        );
    }
    session.close()?;
    Ok(())
}
