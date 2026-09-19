use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::ingest::{INGEST_SOURCE_REGISTRY, KNOWN_INGEST_HARNESS_CONFIG};

fn parse(source: &str, value: Value) -> ParsedImport {
    INGEST_SOURCE_REGISTRY
        .get(source)
        .unwrap()
        .parse_import(&value.to_string(), 100)
        .unwrap()
}

#[test]
fn platform_exports_converge_without_losing_content_or_time() {
    let fixtures = [
        (
            "chatgpt",
            serde_json::json!([{"id":"thread", "mapping":{"node":{"message":{"id":"m","author":{"role":"user"},"create_time":12.5,"content":{"parts":["first","second"]}}}}}]),
        ),
        (
            "claude",
            serde_json::json!([{"uuid":"thread", "chat_messages":[{"uuid":"m","sender":"human","created_at":"1970-01-01T00:00:12Z","text":"first\nsecond"}]}]),
        ),
        (
            "gemini",
            serde_json::json!([{"id":"m","title":"first\nsecond","time":"1970-01-01T00:00:12Z"}]),
        ),
    ];
    for (source, fixture) in fixtures {
        let imported = parse(source, fixture);
        let message = &imported.messages[0];
        assert_eq!(message.platform_source, source);
        assert_eq!(message.message_id, "m");
        assert_eq!(message.content, "first\nsecond");
        assert_eq!(message.occurred_at, Some(12));
        assert_eq!(message.recorded_at, 100);
        assert_eq!(imported.normalized.records[0].text, message.content);
        assert!(imported.normalized.claims.is_empty());
        let wire = serde_json::to_value(message).unwrap();
        assert_eq!(wire["platformSource"], source);
        assert_eq!(
            serde_json::from_value::<ParsedMessage>(wire).unwrap(),
            *message
        );
    }
}

#[test]
fn character_card_log_directory_markdown_and_knowledge_have_distinct_targets() {
    let card = parse(
        "sillytavern",
        serde_json::json!({"spec":"chara_card_v2","data":{"name":"Companion","description":"A fictional character","personality":"patient"}}),
    );
    assert_eq!(card.normalized.claims[0].predicate, "companion.persona");
    assert!(card.messages[0].character_card.is_some());
    let log = INGEST_SOURCE_REGISTRY.get("sillytavern").unwrap().parse_import(
        "{\"user_name\":\"Owner\",\"chat_metadata\":{}}\n{\"name\":\"Owner\",\"is_user\":true,\"mes\":\"hello\"}", 100).unwrap();
    assert_eq!(log.messages[0].role, "user");
    assert_eq!(log.normalized.records[0].text, "hello");
    for source in ["claude-code", "codex", "hermes", "openclaw"] {
        let memory = parse(
            source,
            serde_json::json!({"files":[{"path":"memory/MEMORY.md","content":"# Remember\nOriginal text"}]}),
        );
        assert_eq!(
            memory.normalized.records[0].text,
            "# Remember\nOriginal text"
        );
        assert_eq!(memory.messages[0].platform_source, source);
        assert!(
            INGEST_SOURCE_REGISTRY
                .get(source)
                .unwrap()
                .normalize(r#"{"files":[{"path":"../secret","content":"bad"}]}"#)
                .is_err()
        );
    }
    let markdown = INGEST_SOURCE_REGISTRY
        .get("markdown")
        .unwrap()
        .normalize("# Title\n\n  exact spacing")
        .unwrap();
    assert_eq!(markdown.records[0].text, "# Title\n\n  exact spacing");
    let knowledge = parse(
        "okf",
        serde_json::json!({"concepts":[{"id":"c","predicate":"profile.name","value":"A","approval":"auto","source":"user_stated"}],"resources":[{"uri":"https://example.test/person"}]}),
    );
    assert_eq!(knowledge.normalized.claims.len(), 1);
    assert_eq!(knowledge.resource_uris, ["https://example.test/person"]);
    assert_eq!(
        INGEST_SOURCE_REGISTRY
            .get_config("okf")
            .unwrap()
            .trust_ceiling
            .claim_source,
        ClaimSource::Imported
    );
    assert_eq!(
        INGEST_SOURCE_REGISTRY
            .get_config("okf")
            .unwrap()
            .default_admission,
        ClaimApprovalStatus::Proposed
    );
}

#[test]
fn memory_archives_keep_history_as_records_not_new_entity_types() {
    let fixtures = [
        (
            "letta",
            serde_json::json!({"agents":[{"id":"a","messages":[{"id":"1","role":"user","text":"old"},{"id":"2","role":"assistant","text":"new"}]}]}),
        ),
        (
            "zep",
            serde_json::json!({"sessions":[{"session_id":"s","messages":[{"id":"1","role":"user","content":"old"},{"id":"2","role":"assistant","content":"new"}]}]}),
        ),
        (
            "mem0",
            serde_json::json!({"memories":[{"id":"1","memory":"new","history":[{"id":"2","old_memory":"earlier","new_memory":"old"}]}]}),
        ),
    ];
    for (source, fixture) in fixtures {
        let imported = parse(source, fixture);
        assert_eq!(imported.normalized.records.len(), 2);
        let texts: BTreeSet<_> = imported
            .normalized
            .records
            .iter()
            .map(|r| r.text.as_str())
            .collect();
        assert_eq!(texts, BTreeSet::from(["old", "new"]));
        assert!(imported.normalized.entities.is_empty());
        assert!(imported.normalized.claims.is_empty());
    }
}

#[test]
fn registry_parity_all_export_adapters_are_imported_and_fail_closed() {
    let expected = [
        "chatgpt",
        "claude",
        "gemini",
        "sillytavern",
        "claude-code",
        "codex",
        "hermes",
        "openclaw",
        "markdown",
        "okf",
        "letta",
        "zep",
        "mem0",
    ];
    let actual: BTreeSet<_> = INGEST_SOURCE_REGISTRY
        .source_configs()
        .filter(|c| c.format == crate::ingest::IngestSourceFormat::NativeExport)
        .map(|c| c.source_id)
        .collect();
    assert_eq!(actual, BTreeSet::from(expected));
    for source in expected {
        let config = INGEST_SOURCE_REGISTRY.get_config(source).unwrap();
        assert_eq!(Some(config), KNOWN_INGEST_HARNESS_CONFIG.get_config(source));
        assert!(config.adapter_skill.is_some());
        assert_eq!(config.trust_ceiling.claim_source, ClaimSource::Imported);
        assert_eq!(config.default_admission, ClaimApprovalStatus::Proposed);
        for sensitivity in [None, Some(0), Some(4)] {
            assert!(!config.trust_ceiling.permits_auto(sensitivity));
        }
    }
    assert!(
        INGEST_SOURCE_REGISTRY
            .get("claude")
            .unwrap()
            .normalize(r#"[{"chat_messages":[{"role":"owner","text":"x"}]}]"#)
            .is_err()
    );
    assert!(INGEST_SOURCE_REGISTRY.get("chatgpt").unwrap().normalize(r#"[{"mapping":{"x":{"message":{"id":"same","text":"a"}},"y":{"message":{"id":"same","text":"b"}}}}]"#).is_err());
}
