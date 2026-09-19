//! Exact revision consistency across facade recall, hydration, and document chat.
use super::*;

#[test]
fn recall_items_and_document_chat_keep_the_indexed_revision() {
    let (_dir, vault) = open_vault();
    let actor = put_person(&vault, 0x6A);
    let facade = facade_for(&vault, actor);
    let id = EntityId::from_bytes([0x6B; 16]).unwrap();
    let put = |content: &str| {
        let body =
            rmp_serde::to_vec_named(&serde_json::json!({"name": content, "content": content}))
                .unwrap();
        vault
            .batch()
            .put(
                &id,
                crate::registry::ENTITY_TYPE_EVENT,
                crate::TimeRange {
                    start: 1400,
                    end: 1400,
                },
                1400,
                &body,
            )
            .text(&id, &[("content", content)])
            .commit()
            .unwrap();
    };
    put("revisionanchor original evidence");
    let reference = vault.pinned_short_ref(&id).unwrap();
    put("replacement body unrelated");
    let pack = facade
        .recall(
            "revisionanchor",
            Effort::Medium,
            &RecallScope::default(),
            10,
            Some("json"),
            None,
        )
        .unwrap();
    assert_eq!(pack.items.len(), 1);
    assert_eq!(pack.items[0].short_id, reference);
    assert_eq!(pack.items[0].value_text, "revisionanchor original evidence");
    let rendered: serde_json::Value =
        serde_json::from_str(pack.rendered.as_ref().unwrap()).unwrap();
    assert!(
        rendered
            .to_string()
            .contains("revisionanchor original evidence")
    );
    let view = facade.hydrate(std::slice::from_ref(&reference)).unwrap();
    assert_eq!(view[0].short_ref.as_deref(), Some(reference.as_str()));
    let response = facade
        .chat(
            "what evidence",
            crate::memory::ChatDepth::Light,
            crate::memory::ChatOptions {
                scope: crate::memory::ChatScope::Documents {
                    source_short_ids: vec![reference.clone()],
                },
                limit: 10,
                format: Some("json"),
                lease: None,
                composer: None,
            },
        )
        .unwrap();
    let crate::memory::ChatResponse::Answered {
        source_short_ids,
        retrieval,
        ..
    } = response
    else {
        panic!("the pinned document must answer");
    };
    assert_eq!(source_short_ids, vec![reference.clone()]);
    assert_eq!(retrieval.items[0].short_id, reference);
    assert_eq!(
        facade.hydrate(&source_short_ids).unwrap()[0]
            .body
            .as_ref()
            .unwrap()["content"],
        serde_json::json!("revisionanchor original evidence")
    );
}
