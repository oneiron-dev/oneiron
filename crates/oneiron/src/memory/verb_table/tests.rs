use super::*;
use serde_json::json;
use std::cell::Cell;

struct Counted<T> {
    inner: T,
    calls: Cell<usize>,
}
impl<T: FacadeTransport> FacadeTransport for Counted<T> {
    fn call(&self, verb: FacadeVerb, body: serde_json::Value) -> MemoryResult<serde_json::Value> {
        self.calls.set(self.calls.get() + 1);
        self.inner.call(verb, body)
    }
}

#[test]
fn typed_verbs_remember_forget_and_execute_reach_engine_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).expect("vault");
    let actor = vault.ensure_embedded_owner_actor().expect("owner");
    let memory = vault.memory(actor, crate::EdgeActorClass::Human);
    let client = FacadeClient(Counted {
        inner: &memory,
        calls: Cell::new(0),
    });
    let input: ClaimInput = serde_json::from_value(json!({
        "predicate":"profile.city", "subject_ref":actor.to_hex(), "value":"Kyoto",
        "confidence":1.0, "source":"user_stated", "occurred_at":100, "learned_at":100,
    }))
    .expect("input");
    let receipt = client.remember(&input).expect("remember");
    let active = memory
        .claim_list(&ClaimListFilter {
            subject_ref: Some(actor.to_hex()),
            predicate: Some("profile.city".into()),
            lifecycle: Some("active".into()),
            limit: 10,
        })
        .expect("active");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].value, json!("Kyoto"));
    assert_eq!(client.0.calls.get(), 1);
    let result = client
        .execute(&ExecuteRequest {
            calls: vec![FacadeRequest::ClaimList(ClaimListFilter {
                subject_ref: Some(actor.to_hex()),
                predicate: Some("profile.city".into()),
                lifecycle: Some("active".into()),
                limit: 10,
            })],
        })
        .expect("execute");
    let FacadeResponse::ClaimList(claims) = &result.results[0] else {
        panic!("typed result");
    };
    assert_eq!(claims[0].value, json!("Kyoto"));
    assert_eq!(client.0.calls.get(), 2);
    let forgotten = client
        .forget(&ForgetSelector {
            short_ref: Some(receipt.claim_short_id),
            subject_ref: None,
            predicate: None,
        })
        .expect("forget");
    assert_eq!(forgotten.len(), 1);
    let retracted = memory
        .claim_list(&ClaimListFilter {
            subject_ref: Some(actor.to_hex()),
            predicate: Some("profile.city".into()),
            lifecycle: Some("retracted".into()),
            limit: 10,
        })
        .expect("retracted");
    assert_eq!(retracted.len(), 1);
    let rejected = client
        .execute(&ExecuteRequest {
            calls: vec![FacadeRequest::Remember(input)],
        })
        .expect_err("cannot smuggle write");
    assert_eq!(rejected.code, MEMORY_CODE_BAD_REQUEST);
}

#[test]
fn builder_plans_are_lazy_and_each_run_has_one_real_host_call() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).expect("vault");
    let actor = vault.ensure_embedded_owner_actor().expect("owner");
    let memory = vault.memory(actor, crate::EdgeActorClass::Human);
    let client = FacadeClient(Counted {
        inner: &memory,
        calls: Cell::new(0),
    });
    let query = client.query_builder().text("no-such-data").limit(2);
    let pack = client.context_pack_builder().text("no-such-data").limit(2);
    assert_eq!(client.0.calls.get(), 0);
    assert!(query.run().expect("query").items.is_empty());
    assert_eq!(client.0.calls.get(), 1);
    pack.run().expect("pack");
    assert_eq!(client.0.calls.get(), 2);
}

#[test]
fn search_census_contains_every_callable_row_with_typed_documents() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).expect("vault");
    let actor = vault.ensure_embedded_owner_actor().expect("owner");
    let memory = vault.memory(actor, crate::EdgeActorClass::Human);
    let result = memory
        .search(&SearchRequest {
            query: String::new(),
            limit: Some(1000),
        })
        .expect("search");
    assert_eq!(result.len(), FacadeVerb::COUNT);
    for (row, verb) in result.iter().zip(FacadeVerb::ALL) {
        assert_eq!(row.wire, verb.wire_name());
        assert_eq!(FacadeVerb::parse_sdk(&row.sdk), Some(verb));
        assert!(!row.request_type.is_empty());
        // Each registered operation reaches its typed decoder, not a fallback.
        assert_eq!(
            dispatch_facade_verb(&memory, verb, json!(null))
                .expect_err("invalid DTO")
                .code,
            MEMORY_CODE_BAD_REQUEST
        );
    }
}

#[test]
fn campaign_dto_projection_preserves_owner_binding_and_cas() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = crate::Vault::open(dir.path(), crate::VaultConfig::default()).expect("vault");
    crate::campaign::register_crm_pack(&vault, 108, 109).expect("register CRM pack");
    let actor = vault.ensure_embedded_owner_actor().expect("owner");
    let memory = vault.memory(actor, crate::EdgeActorClass::Human);
    let client = FacadeClient(&memory);
    let created = client
        .campaign_create(&CampaignCreateRequest {
            name: "A campaign".into(),
            schema_version: None,
        })
        .expect("create");
    assert_eq!(created.definition.owner_actor, actor.to_hex());
    let read = client
        .campaign_read(&CampaignRefRequest {
            campaign_ref: created.campaign_ref.clone(),
        })
        .expect("read");
    assert!(read.found);
    assert_eq!(read.record.expect("record").definition.name, "A campaign");
    let archived = client
        .campaign_archive(&CampaignArchiveRequest {
            campaign_ref: created.campaign_ref,
            expected_definition_version: created.definition.definition_version,
        })
        .expect("archive");
    assert_eq!(archived.definition.lifecycle, "archived");
}
