//! Stateless chat is not Memory::chat, agent chat, or an off-record room read.

use super::*;
use crate::llm::{BudgetExhaustionPolicy, BudgetGuard};
use crate::off_record::OffRecordBackendClass;
use crate::off_record::anonymous_chat::{
    AnonymousChatBlockReason, AnonymousChatResponder, AnonymousChatTarget, AnonymousChatTurn,
};
use crate::registry::ENTITY_TYPE_TURN;
use crate::temporal::TimeRange;

struct Responder {
    calls: Mutex<Vec<(AnonymousChatTarget, String)>>,
    answer: &'static str,
}

impl Responder {
    fn new(answer: &'static str) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            answer,
        }
    }
}

impl AnonymousChatResponder for Responder {
    fn respond<'a>(
        &'a self,
        target: AnonymousChatTarget,
        text: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String>> + Send + 'a>> {
        self.calls
            .lock()
            .expect("calls mutex")
            .push((target, text.to_owned()));
        Box::pin(async move { Ok(self.answer.to_owned()) })
    }
}

type AnonymousRows = Vec<(Vec<u8>, Vec<u8>)>;

fn base_rows(vault: &Vault) -> Result<Vec<AnonymousRows>> {
    let txn = vault.store.env.read_txn()?;
    let mut tables = Vec::new();
    for db in [
        &vault.store.entities,
        &vault.store.edges_out,
        &vault.store.edges_in,
        &vault.store.vectors,
        &vault.store.hnsw_neighbors,
        &vault.store.hnsw_meta,
        &vault.store.text_postings,
        &vault.store.text_meta,
        &vault.store.text_forward,
        &vault.store.text_bm25_field_stats,
        &vault.store.text_doc_field_lengths,
        &vault.store.vault_meta,
        &vault.store.ppr_cache,
        &vault.store.ppr_cache_deps,
        &vault.store.type_index,
        &vault.store.temporal_occurred_start,
        &vault.store.temporal_occurred_end,
        &vault.store.temporal_learned,
        &vault.store.temporal_long_intervals,
        &vault.store.phonetic_index,
        &vault.store.phonetic_forward,
        &vault.store.short_ids,
        &vault.store.short_ids_reverse,
        &vault.store.sync_queue,
        &vault.store.attempt_records,
        &vault.store.attempt_ready,
        &vault.store.attempt_dedupe,
    ] {
        let mut rows = Vec::new();
        for row in db.iter(&txn)? {
            let (key, value) = row?;
            rows.push((key.to_vec(), value.to_vec()));
        }
        tables.push(rows);
    }
    let mut sync_rows = Vec::new();
    for row in vault.store.sync_state.iter(&txn)? {
        let (key, value) = row?;
        sync_rows.push((key.as_bytes().to_vec(), value.to_vec()));
    }
    tables.push(sync_rows);
    Ok(tables)
}

#[test]
fn open_chat_close_has_no_vault_diff_and_no_memory_in_model_input() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    // Real base memory exists. The host model receives only the new turn.
    let id = crate::entity_id::EntityId::now();
    vault.put_entity(
        &id,
        ENTITY_TYPE_TURN,
        TimeRange { start: 10, end: 10 },
        10,
        b"private base memory needle",
    )?;
    let before = base_rows(&vault)?;
    let session = vault.open_anonymous_chat("stateless", OffRecordBackendClass::Local)?;
    let responder = Responder::new("model answer");
    let backend = CountingPolicyBackend::clean();
    let budget = BudgetGuard::with_reserve_units("anon", 100, 10, BudgetExhaustionPolicy::Suspend);
    for target in [
        AnonymousChatTarget::HouseMind,
        AnonymousChatTarget::PlainModel,
    ] {
        let result = block_on(session.chat(
            "one new question",
            target,
            &responder,
            &backend,
            &budget,
            &PolicyModelConfig::default(),
        ))?;
        assert!(
            matches!(result, AnonymousChatTurn::Reply { content, notices } if content == "model answer" && notices.is_empty())
        );
    }
    assert_eq!(
        responder.calls.lock().expect("calls mutex").as_slice(),
        &[
            (
                AnonymousChatTarget::HouseMind,
                "one new question".to_owned()
            ),
            (
                AnonymousChatTarget::PlainModel,
                "one new question".to_owned()
            ),
        ]
    );
    assert_eq!(backend.calls(), 0, "disabled policy calls no safeguard");
    let close = session.close()?;
    assert_eq!(close.turns_deleted, 0);
    assert_eq!(close.context_receipts_deleted, 0);
    assert_eq!(close.emit_receipts_deleted, 0);
    assert_eq!(close.promoted_turns_kept, 0);
    assert_eq!(
        base_rows(&vault)?,
        before,
        "no base entity, claim, telemetry, or receipt may change"
    );
    Ok(())
}

#[test]
fn policy_blocks_input_and_output_visibly_without_receipts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    put_policy_manifest_bytes(
        &vault,
        crate::entity_id::EntityId::now(),
        &spoiler_manifest("block"),
    )?;
    let before = base_rows(&vault)?;
    let session = vault.open_anonymous_chat("policy-stateless", OffRecordBackendClass::Local)?;
    let backend = CountingPolicyBackend::clean();
    let budget =
        BudgetGuard::with_reserve_units("anon-policy", 100, 10, BudgetExhaustionPolicy::Suspend);
    let responder = Responder::new("spoiler in model output");
    let input = block_on(session.chat(
        "spoiler in input",
        AnonymousChatTarget::HouseMind,
        &responder,
        &backend,
        &budget,
        &PolicyModelConfig::default(),
    ))?;
    let AnonymousChatTurn::Blocked {
        input: true,
        notice,
        ..
    } = input
    else {
        panic!("input must block")
    };
    assert_eq!(notice.notice_type, "policy_block");
    assert_eq!(notice.audience, "user_and_model");
    assert_eq!(notice.row_ref.as_deref(), Some("owner:spoilers"));
    assert!(
        notice.body.contains("owner:spoilers"),
        "the notice explains the matched policy row"
    );
    assert!(
        responder.calls.lock().expect("calls mutex").is_empty(),
        "blocked input never reaches model"
    );

    let output = block_on(session.chat(
        "ordinary question",
        AnonymousChatTarget::PlainModel,
        &responder,
        &backend,
        &budget,
        &PolicyModelConfig::default(),
    ))?;
    let AnonymousChatTurn::Blocked {
        input: false,
        notice: output_notice,
        ..
    } = output
    else {
        panic!("output must block")
    };
    assert_eq!(
        output_notice, notice,
        "both directions give the same explained shared notice"
    );
    assert_eq!(responder.calls.lock().expect("calls mutex").len(), 1);
    assert_eq!(session.close()?.promoted_turns_kept, 0);
    assert_eq!(
        base_rows(&vault)?,
        before,
        "a block must not file a gate decision"
    );
    Ok(())
}

#[test]
fn anonymous_human_hold_refuses_without_promising_a_queue() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let mut row = owner_row_with_action("owner:human", "Review this", "warn");
    let Value::Map(ref mut fields) = row else {
        unreachable!()
    };
    fields.push((Value::from("human"), Value::from("moderator:offline")));
    put_policy_manifest_bytes(
        &vault,
        crate::entity_id::EntityId::now(),
        &patterned_owner_manifest(
            vec![row],
            vec![owner_pattern(
                "human.pattern",
                "review-needed",
                "owner:human",
                Some("decide"),
            )],
        ),
    )?;
    let before = base_rows(&vault)?;
    let session = vault.open_anonymous_chat("human-hold", OffRecordBackendClass::Local)?;
    let responder = Responder::new("never sent");
    let backend = CountingPolicyBackend::clean();
    let budget =
        BudgetGuard::with_reserve_units("anon-hold", 10, 5, BudgetExhaustionPolicy::Suspend);
    let config = PolicyModelConfig {
        owner_hold_notice: Some("Review is queued".to_owned()),
        ..PolicyModelConfig::default()
    };
    let result = block_on(session.chat(
        "review-needed",
        AnonymousChatTarget::HouseMind,
        &responder,
        &backend,
        &budget,
        &config,
    ))?;
    let AnonymousChatTurn::Blocked {
        input: true,
        notice,
        preceding_notices,
        reason,
    } = result
    else {
        panic!("human row must refuse")
    };
    assert_eq!(reason, AnonymousChatBlockReason::HumanReviewUnavailable);
    assert!(preceding_notices.is_empty());
    assert_eq!(notice.notice_type, "policy_block");
    assert_eq!(notice.audience, "user_and_model");
    assert_eq!(notice.row_ref.as_deref(), Some("owner:human"));
    assert!(
        !notice.body.contains("queued"),
        "no phantom human review may be promised"
    );
    assert!(responder.calls.lock().expect("calls mutex").is_empty());
    assert!(vault.policy_holds(5)?.is_empty());
    session.close()?;
    assert_eq!(base_rows(&vault)?, before);
    Ok(())
}
