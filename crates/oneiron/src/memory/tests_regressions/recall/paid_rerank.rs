// Recall at high, xhigh and max through a host's reranker
// (`memory/recall/paid.rs`): its scores apply only to the words they were
// given.

/// A host reranker that scores each document with `score(call, text)` and
/// runs `during(call)` first, as a write landing while a model scores would.
struct ScriptedReranker<'a> {
    lease: crate::llm::BudgetLease,
    calls: std::sync::atomic::AtomicUsize,
    score: &'a (dyn Fn(usize, &str) -> f32 + Sync),
    during: &'a (dyn Fn(usize) + Sync),
}

impl crate::memory::RecallRerankHost for ScriptedReranker<'_> {
    fn lease(&self) -> &crate::llm::BudgetLease {
        &self.lease
    }

    fn score(
        &self,
        _query: &str,
        documents: &[crate::memory::RerankDocument<'_>],
        _answer_at: Option<std::time::Instant>,
    ) -> MemoryResult<crate::memory::RerankScores> {
        let call = self
            .calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        (self.during)(call);
        Ok(crate::memory::RerankScores {
            scores: documents
                .iter()
                .map(|document| (self.score)(call, document.text))
                .collect(),
            model: "test/reranker@v1".to_owned(),
            served_model: None,
        })
    }
}

/// Done-means (G1 check 4) at the engine's recall door: a turn whose message
/// is edited while its block is scored, past the words its item shows, takes
/// none of the first call's scores. The block is scored again, and the turn
/// is served at the words its second score is for. Sol round 2 (R2-3) asked
/// that the scores bind a row's words, not only its id, score and rank; the
/// edit here moves those too (it binds its actor with a claim that joins the
/// block), so the round-1 door refused the stale block as well.
#[cfg(feature = "sync")]
#[test]
fn a_turn_edited_while_it_is_scored_takes_none_of_the_stale_scores() {
    use crate::entity_doc::{AnchoredEdit, DocAuthorization, EditVerb, TextField};
    // Longer than an item shows, so only the words past it change.
    let shown = "the lantern hangs in the attic. ".repeat(20);
    let first = format!("{shown}brass hook");
    let reordered = format!("{shown}hook brass");
    let (_dir, vault) = open_embedding_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let facade = facade_for(&vault, owner);
    let edited = witness_turn(&facade, 0xE1, &[first.as_str()], 1_900);
    witness_turn(&facade, 0xE2, &["a lantern shop that sells wicks"], 1_900);
    let message = first_message(&vault, &edited);
    let actor = crate::write_envelope::WriteActor::new(owner, EdgeActorClass::Human);
    let authenticated = vault
        .authenticate_owner(
            owner,
            "principal:paid-rerank-test",
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner");
    let authorization = DocAuthorization::Owner(&authenticated);
    vault
        .migrate_entity_text(
            &message,
            &TextField::MapField("content".into()),
            actor,
            &authorization,
        )
        .expect("move the message's text into its document");
    let during = |call: usize| {
        if call != 1 {
            return;
        }
        let end = vault.entity_text(&message).expect("text").chars().count();
        let whole = vault.entity_text_anchor(&message, 0, end).expect("anchor");
        vault
            .edit_entity_text(
                &message,
                &[AnchoredEdit {
                    actor: Some(actor),
                    verb: EditVerb::ReplaceQuotedSpan {
                        span: whole,
                        text: reordered.clone(),
                    },
                }],
                &authorization,
                2_000,
            )
            .expect("edit the message");
    };
    // The first call prefers every row but the edited turn; later calls the
    // edited turn.
    let score = |call: usize, text: &str| match (call, text.contains("hangs")) {
        (1, true) | (2.., false) => 0.0,
        (1, false) | (2.., true) => 10.0,
        (0, _) => unreachable!(),
    };
    let host = ScriptedReranker {
        lease: crate::BudgetGuard::new(
            "paid-rerank-test",
            100_000,
            crate::BudgetExhaustionPolicy::Suspend,
        )
        .admit()
        .expect("a lease")
        .lease,
        calls: std::sync::atomic::AtomicUsize::new(0),
        score: &score,
        during: &during,
    };
    let pack = crate::task_verb::sdk::recall_at_door(
        &facade,
        crate::task_verb::sdk::RecallRequest {
            query: "lantern".to_owned(),
            effort: Some(crate::memory::RecallEffort::High),
            scope: None,
            limit: Some(10),
            format: None,
            as_of: None,
            deadline_ms: None,
        },
        |_| None,
        &crate::task_verb::sdk::RecallDoor {
            arrived: std::time::Instant::now(),
            on_cut: None,
            rerank: crate::memory::RecallRerank::Host(&host),
        },
    )
    .expect("recall");
    let turns: Vec<&str> = pack
        .items
        .iter()
        .filter(|item| item.kind == "TURN")
        .map(|item| item.value_text.as_str())
        .collect();
    assert_eq!(turns.len(), 2, "{pack:?}");
    assert_eq!(
        host.calls.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the edited block is scored again: {turns:?}"
    );
    assert!(turns[0].starts_with("the lantern hangs"), "{turns:?}");
    assert!(matches!(
        pack.retrieval_meta.rerank,
        Some(crate::memory::RerankReport::Applied { calls: 2, .. })
    ));
}
