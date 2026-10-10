//! Typed CLAIM/SUMMARY inputs at the embedding and egress boundaries.

use super::*;

struct SummaryBackend;

impl crate::compaction::CompactionBackend for SummaryBackend {
    fn backend_key(&self) -> &str {
        "test.summary"
    }

    fn tier_class(&self) -> crate::compaction::CompactionTierClass {
        crate::compaction::CompactionTierClass::Cheap
    }

    fn compact(
        &self,
        _request: &crate::compaction::CompactionRequest,
    ) -> Result<crate::compaction::CompactionProduct> {
        Ok(crate::compaction::CompactionProduct {
            summary_text: "the native epoch prose".to_owned(),
            latency: std::time::Duration::from_millis(1),
        })
    }
}

fn mint_pending_summary(vault: &Vault) -> Result<EntityId> {
    use crate::agent_def::{CompactionOwnership, MemoryProfile};
    use crate::compaction::{CompactionBackendRegistry, CompactionDriver, CompactionWindowMessage};
    use crate::llm::ModelTierRef;

    let crate::session_lifecycle::SessionMintOutcome::Minted(session) = vault.mint_session(10)?
    else {
        panic!("fresh session");
    };
    let actor = entity_id(0x71);
    let turn = entity_id(0x72);
    for (id, kind) in [
        (actor, crate::registry::ENTITY_TYPE_PERSON),
        (turn, crate::registry::ENTITY_TYPE_TURN),
    ] {
        vault.put_entity(&id, kind, TimeRange { start: 1, end: 1 }, 1, b"fixture")?;
    }
    let mut registry = CompactionBackendRegistry::new();
    registry.register(Arc::new(SummaryBackend))?;
    let profile = MemoryProfile::new(
        1_000,
        ModelTierRef("test.summary".to_owned()),
        CompactionOwnership::Engine,
    );
    let mut driver = CompactionDriver::for_profile(&profile, &registry)?.expect("engine driver");
    driver.evaluate_now(vault, u64::MAX)?;
    let request = driver.request_for(
        vault,
        &session,
        vec![CompactionWindowMessage {
            message_id: entity_id(0x73),
            turn_id: turn,
            content: "native source prose".to_owned(),
            turn: 1,
            tokens: 3,
        }],
    )?;
    let product = driver.backend().compact(&request)?;
    let plan = driver.integrate(
        vault,
        &session,
        crate::write_envelope::WriteActor::new(actor, crate::edge::EdgeActorClass::Agent),
        &request,
        product,
        &[],
    )?;
    Ok(plan.summary_id)
}

/// A host consumer must select the decoder before touching the bytes.
fn read_payload_text(payload: &PendingEmbeddingPayload) -> Result<String> {
    match payload {
        PendingEmbeddingPayload::ClaimBody(bytes) => {
            let claim = crate::claim::decode_claim_body(bytes, true)?;
            Ok(claim.value.as_str().expect("fixture claim text").to_owned())
        }
        PendingEmbeddingPayload::SummaryText(text) | PendingEmbeddingPayload::TurnText(text) => {
            Ok(text.clone())
        }
    }
}

struct TypedEmbedder {
    locality: EmbedderLocality,
    seen: Mutex<Vec<PendingEmbeddingInput>>,
}

impl TypedEmbedder {
    fn new(locality: EmbedderLocality) -> Self {
        Self {
            locality,
            seen: Mutex::new(Vec::new()),
        }
    }
}

impl Embedder for TypedEmbedder {
    fn model_id(&self) -> &str {
        "test/embedder@v1"
    }

    fn dimensions(&self) -> usize {
        4
    }

    fn locality(&self) -> EmbedderLocality {
        self.locality
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>> {
        inputs
            .iter()
            .map(|input| {
                let text = read_payload_text(&input.payload)?;
                let vector = match &input.payload {
                    PendingEmbeddingPayload::ClaimBody(_) => {
                        assert_eq!(text, "claim prose");
                        vec![1.0, 0.0, 0.0, 0.0]
                    }
                    PendingEmbeddingPayload::SummaryText(_) => {
                        assert_eq!(text, "the native epoch prose");
                        vec![0.0, 1.0, 0.0, 0.0]
                    }
                    PendingEmbeddingPayload::TurnText(_) => unreachable!("this vault has no turn"),
                };
                self.seen.lock().unwrap().push(input.clone());
                Ok(vector)
            })
            .collect()
    }
}

struct TypedEgress {
    summary_decision: EgressDecision,
    seen: Mutex<Vec<PendingEmbeddingInput>>,
}

impl EgressPredicate for TypedEgress {
    fn decide(&self, input: &PendingEmbeddingInput) -> EgressDecision {
        assert!(
            !read_payload_text(&input.payload)
                .expect("typed egress input")
                .is_empty()
        );
        self.seen.lock().unwrap().push(input.clone());
        match &input.payload {
            PendingEmbeddingPayload::ClaimBody(_) => EgressDecision::Allow,
            PendingEmbeddingPayload::SummaryText(_) => self.summary_decision,
            PendingEmbeddingPayload::TurnText(_) => unreachable!("this vault has no turn"),
        }
    }
}

#[test]
fn real_claim_and_minted_summary_reconcile_through_typed_embedder_and_egress() -> Result<()> {
    for decision in [
        EgressDecision::Allow,
        EgressDecision::Deny,
        EgressDecision::NoVerdict,
    ] {
        let (_dir, vault) = test_vault();
        let claim = entity_id(0x70);
        put_claim(&vault, claim, "claim prose")?;
        let summary = mint_pending_summary(&vault)?;
        let claim_body = vault.get(&claim)?.expect("claim body");
        let summary_body = vault.get(&summary)?.expect("summary body");
        let summary_text = crate::compaction::decode_epoch_summary_body(&summary_body)?.text;
        let claim_token = pending_token(&vault, &claim)?.expect("claim marker");
        let summary_token = pending_token(&vault, &summary)?.expect("native summary marker");
        let queue = SyncQueue::new(Arc::clone(&vault))?;
        // Host queue admission uses the native mint's existing pending marker.
        queue.push_embed_job(&summary, EMBED_PRIORITY_DEVICE)?;
        let local = Arc::new(TypedEmbedder::new(EmbedderLocality::OnDevice));
        let remote = Arc::new(TypedEmbedder::new(EmbedderLocality::OwnerServer));
        let gate = Arc::new(TypedEgress {
            summary_decision: decision,
            seen: Mutex::new(Vec::new()),
        });
        let reconciler =
            PendingEmbeddingReconciler::new(Arc::clone(&vault), local.clone() as Arc<dyn Embedder>)
                .with_remote_rung(RemoteRung::new(
                    remote.clone() as Arc<dyn Embedder>,
                    gate.clone() as Arc<dyn EgressPredicate>,
                ))?;
        let report = reconciler.reconcile_once_at(10)?;
        assert_eq!((report.leased, report.embedded, report.filled), (2, 2, 2));
        assert_eq!(
            report.routed_remote,
            if decision == EgressDecision::Allow {
                2
            } else {
                1
            }
        );
        assert_eq!(
            report.egress_denied,
            usize::from(decision == EgressDecision::Deny)
        );
        assert_eq!(
            report.egress_no_verdict,
            usize::from(decision == EgressDecision::NoVerdict)
        );
        let expected = [
            PendingEmbeddingInput {
                entity_id: claim,
                payload: PendingEmbeddingPayload::ClaimBody(claim_body),
                pending_embedding_token: claim_token,
            },
            PendingEmbeddingInput {
                entity_id: summary,
                payload: PendingEmbeddingPayload::SummaryText(summary_text),
                pending_embedding_token: summary_token,
            },
        ];
        let gated = gate.seen.lock().unwrap();
        let local_inputs = local.seen.lock().unwrap();
        let remote_inputs = remote.seen.lock().unwrap();
        assert_eq!(gated.len(), 2);
        for input in &expected {
            assert!(gated.contains(input));
            let goes_remote = input.entity_id == claim || decision == EgressDecision::Allow;
            assert_eq!(remote_inputs.contains(input), goes_remote);
            assert_eq!(local_inputs.contains(input), !goes_remote);
        }
        drop(gated);
        drop(local_inputs);
        drop(remote_inputs);
        assert_eq!(vault.get_vector(&claim)?, Some(vec![1.0, 0.0, 0.0, 0.0]));
        assert_eq!(vault.get_vector(&summary)?, Some(vec![0.0, 1.0, 0.0, 0.0]));
        assert!(pending_token(&vault, &claim)?.is_none());
        assert!(pending_token(&vault, &summary)?.is_none());
        assert!(queue.drain_embed_jobs()?.is_empty());
        assert_eq!(
            vault.get(&summary)?.expect("unchanged full record"),
            summary_body
        );
        assert_eq!(reconciler.reconcile_once_at(20)?.leased, 0);
    }
    Ok(())
}
