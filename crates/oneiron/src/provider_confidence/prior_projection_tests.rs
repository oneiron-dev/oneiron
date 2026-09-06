//! Read-side corruption and stranding regressions; no production fixture doors.

use super::*;
use crate::claim::{ClaimSource, encode_claim_body};
use crate::identity_topology::{
    IdentityOpEvidence, IdentityOpWrite, IdentityTopologyOp, MergeOp, SurvivorshipPlan,
};
use crate::provider_confidence::write_provider_prior;
use crate::test_util::{embedding_test_config, entity, open_test_vault_with};

fn put_actor(vault: &Vault, id: EntityId, provider: &str) -> Result<()> {
    let bytes = encode_value(&Value::Map(vec![(
        Value::from("provider_key"),
        Value::from(provider),
    )]))?;
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        &bytes,
    )
}

fn merge(vault: &Vault, source: EntityId, survivor: EntityId) -> Result<()> {
    vault.apply_identity_topology_op(
        &IdentityTopologyOp::Merge(MergeOp {
            sources: vec![source],
            survivor,
            evidence: IdentityOpEvidence::default(),
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        }),
        &IdentityOpWrite::auto(ClaimSource::Inferred),
        400,
    )?;
    Ok(())
}

#[test]
fn malformed_prior_on_shell_raises_the_same_structural_error_as_on_actor() -> Result<()> {
    for merged in [false, true] {
        for cached in [false, true] {
            let (_dir, vault) = open_test_vault_with(embedding_test_config());
            let provider = "provider_malformed_projection";
            let actor = entity(0x22);
            put_actor(&vault, actor, provider)?;
            let prior = write_provider_prior(&vault, provider, 0.30, "evidence:initial")?;
            if merged {
                let head = entity(0x23);
                put_actor(&vault, head, provider)?;
                merge(&vault, actor, head)?;
            }
            let mut body = vault.get_claim(&prior)?.expect("stored prior");
            body.evidence = None;
            let bytes = encode_claim_body(&body)?;
            vault.with_write_txn(|wtxn| {
                // Preserve every index and the header. Only the stored prior
                // body is damaged; no ordinary write door admits these bytes.
                let mut raw = vault
                    .store
                    .entities
                    .get(&*wtxn, prior.as_bytes())?
                    .expect("prior row")
                    .to_vec();
                raw.truncate(ENTITY_METADATA_HEADER_LEN);
                raw.extend_from_slice(&bytes);
                vault.store.entities.put(wtxn, prior.as_bytes(), &raw)?;
                if !cached {
                    vault
                        .store
                        .vault_meta
                        .delete(wtxn, &provider_prior_head_index_key(provider))?;
                }
                Ok(())
            })?;
            let error = vault
                .with_write_txn(|wtxn| active_provider_prior_in_txn(&vault, wtxn, provider))
                .expect_err("malformed prior must not become neutral");
            assert!(
                matches!(
                    error,
                    Error::InvalidClaimBody("actor confidence prior must carry string evidence")
                ),
                "merged={merged}, cached={cached}: {error}"
            );
        }
    }
    Ok(())
}

#[test]
fn stranded_write_preserves_exact_actor_and_prior_shortcut_bytes() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let provider = "provider_stranded_indexes";
    let actor = entity(0x22);
    let foreign = entity(0x23);
    put_actor(&vault, actor, provider)?;
    let prior = write_provider_prior(&vault, provider, 0.30, "evidence:initial")?;
    put_actor(&vault, foreign, "provider_other")?;
    merge(&vault, actor, foreign)?;
    let before = vault.count_entities_by_type(ENTITY_TYPE_PERSON)?;
    let error = write_provider_prior(&vault, provider, 0.50, "evidence:no-fork")
        .expect_err("strand must block a replacement actor");
    assert!(matches!(
        error,
        Error::InvalidClaimBody("provider confidence prior stranded by merge")
    ));
    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(
        vault
            .store
            .vault_meta
            .get(&rtxn, &provider_actor_index_key(provider))?
            .as_deref(),
        Some(actor.as_bytes().as_slice())
    );
    assert_eq!(
        vault
            .store
            .vault_meta
            .get(&rtxn, &provider_prior_head_index_key(provider))?
            .as_deref(),
        Some(prior.as_bytes().as_slice())
    );
    drop(rtxn);
    assert_eq!(vault.count_entities_by_type(ENTITY_TYPE_PERSON)?, before);
    Ok(())
}

#[test]
fn a_merge_with_a_missing_or_nonactive_head_strands_its_prior() -> Result<()> {
    for missing in [false, true] {
        let (_dir, vault) = open_test_vault_with(embedding_test_config());
        let provider = "provider_missing_head";
        let actor = entity(0x22);
        let head = entity(0x23);
        put_actor(&vault, actor, provider)?;
        write_provider_prior(&vault, provider, 0.30, "evidence:initial")?;
        put_actor(&vault, head, provider)?;
        merge(&vault, actor, head)?;
        if missing {
            vault.with_write_txn(|wtxn| {
                vault.store.entities.delete(wtxn, head.as_bytes())?;
                Ok(())
            })?;
        } else {
            // With the disposable projection dropped, the resolver returns
            // the source itself. Its lifecycle still prevents acceptance.
            vault.drop_redirect_projection()?;
        }
        let error = vault
            .with_write_txn(|wtxn| active_provider_prior_in_txn(&vault, wtxn, provider))
            .expect_err("a shell without a canonical active owner must not read neutral");
        assert!(matches!(
            error,
            Error::InvalidClaimBody("provider confidence prior stranded by merge")
        ));
    }
    Ok(())
}

#[test]
fn waterfall_rejects_a_merged_claim_whose_canonical_head_is_missing() -> Result<()> {
    let (_dir, vault) = open_test_vault_with(embedding_test_config());
    let shell = entity(0x22);
    let head = entity(0x23);
    let claim = entity(0x24);
    put_actor(&vault, shell, "provider_candidate")?;
    put_actor(&vault, head, "provider_candidate")?;
    let mut body = ClaimBody::new(
        crate::provider_confidence::PREDICATE_PROVIDER_ENRICHMENT,
        ClaimSubject::Entity(shell),
        Value::Map(vec![(
            Value::from("provider"),
            Value::from("provider_score"),
        )]),
        0.95,
        crate::claim::ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Observed);
    vault.put_claim(&claim, &body, TimeRange { start: 1, end: 1 }, 1)?;
    merge(&vault, shell, head)?;
    vault.with_write_txn(|wtxn| {
        vault.store.entities.delete(wtxn, head.as_bytes())?;
        Ok(())
    })?;
    assert!(matches!(
        crate::ingest::evaluate_entity_resolution_waterfall(
            &vault,
            &[crate::ingest::EntityResolutionCandidate {
                subject: shell,
                confidence_claim_ref: claim,
            }],
            false,
        ),
        Err(Error::InvalidClaimBody(
            "waterfall candidate subject is not a canonical active entity"
        ))
    ));
    assert_eq!(
        vault
            .get_claim(&claim)?
            .expect("read-through claim")
            .subject,
        ClaimSubject::Entity(shell)
    );
    Ok(())
}

// These three ONE-1891 ruling oracles moved from effect_spine_oracle.rs so
// their stored unvetted claims can use the existing private replication fixture
// door. They remain base-mode tests and keep the production default policy.
mod one1891_ruling {
    use crate::test_util::embedding_test_config;
    use crate::{
        ClaimApprovalStatus, ClaimSource, ClaimSubject, EntityResolutionCandidate,
        EntityResolutionRoute, Error, Vault,
    };
    use rmpv::Value;

    fn open_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        // Do not use open_test_vault_with: that legacy helper clears policy.
        let vault = Vault::open(dir.path(), embedding_test_config()).expect("open seeded vault");
        (dir, vault)
    }

    mod f {
        use crate::claim::encode_claim_body;
        use crate::provider_confidence::indexes::{
            provider_actor_index_key, provider_prior_head_index_key,
        };
        use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
        use crate::{
            ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
            EntityId, EntityResolutionCandidate, EntityResolutionWaterfallDecision, TimeRange,
            Vault,
        };
        use rmpv::Value;

        pub(super) fn at(ts: u64) -> TimeRange {
            TimeRange { start: ts, end: ts }
        }

        pub(super) fn fixture_id(lead: u8) -> EntityId {
            let mut bytes = [0x5a_u8; 16];
            bytes[0] = lead;
            EntityId::from_bytes(bytes).expect("fixture id")
        }

        pub(super) fn put_person(vault: &Vault, lead: u8) -> EntityId {
            let id = fixture_id(lead);
            vault
                .put_entity(&id, ENTITY_TYPE_PERSON, at(100), 100, b"one1891 person")
                .expect("put person");
            id
        }

        pub(super) fn enrichment_value(provider: &str, siblings: &[(&str, &str)]) -> Value {
            let mut entries = vec![(Value::from("provider"), Value::from(provider))];
            for (key, value) in siblings {
                entries.push((Value::from(*key), Value::from(*value)));
            }
            Value::Map(entries)
        }

        pub(super) fn enrichment_body(
            subject: ClaimSubject,
            value: Value,
            confidence: f32,
        ) -> ClaimBody {
            let mut body = ClaimBody::new(
                crate::PREDICATE_PROVIDER_ENRICHMENT,
                subject,
                value,
                confidence,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            );
            body.valid_from = Some(200);
            body.source = Some(ClaimSource::Observed);
            body
        }

        pub(super) fn put_enrichment(
            vault: &Vault,
            lead: u8,
            subject: EntityId,
            provider: &str,
            confidence: f32,
        ) -> EntityId {
            let id = fixture_id(lead);
            let body = enrichment_body(
                ClaimSubject::Entity(subject),
                enrichment_value(provider, &[]),
                confidence,
            );
            vault
                .put_claim(&id, &body, at(200), 200)
                .expect("put enrichment claim");
            id
        }

        pub(super) fn candidate(
            vault: &Vault,
            subject_lead: u8,
            claim_lead: u8,
            provider: &str,
            confidence: f32,
        ) -> EntityResolutionCandidate {
            let subject = put_person(vault, subject_lead);
            let confidence_claim_ref =
                put_enrichment(vault, claim_lead, subject, provider, confidence);
            EntityResolutionCandidate {
                subject,
                confidence_claim_ref,
            }
        }

        pub(super) fn write_prior(
            vault: &Vault,
            provider: &str,
            prior: f32,
            evidence: &str,
        ) -> EntityId {
            crate::provider_confidence::write_provider_prior(vault, provider, prior, evidence)
                .expect("write provider prior")
        }

        pub(super) fn effective(vault: &Vault, claim: &EntityId) -> f32 {
            crate::provider_confidence::effective_confidence(vault, claim).expect("effective")
        }

        pub(super) fn decide(
            vault: &Vault,
            candidates: &[EntityResolutionCandidate],
            high_collision: bool,
        ) -> EntityResolutionWaterfallDecision {
            crate::evaluate_entity_resolution_waterfall(vault, candidates, high_collision)
                .expect("waterfall")
        }

        pub(super) fn close(actual: f32, expected: f32) -> bool {
            (actual - expected).abs() < 1e-6
        }

        pub(super) fn counts(vault: &Vault) -> (u64, u64) {
            (
                vault
                    .count_entities_by_type(ENTITY_TYPE_PERSON)
                    .expect("person count"),
                vault
                    .count_entities_by_type(ENTITY_TYPE_CLAIM)
                    .expect("claim count"),
            )
        }

        /// Seed replicated-shape truth without asking the local write gate to
        /// auto-approve it. This existing crate-private fixture door retains
        /// structural validation and does not change the vault's policy.
        pub(super) fn put_stored_claim(vault: &Vault, claim: &EntityId, body: &ClaimBody) {
            let bytes = encode_claim_body(body).expect("encode stored claim fixture");
            vault
                .batch()
                .put_replicated(claim, ENTITY_TYPE_CLAIM, at(200), 200, &bytes)
                .commit()
                .expect("seed stored claim through the replication fixture door");
            assert_eq!(
                vault
                    .get_claim(claim)
                    .expect("read stored fixture")
                    .as_ref(),
                Some(body),
                "fixture must preserve source, scope, approval, and lifecycle"
            );
        }

        pub(super) fn index_presence(vault: &Vault, provider: &str) -> (bool, bool) {
            let rtxn = vault.store.env.read_txn().expect("index read transaction");
            (
                vault
                    .store
                    .vault_meta
                    .get(&rtxn, &provider_actor_index_key(provider))
                    .expect("actor index")
                    .is_some(),
                vault
                    .store
                    .vault_meta
                    .get(&rtxn, &provider_prior_head_index_key(provider))
                    .expect("prior index")
                    .is_some(),
            )
        }

        pub(super) fn clear_indexes(vault: &Vault, provider: &str) {
            vault
                .with_write_txn(|wtxn| {
                    vault
                        .store
                        .vault_meta
                        .delete(wtxn, &provider_actor_index_key(provider))?;
                    vault
                        .store
                        .vault_meta
                        .delete(wtxn, &provider_prior_head_index_key(provider))?;
                    Ok(())
                })
                .expect("clear provider shortcut rows");
        }
    }

    #[test]
    fn one1891_generated_restamped_and_tainted_evidence_waits_for_approval() {
        for (source, scope) in [
            (ClaimSource::Generated, None),
            (
                ClaimSource::Imported,
                Some(Value::Map(vec![(
                    Value::from("federated_original_source"),
                    Value::from("generated"),
                )])),
            ),
            (
                ClaimSource::ToolOutput,
                Some(Value::Map(vec![(
                    Value::from("evidence_taint"),
                    Value::from("tool_output"),
                )])),
            ),
            (
                ClaimSource::Imported,
                Some(Value::Map(vec![(
                    Value::from("evidence_taint"),
                    Value::from("imported"),
                )])),
            ),
        ] {
            let (_dir, vault) = open_vault();
            let provider = "provider_unvetted";
            f::write_prior(&vault, provider, 0.95, "evidence:high-band");
            let subject = f::put_person(&vault, 0x31);
            let claim = f::fixture_id(0x41);
            let mut body = f::enrichment_body(
                ClaimSubject::Entity(subject),
                f::enrichment_value(provider, &[]),
                1.0,
            );
            body.source = Some(source);
            body.scope = scope;
            f::put_stored_claim(&vault, &claim, &body);
            assert!(f::close(f::effective(&vault, &claim), 0.95));
            f::clear_indexes(&vault, provider);
            let before = f::counts(&vault);
            let candidate = EntityResolutionCandidate {
                subject,
                confidence_claim_ref: claim,
            };
            let decision = f::decide(&vault, &[candidate], false);
            assert_eq!(decision.claims_suppressed, 1);
            assert!(decision.ranked.is_empty());
            assert_eq!(decision.route, EntityResolutionRoute::ProvisionalEntity);
            assert_eq!(decision.selected, None);
            assert_eq!(decision.selected_effective_confidence, None);
            assert!(!decision.requires_async_verification);
            assert_eq!(f::counts(&vault), before);
            assert_eq!(
                f::index_presence(&vault, provider),
                (false, false),
                "suppressed evidence must not resolve or repair a provider prior"
            );

            body.approval = ClaimApprovalStatus::Approved;
            vault.put_claim(&claim, &body, f::at(200), 200).unwrap();
            let approved = f::decide(&vault, &[candidate], false);
            assert_eq!(approved.claims_suppressed, 0);
            assert_eq!(approved.ranked.len(), 1);
            assert_eq!(approved.selected, Some(subject));
            assert_eq!(approved.route, EntityResolutionRoute::HardLink);
            assert!(f::close(approved.ranked[0].effective_confidence, 0.95));
        }
    }

    #[test]
    fn one1891_unvetted_top_scorer_cannot_veto_a_vetted_candidate() {
        let (_dir, vault) = open_vault();
        let subject = f::put_person(&vault, 0x31);
        let unvetted = EntityResolutionCandidate {
            subject,
            confidence_claim_ref: f::fixture_id(0x41),
        };
        let mut body = f::enrichment_body(
            ClaimSubject::Entity(subject),
            f::enrichment_value("provider_unvetted", &[]),
            0.99,
        );
        body.source = Some(ClaimSource::Generated);
        f::put_stored_claim(&vault, &unvetted.confidence_claim_ref, &body);
        let vetted = f::candidate(&vault, 0x32, 0x42, "provider_vetted", 0.80);
        for candidates in [[unvetted, vetted], [vetted, unvetted]] {
            let decision = f::decide(&vault, &candidates, false);
            assert_eq!(decision.claims_suppressed, 1);
            assert_eq!(decision.ranked.len(), 1);
            assert_eq!(decision.ranked[0].candidate, vetted);
            assert_eq!(decision.selected, Some(vetted.subject));
        }
    }

    #[test]
    fn one1891_suppressed_evidence_still_obeys_closed_reference_errors() {
        let (_dir, vault) = open_vault();
        for (lead, lifecycle) in [
            (0x41, crate::ClaimLifecycleStatus::Retracted),
            (0x42, crate::ClaimLifecycleStatus::Superseded),
        ] {
            let subject = f::put_person(&vault, lead - 0x10);
            let claim = f::fixture_id(lead);
            let mut body = f::enrichment_body(
                ClaimSubject::Entity(subject),
                f::enrichment_value("provider_closed", &[]),
                0.99,
            );
            body.source = Some(ClaimSource::Generated);
            body.lifecycle = lifecycle;
            f::put_stored_claim(&vault, &claim, &body);
            assert!(matches!(
                crate::evaluate_entity_resolution_waterfall(
                    &vault,
                    &[EntityResolutionCandidate {
                        subject,
                        confidence_claim_ref: claim
                    }],
                    false,
                ),
                Err(Error::InvalidClaimBody(
                    "waterfall confidence claim is not active"
                ))
            ));
        }
    }
}
