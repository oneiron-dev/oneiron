//! The deferred-supersession coaching settlement over a tool-output-tainted
//! pair (FIX 23206). A Dreamer correction of an attributed tool-output claim
//! parks behind a coaching marker; the owner's approval grants the pair and
//! the settlement answers the marker. The answer inherits the marker's
//! scope, taint stamp included, so its source meets that taint as the
//! companion writer's does: on main the Generated source over the inherited
//! ToolOutput taint fails the lineage guard and the approval errors.
//!
//! `cargo test --locked -p oneiron --all-features --test coaching_settlement_generated_over_tooloutput_taint`
#![cfg(feature = "test-support")]

use oneiron::claim::ClaimBody;
use oneiron::dreamer_consolidation::{
    ConsolidationProvenanceHop, ConsolidationProvenanceHopKind, PromotionCandidate,
};
use oneiron::dreamer_promotion::{DreamerRunContext, promote_consolidated_claims};
use oneiron::dreamer_runner::EnqueueDreamerAttempt;
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use oneiron::write_envelope::ClaimCandidate;
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject, DreamerRunnerStore,
    EdgeKind, EnqueueDreamerAttemptOutcome, EntityId, TimeRange, Vault, VaultConfig,
};
use rmpv::Value as Mp;

const RUN_ID: &str = "run-coaching-settlement-taint";
const PREDICATE: &str = "profile.name";
/// The owner's approval lands after the correction it confirms.
const APPROVE_AT: u64 = 9_001;

/// A policy manifest that grants the Dreamer's Auto request: auto ceilings
/// for the system, human and first-party classes and an auto permit for
/// every source. The same manifest as the promotion writer's own tests.
fn auto_permitting_manifest() -> Vec<u8> {
    let source_row = || {
        Mp::Map(vec![
            (Mp::from("max_auto_sensitivity"), Mp::from(3_u64)),
            (Mp::from("receipted"), Mp::Boolean(true)),
            (Mp::from("warned"), Mp::Boolean(true)),
        ])
    };
    let manifest = Mp::Map(vec![
        (
            Mp::from("schema_version"),
            Mp::from(oneiron_store::policy_record::POLICY_SCHEMA_VERSION),
        ),
        (Mp::from("pack_id"), Mp::from("coaching-settlement-test")),
        (Mp::from("pack_version"), Mp::from("v1")),
        (
            Mp::from("min_engine_version"),
            Mp::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Mp::from("defaults"),
            Mp::Map(vec![
                (Mp::from("criticality"), Mp::from("normal")),
                (Mp::from("sensitivity"), Mp::from("normal")),
            ]),
        ),
        (Mp::from("rules"), Mp::Array(Vec::new())),
        (
            Mp::from("actor_ceilings"),
            Mp::Array(
                ["system", "human", "first_party"]
                    .into_iter()
                    .map(|actor_class| {
                        Mp::Map(vec![
                            (Mp::from("actor_class"), Mp::from(actor_class)),
                            (Mp::from("ceiling"), Mp::from("auto")),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            Mp::from("source_trust"),
            Mp::Map(
                [
                    ClaimSource::UserStated,
                    ClaimSource::Observed,
                    ClaimSource::Inferred,
                    ClaimSource::Imported,
                    ClaimSource::ToolOutput,
                    ClaimSource::Generated,
                ]
                .into_iter()
                .map(|source| (Mp::from(source.as_str()), source_row()))
                .collect(),
            ),
        ),
        (
            Mp::from("signature"),
            Mp::Map(vec![
                (Mp::from("alg"), Mp::from("ed25519")),
                (Mp::from("key_id"), Mp::from("coaching-settlement-test")),
                (
                    Mp::from("sig"),
                    Mp::from("coaching-settlement-test-signature"),
                ),
            ]),
        ),
    ]);
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &manifest).expect("encode the policy manifest");
    out
}

fn occurred(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

struct Fixture {
    vault: Vault,
    run: DreamerRunContext,
    subject: EntityId,
    turn: EntityId,
    peer: EntityId,
    // Dropped after the vault.
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("vault dir");
        let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
        vault.install_device_keystore(std::sync::Arc::new(oneiron_keystore::MemoryKeystore::new()));
        // The Dreamer is a MACHINE writer: the host roots the vault and
        // provisions the engine's identities.
        oneiron::test_support::provision_engine_machines(&vault);
        let manifest_id = oneiron_store::policy_record::default_policy_manifest_id()
            .expect("default policy manifest id");
        oneiron::test_support::put_policy_manifest_bytes(
            &vault,
            manifest_id,
            &auto_permitting_manifest(),
        )
        .expect("seed the auto-permitting policy manifest");

        let subject = EntityId::now();
        let conversation = EntityId::now();
        let turn = EntityId::now();
        let peer = EntityId::now();
        vault
            .put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"subject")
            .expect("subject");
        vault
            .put_entity(&peer, ENTITY_TYPE_PERSON, occurred(1), 1, b"peer")
            .expect("peer");
        vault
            .put_entity(
                &conversation,
                ENTITY_TYPE_SESSION,
                occurred(1),
                1,
                b"session",
            )
            .expect("session");
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &Mp::Map(vec![
                (Mp::from("txt"), Mp::from("my name is Ada")),
                (Mp::from("spkr"), Mp::from("user")),
            ]),
        )
        .expect("turn body");
        vault
            .batch()
            .put(&turn, ENTITY_TYPE_TURN, occurred(5), 5, &body)
            .edge(&turn, EdgeKind::ChildOf, &conversation, 1.0)
            .commit()
            .expect("evidence turn");

        let status = match DreamerRunnerStore::new(&vault)
            .enqueue(EnqueueDreamerAttempt {
                attempt_type: "coaching-settlement-test".to_owned(),
                input: Mp::from("input"),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(RUN_ID.to_owned()),
                now: 6,
            })
            .expect("enqueue the Dreamer attempt")
        {
            EnqueueDreamerAttemptOutcome::Enqueued(status)
            | EnqueueDreamerAttemptOutcome::Existing(status) => status,
            // The outcome enum is `#[non_exhaustive]` outside the crate.
            other => panic!("unexpected enqueue outcome {other:?}"),
        };
        let run = DreamerRunContext {
            run_id: RUN_ID.to_owned(),
            attempt_id: status.attempt.id,
            agent_actor: vault.dreamer_authority().expect("Dreamer authority"),
            now_ms: 10_000,
        };
        Self {
            vault,
            run,
            subject,
            turn,
            peer,
            _directory: directory,
        }
    }

    /// An attributed peer-style candidate: its provenance chain names the
    /// answering peer, so the parked pair opens a coaching marker.
    fn candidate(
        &self,
        value: &str,
        meet: ClaimSource,
        supersedes: Option<EntityId>,
    ) -> PromotionCandidate {
        PromotionCandidate {
            claim_id: EntityId::now(),
            candidate: ClaimCandidate::new(
                PREDICATE,
                ClaimSubject::Entity(self.subject),
                Mp::from(value),
                0.7,
            ),
            evidence_turn_refs: vec![self.turn],
            provenance_chain: vec![ConsolidationProvenanceHop {
                kind: ConsolidationProvenanceHopKind::AnswerTurn,
                entity_ref: self.turn,
                actor_ref: Some(self.peer),
            }],
            supersedes,
            evidence_meet: meet,
            occurred: occurred(9_000),
            learned_at: 9_000,
            decisions: Vec::new(),
        }
    }

    fn claim(&self, id: EntityId) -> ClaimBody {
        self.vault
            .get_claim(&id)
            .expect("read claim")
            .expect("claim exists")
    }

    fn subject_claims(&self) -> Vec<(EntityId, ClaimBody)> {
        self.vault
            .claims_for_subject(&self.subject)
            .expect("the subject's claims")
            .into_iter()
            .map(|id| (id, self.claim(id)))
            .collect()
    }
}

/// The `evidence_taint` stamp on the claim's scope map, if it carries one.
fn scope_taint(body: &ClaimBody) -> Option<ClaimSource> {
    let Mp::Map(rows) = body.scope.as_ref()? else {
        return None;
    };
    let (_, value) = rows
        .iter()
        .find(|(key, _)| key.as_str() == Some("evidence_taint"))?;
    value.as_str().and_then(ClaimSource::parse)
}

/// The marker a settlement answer names, if it names one.
fn answer_marker(body: &ClaimBody) -> Option<EntityId> {
    let Mp::Map(rows) = &body.value else {
        return None;
    };
    let found = rows
        .iter()
        .find(|(key, _)| key.as_str() == Some("open_marker"))?;
    let (_, Mp::Binary(raw)) = found else {
        return None;
    };
    EntityId::from_bytes(raw.as_slice().try_into().ok()?).ok()
}

/// Promotes an attributed head and its parked correction at `meet`, has the
/// owner confirm the correction, and returns the settlement answer's source.
fn settled_answer_source(meet: ClaimSource) -> ClaimSource {
    let f = Fixture::new();
    let head = f.candidate("Ada", meet, None);
    let head_id = head.claim_id;
    let landed =
        promote_consolidated_claims(&f.vault, &f.run, vec![head]).expect("promote the head");
    assert_eq!(landed.landed, vec![head_id], "the head lands");
    assert_eq!(f.claim(head_id).source, Some(meet));

    let new = f.candidate("Ada Lovelace", meet, Some(head_id));
    let new_id = new.claim_id;
    let outcome =
        promote_consolidated_claims(&f.vault, &f.run, vec![new]).expect("promote the correction");
    assert_eq!(outcome.pended, vec![new_id], "the correction parks");
    assert_eq!(
        f.vault
            .pending_claim_supersession(&new_id)
            .expect("read the parked closure"),
        Some(head_id)
    );

    // The attributed pair waits behind one coaching marker carrying the
    // pair's taint.
    let markers: Vec<(EntityId, ClaimBody)> = f
        .subject_claims()
        .into_iter()
        .filter(|(_, body)| body.predicate == "core.conflict.open")
        .collect();
    assert_eq!(markers.len(), 1, "one coaching marker waits");
    assert_eq!(
        scope_taint(&markers[0].1),
        Some(meet),
        "the marker carries the pair's taint"
    );

    let proposed = f
        .vault
        .get(&new_id)
        .expect("read proposed correction")
        .expect("proposal bytes");
    f.vault
        .approve_inbox_member_with_edit_at(&new_id, &proposed, APPROVE_AT)
        .expect("the owner confirms the attributed correction");

    assert_eq!(f.claim(new_id).approval, ClaimApprovalStatus::Approved);
    assert_eq!(
        f.claim(head_id).lifecycle,
        ClaimLifecycleStatus::Superseded,
        "the wrong head is superseded, never deleted"
    );

    let answers: Vec<ClaimBody> = f
        .subject_claims()
        .into_iter()
        .filter(|(_, body)| body.predicate == "core.conflict.resolved")
        .filter(|(_, body)| answer_marker(body) == Some(markers[0].0))
        .map(|(_, body)| body)
        .collect();
    assert_eq!(answers.len(), 1, "one settlement answers the marker");
    answers[0].source.expect("the answer has a source")
}

#[test]
fn owner_approval_answers_a_tooloutput_coaching_marker_with_the_meet() {
    assert_eq!(
        settled_answer_source(ClaimSource::ToolOutput),
        ClaimSource::ToolOutput,
        "the settlement meets its source with the inherited taint"
    );
}

#[test]
fn owner_approval_answers_a_generated_coaching_marker_as_generated() {
    assert_eq!(
        settled_answer_source(ClaimSource::Generated),
        ClaimSource::Generated,
        "without taint the settlement keeps its generated source"
    );
}
