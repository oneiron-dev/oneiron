//! The owner inbox's bulk answer to a Dreamer run's parked replacement
//! (FIX INBOX-REJECT-ALL-LEAVES-DEFERRED-ROW). A run's replacement of a
//! landed head parks behind a run-stamped tray row and a deferred closure
//! of the head. Rejecting the run's group closes the tray row and cancels
//! the parked closure with it, as the bundle and settle declines do.
//! Accepting it still closes the head it replaces.
//!
//! `cargo test --locked -p oneiron --all-features --test inbox_reject_cancels_deferred`
#![cfg(feature = "test-support")]

use oneiron::dreamer_consolidation::PromotionCandidate;
use oneiron::dreamer_promotion::{DreamerRunContext, promote_consolidated_claims};
use oneiron::dreamer_runner::EnqueueDreamerAttempt;
use oneiron::inbox::{InboxBulkVerb, InboxReviewDial, UnifiedInboxGroup};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION, ENTITY_TYPE_TURN};
use oneiron::write_envelope::ClaimCandidate;
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource, ClaimSubject, DreamerRunnerStore,
    EdgeKind, EnqueueDreamerAttemptOutcome, EntityId, Error, TimeRange, Vault, VaultConfig,
};
use rmpv::Value as Mp;

const RUN_ID: &str = "run-inbox-reject";

/// A policy manifest that grants the Dreamer's Auto request: auto ceilings
/// for the system, human and first-party classes and an auto permit for
/// every source, signed as the Dreamer's auto grant requires. The same
/// manifest as the promotion writer's own tests.
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
        (Mp::from("pack_id"), Mp::from("inbox-reject-test")),
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
                (Mp::from("key_id"), Mp::from("inbox-reject-test")),
                (Mp::from("sig"), Mp::from("inbox-reject-test-signature")),
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
        vault
            .put_entity(&subject, ENTITY_TYPE_PERSON, occurred(1), 1, b"subject")
            .expect("subject");
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
                attempt_type: "inbox-reject-test".to_owned(),
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
            _directory: directory,
        }
    }

    fn candidate(&self, value: &str, supersedes: Option<EntityId>) -> PromotionCandidate {
        PromotionCandidate {
            claim_id: EntityId::now(),
            candidate: ClaimCandidate::new(
                "profile.name",
                ClaimSubject::Entity(self.subject),
                Mp::from(value),
                0.7,
            ),
            evidence_turn_refs: vec![self.turn],
            provenance_chain: Vec::new(),
            supersedes,
            evidence_meet: ClaimSource::Generated,
            occurred: occurred(9_000),
            learned_at: 9_000,
            decisions: Vec::new(),
        }
    }

    /// A landed head and the run's parked replacement of it: `(head, new)`.
    fn parked_replacement(&self) -> (EntityId, EntityId) {
        let first = self.candidate("Ada", None);
        let head = first.claim_id;
        let landed = promote_consolidated_claims(&self.vault, &self.run, vec![first])
            .expect("promote the head");
        assert_eq!(landed.landed, vec![head], "the head lands");
        let second = self.candidate("Ada Lovelace", Some(head));
        let new = second.claim_id;
        let outcome = promote_consolidated_claims(&self.vault, &self.run, vec![second])
            .expect("promote the replacement");
        assert_eq!(outcome.pended, vec![new], "the replacement parks");
        assert_eq!(
            self.vault
                .pending_claim_supersession(&new)
                .expect("read the parked closure"),
            Some(head)
        );
        let row = self
            .vault
            .pending_gate_consents(64)
            .expect("read the tray")
            .into_iter()
            .find(|row| row.claim_id == *new.as_bytes())
            .expect("the replacement has a tray row");
        assert_eq!(row.dreamer_run_id.as_deref(), Some(RUN_ID));
        self.vault
            .set_inbox_review_dial(InboxReviewDial::ReviewEverything)
            .expect("show every member");
        assert!(
            self.inbox_claim_ids().contains(&new.to_hex()),
            "the run's group lists the replacement"
        );
        (head, new)
    }

    fn inbox_claim_ids(&self) -> Vec<String> {
        self.vault
            .inbox_groups_unified(1_000_000, 64, None)
            .expect("project the owner's inbox")
            .groups
            .into_iter()
            .filter_map(|group| match group {
                UnifiedInboxGroup::Dreamer { group } => Some(group),
                UnifiedInboxGroup::Shape { .. } => None,
            })
            .flat_map(|group| group.members)
            .flat_map(|member| std::iter::once(member.claim_id).chain(member.duplicate_claim_ids))
            .collect()
    }

    fn has_tray_row(&self, id: EntityId) -> bool {
        self.vault
            .pending_gate_consents(64)
            .expect("read the tray")
            .iter()
            .any(|row| row.claim_id == *id.as_bytes())
    }

    fn lifecycle(&self, id: EntityId) -> ClaimLifecycleStatus {
        self.vault
            .get_claim(&id)
            .expect("read claim")
            .expect("claim exists")
            .lifecycle
    }
}

#[test]
fn rejecting_a_runs_replacement_in_the_inbox_cancels_its_parked_closure() {
    let f = Fixture::new();
    let (head, new) = f.parked_replacement();

    let rejected = f
        .vault
        .resolve_inbox_group(RUN_ID, InboxBulkVerb::RejectAll)
        .expect("the owner rejects the run's group");

    assert_eq!(rejected.item_receipts.len(), 1, "one member was rejected");
    assert!(!f.has_tray_row(new), "the tray row is closed");
    // The parked closure is gone with it: a grant finds nothing to close.
    // A closure left behind is read by the grant, which answers
    // `GateConsentStale` because its tray row is gone.
    let grant = f.vault.grant_deferred_claim_auto(&new, 20_000);
    assert!(
        matches!(grant, Err(Error::EntityNotFound)),
        "no parked closure is left behind: {grant:?}"
    );
    assert_eq!(
        f.lifecycle(head),
        ClaimLifecycleStatus::Active,
        "the head stands"
    );
}

#[test]
fn accepting_a_runs_replacement_in_the_inbox_closes_the_head_it_replaces() {
    let f = Fixture::new();
    let (head, new) = f.parked_replacement();

    // A VAD consolidation error after the commit leaves the approval
    // landed, so the state below is the test.
    let accepted = f
        .vault
        .resolve_inbox_group(RUN_ID, InboxBulkVerb::AcceptAll);

    assert!(!f.has_tray_row(new), "the tray row is closed: {accepted:?}");
    assert_eq!(
        f.vault
            .get_claim(&new)
            .expect("read claim")
            .expect("claim exists")
            .approval,
        ClaimApprovalStatus::Approved,
        "the replacement lands: {accepted:?}"
    );
    assert_eq!(
        f.lifecycle(head),
        ClaimLifecycleStatus::Superseded,
        "the head it replaces closes: {accepted:?}"
    );
}
