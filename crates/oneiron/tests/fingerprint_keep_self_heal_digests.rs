//! K-proof for self-heal legacy digests at d28afbfe74de: existing stored, keyed
//! and compared identities keep main's bytes through the fingerprint K door.
//!
//! A blocked report's diagnostic stores its receipt content's replay hash, and
//! a consent-depth finding stores its queue's. The graded-window table is keyed
//! by detector, minted and centroid window keys. A minted registration stores
//! its revision. A model finding stores its retrieval-window digest as its
//! replay content hash, an observed window stores it as its coordinate with
//! each run's replay hash, and a minted T2's example window is compared with
//! it. A tier-1 source proof pins each source row, and the witness carries the
//! pin. A healer run receipt is keyed by its run name's digest. A question past
//! the text room is keyed by its wording's digest, and a finding basis stores
//! its recipe revision and window context in the issue row.
//!
//! The base modules copy exact main lines. Inline hash lines have hand-written
//! headers and returns. Stand-ins hold only what main's lines read: a blocked
//! receipt's content; a queued observation's payload digest and the detector's
//! snapshot time; an observed run's fields; a policy's prompt and rubric; the
//! window grade and finding basis fields. `detector_window_key`,
//! `minted_window_key` and `MintedT2::revision` are public, so the test calls
//! them directly.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_self_heal_digests`.
#![cfg(oneiron_test_support)]

use std::collections::BTreeSet;

use oneiron::EntityId;
use oneiron::self_heal::DiagnosticEventClass;
use oneiron::self_heal::detector_pass::{detector_window_key, minted_window_key};
use oneiron::self_heal::distillation::MintedT2;
use oneiron::self_heal::tiered::{DetectorPolicy, ProposedTier};
use oneiron::store::{
    RetrievalAction, RetrievalRunRecord, RetrievalScoreBreakdown, RetrievalScoreComponent,
    RetrievalSignal, RetrievalState,
};
use oneiron::test_doors::fingerprint_keep_self_heal_digests as door;
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_tier {
    // main d28afbfe74de: crates/oneiron/src/self_heal/tiered.rs:42-58
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ProposedTier {
        Centroid,
        PromptClassifier,
        Judge,
        SessionJudge,
    }
    impl ProposedTier {
        pub(super) fn token(self) -> &'static str {
            match self {
                Self::Centroid => "t2a",
                Self::PromptClassifier => "t2b",
                Self::Judge => "t3",
                Self::SessionJudge => "session_judge",
            }
        }
    }
    pub(crate) fn of(tier: oneiron::self_heal::tiered::ProposedTier) -> ProposedTier {
        use oneiron::self_heal::tiered::ProposedTier as Head;
        match tier {
            Head::Centroid => ProposedTier::Centroid,
            Head::PromptClassifier => ProposedTier::PromptClassifier,
            Head::Judge => ProposedTier::Judge,
            Head::SessionJudge => ProposedTier::SessionJudge,
        }
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_blocked {
    // Stand-ins: the receipt's content, as BlockedReceipt::content returns it;
    // the ingested entry; the replay coordinate field main's line writes.
    pub(crate) struct Receipt(pub(crate) String);
    impl Receipt {
        pub(crate) fn content(&self) -> Result<String, ()> {
            Ok(self.0.clone())
        }
    }
    pub(crate) struct Entry {
        pub(crate) receipt: Receipt,
    }
    pub(crate) struct Replay {
        pub(crate) content_hash: [u8; 32],
    }
    pub(crate) fn content_hash(entry: &Entry) -> Result<[u8; 32], ()> {
        Ok(Replay {
            // main d28afbfe74de: crates/oneiron/src/self_heal/blocked_reports.rs:126-126
                            content_hash: *blake3::hash(entry.receipt.content()?.as_bytes()).as_bytes(),
        }
        .content_hash)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_consent {
    // Stand-ins: a queued observation's payload digest; the detector's snapshot time.
    pub(crate) struct Observation {
        pub(crate) payload_digest: [u8; 32],
    }
    pub(crate) struct Detector {
        pub(crate) snapshot_at: u64,
    }
    impl Detector {
        pub(crate) fn content_hash(&self, queued: &[Observation], threshold: u64) -> [u8; 32] {
            let queued: Vec<&Observation> = queued.iter().collect();
            // main d28afbfe74de: crates/oneiron/src/self_heal/consent_depth.rs:142-147
                    let mut hash = blake3::Hasher::new();
                    for o in &queued {
                        hash.update(&o.payload_digest);
                    }
                    hash.update(&self.snapshot_at.to_be_bytes());
                    hash.update(&threshold.to_be_bytes());
            *hash.finalize().as_bytes()
        }
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_detector_pass {
    use super::base_tier::ProposedTier;
    use oneiron::self_heal::tiered::DetectorPolicy;
    use oneiron::store::RetrievalRunRecord;
    // main d28afbfe74de: crates/oneiron/src/self_heal/detector_pass.rs:37-77
    #[must_use]
    pub fn detector_window_key(
        policy: &DetectorPolicy,
        tier: ProposedTier,
        runs: &[&RetrievalRunRecord],
    ) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        for part in [
            tier.token(),
            policy.family.as_str(),
            policy.class.as_str(),
            policy.prompt.as_str(),
            policy.rubric.as_str(),
        ] {
            hash.update(&(part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
        hash.update(&(policy.consecutive as u64).to_be_bytes());
        for run in runs {
            hash.update(&run.run_id.as_bytes());
        }
        *hash.finalize().as_bytes()
    }

    /// The key of one window under a registered T2: its seed's wording at T2b and
    /// the corpus revision it asks with, so a new revision grades it afresh.
    #[must_use]
    pub fn minted_window_key(
        policy: &DetectorPolicy,
        revision: &[u8; 32],
        runs: &[&RetrievalRunRecord],
    ) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(&detector_window_key(
            policy,
            ProposedTier::PromptClassifier,
            runs,
        ));
        hash.update(revision);
        *hash.finalize().as_bytes()
    }
    pub(crate) fn centroid_revision_key(key: &[u8; 32], revision: &[u8; 32]) -> [u8; 32] {
        // main d28afbfe74de: crates/oneiron/src/self_heal/detector_pass.rs:88-92
            let mut hash = blake3::Hasher::new();
            hash.update(ProposedTier::Centroid.token().as_bytes());
            hash.update(key);
            hash.update(revision);
            *hash.finalize().as_bytes()
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_minted {
    use oneiron::self_heal::distillation::MintedT2;
    // main d28afbfe74de: crates/oneiron/src/self_heal/distillation.rs:133-154
    fn minted_revision(minted: &MintedT2) -> [u8; 32] {
        let policy = &minted.policy;
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron.self_heal.minted_t2.v1\0");
        for part in [
            policy.family.as_str(),
            policy.class.as_str(),
            policy.prompt.as_str(),
            policy.rubric.as_str(),
        ] {
            hash.update(&(part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
        hash.update(&(policy.consecutive as u64).to_be_bytes());
        for ids in [&minted.positive_events, &minted.negative_events] {
            hash.update(&(ids.len() as u64).to_be_bytes());
            for id in ids {
                hash.update(id.as_bytes());
            }
        }
        *hash.finalize().as_bytes()
    }
    pub(crate) fn revision(minted: &MintedT2) -> [u8; 32] {
        minted_revision(minted)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_replays {
    use oneiron::store::RetrievalRunRecord;
    use oneiron::{Error, Result};
    pub(crate) fn digest(runs: &[RetrievalRunRecord]) -> Result<[u8; 32]> {
        // main d28afbfe74de: crates/oneiron/src/self_heal/distillation.rs:495-501
            let mut hasher = blake3::Hasher::new();
            for run in runs {
                let bytes = rmp_serde::to_vec_named(run)
                    .map_err(|_| Error::InvariantViolation("retrieval telemetry encode"))?;
                hasher.update(&(bytes.len() as u64).to_be_bytes());
                hasher.update(&bytes);
            }
        Ok(*hasher.finalize().as_bytes())
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_observed {
    use oneiron::self_heal::DiagnosticReplayCoordinate;
    use oneiron::store::RetrievalRunRecord;
    use oneiron::{Error, Result};
    // Stand-in: the three fields of an observed run.
    pub(crate) struct ObservedRun {
        pub(crate) run: [u8; 16],
        pub(crate) replay: [u8; 32],
        pub(crate) started_at: u64,
    }
    // main d28afbfe74de: crates/oneiron/src/self_heal/issue_evidence.rs:251-273
    pub(super) fn observed_window(
        runs: &[RetrievalRunRecord],
    ) -> Result<(Vec<ObservedRun>, DiagnosticReplayCoordinate)> {
        let mut digest = blake3::Hasher::new();
        let mut observed = Vec::with_capacity(runs.len());
        for run in runs {
            let bytes = rmp_serde::to_vec_named(run)
                .map_err(|_| Error::InvariantViolation("retrieval telemetry encode"))?;
            digest.update(&(bytes.len() as u64).to_be_bytes());
            digest.update(&bytes);
            observed.push(ObservedRun {
                run: run.run_id.as_bytes(),
                replay: *blake3::hash(&bytes).as_bytes(),
                started_at: run.started_at,
            });
        }
        let coordinate = DiagnosticReplayCoordinate {
            content_hash: *digest.finalize().as_bytes(),
            run_ref: runs.last().map(|run| run.run_id.to_hex()),
            checkpoint_ref: None,
        };
        Ok((observed, coordinate))
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_tier1 {
    use oneiron::{Error, Result};
    // main d28afbfe74de: crates/oneiron/src/self_heal/tier1_source.rs:55-59
    fn digest<T: serde::Serialize>(value: &T) -> Result<[u8; 32]> {
        let bytes = rmp_serde::to_vec_named(value)
            .map_err(|_| Error::InvariantViolation("tier-1 source encoding failed"))?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }
    pub(crate) fn pin<T: serde::Serialize>(value: &T) -> Result<[u8; 32]> {
        digest(value)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_healer {
    // main d28afbfe74de: crates/oneiron/src/self_heal/healer_host.rs:163-165
    fn run_digest(run: &str) -> [u8; 32] {
        *blake3::hash(run.as_bytes()).as_bytes()
    }
    pub(crate) fn digest(run: &str) -> [u8; 32] {
        run_digest(run)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_wording {
    // Stand-in: the two policy fields main's lines read.
    pub(crate) struct Policy {
        pub(crate) prompt: String,
        pub(crate) rubric: String,
    }
    impl Policy {
        pub(crate) fn digest(&self) -> [u8; 32] {
            // main d28afbfe74de: crates/oneiron/src/self_heal/tiered.rs:124-129
                    let mut hasher = blake3::Hasher::new();
                    for part in [self.prompt.as_str(), self.rubric.as_str()] {
                        hasher.update(&(part.len() as u64).to_be_bytes());
                        hasher.update(part.as_bytes());
                    }
                    let digest = hasher.finalize();
            *digest.as_bytes()
        }
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_recipe {
    use super::base_tier::ProposedTier;
    use oneiron::EntityId;
    use oneiron::self_heal::tiered::DetectorPolicy;
    // main d28afbfe74de: crates/oneiron/src/self_heal/tiered.rs:282-317
    pub(super) fn recipe_revision(
        policy: &DetectorPolicy,
        tier: ProposedTier,
        examples: (&[EntityId], &[EntityId]),
        corpus: Option<&[u8; 32]>,
    ) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(b"oneiron.self_heal.finding_recipe.v1\0");
        for part in [
            tier.token(),
            policy.family.as_str(),
            policy.class.as_str(),
            policy.prompt.as_str(),
            policy.rubric.as_str(),
        ] {
            hash.update(&(part.len() as u64).to_be_bytes());
            hash.update(part.as_bytes());
        }
        hash.update(&(policy.consecutive as u64).to_be_bytes());
        for ids in [examples.0, examples.1] {
            hash.update(&(ids.len() as u64).to_be_bytes());
            for id in ids {
                hash.update(id.as_bytes());
            }
        }
        match corpus {
            Some(revision) => {
                hash.update(&[1]);
                hash.update(revision);
            }
            None => {
                hash.update(&[0]);
            }
        }
        *hash.finalize().as_bytes()
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_window_evidence {
    use oneiron::store::RetrievalRunRecord;
    use oneiron::{EntityId, Error, Result};
    pub(crate) fn evidence(runs: &[RetrievalRunRecord]) -> Result<([u8; 32], Vec<EntityId>)> {
        // main d28afbfe74de: crates/oneiron/src/self_heal/tiered.rs:337-347
            let mut digest = blake3::Hasher::new();
            let mut evidence = Vec::new();
            for run in runs {
                let bytes = rmp_serde::to_vec_named(run)
                    .map_err(|_| Error::InvariantViolation("retrieval telemetry encode"))?;
                digest.update(&(bytes.len() as u64).to_be_bytes());
                digest.update(&bytes);
                evidence.push(EntityId::from_bytes(run.run_id.as_bytes())?);
            }
            evidence.sort();
            evidence.dedup();
        Ok((*digest.finalize().as_bytes(), evidence))
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_context {
    // main d28afbfe74de: crates/oneiron/src/self_heal/tiered.rs:248-252
    /// Folds one asked state's exact bytes into a window's context digest (OF-418 L3).
    fn read_state(context: &mut blake3::Hasher, bytes: &[u8]) {
        context.update(&(bytes.len() as u64).to_be_bytes());
        context.update(bytes);
    }
    // Stand-ins: the window grade's context field and the finding basis's digest.
    pub(crate) struct Grade {
        pub(crate) context: blake3::Hasher,
    }
    pub(crate) struct Basis {
        pub(crate) context_digest: [u8; 32],
    }
    pub(crate) fn digest(states: &[&[u8]]) -> [u8; 32] {
        let mut grade = Grade {
            // main d28afbfe74de: crates/oneiron/src/self_heal/tiered.rs:559-559
                        context: blake3::Hasher::new(),
        };
        for bytes in states {
            read_state(&mut grade.context, bytes);
        }
        Basis {
            // main d28afbfe74de: crates/oneiron/src/self_heal/tiered.rs:661-661
                        context_digest: *grade.context.finalize().as_bytes(),
        }
        .context_digest
    }
}

const TIERS: [ProposedTier; 4] = [
    ProposedTier::Centroid,
    ProposedTier::PromptClassifier,
    ProposedTier::Judge,
    ProposedTier::SessionJudge,
];

fn id(n: u8) -> EntityId {
    let mut bytes = [0x5a; 16];
    bytes[0] = n;
    EntityId::from_bytes(bytes).expect("unreserved entity id")
}

fn texts() -> Vec<String> {
    vec![
        String::new(),
        "ordinary".into(),
        "é 日本 α".into(),
        "a\0b".into(),
        "blocked:{\"category\":\"tool\"}".into(),
        "長x".repeat(600),
    ]
}

fn policy(
    family: &str,
    class: DiagnosticEventClass,
    prompt: &str,
    rubric: &str,
    consecutive: usize,
) -> DetectorPolicy {
    DetectorPolicy {
        family: family.into(),
        class,
        prompt: prompt.into(),
        rubric: rubric.into(),
        consecutive,
    }
}

/// Policies that differ in one field each, plus two that move one byte across
/// the prompt and rubric boundary and a long wording.
fn policies() -> Vec<DetectorPolicy> {
    vec![
        policy(
            "missed_recall",
            DiagnosticEventClass::RetrievalMiss,
            "Did recall miss?",
            "Yes if a known entity is absent.",
            3,
        ),
        policy(
            "missed_recall",
            DiagnosticEventClass::RetrievalMiss,
            "Did recall miss?",
            "Yes if a known entity is absent.",
            4,
        ),
        policy(
            "missed_recall",
            DiagnosticEventClass::ConsentDenied,
            "Did recall miss?",
            "Yes if a known entity is absent.",
            3,
        ),
        policy(
            "stale_pack",
            DiagnosticEventClass::RetrievalMiss,
            "Did recall miss?",
            "Yes if a known entity is absent.",
            3,
        ),
        policy(
            "missed_recall",
            DiagnosticEventClass::RetrievalMiss,
            "ab",
            "c",
            1,
        ),
        policy(
            "missed_recall",
            DiagnosticEventClass::RetrievalMiss,
            "a",
            "bc",
            1,
        ),
        policy(
            "missed_recall",
            DiagnosticEventClass::RetrievalMiss,
            &"長x".repeat(900),
            "é 日本",
            2,
        ),
    ]
}

fn run(seed: u8, started_at: u64, results: &[[u8; 16]]) -> RetrievalRunRecord {
    let mut run_id = [0x5a; 16];
    run_id[0] = seed;
    RetrievalRunRecord {
        version: 0,
        run_id: door::retrieval_run_id(run_id),
        action: RetrievalAction::Pipeline,
        started_at,
        elapsed_us: u64::from(seed) * 10,
        state: RetrievalState {
            result_count: u8::try_from(results.len()).expect("a short result list"),
            ..Default::default()
        },
        policy_trace: None,
        replay_inputs: None,
        turn: None,
        query_expander_id: None,
        dispatch_attempt: None,
        policy_manifest_ref: None,
        policy_manifest_body_hash: None,
        reranker_id: None,
        signals: vec![RetrievalSignal::Text],
        result_ids: results.to_vec(),
        score_breakdown: (1_u32..)
            .zip(results)
            .map(|(rank, result_id)| RetrievalScoreBreakdown {
                result_id: *result_id,
                final_rank: rank,
                final_score: 1.0 / rank as f32,
                components: vec![RetrievalScoreComponent {
                    signal: RetrievalSignal::Relevance,
                    rank,
                    score: 0.5,
                }],
                access_factor: None,
            })
            .collect(),
        total_in_scope: results.len() * 3,
        claims_suppressed: 0,
        empty_reason: results.is_empty().then(|| "no match".to_owned()),
        trace: None,
        quality: None,
        degradation: Vec::new(),
        confidence_adjustment: None,
    }
}

/// Oldest-first windows: empty, one run, two runs in both orders, a repeated
/// run, and runs that differ only in their start or their results.
fn windows() -> Vec<Vec<RetrievalRunRecord>> {
    let a = run(1, 100, &[[0x41; 16]]);
    let b = run(2, 200, &[[0x42; 16], [0x43; 16]]);
    let c = run(3, 300, &[]);
    vec![
        vec![],
        vec![a.clone()],
        vec![a.clone(), b.clone()],
        vec![b.clone(), a.clone()],
        vec![a.clone(), a.clone()],
        vec![a.clone(), b.clone(), c],
        vec![run(1, 101, &[[0x41; 16]])],
        vec![run(1, 100, &[[0x44; 16]])],
    ]
}

#[test]
fn the_purposes_keep_main_s_recipes() {
    // distillation.rs:136 and tiered.rs:289 write their tags inline; their bytes
    // are written out here.
    let recipes: [(LegacyPurpose, LegacyHash, TagMode, &[u8]); 13] = [
        (
            purposes::self_heal::BLOCKED_REPORT_CONTENT,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.self_heal.blocked_report_content.v1",
        ),
        (
            purposes::self_heal::CENTROID_WINDOW,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.self_heal.centroid_window.v1",
        ),
        (
            purposes::self_heal::CONSENT_DEPTH,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.self_heal.consent_depth.v1",
        ),
        (
            purposes::self_heal::DETECTOR_WINDOW,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.self_heal.detector_window.v1",
        ),
        (
            purposes::self_heal::DETECTOR_WORDING,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.self_heal.detector_wording.v1",
        ),
        (
            purposes::self_heal::FINDING_RECIPE,
            LegacyHash::Blake3,
            TagMode::HashedFirst,
            b"oneiron.self_heal.finding_recipe.v1\0",
        ),
        (
            purposes::self_heal::HEALER_RUN,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.self_heal.healer_run.v1",
        ),
        (
            purposes::self_heal::MINTED_T2_REVISION,
            LegacyHash::Blake3,
            TagMode::HashedFirst,
            b"oneiron.self_heal.minted_t2.v1\0",
        ),
        (
            purposes::self_heal::MINTED_WINDOW,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.self_heal.minted_window.v1",
        ),
        (
            purposes::self_heal::OBSERVED_RUN_REPLAY,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.self_heal.observed_run_replay.v1",
        ),
        (
            purposes::self_heal::RETRIEVAL_WINDOW,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.self_heal.retrieval_window.v1",
        ),
        (
            purposes::self_heal::TIER1_SOURCE,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.self_heal.tier1_source.v1",
        ),
        (
            purposes::self_heal::WINDOW_CONTEXT,
            LegacyHash::Blake3,
            TagMode::NotHashed,
            b"oneiron.self_heal.window_context.v1",
        ),
    ];
    for (purpose, hash, mode, tag) in recipes {
        assert_eq!(purpose.tag().as_bytes(), tag);
        assert_eq!(purpose.hash(), hash);
        assert_eq!(purpose.tag_mode(), mode);
    }
}

#[test]
fn blocked_report_contents_keep_main_s_bytes() {
    let mut digests = BTreeSet::new();
    for content in texts() {
        let head = door::blocked_report_content(&content);
        let entry = base_blocked::Entry {
            receipt: base_blocked::Receipt(content),
        };
        assert_eq!(Ok(head), base_blocked::content_hash(&entry));
        digests.insert(head);
    }
    assert_eq!(digests.len(), texts().len());
}

#[test]
fn consent_depths_keep_main_s_bytes() {
    let digest_lists: [&[[u8; 32]]; 5] = [
        &[],
        &[[0x01; 32]],
        &[[0x01; 32], [0x02; 32]],
        &[[0x02; 32], [0x01; 32]],
        &[[0x01; 32], [0x01; 32]],
    ];
    let mut digests = BTreeSet::new();
    let mut rows = 0;
    for list in digest_lists {
        for snapshot_at in [0, 1_700_000_000_000, u64::MAX] {
            for threshold in [1, 10] {
                let head = door::consent_depth_digest(list, snapshot_at, threshold);
                let queued: Vec<base_consent::Observation> = list
                    .iter()
                    .map(|payload_digest| base_consent::Observation {
                        payload_digest: *payload_digest,
                    })
                    .collect();
                let detector = base_consent::Detector { snapshot_at };
                assert_eq!(head, detector.content_hash(&queued, threshold));
                digests.insert(head);
                rows += 1;
            }
        }
    }
    assert_eq!((rows, digests.len()), (30, 30));
}

#[test]
fn detector_window_keys_keep_main_s_bytes() {
    let windows = windows();
    let mut keys = BTreeSet::new();
    let mut rows = 0;
    for policy in &policies() {
        for tier in TIERS {
            for window in &windows {
                let runs: Vec<&RetrievalRunRecord> = window.iter().collect();
                let head = detector_window_key(policy, tier, &runs);
                assert_eq!(
                    head,
                    base_detector_pass::detector_window_key(policy, base_tier::of(tier), &runs)
                );
                keys.insert(head);
                rows += 1;
            }
        }
    }
    // The key reads only run ids: the windows that differ in a run's start or
    // results key alike, so 6 of the 8 windows are distinct per policy and tier.
    assert_eq!((rows, keys.len()), (224, 168));
}

#[test]
fn minted_window_keys_keep_main_s_bytes() {
    let windows = windows();
    let mut keys = BTreeSet::new();
    let mut rows = 0;
    for policy in &policies() {
        for revision in [[0; 32], [0xf0; 32]] {
            for window in &windows {
                let runs: Vec<&RetrievalRunRecord> = window.iter().collect();
                let head = minted_window_key(policy, &revision, &runs);
                assert_eq!(
                    head,
                    base_detector_pass::minted_window_key(policy, &revision, &runs)
                );
                keys.insert(head);
                rows += 1;
            }
        }
    }
    assert_eq!((rows, keys.len()), (112, 84));
}

#[test]
fn centroid_window_keys_keep_main_s_bytes() {
    let mut keys = BTreeSet::new();
    for key in [[0; 32], [0x11; 32], [0xff; 32]] {
        for revision in [[0; 32], [0x22; 32], [0xee; 32]] {
            let head = door::centroid_window(&key, &revision);
            assert_eq!(
                head,
                base_detector_pass::centroid_revision_key(&key, &revision)
            );
            keys.insert(head);
        }
    }
    assert_eq!(keys.len(), 9);
}

#[test]
fn minted_revisions_keep_main_s_bytes() {
    let example_sets: [(Vec<EntityId>, Vec<EntityId>); 5] = [
        (vec![], vec![]),
        (vec![id(1)], vec![]),
        (vec![], vec![id(1)]),
        (vec![id(1), id(2)], vec![id(3)]),
        (vec![id(2), id(1)], vec![id(3)]),
    ];
    let mut revisions = BTreeSet::new();
    let mut rows = 0;
    for policy in policies() {
        for (positive, negative) in &example_sets {
            let minted = MintedT2 {
                policy: policy.clone(),
                positive_events: positive.clone(),
                negative_events: negative.clone(),
            };
            let head = minted.revision();
            assert_eq!(head, base_minted::revision(&minted));
            revisions.insert(head);
            rows += 1;
        }
    }
    assert_eq!((rows, revisions.len()), (35, 35));
}

#[test]
fn retrieval_window_digests_keep_main_s_bytes() {
    let windows = windows();
    let mut digests = BTreeSet::new();
    for window in &windows {
        let main = base_replays::digest(window).expect("main window digest");
        assert_eq!(door::replays_digest(window).expect("window digest"), main);
        // The observed window's coordinate and a model finding's replay hash
        // are the same digest at main.
        let (_, coordinate) = base_observed::observed_window(window).expect("main observed window");
        assert_eq!(coordinate.content_hash, main);
        let (finding, _) = base_window_evidence::evidence(window).expect("main window evidence");
        assert_eq!(finding, main);
        let (_, observed, _) = door::observed_window(window).expect("observed window");
        assert_eq!(observed, main);
        let (finding, _) = door::window_evidence(window).expect("window evidence");
        assert_eq!(finding, main);
        digests.insert(main);
    }
    assert_eq!(digests.len(), windows.len());
}

#[test]
fn observed_runs_keep_main_s_bytes() {
    let mut replays = BTreeSet::new();
    for window in &windows() {
        let (runs, _, run_ref) = door::observed_window(window).expect("observed window");
        let (main_runs, coordinate) =
            base_observed::observed_window(window).expect("main observed window");
        let main_runs: Vec<([u8; 16], [u8; 32], u64)> = main_runs
            .into_iter()
            .map(|run| (run.run, run.replay, run.started_at))
            .collect();
        assert_eq!(runs, main_runs);
        assert_eq!(run_ref, coordinate.run_ref);
        assert_eq!(coordinate.checkpoint_ref, None);
        replays.extend(runs.iter().map(|run| run.1));
    }
    // Five distinct records: a, b, c and the two variants of a.
    assert_eq!(replays.len(), 5);
}

#[test]
fn window_evidence_keeps_main_s_ids() {
    for window in &windows() {
        let (_, evidence) = door::window_evidence(window).expect("window evidence");
        let (_, main) = base_window_evidence::evidence(window).expect("main window evidence");
        assert_eq!(evidence, main);
    }
}

#[test]
fn tier1_source_pins_keep_main_s_bytes() {
    let mut pins = BTreeSet::new();
    let mut rows = 0;
    for window in windows() {
        for record in &window {
            let head = door::tier1_source_digest(record).expect("source pin");
            assert_eq!(head, base_tier1::pin(record).expect("main source pin"));
            pins.insert(head);
            rows += 1;
        }
    }
    for text in texts() {
        let head = door::tier1_source_digest(&text).expect("text pin");
        assert_eq!(head, base_tier1::pin(&text).expect("main text pin"));
        pins.insert(head);
        rows += 1;
    }
    let pair = (7_u64, vec![[0x31_u8; 16]], Some("receipt".to_owned()));
    let head = door::tier1_source_digest(&pair).expect("pair pin");
    assert_eq!(head, base_tier1::pin(&pair).expect("main pair pin"));
    pins.insert(head);
    rows += 1;
    // 12 record copies over 5 distinct records, 6 texts and one tuple.
    assert_eq!((rows, pins.len()), (19, 12));
}

#[test]
fn healer_run_digests_keep_main_s_bytes() {
    let mut digests = BTreeSet::new();
    for run in texts() {
        let head = door::healer_run(&run);
        assert_eq!(head, base_healer::digest(&run));
        digests.insert(head);
    }
    assert_eq!(digests.len(), texts().len());
}

#[test]
fn detector_wordings_keep_main_s_bytes() {
    let mut digests = BTreeSet::new();
    let mut rows = 0;
    for prompt in texts() {
        for rubric in ["", "ab", "Yes if a known entity is absent."] {
            let head = door::detector_wording(&prompt, rubric);
            let policy = base_wording::Policy {
                prompt: prompt.clone(),
                rubric: rubric.into(),
            };
            assert_eq!(head, policy.digest());
            digests.insert(head);
            rows += 1;
        }
    }
    // The length prefixes keep ("ab", "c") and ("a", "bc") apart.
    let split = door::detector_wording("ab", "c");
    assert_ne!(split, door::detector_wording("a", "bc"));
    assert_eq!(
        split,
        base_wording::Policy {
            prompt: "ab".into(),
            rubric: "c".into(),
        }
        .digest()
    );
    assert_eq!((rows, digests.len()), (18, 18));
}

#[test]
fn finding_recipes_keep_main_s_bytes() {
    let example_sets: [(Vec<EntityId>, Vec<EntityId>); 4] = [
        (vec![], vec![]),
        (vec![id(1)], vec![]),
        (vec![], vec![id(1)]),
        (vec![id(1), id(2)], vec![id(3)]),
    ];
    let corpora: [Option<[u8; 32]>; 3] = [None, Some([0; 32]), Some([0x5c; 32])];
    let mut revisions = BTreeSet::new();
    let mut rows = 0;
    for policy in &policies() {
        for tier in TIERS {
            for (positive, negative) in &example_sets {
                for corpus in &corpora {
                    let head =
                        door::finding_recipe(policy, tier, positive, negative, corpus.as_ref());
                    let main = base_recipe::recipe_revision(
                        policy,
                        base_tier::of(tier),
                        (positive, negative),
                        corpus.as_ref(),
                    );
                    assert_eq!(head, main);
                    revisions.insert(head);
                    rows += 1;
                }
            }
        }
    }
    assert_eq!((rows, revisions.len()), (336, 336));
}

#[test]
fn window_contexts_keep_main_s_bytes() {
    let state_lists: [&[&[u8]]; 6] = [
        &[],
        &[b""],
        &[b"{\"target\":1}"],
        &[b"{\"target\":1}", b"{\"target\":2}"],
        &[b"{\"target\":2}", b"{\"target\":1}"],
        &[b"ab", b"c"],
    ];
    let mut digests = BTreeSet::new();
    for states in state_lists {
        let head = door::window_context(states);
        assert_eq!(head, base_context::digest(states));
        digests.insert(head);
    }
    let split: &[&[u8]] = &[b"a", b"bc"];
    let joined: &[&[u8]] = &[b"ab", b"c"];
    assert_ne!(door::window_context(split), door::window_context(joined));
    assert_eq!(digests.len(), state_lists.len());
}
