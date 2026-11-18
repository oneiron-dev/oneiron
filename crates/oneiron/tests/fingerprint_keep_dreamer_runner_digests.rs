//! K-proof for dreamer-runner legacy digests at b1897bd53d07: existing stored and
//! compared identities keep main's bytes through the fingerprint K door.
//!
//! The maintenance queue stores the Coach ask's dedupe key and the wake-key
//! dedupe keys of the policy-author, honesty-audit and stewardship queues.
//! review_state rows and card outcomes store the health_review receipt id. A
//! grant-environment proposal stores its terms digest, and landing compares it
//! with the rebuilt terms. WORK stores and finds a blocked report's code-fix
//! work by its key. The digest-assess queue, its witnesses and STATE store the
//! harm basis; the host-built assessment queue stores the host witness key.
//! SUGGESTED, JOURNAL and DECLARED store and compare the fold-default, upkeep
//! evidence and room source states. STEP keys turn-program rows by step id and
//! settles an outbound step with its result digest. Replay capsules store the
//! route prompt digest and compare it with the route pin.
//!
//! The base modules copy exact main lines. Inline hash blocks have hand-written
//! headers and returns. Stand-ins hold only what main's lines read: the health
//! card's fields, the team receipt's fields, the outbound record's payload hash,
//! a body whose reader is its bytes, and the grant encoder (the encoded body is
//! the input). The policy-author facet keeps main's value line under a
//! hand-written header: its `pub(in ...)` visibility names a module this crate
//! lacks.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test fingerprint_keep_dreamer_runner_digests`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};

use oneiron::EntityId;
use oneiron::dreamer_runner::maintenance::agent_health::HealthBriefPin;
use oneiron::dreamer_runner::maintenance::digest::{
    DigestHarmCandidate, DigestHarmResult, DigestNeededBefore, DigestVersionRef,
};
use oneiron::store::diagnostic_record::AgentHealthSignal;
use oneiron::team::TeamPattern;
use oneiron::test_doors::fingerprint_keep_dreamer_runner_digests::{self as door, UpkeepTeam};
use oneiron::workspace_roster::RoomUpkeepInput;
use oneiron_contracts::fingerprint::{LegacyHash, LegacyPurpose, TagMode, purposes};

// Main's copied host-witness lines name this path.
mod entity_id {
    pub(crate) use oneiron_contracts::entity_id::bytes_to_hex_lower;
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_ask {
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/agent_health/ask.rs:35-35
    pub const COACH_AGENT_HEALTH_ASK_FACET: &str = "coach.agent_health_ask";
    pub(crate) fn key(handle: &str, at: u64) -> String {
        // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/agent_health/ask.rs:161-163
            let mut dedupe = blake3::Hasher::new();
            dedupe.update(handle.as_bytes());
            dedupe.update(&at.to_le_bytes());
        format!(
            // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/agent_health/ask.rs:173-174
                        "{COACH_AGENT_HEALTH_ASK_FACET}:{}",
                        dedupe.finalize().to_hex()
        )
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_review {
    use oneiron::EntityId;
    use oneiron::dreamer_runner::maintenance::agent_health::HealthBriefPin;
    use oneiron::store::diagnostic_record::AgentHealthSignal;
    use oneiron_verb_wire::dreamer_runner::maintenance::agent_health::vocabulary::card_key;
    // main b1897bd53d07: crates/oneiron/src/skill/health_review.rs:12-12
    pub const HEALTH_REVIEW_RECEIPT_PREFIX: &str = "health_review:";
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/agent_health/outcomes.rs:42-42
    const REVIEW_STATE_DOMAIN: &[u8] = b"oneiron.coach.agent_health.review_state.v1";
    // Stand-in: the card fields main's id reads.
    pub(crate) struct AgentHealthCard {
        pub(crate) subject: EntityId,
        pub(crate) signal: AgentHealthSignal,
        pub(crate) task: Option<EntityId>,
        pub(crate) reviewer: String,
        pub(crate) diagnostics: Vec<EntityId>,
        pub(crate) evidence: Vec<EntityId>,
        pub(crate) observed_brief: Option<HealthBriefPin>,
    }
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/agent_health/outcomes.rs:117-149
    fn review_state_id(card: &AgentHealthCard) -> String {
        let (subject, signal, task) = card_key(card.subject, card.signal, card.task);
        let mut hasher = blake3::Hasher::new();
        hasher.update(REVIEW_STATE_DOMAIN);
        hasher.update(&subject);
        hasher.update(&signal);
        hasher.update(&task);
        hasher.update(&(card.reviewer.len() as u64).to_le_bytes());
        hasher.update(card.reviewer.as_bytes());
        for ids in [&card.diagnostics, &card.evidence] {
            let mut sorted: Vec<&EntityId> = ids.iter().collect();
            sorted.sort_unstable();
            hasher.update(&(sorted.len() as u64).to_le_bytes());
            for id in sorted {
                hasher.update(id.as_bytes());
            }
        }
        match &card.observed_brief {
            Some(pin) => {
                hasher.update(&[1_u8]);
                hasher.update(pin.task.as_bytes());
                hasher.update(&pin.rev.to_le_bytes());
                hasher.update(pin.digest.as_bytes());
            }
            None => {
                hasher.update(&[0_u8]);
            }
        }
        format!(
            "{HEALTH_REVIEW_RECEIPT_PREFIX}{}",
            hasher.finalize().to_hex()
        )
    }
    pub(crate) fn id(card: &AgentHealthCard) -> String { review_state_id(card) }
    pub(crate) fn tag() -> &'static [u8] { REVIEW_STATE_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_grant {
    // Stand-in: the encoded grant body is the input.
    fn encode_access_grant_body(grant: &[u8]) -> oneiron::Result<Vec<u8>> { Ok(grant.to_vec()) }
    pub(crate) fn terms(grant: &[u8]) -> oneiron::Result<[u8; 32]> {
        // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/coach_environment.rs:69-69
            let terms_digest = *blake3::hash(&encode_access_grant_body(&grant)?).as_bytes();
        Ok(terms_digest)
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_blocked {
    use oneiron::EntityId;
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/code_fix.rs:91-91
    const BLOCKED_WORK_DOMAIN: &[u8] = b"oneiron.code-fix.blocked.v1\0";
    pub(crate) fn key(receipt: &EntityId) -> oneiron::Result<EntityId> {
        // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/code_fix/work.rs:36-41
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(BLOCKED_WORK_DOMAIN);
                    hasher.update(receipt.as_bytes());
                    let mut key = [0; 16];
                    key.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
                    Ok(EntityId::from_bytes(key)?)
    }
    pub(crate) fn tag() -> &'static [u8] { BLOCKED_WORK_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_wake_policy {
    const PROACTIVITY_POLICY_FACET: &str =
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/digest/policy_author.rs:9-9
        "dreamer.digest.policy";
    pub(crate) fn key(key: &str) -> String {
        format!(
            // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/digest/policy_author.rs:30-31
                                "{PROACTIVITY_POLICY_FACET}:{}",
                                blake3::hash(key.as_bytes()).to_hex()
        )
    }
    pub(crate) fn facet() -> &'static str { PROACTIVITY_POLICY_FACET }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_wake_honesty {
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/honesty.rs:12-12
    pub const HONESTY_AUDIT_FACET: &str = "coach.honesty_audits";
    pub(crate) fn key(key: &str) -> String {
        format!(
            // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/honesty.rs:33-34
                                "{HONESTY_AUDIT_FACET}:{}",
                                blake3::hash(key.as_bytes()).to_hex()
        )
    }
    pub(crate) fn facet() -> &'static str { HONESTY_AUDIT_FACET }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_wake_stewardship {
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/stewardship.rs:45-45
    pub const STEWARDSHIP_FACET: &str = "dreamer.stewardship";
    pub(crate) fn key(key: &str) -> String {
        format!(
            // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/stewardship.rs:416-417
                                "{STEWARDSHIP_FACET}:{}",
                                blake3::hash(key.as_bytes()).to_hex()
        )
    }
    pub(crate) fn facet() -> &'static str { STEWARDSHIP_FACET }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_urgent {
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/digest/urgent.rs:50-50
    pub const DIGEST_URGENT_FACET: &str = "dreamer.digest.urgent";
    pub(crate) fn basis(json: &[u8], question: &str) -> oneiron::Result<[u8; 32]> {
        // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/digest/urgent.rs:95-100
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"oneiron:digest-harm:v1");
                hasher.update(&(json.len() as u64).to_be_bytes());
                hasher.update(&json);
                hasher.update(question.as_bytes());
                Ok(*hasher.finalize().as_bytes())
    }
    pub(crate) fn host(json: &[u8]) -> oneiron::Result<String> {
        // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/digest/urgent.rs:459-466
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"oneiron:digest-harm-host:v1");
            hasher.update(&(json.len() as u64).to_be_bytes());
            hasher.update(&json);
            Ok(format!(
                "{DIGEST_URGENT_FACET}:host:{}",
                crate::entity_id::bytes_to_hex_lower(hasher.finalize().as_bytes())
            ))
    }
}

#[rustfmt::skip]
#[allow(unreachable_pub, dead_code)]
mod base_fold {
    use oneiron::EntityId;
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/fold_suggestions.rs:44-44
    const STATE_DOMAIN: &[u8] = b"oneiron:coach-fold-suggestions:v1";
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/fold_suggestions.rs:76-86
    /// One suggested fold default.
    struct FoldSuggestion {
        kind: &'static str,
        /// Fold this kind once it is this many steps old; `None` when no kept
        /// fold recorded the step it was marked at.
        keep_last_steps: Option<u64>,
        median_span_steps: u64,
        runs: usize,
        folds: u64,
        unfolded: u64,
    }
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/fold_suggestions.rs:231-243
    /// A hash of the defaults themselves, never of the counts behind them.
    fn suggestion_state(definition: EntityId, suggestions: &[FoldSuggestion]) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(STATE_DOMAIN);
        hash.update(definition.as_bytes());
        for suggestion in suggestions {
            hash.update(suggestion.kind.as_bytes());
            hash.update(&[0]);
            hash.update(&suggestion.keep_last_steps.unwrap_or(u64::MAX).to_be_bytes());
            hash.update(&suggestion.median_span_steps.to_be_bytes());
        }
        *hash.finalize().as_bytes()
    }
    pub(crate) fn state(definition: EntityId, rows: &[(&'static str, Option<u64>, u64)]) -> [u8; 32] {
        let suggestions: Vec<FoldSuggestion> = rows.iter().map(|&(kind, keep_last_steps, median_span_steps)| FoldSuggestion { kind, keep_last_steps, median_span_steps, runs: 0, folds: 0, unfolded: 0 }).collect();
        suggestion_state(definition, &suggestions)
    }
    pub(crate) fn tag() -> &'static [u8] { STATE_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_room {
    use oneiron::workspace_roster::RoomUpkeepInput;
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/room_upkeep.rs:42-42
    const STATE_DOMAIN: &[u8] = b"oneiron:coach-room-upkeep-summary:v1";
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/room_upkeep.rs:308-317
    /// The room and the turns in the Coach's reach there, as one hash.
    fn source_state(input: &RoomUpkeepInput) -> [u8; 32] {
        let mut hash = blake3::Hasher::new();
        hash.update(STATE_DOMAIN);
        hash.update(input.room.as_bytes());
        for turn in &input.source_refs {
            hash.update(turn.as_bytes());
        }
        *hash.finalize().as_bytes()
    }
    pub(crate) fn state(input: &RoomUpkeepInput) -> [u8; 32] { source_state(input) }
    pub(crate) fn tag() -> &'static [u8] { STATE_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_upkeep {
    use std::collections::BTreeMap;
    use oneiron::team::TeamPattern;
    // Stand-ins: the receipt fields main's digest reads.
    pub(crate) struct TypeRef { pub(crate) node_id: String, pub(crate) tree_version: u64 }
    pub(crate) struct TeamOutcome { pub(crate) success: bool }
    pub(crate) struct TeamReceipt {
        pub(crate) team_ref: String,
        pub(crate) type_ref: TypeRef,
        pub(crate) pattern: TeamPattern,
        pub(crate) models: Vec<String>,
        pub(crate) outcome: Option<TeamOutcome>,
        pub(crate) at: u64,
    }
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/fork_promote/project_upkeep/state.rs:24-24
    const EVIDENCE_DOMAIN: &[u8] = b"oneiron:project-tree-upkeep:evidence:v1\0";
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/maintenance/fork_promote/project_upkeep/state.rs:116-153
    pub(super) fn evidence_digest(teams: &[TeamReceipt], tasks: &BTreeMap<String, String>) -> [u8; 32] {
        let settled: BTreeMap<&str, &TeamReceipt> = teams
            .iter()
            .filter(|team| team.outcome.is_some())
            .map(|team| (team.team_ref.as_str(), team))
            .collect();
        let mut hasher = blake3::Hasher::new();
        hasher.update(EVIDENCE_DOMAIN);
        for (team_ref, team) in settled {
            field(&mut hasher, team_ref.as_bytes());
            field(&mut hasher, team.type_ref.node_id.as_bytes());
            hasher.update(&team.type_ref.tree_version.to_be_bytes());
            field(&mut hasher, team.pattern.as_str().as_bytes());
            hasher.update(&(team.models.len() as u64).to_be_bytes());
            for model in &team.models {
                field(&mut hasher, model.as_bytes());
            }
            let success = team.outcome.as_ref().is_some_and(|outcome| outcome.success);
            hasher.update(&[u8::from(success)]);
            hasher.update(&team.at.to_be_bytes());
            match tasks.get(team_ref) {
                Some(task) => {
                    hasher.update(&[1]);
                    field(&mut hasher, task.as_bytes());
                }
                None => {
                    hasher.update(&[0]);
                }
            }
        }
        *hasher.finalize().as_bytes()
    }

    /// One length-prefixed field of the digest.
    fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
        hasher.update(&(bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    pub(crate) fn evidence(teams: &[TeamReceipt], tasks: &BTreeMap<String, String>) -> [u8; 32] { evidence_digest(teams, tasks) }
    pub(crate) fn tag() -> &'static [u8] { EVIDENCE_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_step {
    use oneiron::{EntityId, Result};
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/program/run.rs:43-43
    const STEP_DOMAIN: &[u8] = b"oneiron:dreamer:turn-program-step:v1";
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/program/run.rs:188-198
    fn step_id(parts: &[&[u8]]) -> Result<EntityId> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(STEP_DOMAIN);
        for part in parts {
            hasher.update(&(part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        EntityId::from_bytes(bytes)
    }
    // Stand-ins: the outbound record's payload hash, and a body whose reader is its bytes.
    struct Record { payload_hash: [u8; 32] }
    struct Body(Vec<u8>);
    impl Body { fn reader(&self) -> &[u8] { &self.0 } }
    pub(crate) fn outbound(payload_hash: [u8; 32], body: Option<Vec<u8>>) -> Result<[u8; 32]> {
        let record = Record { payload_hash };
        let body = body.map(Body);
        // main b1897bd53d07: crates/oneiron/src/dreamer_runner/program/run.rs:505-510
                let mut hasher = blake3::Hasher::new();
                hasher.update(STEP_DOMAIN).update(&record.payload_hash);
                if let Some(body) = &body {
                    hasher.update_reader(body.reader())?;
                }
                let result_digest = *hasher.finalize().as_bytes();
        Ok(result_digest)
    }
    pub(crate) fn id(parts: &[&[u8]]) -> Result<EntityId> { step_id(parts) }
    pub(crate) fn tag() -> &'static [u8] { STEP_DOMAIN }
}

#[rustfmt::skip]
#[allow(unreachable_pub)]
mod base_route {
    // main b1897bd53d07: crates/oneiron/src/dreamer_runner/step_replay.rs:50-55
    #[must_use]
    pub fn route_prompt_digest(prompt: Option<&str>) -> [u8; 32] {
        // A string always encodes as JSON; nothing here can fail.
        let json = serde_json::to_vec(&prompt).unwrap_or_default();
        *blake3::hash(&json).as_bytes()
    }
}

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
        " \t\n".into(),
        "長x".repeat(600),
    ]
}

fn byte_rows() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0],
        b"ab".to_vec(),
        "é 日本".as_bytes().to_vec(),
        b"{\"kind\":\"grant\"}".to_vec(),
        "長x".repeat(600).into_bytes(),
        vec![0xa5; 70_000],
    ]
}

#[test]
fn the_purposes_keep_main_s_recipes() {
    // urgent.rs:96 and :460 write their tags inline; their bytes are written out here.
    let recipes: [(LegacyPurpose, TagMode, &[u8]); 12] = [
        (
            purposes::dreamer_runner::AGENT_HEALTH_REVIEW_STATE,
            TagMode::HashedFirst,
            base_review::tag(),
        ),
        (
            purposes::dreamer_runner::COACH_ASK_DEDUPE,
            TagMode::NotHashed,
            b"oneiron.dreamer_runner.coach_ask_dedupe.v1",
        ),
        (
            purposes::dreamer_runner::CODE_FIX_BLOCKED_WORK,
            TagMode::HashedFirst,
            base_blocked::tag(),
        ),
        (
            purposes::dreamer_runner::DIGEST_HARM_BASIS,
            TagMode::HashedFirst,
            b"oneiron:digest-harm:v1",
        ),
        (
            purposes::dreamer_runner::DIGEST_HARM_HOST_WITNESS,
            TagMode::HashedFirst,
            b"oneiron:digest-harm-host:v1",
        ),
        (
            purposes::dreamer_runner::ENVIRONMENT_GRANT_TERMS,
            TagMode::NotHashed,
            b"oneiron.dreamer_runner.environment_grant_terms.v1",
        ),
        (
            purposes::dreamer_runner::FOLD_SUGGESTION_STATE,
            TagMode::HashedFirst,
            base_fold::tag(),
        ),
        (
            purposes::dreamer_runner::MAINTENANCE_WAKE_KEY,
            TagMode::NotHashed,
            b"oneiron.dreamer_runner.maintenance_wake_key.v1",
        ),
        (
            purposes::dreamer_runner::PROJECT_TREE_UPKEEP_EVIDENCE,
            TagMode::HashedFirst,
            base_upkeep::tag(),
        ),
        (
            purposes::dreamer_runner::ROOM_UPKEEP_SOURCE_STATE,
            TagMode::HashedFirst,
            base_room::tag(),
        ),
        (
            purposes::dreamer_runner::ROUTE_PROMPT,
            TagMode::NotHashed,
            b"oneiron.dreamer_runner.route_prompt.v1",
        ),
        (
            purposes::dreamer_runner::TURN_PROGRAM_STEP,
            TagMode::HashedFirst,
            base_step::tag(),
        ),
    ];
    for (purpose, mode, tag) in recipes {
        assert_eq!(purpose.tag().as_bytes(), tag);
        assert_eq!(purpose.hash(), LegacyHash::Blake3);
        assert_eq!(purpose.tag_mode(), mode);
    }
    assert_eq!(
        purposes::dreamer_runner::CODE_FIX_BLOCKED_WORK
            .tag()
            .as_bytes()
            .last(),
        Some(&0)
    );
    assert_eq!(
        purposes::dreamer_runner::PROJECT_TREE_UPKEEP_EVIDENCE
            .tag()
            .as_bytes()
            .last(),
        Some(&0)
    );
}

#[test]
fn coach_ask_dedupe_keeps_main_s_bytes() {
    let mut keys = BTreeSet::new();
    let mut rows = 0;
    for handle in texts()
        .iter()
        .chain([&format!("health:{}", "0f".repeat(16))])
    {
        for at in [0, 1, 1_700_000_000, u64::MAX] {
            let head = door::coach_ask_dedupe(handle, at);
            assert_eq!(head, base_ask::key(handle, at));
            assert!(head.starts_with(&format!("{}:", base_ask::COACH_AGENT_HEALTH_ASK_FACET)));
            keys.insert(head);
            rows += 1;
        }
    }
    assert_eq!((rows, keys.len()), (28, 28));
}

#[test]
fn agent_health_review_state_keeps_main_s_bytes() {
    let pin = |task, rev, digest: &str, observed_at| HealthBriefPin {
        task,
        rev,
        digest: digest.to_owned(),
        observed_at,
    };
    let pins = [
        None,
        Some(pin(id(7), 0, "", 0)),
        Some(pin(id(8), u32::MAX, &"ab".repeat(32), u64::MAX)),
    ];
    let lists: Vec<Vec<EntityId>> = vec![
        vec![],
        vec![id(1)],
        vec![id(3), id(1), id(2)],
        vec![id(2), id(2)],
    ];
    let reviewers = [
        "".to_owned(),
        "coach.agent_health.loop.v1".to_owned(),
        "é 日本 α".to_owned(),
        "長x".repeat(600),
    ];
    let mut ids = BTreeSet::new();
    let mut rows = 0;
    for signal in AgentHealthSignal::all() {
        for task in [None, Some(id(9))] {
            for reviewer in &reviewers {
                for diagnostics in &lists {
                    for evidence in &lists {
                        for observed in &pins {
                            let head = door::agent_health_review_state(
                                id(5),
                                signal,
                                task,
                                reviewer,
                                diagnostics,
                                evidence,
                                observed.as_ref(),
                            );
                            let card = base_review::AgentHealthCard {
                                subject: id(5),
                                signal,
                                task,
                                reviewer: reviewer.clone(),
                                diagnostics: diagnostics.clone(),
                                evidence: evidence.clone(),
                                observed_brief: observed.clone(),
                            };
                            assert_eq!(head, base_review::id(&card));
                            assert!(head.starts_with(base_review::HEALTH_REVIEW_RECEIPT_PREFIX));
                            ids.insert(head);
                            rows += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!((rows, ids.len()), (3072, 3072));
    // Main sorts both lists and leaves the pin's observation time out.
    let state = |diagnostics: &[EntityId], observed: Option<&HealthBriefPin>| {
        door::agent_health_review_state(
            id(5),
            AgentHealthSignal::Loop,
            None,
            "r",
            diagnostics,
            &[],
            observed,
        )
    };
    assert_eq!(
        state(&[id(3), id(1), id(2)], None),
        state(&[id(1), id(2), id(3)], None)
    );
    let later = pin(id(7), 0, "", 9);
    assert_eq!(state(&[], pins[1].as_ref()), state(&[], Some(&later)));
}

#[test]
fn environment_grant_terms_keeps_main_s_bytes() {
    let rows = byte_rows();
    let mut digests = BTreeSet::new();
    for encoded in &rows {
        let head = door::environment_grant_terms(encoded);
        assert_eq!(head, base_grant::terms(encoded).expect("main digest"));
        digests.insert(head);
    }
    assert_eq!(digests.len(), rows.len());
}

#[test]
fn code_fix_blocked_work_keeps_main_s_bytes() {
    let mut keys = BTreeSet::new();
    let receipts = [
        id(1),
        id(2),
        id(0x7f),
        id(0xfe),
        EntityId::from_bytes([0x01; 16]).expect("unreserved entity id"),
    ];
    for receipt in &receipts {
        let head = door::code_fix_blocked_work(receipt).expect("head key");
        assert_eq!(head, base_blocked::key(receipt).expect("main key"));
        keys.insert(*head.as_bytes());
    }
    assert_eq!(keys.len(), receipts.len());
}

#[test]
fn maintenance_wake_keys_keep_main_s_bytes() {
    let sites: [(&str, fn(&str) -> String); 3] = [
        (base_wake_policy::facet(), base_wake_policy::key),
        (base_wake_honesty::facet(), base_wake_honesty::key),
        (base_wake_stewardship::facet(), base_wake_stewardship::key),
    ];
    let mut keys = BTreeSet::new();
    let mut rows = 0;
    for (facet, base) in sites {
        for key in texts().iter().chain([&"wake:due:2026-11-16".to_owned()]) {
            let head = door::maintenance_wake_key(facet, key);
            assert_eq!(head, base(key));
            assert!(head.starts_with(&format!("{facet}:")));
            keys.insert(head);
            rows += 1;
        }
    }
    assert_eq!((rows, keys.len()), (21, 21));
}

fn candidates() -> Vec<DigestHarmCandidate> {
    let version = |n| DigestVersionRef {
        claim_ref: id(n),
        body_hash: [n; 32],
    };
    let result = |n, group: &str| DigestHarmResult {
        claim_ref: id(n),
        revision: [n; 32],
        group: group.to_owned(),
    };
    vec![
        DigestHarmCandidate {
            recipient: id(1),
            intent: version(2),
            result: result(3, ""),
            needed_before: None,
            next_regular_at: 0,
            period_secs: 0,
        },
        DigestHarmCandidate {
            recipient: id(4),
            intent: version(5),
            result: result(6, "é 日本"),
            needed_before: Some(DigestNeededBefore {
                at_unix_secs: u64::MAX,
                source_ref: id(7),
                source_body_hash: [0xff; 32],
            }),
            next_regular_at: u64::MAX,
            period_secs: 86_400,
        },
    ]
}

#[test]
fn digest_harm_basis_keeps_main_s_bytes() {
    let questions = texts();
    let mut digests = BTreeSet::new();
    let mut rows = 0;
    for json in byte_rows() {
        for question in &questions {
            let head = door::digest_harm_basis(&json, question);
            assert_eq!(
                head,
                base_urgent::basis(&json, question).expect("main basis")
            );
            digests.insert(head);
            rows += 1;
        }
    }
    assert_eq!((rows, digests.len()), (42, 42));
    assert_ne!(
        door::digest_harm_basis(b"ab", "c"),
        door::digest_harm_basis(b"a", "bc")
    );
    // The public path: a candidate's basis is the same digest over its JSON.
    for candidate in candidates() {
        let json = serde_json::to_vec(&candidate).expect("candidate JSON");
        for question in &questions {
            assert_eq!(
                candidate.basis(question).expect("head basis"),
                base_urgent::basis(&json, question).expect("main basis")
            );
        }
    }
}

#[test]
fn digest_harm_host_witness_keeps_main_s_bytes() {
    let rows = byte_rows();
    let mut keys = BTreeSet::new();
    for json in &rows {
        let head = door::digest_harm_host_witness(json);
        assert_eq!(head, base_urgent::host(json).expect("main key"));
        assert!(head.starts_with(&format!("{}:host:", base_urgent::DIGEST_URGENT_FACET)));
        keys.insert(head);
    }
    assert_eq!(keys.len(), rows.len());
}

#[test]
fn fold_suggestion_state_keeps_main_s_bytes() {
    let long: &'static str = "長x".repeat(600).leak();
    let lists: Vec<Vec<(&'static str, Option<u64>, u64)>> = vec![
        vec![],
        vec![("tool_output", None, 0)],
        vec![("tool_output", Some(0), u64::MAX)],
        vec![("tool_output", Some(u64::MAX), 3)],
        vec![("", Some(4), 5), ("é 日本", None, 6)],
        vec![("é 日本", None, 6), ("", Some(4), 5)],
        vec![(long, Some(1), 2), ("a\0b", Some(1), 2)],
        vec![("ab", Some(1), 2)],
        vec![("a", Some(1), 2)],
    ];
    let mut states = BTreeSet::new();
    let mut rows = 0;
    for definition in [id(1), id(2)] {
        for list in &lists {
            let head = door::fold_suggestion_state(definition, list);
            assert_eq!(head, base_fold::state(definition, list));
            states.insert(head);
            rows += 1;
        }
    }
    assert_eq!((rows, states.len()), (18, 18));
    // Main writes an absent keep_last_steps as u64::MAX.
    assert_eq!(
        door::fold_suggestion_state(id(1), &[("k", None, 1)]),
        door::fold_suggestion_state(id(1), &[("k", Some(u64::MAX), 1)])
    );
}

#[test]
fn room_upkeep_source_state_keeps_main_s_bytes() {
    let turns: Vec<Vec<EntityId>> = vec![
        vec![],
        vec![id(2)],
        vec![id(2), id(3)],
        vec![id(3), id(2)],
        vec![id(2), id(2)],
        (1..=200).map(id).collect(),
    ];
    let mut states = BTreeSet::new();
    let mut rows = 0;
    for room in [id(1), id(9)] {
        for source_refs in &turns {
            for last_activity in [None, Some(0), Some(u64::MAX)] {
                let input = RoomUpkeepInput {
                    room,
                    source_refs: source_refs.clone(),
                    last_activity,
                    threads: Vec::new(),
                };
                let head = door::room_upkeep_source_state(&input);
                assert_eq!(head, base_room::state(&input));
                states.insert(head);
                rows += 1;
            }
        }
    }
    // The newest-activity time and the threads never enter the state.
    assert_eq!((rows, states.len()), (36, 12));
}

/// One team, built both as the door reads it and as main's stand-in receipt.
#[derive(Clone)]
struct Team {
    team_ref: String,
    node_id: String,
    tree_version: u64,
    pattern: TeamPattern,
    models: Vec<String>,
    outcome: Option<bool>,
    at: u64,
}

impl Team {
    fn new(team_ref: &str, outcome: Option<bool>) -> Self {
        Self {
            team_ref: team_ref.to_owned(),
            node_id: "node".to_owned(),
            tree_version: 1,
            pattern: TeamPattern::CeoDecides,
            models: Vec::new(),
            outcome,
            at: 7,
        }
    }

    fn door(&self) -> UpkeepTeam<'_> {
        UpkeepTeam {
            team_ref: &self.team_ref,
            node_id: &self.node_id,
            tree_version: self.tree_version,
            pattern: self.pattern,
            models: &self.models,
            outcome: self.outcome,
            at: self.at,
        }
    }

    fn base(&self) -> base_upkeep::TeamReceipt {
        base_upkeep::TeamReceipt {
            team_ref: self.team_ref.clone(),
            type_ref: base_upkeep::TypeRef {
                node_id: self.node_id.clone(),
                tree_version: self.tree_version,
            },
            pattern: self.pattern,
            models: self.models.clone(),
            outcome: self
                .outcome
                .map(|success| base_upkeep::TeamOutcome { success }),
            at: self.at,
        }
    }
}

fn evidence(teams: &[Team], tasks: &BTreeMap<String, String>) -> [u8; 32] {
    let door_teams: Vec<UpkeepTeam<'_>> = teams.iter().map(Team::door).collect();
    let base_teams: Vec<base_upkeep::TeamReceipt> = teams.iter().map(Team::base).collect();
    let head = door::project_tree_upkeep_evidence(&door_teams, tasks);
    assert_eq!(head, base_upkeep::evidence(&base_teams, tasks));
    head
}

#[test]
fn project_tree_upkeep_evidence_keeps_main_s_bytes() {
    let a = Team::new("a", Some(true));
    let with = |change: &dyn Fn(&mut Team)| {
        let mut team = a.clone();
        change(&mut team);
        team
    };
    let mut sets: Vec<Vec<Team>> = vec![
        vec![],
        vec![a.clone()],
        vec![with(&|t| t.outcome = Some(false))],
    ];
    for pattern in [
        TeamPattern::CeoDecides,
        TeamPattern::Committee,
        TeamPattern::Vote,
        TeamPattern::Market,
        TeamPattern::Rotation,
        TeamPattern::Solo,
    ] {
        if pattern != TeamPattern::CeoDecides {
            sets.push(vec![with(&|t| t.pattern = pattern)]);
        }
    }
    for models in [
        vec!["model@1".to_owned()],
        vec!["a".to_owned(), "bc".to_owned()],
        vec!["ab".to_owned(), "c".to_owned()],
        vec![String::new(); 3],
    ] {
        sets.push(vec![with(&|t| t.models = models.clone())]);
    }
    sets.push(vec![with(&|t| t.tree_version = 0)]);
    sets.push(vec![with(&|t| t.tree_version = u64::MAX)]);
    sets.push(vec![with(&|t| t.at = u64::MAX)]);
    sets.push(vec![with(&|t| t.node_id = String::new())]);
    sets.push(vec![with(&|t| t.node_id = "長x".repeat(600))]);
    sets.push(vec![with(&|t| t.team_ref = "é 日本".to_owned())]);
    sets.push(vec![a.clone(), Team::new("b", Some(false))]);
    let task_maps: [BTreeMap<String, String>; 3] = [
        BTreeMap::new(),
        BTreeMap::from([("a".to_owned(), "task-1".to_owned())]),
        BTreeMap::from([("a".to_owned(), String::new())]),
    ];
    let mut digests = BTreeSet::new();
    let mut rows = 0;
    for teams in &sets {
        for tasks in &task_maps {
            digests.insert(evidence(teams, tasks));
            rows += 1;
        }
    }
    // 19 sets x 3 maps. The task maps name only team "a": the empty set and the set whose
    // team is "é 日本" read no task in any of them, so each repeats its digest twice.
    assert_eq!(sets.len(), 19);
    assert_eq!((rows, digests.len()), (57, 53));
    // Main keeps settled teams only, in team-ref order, the last of a repeated ref.
    let none = BTreeMap::new();
    assert_eq!(
        evidence(&[a.clone(), Team::new("open", None)], &none),
        evidence(&[a.clone()], &none)
    );
    let b = Team::new("b", Some(false));
    assert_eq!(
        evidence(&[b.clone(), a.clone()], &none),
        evidence(&[a.clone(), b], &none)
    );
    let later = with(&|t| t.at = 8);
    assert_eq!(
        evidence(&[a.clone(), later.clone()], &none),
        evidence(&[later], &none)
    );
}

#[test]
fn turn_program_steps_keep_main_s_bytes() {
    let lists: Vec<Vec<Vec<u8>>> = vec![
        vec![],
        vec![vec![]],
        vec![vec![], vec![]],
        vec![b"ab".to_vec(), b"c".to_vec()],
        vec![b"a".to_vec(), b"bc".to_vec()],
        vec![
            b"model".to_vec(),
            b"code-run".to_vec(),
            0_u64.to_be_bytes().to_vec(),
        ],
        vec![
            b"model".to_vec(),
            b"code-run".to_vec(),
            u64::MAX.to_be_bytes().to_vec(),
        ],
        vec![b"outbound".to_vec(), vec![0x33; 16]],
        vec![vec![0x07; 70_000]],
    ];
    let mut step_ids = BTreeSet::new();
    for list in &lists {
        let parts: Vec<&[u8]> = list.iter().map(Vec::as_slice).collect();
        let head = door::turn_program_step_id(&parts).expect("head step id");
        assert_eq!(head, base_step::id(&parts).expect("main step id"));
        step_ids.insert(*head.as_bytes());
    }
    assert_eq!(step_ids.len(), lists.len());
    let bodies: Vec<Option<Vec<u8>>> = vec![
        None,
        Some(Vec::new()),
        Some(b"ok".to_vec()),
        Some(vec![0xa5; 65_536]),
        Some((0..200_000_u32).map(|n| n.to_le_bytes()[0]).collect()),
    ];
    let mut digests = BTreeSet::new();
    let mut rows = 0;
    for payload in [[0; 32], [0xff; 32], [0x5a; 32]] {
        for body in &bodies {
            let head =
                door::turn_program_outbound_result(&payload, body.as_deref()).expect("head digest");
            assert_eq!(
                head,
                base_step::outbound(payload, body.clone()).expect("main digest")
            );
            digests.insert(head);
            rows += 1;
        }
    }
    // No presence byte: an absent body and an empty one write the same bytes.
    assert_eq!((rows, digests.len()), (15, 12));
    // One tag, two layouts: no step id is the first 16 bytes of an outbound digest here.
    for digest in &digests {
        let mut first = [0; 16];
        first.copy_from_slice(&digest[..16]);
        assert!(!step_ids.contains(&first));
    }
}

#[test]
fn route_prompt_keeps_main_s_bytes() {
    let values = texts();
    let mut prompts: Vec<Option<&str>> = vec![None, Some("null"), Some("\"quoted\" \\ back")];
    prompts.extend(values.iter().map(|text| Some(text.as_str())));
    let mut digests = BTreeSet::new();
    for prompt in &prompts {
        let head = door::route_prompt(*prompt);
        assert_eq!(head, base_route::route_prompt_digest(*prompt));
        digests.insert(head);
    }
    assert_eq!(digests.len(), prompts.len());
}
