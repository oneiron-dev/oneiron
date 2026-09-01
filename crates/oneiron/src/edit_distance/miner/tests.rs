use super::*;

use crate::actor_claims::edit_cost_scope_name;
use crate::claim::ClaimBody;
use crate::config::VaultConfig;
use crate::edge::EdgeActorClass;
use crate::edit_distance::attribution::{
    AmendmentCause, AmendmentEvidence, judge_amendment, record_amendment_evidence,
};
use crate::edit_distance::delta::{delta_from_recorded_ops, put_amendment_delta_in_txn};
use crate::edit_distance::{
    FinalizedProposalText, LoroOpRef, OpAttribution, OpSpan, ProposalArtifactRef,
    put_finalized_proposal_text,
};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_SESSION};
use crate::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};

// ─── fixtures ───────────────────────────────────────────────────────────

/// A vault that KEEPS its default policy manifest, so the miner's gated claim
/// write is evaluated the way production's is.
fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn t(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn put_actor(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, t(1), 1, b"ed04 actor fixture")
        .expect("actor entity");
    id
}

/// The pass as its caller supplies it: a sitting, the Dreamer run whose inbox
/// group the proposals land in, and an `Agent`-class actor (D13 admits `Agent`
/// for a PERSON, and `gate.rs` derives the group key only for `Agent`).
fn miner_run(vault: &Vault) -> MinerRun {
    let session = EntityId::now();
    vault
        .put_entity(&session, ENTITY_TYPE_SESSION, t(1), 1, b"ed04 sitting")
        .expect("session entity");
    let agent = EntityId::now();
    vault
        .put_entity(&agent, ENTITY_TYPE_PERSON, t(1), 1, b"ed04 dreamer")
        .expect("agent entity");
    MinerRun {
        session,
        run_id: "run-ed04".to_owned(),
        agent: WriteActor::new(agent, EdgeActorClass::Agent),
    }
}

/// Whether a cluster may propose, asked the way production asks it: inside a
/// transaction.
fn eligible(vault: &Vault, handle: &[u8; 32], now: u64) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    cluster_is_eligible(vault, &rtxn, handle, now)
}

fn put_skill(vault: &Vault) -> EntityId {
    put_skill_as(vault, EntityId::now())
}

fn put_skill_as(vault: &Vault, id: EntityId) -> EntityId {
    let tree_hash = canonical_skill_tree_hash([("SKILL.md", b"# ed04 fixture\n".as_slice())])
        .expect("fixture tree hashes");
    let candidate = SkillRecord::new(
        "ed04-fixture",
        "ed04 fixture skill",
        "1.0.0",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Imported,
        0.9,
        false,
        true,
        Vec::new(),
        Value::Map(vec![(Value::from("source"), Value::from("ed04-fixture"))]),
    )
    .with_content_hash(tree_hash);
    vault
        .put_skill_record(&id, &candidate, t(10), 11)
        .expect("skill candidate");
    let mut active = candidate;
    active.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&id, &active, t(12), 13)
        .expect("skill activation");
    id
}

/// One amendment, landed the way the ED ladder lands one: an ED-00 artifact
/// holding both texts and the recorded op window, an ED-01 Δ measured over that
/// artifact (so its refs resolve back to it), ED-03 routing facts, and ED-03's
/// judgment.
struct Amendment {
    receipt_id: String,
    scope: String,
    actor: EntityId,
    skill: Option<EntityId>,
    cause: AmendmentCause,
    proposed: String,
    finalized: String,
    at: u64,
}

impl Amendment {
    fn land(&self, vault: &Vault) -> Result<()> {
        let artifact_ref = ProposalArtifactRef::mint();
        let record = FinalizedProposalText {
            artifact_ref,
            proposed_ref: LoroOpRef::from_bytes(window_bytes(artifact_ref, 0)),
            final_ref: LoroOpRef::from_bytes(window_bytes(artifact_ref, 1)),
            // ONE recorded change covering the whole edit — what a decider's
            // single correction run looks like on replay.
            ops_by_actor: vec![(
                OpAttribution::DevicePeer,
                OpSpan {
                    peer_id: 7,
                    counter: 0,
                    len: 1,
                    lamport: 1,
                    timestamp: 1,
                    before_text: self.proposed.clone(),
                    after_text: self.finalized.clone(),
                },
            )],
            proposed_text: self.proposed.clone(),
            final_text: self.finalized.clone(),
            source_turn_ref: None,
        };
        put_finalized_proposal_text(vault, &record)?;
        let delta = delta_from_recorded_ops(&record);
        vault.with_write_txn(|wtxn| {
            put_amendment_delta_in_txn(vault, wtxn, &self.receipt_id, &delta)?;
            Ok(())
        })?;

        let mut evidence = AmendmentEvidence::new(&self.receipt_id, self.actor, &self.scope)
            .at(self.at)
            .with_cause(self.cause)
            .with_routing_facts(true, true);
        if let Some(skill) = self.skill {
            evidence = evidence.with_skill(skill);
        }
        record_amendment_evidence(vault, &evidence)?;
        assert!(
            judge_amendment(vault, &self.receipt_id)?.is_some(),
            "the fixture's routing facts must settle a class"
        );
        Ok(())
    }
}

/// Op-window bytes unique per artifact, so two artifacts never share an index
/// entry.
fn window_bytes(artifact_ref: ProposalArtifactRef, end: u8) -> Vec<u8> {
    let mut bytes = artifact_ref.entity_id().as_bytes().to_vec();
    bytes.push(end);
    bytes
}

/// A sign-off swap: `regards` -> `cheers`, with `index` varying only the
/// untouched surroundings so every amendment is its own artifact.
fn sign_off(receipt_id: &str, scope: &str, actor: EntityId, index: usize, at: u64) -> Amendment {
    Amendment {
        receipt_id: receipt_id.to_owned(),
        scope: scope.to_owned(),
        actor,
        skill: None,
        cause: AmendmentCause::DeciderPreference,
        proposed: format!("draft {index} is attached\nregards"),
        finalized: format!("draft {index} is attached\ncheers"),
        at,
    }
}

/// A content correction: a recurring `fri` -> `mon`.
fn reschedule(
    receipt_id: &str,
    scope: &str,
    actor: EntityId,
    skill: Option<EntityId>,
    index: usize,
    at: u64,
) -> Amendment {
    Amendment {
        receipt_id: receipt_id.to_owned(),
        scope: scope.to_owned(),
        actor,
        skill,
        cause: if skill.is_some() {
            AmendmentCause::ProposalWrong
        } else {
            AmendmentCause::DeciderPreference
        },
        proposed: format!("review {index} is on fri"),
        finalized: format!("review {index} is on mon"),
        at,
    }
}

/// Lands `count` sign-off amendments in one scope, stamped `100..100 + count`.
fn land_sign_offs(vault: &Vault, actor: EntityId, scope: &str, count: usize) -> Result<()> {
    for index in 0..count {
        sign_off(
            &format!("gate:{scope}-{index}"),
            scope,
            actor,
            index,
            100 + index as u64,
        )
        .land(vault)?;
    }
    Ok(())
}

fn preference_rows(vault: &Vault, actor: &EntityId) -> Result<Vec<(EntityId, ClaimBody)>> {
    let mut out = Vec::new();
    for id in vault.claims_for_subject(actor)? {
        let Some(body) = vault.get_claim(&id)? else {
            continue;
        };
        if body.predicate == PREDICATE_PREFERENCE_PHRASING {
            out.push((id, body));
        }
    }
    Ok(out)
}

fn preference_ids(vault: &Vault, actor: &EntityId) -> Result<Vec<EntityId>> {
    Ok(preference_rows(vault, actor)?
        .into_iter()
        .map(|(id, _)| id)
        .collect())
}

fn value_field(body: &ClaimBody, key: &str) -> Option<String> {
    let Value::Map(entries) = &body.value else {
        return None;
    };
    entries
        .iter()
        .find(|(entry, _)| entry.as_str() == Some(key))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned)
}

fn sign_off_cluster(vault: &Vault, scope: &str) -> Result<SubstitutionCluster> {
    Ok(mine_substitution_clusters(vault)?
        .into_iter()
        .find(|cluster| {
            cluster.scope == scope && cluster.from == "regards" && cluster.to == "cheers"
        })
        .expect("the sign-off swap clusters"))
}

fn content_cluster(vault: &Vault, scope: &str) -> Result<SubstitutionCluster> {
    Ok(mine_substitution_clusters(vault)?
        .into_iter()
        .find(|cluster| cluster.scope == scope && cluster.from == "fri" && cluster.to == "mon")
        .expect("the reschedule correction clusters"))
}

fn emitted(outcomes: &[MinedOutcome]) -> Vec<MinedOutcome> {
    outcomes
        .iter()
        .filter(|outcome| !matches!(outcome, MinedOutcome::BelowThreshold))
        .copied()
        .collect()
}

// ─── the K threshold ────────────────────────────────────────────────────

#[test]
fn three_identical_substitutions_in_one_scope_emit_exactly_one_proposal() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    land_sign_offs(&vault, actor, "outbound", 3)?;

    let cluster = sign_off_cluster(&vault, "outbound")?;
    assert_eq!(cluster.count, 3, "three distinct receipts, one bucket");
    assert_eq!(cluster.receipt_refs.len(), 3);
    assert_eq!(cluster.actor, actor);

    let outcomes = run_substitution_miner(&vault, &run)?;
    let emissions = emitted(&outcomes);
    assert_eq!(emissions.len(), 1, "one cluster at threshold, one proposal");
    assert!(matches!(emissions[0], MinedOutcome::PreferenceClaim(_)));
    assert_eq!(preference_rows(&vault, &actor)?.len(), 1);
    Ok(())
}

#[test]
fn two_receipts_stay_below_threshold() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    land_sign_offs(&vault, actor, "outbound", 2)?;

    let outcomes = run_substitution_miner(&vault, &run)?;
    assert!(!outcomes.is_empty(), "the cluster exists, it is just short");
    assert!(
        emitted(&outcomes).is_empty(),
        "two identical corrections are a pair, not a habit"
    );
    assert!(preference_rows(&vault, &actor)?.is_empty());
    Ok(())
}

#[test]
fn k_is_read_from_the_settings_dial() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    assert_eq!(miner_k(&vault)?, MINER_K_DEFAULT);
    set_miner_k(&vault, 2)?;
    assert_eq!(miner_k(&vault)?, 2);

    land_sign_offs(&vault, actor, "outbound", 2)?;
    run_substitution_miner(&vault, &run)?;
    assert_eq!(
        preference_rows(&vault, &actor)?.len(),
        1,
        "K=2 makes the same pair a habit"
    );
    Ok(())
}

#[test]
fn a_zero_threshold_is_refused() {
    let (_dir, vault) = temp_vault();
    assert!(set_miner_k(&vault, 0).is_err());
    assert_eq!(miner_k(&vault).expect("dial"), MINER_K_DEFAULT);
}

// ─── the chooser ────────────────────────────────────────────────────────

#[test]
fn the_chooser_routes_tone_lexicon_swaps_to_the_lexical_lane() {
    assert_eq!(
        classify_substitution("regards", "cheers"),
        SubstitutionClass::Lexical
    );
    assert_eq!(
        classify_substitution("dear sir", "hi"),
        SubstitutionClass::Lexical
    );
    // Punctuation rides on prose; the sign-off underneath is still a sign-off.
    assert_eq!(
        classify_substitution("regards,", "cheers,"),
        SubstitutionClass::Lexical
    );
    assert_eq!(
        classify_substitution("fri", "mon"),
        SubstitutionClass::Content
    );
    // One unlisted token on one side is enough: the safe direction is a
    // proposal a human reads.
    assert_eq!(
        classify_substitution("please", "please invoice"),
        SubstitutionClass::Content
    );
}

#[test]
fn the_tone_lexicon_is_sorted() {
    let mut sorted = TONE_LEXICON;
    sorted.sort_unstable();
    assert_eq!(
        TONE_LEXICON, sorted,
        "membership is a binary search, so the table must stay sorted"
    );
}

#[test]
fn a_lexical_cluster_lands_a_proposed_scope_tagged_preference_claim() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    land_sign_offs(&vault, actor, "outbound", 3)?;
    run_substitution_miner(&vault, &run)?;

    let rows = preference_rows(&vault, &actor)?;
    let (_, body) = rows.first().expect("one preference claim");
    assert_eq!(
        body.approval,
        ClaimApprovalStatus::Proposed,
        "a mined preference is never auto"
    );
    assert_eq!(body.source, Some(ClaimSource::Generated));
    assert!(
        body.session_tag.is_none(),
        "a sess tag would make the claim unacceptable at the inbox door"
    );
    assert_eq!(
        edit_cost_scope_name(body.scope.as_ref()),
        Some("outbound"),
        "the claim is scope-tagged in the ED lane's own scope shape"
    );
    assert_eq!(
        value_field(body, PREFERENCE_VALUE_KEY_FROM).as_deref(),
        Some("regards")
    );
    assert_eq!(
        value_field(body, PREFERENCE_VALUE_KEY_TO).as_deref(),
        Some("cheers")
    );
    assert_eq!(
        value_field(body, PREFERENCE_VALUE_KEY_CLASS).as_deref(),
        Some(SubstitutionClass::Lexical.as_str())
    );
    assert_eq!(
        value_field(body, PREFERENCE_VALUE_KEY_RATIONALE).as_deref(),
        Some(SubstitutionClass::Lexical.rationale()),
        "the chooser's rationale is receipted on the body"
    );
    Ok(())
}

#[test]
fn a_content_cluster_mints_a_gated_skill_edit_proposal() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    let skill = put_skill(&vault);
    let before_edit = vault.get_skill_record(&skill)?.expect("skill record");

    for index in 0..3 {
        reschedule(
            &format!("gate:sched-{index}"),
            "scheduling",
            actor,
            Some(skill),
            index,
            200 + index as u64,
        )
        .land(&vault)?;
    }

    let outcomes = run_substitution_miner(&vault, &run)?;
    let proposal_id = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            MinedOutcome::SkillEditProposal(id) => Some(*id),
            _ => None,
        })
        .expect("a recurring content correction mints a skill-edit proposal");

    let proposal = mined_skill_edit(&vault, &proposal_id)?.expect("proposal row");
    assert_eq!(proposal.skill, skill);
    assert_eq!(proposal.scope, "scheduling");
    assert_eq!(proposal.from, "fri");
    assert_eq!(proposal.to, "mon");
    assert_eq!(proposal.evidence_receipts.len(), 3);
    assert_eq!(proposal.rationale, SubstitutionClass::Content.rationale());
    assert_eq!(pending_substitution_skill_edits(&vault)?.len(), 1);

    // Minting is not applying: the skill's content and its version are exactly
    // where they were.
    let after = vault.get_skill_record(&skill)?.expect("skill record");
    assert_eq!(after.content_hash, before_edit.content_hash);
    assert_eq!(after.version, before_edit.version);
    assert!(
        preference_rows(&vault, &actor)?.is_empty(),
        "a content correction never launders into a preference claim"
    );
    Ok(())
}

#[test]
fn a_content_cluster_naming_no_skill_proposes_nothing() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    for index in 0..3 {
        reschedule(
            &format!("gate:sched-{index}"),
            "scheduling",
            actor,
            None,
            index,
            200 + index as u64,
        )
        .land(&vault)?;
    }

    let outcomes = run_substitution_miner(&vault, &run)?;
    assert!(
        emitted(&outcomes).is_empty(),
        "a content correction with no skill to edit is absent, never emitted"
    );
    assert!(pending_substitution_skill_edits(&vault)?.is_empty());
    assert!(preference_rows(&vault, &actor)?.is_empty());
    Ok(())
}

// ─── scope isolation ────────────────────────────────────────────────────

#[test]
fn the_same_pair_in_two_scopes_is_two_clusters_with_independent_counts() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    land_sign_offs(&vault, actor, "outbound", 3)?;
    land_sign_offs(&vault, actor, "internal", 1)?;

    let buckets = mine_substitution_clusters(&vault)?
        .into_iter()
        .filter(|cluster| cluster.from == "regards" && cluster.to == "cheers")
        .count();
    assert_eq!(buckets, 2, "one bucket per scope");
    assert_eq!(sign_off_cluster(&vault, "internal")?.count, 1);
    assert_eq!(sign_off_cluster(&vault, "outbound")?.count, 3);

    run_substitution_miner(&vault, &run)?;
    let rows = preference_rows(&vault, &actor)?;
    assert_eq!(rows.len(), 1, "only the scope that crossed K proposes");
    assert_eq!(
        edit_cost_scope_name(rows[0].1.scope.as_ref()),
        Some("outbound")
    );
    Ok(())
}

// ─── dedup + hysteresis ─────────────────────────────────────────────────

#[test]
fn a_rerun_over_fresh_evidence_proposes_nothing_new() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    land_sign_offs(&vault, actor, "outbound", 3)?;
    run_substitution_miner(&vault, &run)?;
    let first = preference_ids(&vault, &actor)?;
    assert_eq!(first.len(), 1);

    // A fourth amendment shows the same pair: new evidence, same open proposal.
    sign_off("gate:outbound-3", "outbound", actor, 3, 200).land(&vault)?;
    let outcomes = run_substitution_miner(&vault, &run)?;
    assert_eq!(sign_off_cluster(&vault, "outbound")?.count, 4);
    assert!(
        emitted(&outcomes).is_empty(),
        "the cluster's proposal is open, so the cluster says nothing"
    );
    assert_eq!(
        preference_ids(&vault, &actor)?,
        first,
        "no duplicate proposal"
    );
    Ok(())
}

/// The crash-replay property, at the level a test can observe it: because a
/// proposal and its mint-mark commit in ONE transaction, the only reachable
/// states are BOTH and NEITHER — so a replay finds the mark and emits once.
///
/// It does not kill the process mid-transaction; the harness has no abort seam.
/// What it checks is the invariant that guarantee buys, across three passes that
/// each see genuinely new evidence: exactly one live proposal, and a mark that
/// names it.
#[test]
fn a_replayed_pass_emits_once_and_leaves_no_half_state() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    land_sign_offs(&vault, actor, "outbound", 3)?;

    for round in 0..3_usize {
        sign_off(
            &format!("gate:replay-{round}"),
            "outbound",
            actor,
            10 + round,
            300 + round as u64,
        )
        .land(&vault)?;
        run_substitution_miner(&vault, &run)?;

        let claims = preference_ids(&vault, &actor)?;
        assert_eq!(claims.len(), 1, "a replay never double-proposes");
        let cluster = sign_off_cluster(&vault, "outbound")?;
        let rtxn = vault.store.env.read_txn()?;
        let mark = mint_mark_in_txn(&vault, &rtxn, &cluster_handle(&cluster))?
            .expect("the emission left a mark");
        assert_eq!(mark.kind, MARK_KIND_PREFERENCE);
        assert_eq!(
            mark.reference,
            claims[0].to_hex(),
            "the mark names the claim it committed with"
        );
    }
    Ok(())
}

#[test]
fn a_rejected_proposal_is_silent_inside_its_cooldown_and_speaks_after_it() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    land_sign_offs(&vault, actor, "outbound", 3)?;
    run_substitution_miner(&vault, &run)?;
    let first = preference_ids(&vault, &actor)?;
    let handle = cluster_handle(&sign_off_cluster(&vault, "outbound")?);

    // The decider says no, just now — through the door that really says it.
    let now = 1_000_000;
    answer_group(&vault, &run, crate::inbox::InboxBulkVerb::RejectAll, now);
    assert_eq!(
        vault.get_claim(&first[0])?.expect("claim").approval,
        ClaimApprovalStatus::Proposed,
        "a rejection leaves the body Proposed — the verdict lives in the ledger"
    );
    assert!(!eligible(&vault, &handle, now)?, "a fresh no is respected");
    assert!(
        !eligible(&vault, &handle, now + MINER_REJECTION_COOLDOWN_SECS - 1)?,
        "the cooldown is a real window"
    );
    assert!(
        eligible(&vault, &handle, now + MINER_REJECTION_COOLDOWN_SECS)?,
        "and it is a dial, not a wall"
    );
    Ok(())
}

#[test]
fn an_open_or_landed_preference_never_re_proposes() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    land_sign_offs(&vault, actor, "outbound", 3)?;
    run_substitution_miner(&vault, &run)?;
    let claim = preference_ids(&vault, &actor)?[0];
    let handle = cluster_handle(&sign_off_cluster(&vault, "outbound")?);
    let far_future = 10 * MINER_REJECTION_COOLDOWN_SECS;

    assert!(
        !eligible(&vault, &handle, far_future)?,
        "an open proposal is the cluster's word, already said"
    );
    answer_group(&vault, &run, crate::inbox::InboxBulkVerb::AcceptAll, 1_000);
    assert_eq!(
        vault.get_claim(&claim)?.expect("claim").approval,
        ClaimApprovalStatus::Approved
    );
    assert!(
        !eligible(&vault, &handle, far_future)?,
        "a landed preference is standing truth; re-proposing it is nagging"
    );
    Ok(())
}

#[test]
fn a_mined_proposal_is_reviewable_in_its_run_group() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    land_sign_offs(&vault, actor, "outbound", 3)?;
    run_substitution_miner(&vault, &run)?;
    let claim = preference_ids(&vault, &actor)?[0];

    let group = mined_group(&vault, &run);
    assert!(
        group
            .members
            .iter()
            .any(|member| member.claim_id == claim.to_hex()),
        "the pending row must reach the decider, or the proposal is a dead end"
    );
    Ok(())
}

#[test]
fn a_pass_with_no_review_surface_is_refused() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let mut run = miner_run(&vault);
    land_sign_offs(&vault, actor, "outbound", 3)?;

    run.run_id = String::new();
    assert!(run_substitution_miner(&vault, &run).is_err());
    run.run_id = "run-ed04".to_owned();
    run.agent = WriteActor::new(run.agent.entity_ref(), EdgeActorClass::System);
    assert!(run_substitution_miner(&vault, &run).is_err());
    assert!(
        preference_rows(&vault, &actor)?.is_empty(),
        "a refused pass writes nothing"
    );
    Ok(())
}

#[test]
fn a_skill_edit_mark_stays_settled_while_its_proposal_is_pending() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    let skill = put_skill(&vault);
    for index in 0..3 {
        reschedule(
            &format!("gate:sched-{index}"),
            "scheduling",
            actor,
            Some(skill),
            index,
            200 + index as u64,
        )
        .land(&vault)?;
    }
    run_substitution_miner(&vault, &run)?;
    assert_eq!(pending_substitution_skill_edits(&vault)?.len(), 1);

    reschedule("gate:sched-3", "scheduling", actor, Some(skill), 3, 300).land(&vault)?;
    let outcomes = run_substitution_miner(&vault, &run)?;
    assert!(emitted(&outcomes).is_empty());
    assert_eq!(
        pending_substitution_skill_edits(&vault)?.len(),
        1,
        "one pending proposal per cluster, however much more evidence arrives"
    );
    Ok(())
}

// ─── the watermark work gate ────────────────────────────────────────────

#[test]
fn a_pass_with_no_new_judgments_does_no_work() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    assert_eq!(miner_watermark(&vault)?, MinerWatermark::default());
    land_sign_offs(&vault, actor, "outbound", 2)?;

    let first = run_substitution_miner(&vault, &run)?;
    assert!(!first.is_empty(), "the first pass sees the evidence");
    assert_eq!(
        miner_watermark(&vault)?,
        MinerWatermark {
            at: 101,
            boundary: 1
        }
    );

    let second = run_substitution_miner(&vault, &run)?;
    assert!(
        second.is_empty(),
        "nothing newer arrived, so there is nothing to conclude"
    );
    Ok(())
}

#[test]
fn recurrence_accumulates_across_passes() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);

    // One sitting per correction. The watermark must not reset the count, or a
    // habit spread over three sittings would never be seen at all.
    for index in 0..3 {
        sign_off(
            &format!("gate:outbound-{index}"),
            "outbound",
            actor,
            index,
            100 + index as u64,
        )
        .land(&vault)?;
        run_substitution_miner(&vault, &run)?;
    }
    assert_eq!(
        preference_rows(&vault, &actor)?.len(),
        1,
        "three sittings, one habit, one proposal"
    );
    Ok(())
}

#[test]
fn an_unjudged_amendment_contributes_nothing() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    // Same three corrections, but the routing facts never settle a cause, so
    // ED-03 abstains and no judgment lands. Nothing to mine.
    for index in 0..3 {
        let artifact_ref = ProposalArtifactRef::mint();
        let proposed = format!("draft {index} is attached\nregards");
        let finalized = format!("draft {index} is attached\ncheers");
        let record = FinalizedProposalText {
            artifact_ref,
            proposed_ref: LoroOpRef::from_bytes(window_bytes(artifact_ref, 0)),
            final_ref: LoroOpRef::from_bytes(window_bytes(artifact_ref, 1)),
            ops_by_actor: Vec::new(),
            proposed_text: proposed.clone(),
            final_text: finalized.clone(),
            source_turn_ref: None,
        };
        put_finalized_proposal_text(&vault, &record)?;
        let delta = delta_from_recorded_ops(&record);
        let receipt_id = format!("gate:unjudged-{index}");
        vault.with_write_txn(|wtxn| {
            put_amendment_delta_in_txn(&vault, wtxn, &receipt_id, &delta)?;
            Ok(())
        })?;
        record_amendment_evidence(
            &vault,
            &AmendmentEvidence::new(&receipt_id, actor, "outbound").at(100 + index as u64),
        )?;
        assert!(judge_amendment(&vault, &receipt_id)?.is_none(), "abstains");
    }
    assert!(mine_substitution_clusters(&vault)?.is_empty());
    Ok(())
}

/// The crash-replay guarantee at PASS granularity, not cluster granularity.
///
/// Two eligible clusters; the second one fails. The work gate must not have
/// moved, or the replay that exists to emit the second cluster would find
/// nothing new to do and that proposal would be lost for good.
#[test]
fn a_pass_that_dies_between_clusters_leaves_the_unreached_one_minable() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    // `outbound` sorts before `scheduling`, so the lexical cluster is ruled on
    // first and the content one fails after it has already committed — its
    // skill was deleted between the corrections and the pass.
    land_sign_offs(&vault, actor, "outbound", 3)?;
    let skill = put_skill(&vault);
    for index in 0..3 {
        reschedule(
            &format!("gate:sched-{index}"),
            "scheduling",
            actor,
            Some(skill),
            index,
            200 + index as u64,
        )
        .land(&vault)?;
    }
    assert!(vault.delete_entity(&skill)?, "the skill goes away");

    assert!(
        run_substitution_miner(&vault, &run).is_err(),
        "the second cluster names a skill that is no longer there"
    );
    assert_eq!(
        preference_rows(&vault, &actor)?.len(),
        1,
        "the first landed"
    );
    assert_eq!(
        miner_watermark(&vault)?,
        MinerWatermark::default(),
        "a pass that did not finish has not seen its evidence"
    );

    put_skill_as(&vault, skill);
    run_substitution_miner(&vault, &run)?;
    assert_eq!(
        pending_substitution_skill_edits(&vault)?.len(),
        1,
        "the replay reaches the cluster the dead pass never ruled on"
    );
    assert_eq!(
        preference_rows(&vault, &actor)?.len(),
        1,
        "and the cluster that did commit is still held by its mint-mark"
    );
    Ok(())
}

/// Judgment stamps are second-granular. A receipt landing in the boundary
/// second is evidence no pass has folded in, and a gate that cannot see it
/// strands the cluster until some unrelated judgment happens to arrive later —
/// forever, if none ever does.
#[test]
fn a_receipt_landing_in_the_boundary_second_is_still_new_evidence() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    for index in 0..2 {
        sign_off(
            &format!("gate:outbound-{index}"),
            "outbound",
            actor,
            index,
            100,
        )
        .land(&vault)?;
    }
    assert!(
        emitted(&run_substitution_miner(&vault, &run)?).is_empty(),
        "two is short of K"
    );
    assert_eq!(
        miner_watermark(&vault)?,
        MinerWatermark {
            at: 100,
            boundary: 2
        }
    );

    sign_off("gate:outbound-2", "outbound", actor, 2, 100).land(&vault)?;
    assert_eq!(
        emitted(&run_substitution_miner(&vault, &run)?).len(),
        1,
        "the third receipt shares the boundary second and still crosses K"
    );
    assert_eq!(preference_rows(&vault, &actor)?.len(), 1);
    Ok(())
}

/// The dedup check reads the marks in the transaction that WRITES them.
///
/// A check with a read transaction of its own answers from the last commit, so
/// two callers both get "eligible" and both commit — LMDB serializes the writes
/// and still ends up with two live proposals for one cluster.
#[test]
fn the_dedup_check_sees_the_mark_written_in_its_own_transaction() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let handle = [7_u8; 32];
    let proposal_id = EntityId::now();
    let row = encode_row(
        &StoredSkillEdit {
            v: ROW_VERSION,
            skill: EntityId::now().to_hex(),
            scope: "scheduling".to_owned(),
            from: "fri".to_owned(),
            to: "mon".to_owned(),
            evidence_receipts: Vec::new(),
            rationale: SubstitutionClass::Content.rationale().to_owned(),
            at: 1,
            decision: None,
        },
        SKILL_EDIT_ROW_LABEL,
    )?;
    let mark = encode_row(
        &StoredMintMark::new(MARK_KIND_SKILL_EDIT, &proposal_id),
        MINT_MARK_ROW_LABEL,
    )?;

    vault.with_write_txn(|wtxn| {
        assert!(
            cluster_is_eligible(&vault, wtxn, &handle, 0)?,
            "an unmarked cluster may propose"
        );
        vault.store.vault_meta.put(
            wtxn,
            &meta_key(SKILL_EDIT_KEY_PREFIX, proposal_id.as_bytes()),
            &row,
        )?;
        vault
            .store
            .vault_meta
            .put(wtxn, &mint_mark_key(&handle), &mark)?;
        assert!(
            !cluster_is_eligible(&vault, wtxn, &handle, 0)?,
            "and the uncommitted mark is what stops the second proposal"
        );
        Ok(())
    })
}

/// The content class's hysteresis, which row-existence alone cannot express: a
/// deleted proposal cannot say whether it was applied or refused, so the
/// verdict is recorded on the proposal instead.
#[test]
fn a_rejected_skill_edit_is_silent_inside_its_cooldown_and_speaks_after_it() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    let skill = put_skill(&vault);
    for index in 0..3 {
        reschedule(
            &format!("gate:sched-{index}"),
            "scheduling",
            actor,
            Some(skill),
            index,
            200 + index as u64,
        )
        .land(&vault)?;
    }
    run_substitution_miner(&vault, &run)?;
    let proposal = pending_substitution_skill_edits(&vault)?
        .pop()
        .expect("one open proposal");
    let handle = cluster_handle(&content_cluster(&vault, "scheduling")?);
    let far_future = 10 * MINER_REJECTION_COOLDOWN_SECS;
    assert!(
        !eligible(&vault, &handle, far_future)?,
        "an open proposal is the cluster's word, already said"
    );

    let now = 1_000_000;
    resolve_mined_skill_edit(
        &vault,
        &proposal.proposal_id,
        MinedSkillEditVerdict::Rejected,
        now,
    )?;
    assert!(
        pending_substitution_skill_edits(&vault)?.is_empty(),
        "an answered proposal is no longer work"
    );
    assert_eq!(
        mined_skill_edit(&vault, &proposal.proposal_id)?
            .expect("the answered proposal is still readable")
            .decision,
        Some(MinedSkillEditDecision {
            verdict: MinedSkillEditVerdict::Rejected,
            at: now
        })
    );
    assert!(!eligible(&vault, &handle, now)?, "a fresh no is respected");
    assert!(
        !eligible(&vault, &handle, now + MINER_REJECTION_COOLDOWN_SECS - 1)?,
        "the cooldown is a real window"
    );
    assert!(
        eligible(&vault, &handle, now + MINER_REJECTION_COOLDOWN_SECS)?,
        "and it is a dial, not a wall"
    );

    resolve_mined_skill_edit(
        &vault,
        &proposal.proposal_id,
        MinedSkillEditVerdict::Accepted,
        now,
    )?;
    assert!(
        !eligible(&vault, &handle, far_future)?,
        "an applied edit is standing truth; re-proposing it is nagging"
    );
    assert!(
        resolve_mined_skill_edit(
            &vault,
            &EntityId::now(),
            MinedSkillEditVerdict::Rejected,
            now
        )
        .is_err(),
        "an answer to a question nobody asked is a caller bug"
    );
    Ok(())
}

// ─── extraction ─────────────────────────────────────────────────────────

#[test]
fn a_pure_insertion_or_deletion_is_not_a_substitution() {
    assert_eq!(substitution_pair("hello", "hello there"), None);
    assert_eq!(substitution_pair("hello there", "hello"), None);
    assert_eq!(substitution_pair("same", "same"), None);
    assert_eq!(substitution_pair("", ""), None);
}

#[test]
fn the_pair_is_the_changed_run_not_the_whole_text() {
    let pair = substitution_pair("review 0 is on fri", "review 0 is on mon")
        .expect("a one-word correction is a substitution");
    assert_eq!(pair.from, "fri");
    assert_eq!(pair.to, "mon");
}

#[test]
fn the_changed_run_widens_to_whole_tokens() {
    // `regards` and `cheers` share a trailing `s`; without token alignment the
    // pair would be `regard` -> `cheer`, which is in no lexicon.
    let pair = substitution_pair("attached\nregards", "attached\ncheers").expect("substitution");
    assert_eq!(pair.from, "regards");
    assert_eq!(pair.to, "cheers");
}

#[test]
fn normalization_is_lowercase_trim_and_collapse_only() {
    let pair = substitution_pair("say   Dear  Sir now", "say Hi now").expect("substitution");
    assert_eq!(pair.from, "dear sir");
    assert_eq!(pair.to, "hi");
}

#[test]
fn a_rewrite_past_the_token_bound_is_not_clustered() {
    let long: String = (0..=MAX_SUBSTITUTION_TOKENS)
        .map(|index| format!("word{index} "))
        .collect();
    assert_eq!(substitution_pair("x", long.trim()), None);
}

#[test]
fn a_line_count_change_pairs_nothing() {
    assert!(
        line_substitutions("a\nb\nc", "a\nb1\nb2\nc").is_empty(),
        "pairing across a length change would cluster unrelated lines"
    );
}

#[test]
fn line_pairing_reports_one_substitution_per_replaced_line() {
    let pairs = line_substitutions("keep\nfri talk\nkeep2", "keep\nmon talk\nkeep2");
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].from, "fri");
    assert_eq!(pairs[0].to, "mon");
}

// ─── the dreamer payload ────────────────────────────────────────────────

#[test]
fn the_attempt_payload_round_trips_the_sitting() -> Result<()> {
    let session = EntityId::now();
    assert_eq!(
        miner_session_from_input(&miner_attempt_input(&session))?,
        session
    );
    assert!(miner_session_from_input(&Value::from("not a payload")).is_err());
    // A payload naming no sitting is refused rather than guessed at: a proposal
    // nobody can trace back to a sitting must never reach the tray.
    assert!(miner_session_from_input(&Value::Map(Vec::new())).is_err());
    // The fallback group key names the sitting that earned it.
    assert!(miner_run_id(&session).ends_with(&session.to_hex()));
    Ok(())
}

/// The production inlet: the session-close transaction registers the pass.
///
/// Without this the executor's dispatch arm is unreachable and the miner only
/// ever runs when someone calls it by hand — which is not "runs at the
/// SessionEnd wake".
#[test]
fn ending_a_session_registers_the_miner_pass_on_the_meso_queue() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let session = match vault.mint_session(1_000)? {
        crate::session_lifecycle::SessionMintOutcome::Minted(id) => id,
        crate::session_lifecycle::SessionMintOutcome::AlreadyOpen(id) => {
            panic!("expected a fresh sitting, got open {id:?}")
        }
    };
    vault
        .end_session_with_wake(
            &session,
            crate::session_lifecycle::SessionClosePredicate::Explicit,
            1_100,
            &crate::session_lifecycle::SessionEndWake::none(0),
        )?
        .expect("the sitting ends");

    let mine: Vec<_> = crate::attempt_queue::AttemptQueue::new(&vault)
        .list()?
        .into_iter()
        .filter(|attempt| attempt.kind == crate::DREAMER_CONSOLIDATION_MESO_ATTEMPT_KIND)
        .filter_map(|attempt| {
            crate::dreamer_runner::decode_dreamer_attempt_payload(&attempt.payload).ok()
        })
        .filter(|payload| {
            payload.attempt_type
                == crate::dreamer_consolidation::DREAMER_SUBSTITUTION_MINE_ATTEMPT_TYPE
        })
        .collect();
    assert_eq!(mine.len(), 1, "the close registers exactly one miner pass");
    assert_eq!(
        miner_session_from_input(&mine[0].input)?,
        session,
        "and the payload names the sitting that closed"
    );
    Ok(())
}

// ─── the decider's verdict, through the real door ───────────────────────

/// The inbox group a mined proposal lands in.
///
/// Its existence is the whole point of the envelope's dreamer provenance: no
/// group, no review surface, and a Proposed claim nobody can ever answer.
fn mined_group(vault: &Vault, run: &MinerRun) -> crate::inbox::InboxGroup {
    vault
        .inbox_groups(crate::inbox::InboxQuery::at(1_000, 16))
        .expect("inbox projection")
        .into_iter()
        .find(|group| group.run_id == run.run_id)
        .expect("a mined proposal is reviewable in its run's group")
}

/// Answers every open member of the run's group. The reject door does NOT flip
/// the claim body's approval — it closes the tray row and appends a `rejected`
/// gate decision — which is exactly why the hysteresis reads those two places
/// rather than the body.
fn answer_group(vault: &Vault, run: &MinerRun, verb: crate::inbox::InboxBulkVerb, now: u64) {
    let group = mined_group(vault, run);
    vault
        .resolve_inbox_group_at(&group.group_key, verb, None, now)
        .expect("the decider answers the group");
}

// ─── the evidence a mined claim cites ───────────────────────────────────

/// The candidate evidence of a landed claim, read the way the door reads it.
fn candidate_evidence(body: &ClaimBody) -> &Value {
    let key = crate::write_envelope::WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY;
    let evidence = body.evidence.as_ref().expect("stamped evidence");
    evidence_key(evidence, key)
}

fn evidence_key<'a>(evidence: &'a Value, key: &str) -> &'a Value {
    let Value::Map(entries) = evidence else {
        panic!("evidence map")
    };
    entries
        .iter()
        .find_map(|(entry, value)| (entry.as_str() == Some(key)).then_some(value))
        .unwrap_or_else(|| panic!("missing evidence key {key}"))
}

/// The mined claim cites the cluster it was mined from, as an entity that
/// RESOLVES — which is what the GATE-12 floor asks of every Dreamer candidate.
#[test]
fn miner_preference_evidence_resolves() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    land_sign_offs(&vault, actor, "outbound", 3)?;
    let cluster = sign_off_cluster(&vault, "outbound")?;

    let outcomes = run_substitution_miner(&vault, &run)?;
    assert_eq!(emitted(&outcomes).len(), 1, "the cluster emits");
    let rows = preference_rows(&vault, &actor)?;
    assert_eq!(rows.len(), 1, "one preference claim lands");
    let (_claim_id, body) = &rows[0];

    let evidence = candidate_evidence(body);
    let decoded = crate::dreamer_consolidation::decode_consolidation_evidence(evidence)?
        .expect("the mined evidence decodes as the consolidation envelope");
    let record_id = mined_evidence_record_id(&cluster_handle(&cluster))?;
    assert_eq!(decoded.refs, vec![record_id]);
    assert!(decoded.chain.is_empty());
    assert_eq!(
        decoded.source_meet,
        ClaimSource::Inferred,
        "a mined preference is derived, never stated"
    );
    // The receipt ids stay readable beside the envelope; they are simply not
    // what a resolver follows.
    assert_eq!(
        evidence_key(evidence, MINED_EVIDENCE_RECEIPTS_KEY),
        &receipt_citations(&cluster)
    );

    // The ref resolves, and the record it resolves to IS the cluster.
    let raw = vault
        .get(&record_id)?
        .expect("the mined evidence record resolves in the same view");
    let record: StoredMinedEvidence = decode_row(&raw, MINED_EVIDENCE_ROW_LABEL)?;
    assert_eq!(record.v, ROW_VERSION);
    assert_eq!(record.scope, cluster.scope);
    assert_eq!(record.from, "regards");
    assert_eq!(record.to, "cheers");
    assert_eq!(record.class, SubstitutionClass::Lexical.as_str());
    assert_eq!(
        record.receipt_refs, cluster.receipt_refs,
        "the distinct receipts, in the cluster's own order"
    );
    assert_eq!(record.count, cluster.count);
    assert_eq!(record.at, cluster.at);
    Ok(())
}

/// The floor is not satisfied by the SHAPE of the evidence.
///
/// Same actor, same `Generated` source, same dreamer provenance, same envelope
/// and the same consolidation envelope the emitter stamps — with one
/// difference: the record it cites was never written, so nothing resolves.
#[test]
fn miner_floor_still_denies() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let run = miner_run(&vault);
    land_sign_offs(&vault, actor, "outbound", 3)?;
    let cluster = sign_off_cluster(&vault, "outbound")?;
    let handle = cluster_handle(&cluster);

    let absent_record = mined_evidence_record_id(&handle)?;
    assert!(
        vault.get(&absent_record)?.is_none(),
        "the negative fixture never persists the record"
    );
    let claim_id = EntityId::now();
    let envelope = miner_envelope(&run, &handle)?;
    let candidate = ClaimCandidate::new(
        PREDICATE_PREFERENCE_PHRASING,
        ClaimSubject::Entity(cluster.actor),
        preference_value(&cluster, SubstitutionClass::Lexical),
        MINER_PREFERENCE_CONFIDENCE,
    )
    .with_evidence(mined_evidence_candidate(&cluster, absent_record))
    .with_scope(edit_cost_scope(&cluster.scope))
    .with_validity(Some(cluster.at), None);
    let occurred = TimeRange {
        start: cluster.at,
        end: cluster.at,
    };

    let err = vault
        .with_write_txn(|wtxn| {
            vault
                .batch_in()
                .claim_candidate(&claim_id, candidate, &envelope, occurred, cluster.at)
                .apply_recording_gate_decisions(wtxn)
        })
        .expect_err("a mined candidate whose record is absent cites nothing that resolves");
    match err {
        Error::GateWriteRejected {
            outcome,
            reason_codes,
        } => {
            assert_eq!(outcome, "deny");
            assert_eq!(reason_codes, ["gate.deny.dreamer_precommit.no_evidence"]);
        }
        other => panic!("expected GateWriteRejected, got {other:?}"),
    }
    assert!(
        vault.get_claim(&claim_id)?.is_none(),
        "the denied write rolled back"
    );
    assert!(
        preference_rows(&vault, &actor)?.is_empty(),
        "no preference row lands behind the denial"
    );
    Ok(())
}
