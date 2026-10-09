use super::*;

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
use crate::error::GateError;
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
        ClaimSource::UserStated,
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
        self.land_bound(vault, Some(fixture_owner(vault)))
    }

    fn land_bound(&self, vault: &Vault, principal: Option<WriteActor>) -> Result<()> {
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
        if let Some(principal) = principal {
            bind_amendment_preference_principal(
                vault,
                principal,
                &self.receipt_id,
                &CompilationTarget::Fallback,
            )?;
        }
        assert!(
            judge_amendment(vault, &self.receipt_id)?.is_some(),
            "the fixture's routing facts must settle a class"
        );
        Ok(())
    }
}

fn fixture_owner(vault: &Vault) -> WriteActor {
    let id = EntityId::from_bytes([0xD1; 16]).expect("fixture owner id");
    vault
        .put_entity(&id, ENTITY_TYPE_PERSON, t(1), 1, b"preference owner")
        .expect("owner");
    WriteActor::new(id, EdgeActorClass::Human)
}

// These fixtures deliberately use historical seconds. The production wrapper
// uses wall time; the explicit-clock entry lets this suite test recurrence,
// hysteresis and replay rather than accidentally test 50 years of decay.
fn run_substitution_miner(vault: &Vault, run: &MinerRun) -> Result<Vec<MinedOutcome>> {
    super::run_substitution_miner_at(vault, run, 10_000)
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

fn emitted(outcomes: &[MinedOutcome]) -> Vec<MinedOutcome> {
    outcomes
        .iter()
        .filter(|outcome| !matches!(outcome, MinedOutcome::BelowThreshold))
        .copied()
        .collect()
}

// ─── the chooser ────────────────────────────────────────────────────────

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

// ─── dedup + hysteresis ─────────────────────────────────────────────────

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
fn a_pass_with_no_review_surface_is_refused() -> Result<()> {
    let (_dir, vault) = temp_vault();
    let actor = put_actor(&vault);
    let mut run = miner_run(&vault);
    land_sign_offs(&vault, actor, "outbound", 3)?;

    run.run_id = String::new();
    assert!(run_substitution_miner(&vault, &run).is_err());
    run.run_id = "run-ed04".to_owned();
    run.agent = WriteActor::new(run.agent.entity_ref(), EdgeActorClass::System);
    assert!(
        run_substitution_miner(&vault, &run).is_err(),
        "foreign System actor refused"
    );
    assert!(
        preference_rows(&vault, &actor)?.is_empty(),
        "a refused pass writes nothing"
    );
    Ok(())
}

// ─── the watermark work gate ────────────────────────────────────────────

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
    assert!(
        vault.delete_entity_with_options(
            &skill,
            crate::deletion::DeleteEntityOptions { purge: true }
        )?,
        "the skill goes away"
    );

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
            principal: None,
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
        vault
            .store
            .vault_meta
            .put(wtxn, &SKILL_EDIT.key_bytes(&proposal_id), &row)?;
        vault
            .store
            .vault_meta
            .put(wtxn, &MINT_MARK.key_bytes(&handle), &mark)?;
        assert!(
            !cluster_is_eligible(&vault, wtxn, &handle, 0)?,
            "and the uncommitted mark is what stops the second proposal"
        );
        Ok(())
    })
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
        Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }) => {
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

mod preference_learning;

#[test]
fn session_end_miner_uses_queued_system_dreamer() -> Result<()> {
    let (_dir, vault) = temp_vault();
    // The Dreamer is a MACHINE writer: the host roots the vault and holds its
    // key. The judging owner keeps writing under the host root.
    crate::test_util::provision_engine_machines(&vault);
    crate::test_util::bind_test_owner(&vault, fixture_owner(&vault).entity_ref());
    let actor = put_actor(&vault);
    let mut run = miner_run(&vault);
    run.agent = vault.dreamer_authority()?;
    land_sign_offs(&vault, actor, "outbound", 3)?;
    let outcomes = run_substitution_miner_at(&vault, &run, 10_000)?;
    assert!(!emitted(&outcomes).is_empty());
    let id = preference_ids(&vault, &actor)?[0];
    let body = vault.get_claim(&id)?.expect("mined proposal");
    let Value::Map(evidence) = body.evidence.expect("writer evidence") else {
        panic!("evidence");
    };
    assert!(
        evidence
            .iter()
            .any(|(key, value)| key.as_str() == Some("actor_class")
                && value.as_u64() == Some(u64::from(EdgeActorClass::System as u8)))
    );
    Ok(())
}
