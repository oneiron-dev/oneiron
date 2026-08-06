//! ONE-1748 (MS-06) unit tests: the scope handle's keying, the
//! streak→offer→tap→grant path, receipted self-demotion, per-scope floors,
//! persistence across reopen, the CID-7 rebuild against the REAL proposal
//! resolution door, and the r7 §5 boundary that keeps identity-topology ops
//! off the ramp.

use super::*;
use crate::identity_topology::{
    IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
    ProposalRuling, SurvivorshipPlan,
};
use crate::store::GateDecisionId;
use crate::{ClaimApprovalStatus, ClaimSource};

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(crate::test_util::embedding_test_config())
}

/// The eligible fixture scope: a propose-lane surface, not an identity-topology
/// op. Deliberately the same tuple the merge/split oracle uses.
fn eligible_scope() -> RampScope {
    RampScope::new("send_email", "client_followup", "agent-a").expect("scope")
}

fn put_person(vault: &Vault, seed: u8) -> EntityId {
    let person = crate::test_util::entity(seed);
    vault
        .put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            crate::temporal::TimeRange {
                start: 100,
                end: 100,
            },
            100,
            b"ramp fixture person",
        )
        .expect("put person");
    person
}

/// The authenticated owner every graduation tap needs. Seeded distinctly from
/// the merge fixtures so no identity is doing two jobs.
fn owner(vault: &Vault) -> crate::consent::AuthenticatedOwner {
    let actor = put_person(vault, 0x25);
    vault
        .authenticate_owner(actor, "principal:owner", true, GateDecisionId::now())
        .expect("authenticate owner")
}

fn merge_op(sources: Vec<EntityId>, survivor: EntityId) -> IdentityTopologyOp {
    IdentityTopologyOp::Merge(MergeOp {
        sources,
        survivor,
        evidence: IdentityOpEvidence {
            refs: Vec::new(),
            rationale: "ramp fixture merge".to_owned(),
        },
        survivorship_plan: SurvivorshipPlan::ReadThrough,
    })
}

/// Parks a merge proposal and rules it, through the REAL MS-05 doors — the one
/// production path that both folds the ramp incrementally AND emits the
/// proposal-outcome receipt a rebuild refolds.
fn park_and_rule(
    vault: &Vault,
    survivor: EntityId,
    loser: EntityId,
    ruling: ProposalRuling<'_>,
    parked_at: u64,
    ruled_at: u64,
) {
    let parked = vault
        .apply_identity_topology_op(
            &merge_op(vec![loser], survivor),
            &IdentityOpWrite {
                approval: ClaimApprovalStatus::Proposed,
                ..IdentityOpWrite::auto(ClaimSource::Inferred)
            },
            parked_at,
        )
        .expect("park proposal");
    let IdentityOpOutcome::Parked { event, .. } = parked else {
        panic!("a Proposed merge must park, got {parked:?}");
    };
    vault
        .resolve_identity_proposal(
            &event,
            ruling,
            &IdentityOpWrite::auto(ClaimSource::UserStated),
            ruled_at,
        )
        .expect("resolve proposal");
}

fn all_stats(vault: &Vault) -> Vec<ScopeOutcomeStats> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let mut rows = Vec::new();
    for entry in vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, RAMP_STATS_KEY_PREFIX)
        .expect("scan stats")
    {
        let (_, raw) = entry.expect("stats row");
        let row: StoredScopeStats = decode_row(&raw, "ramp stats row").expect("decode");
        let (scope, counters) = stats_row_parts(row).expect("parts");
        let state = derive_state_in_txn(vault, &rtxn, &scope, counters).expect("state");
        rows.push(stats_view(scope, counters, state));
    }
    rows.sort_by(|left, right| left.scope.cmp(&right.scope));
    rows
}

fn demotion_receipts_via_public_query(vault: &Vault) -> Vec<crate::receipt::ReceiptRecord> {
    let query = ReceiptQuery::default().with_kind(ReceiptKind::Gate);
    vault
        .receipts(query)
        .expect("gate receipts")
        .into_iter()
        .filter(is_ramp_demotion_receipt)
        .collect()
}

#[test]
fn scope_key_is_deterministic_and_keys_on_the_exact_tuple() {
    let base = eligible_scope();
    assert_eq!(base.key(), eligible_scope().key());

    for variant in [
        RampScope::new("send_email", "client_followup", "agent-b"),
        RampScope::new("send_email", "cold_outreach", "agent-a"),
        RampScope::new("draft_email", "client_followup", "agent-a"),
    ] {
        assert_ne!(base.key(), variant.expect("variant").key());
    }

    // Length-prefixed field hashing: a tuple cannot collide with a differently
    // split one that concatenates to the same bytes.
    let left = RampScope::new("ab", "c", "agent-a").expect("left");
    let right = RampScope::new("a", "bc", "agent-a").expect("right");
    assert_ne!(left.key(), right.key());
}

#[test]
fn scope_fields_normalize_and_reject_the_unbuildable() {
    assert_eq!(
        RampScope::new("  send_email  ", "client_followup", "agent-a").expect("trimmed"),
        eligible_scope()
    );
    assert!(RampScope::new("", "client_followup", "agent-a").is_err());
    assert!(RampScope::new("send_email", "client_followup", " ").is_err());
    assert!(
        RampScope::new(
            "x".repeat(crate::consent::MAX_CONSENT_REF_LEN + 1),
            "client_followup",
            "agent-a"
        )
        .is_err()
    );
}

#[test]
fn clean_streak_surfaces_one_offer_and_never_grants_by_itself() {
    let (_dir, vault) = open_vault();
    let scope = eligible_scope();

    for approvals in 1..DEFAULT_GRADUATION_STREAK_FLOOR {
        let stats = vault
            .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)
            .expect("record");
        assert_eq!(stats.untouched_streak, approvals);
        assert_eq!(stats.state, RampState::Propose);
        assert!(vault.graduation_offers().expect("offers").is_empty());
    }

    let stats = vault
        .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)
        .expect("record at the floor");
    assert_eq!(stats.untouched_streak, DEFAULT_GRADUATION_STREAK_FLOOR);
    assert_eq!(stats.state, RampState::Offered);
    assert_eq!(vault.graduation_offers().expect("offers"), vec![scope]);
    // The offer is an offer: no streak length mints authority.
    assert!(
        vault
            .active_standing_consent_grants()
            .expect("grants")
            .is_empty()
    );
}

#[test]
fn the_owner_tap_is_what_creates_the_grant() {
    let (_dir, vault) = open_vault();
    let scope = eligible_scope();
    let owner = owner(&vault);
    for _ in 0..DEFAULT_GRADUATION_STREAK_FLOOR {
        vault
            .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)
            .expect("record");
    }

    vault
        .accept_graduation_offer(&owner, &scope)
        .expect("owner accepts");
    assert_eq!(
        vault
            .active_standing_consent_grants()
            .expect("grants")
            .len(),
        1
    );
    assert_eq!(
        vault.ramp_scope_state(&scope).expect("state"),
        RampState::Graduated
    );
    // The offer retracts the moment it is taken.
    assert!(vault.graduation_offers().expect("offers").is_empty());
}

#[test]
fn an_amendment_in_a_graduated_scope_demotes_it_receipted() {
    let (_dir, vault) = open_vault();
    let scope = eligible_scope();
    let owner = owner(&vault);
    for _ in 0..DEFAULT_GRADUATION_STREAK_FLOOR {
        vault
            .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)
            .expect("record");
    }
    vault
        .accept_graduation_offer(&owner, &scope)
        .expect("owner accepts");
    assert!(demotion_receipts_via_public_query(&vault).is_empty());

    let stats = vault
        .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedAmended)
        .expect("amended ruling");

    assert_eq!(stats.state, RampState::Propose);
    assert_eq!(stats.untouched_streak, 0);
    assert_eq!(stats.amended, 1);
    assert!(
        vault
            .active_standing_consent_grants()
            .expect("grants")
            .is_empty(),
        "the demotion must revoke the standing grant, not merely stop offering"
    );

    let receipts = demotion_receipts_via_public_query(&vault);
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.receipt_kind, ReceiptKind::Gate);
    assert_eq!(
        receipt.fields.get(crate::receipt::FIELD_DEMOTION_REASON),
        Some(&DemotionReason::Amended.as_str().to_owned())
    );
    assert_eq!(
        receipt.fields.get(crate::receipt::FIELD_OP_KIND),
        Some(&scope.op_kind)
    );
    assert_eq!(
        receipt.fields.get(crate::receipt::FIELD_GRANT_REF),
        Some(&scope.grant_ref().expect("grant ref")),
        "the receipt must name the authority it took away"
    );
}

#[test]
fn a_rejection_demotes_and_a_clean_approval_does_not() {
    let (_dir, vault) = open_vault();
    let scope = eligible_scope();
    let owner = owner(&vault);
    for _ in 0..DEFAULT_GRADUATION_STREAK_FLOOR {
        vault
            .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)
            .expect("record");
    }
    vault
        .accept_graduation_offer(&owner, &scope)
        .expect("owner accepts");

    vault
        .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)
        .expect("clean ruling");
    assert!(demotion_receipts_via_public_query(&vault).is_empty());
    assert_eq!(
        vault.ramp_scope_state(&scope).expect("state"),
        RampState::Graduated
    );

    vault
        .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::Rejected)
        .expect("rejected ruling");
    assert_eq!(demotion_receipts_via_public_query(&vault).len(), 1);
    assert_eq!(
        vault.ramp_scope_state(&scope).expect("state"),
        RampState::Propose
    );
}

#[test]
fn demotion_of_an_ungraduated_scope_is_still_said_out_loud() {
    let (_dir, vault) = open_vault();
    let scope = eligible_scope();
    vault
        .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)
        .expect("record");

    vault
        .demote_scope_to_propose(&scope, DemotionReason::AgentJudgment)
        .expect("self demote");

    let receipts = demotion_receipts_via_public_query(&vault);
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0]
            .fields
            .get(crate::receipt::FIELD_DEMOTION_REASON),
        Some(&DemotionReason::AgentJudgment.as_str().to_owned())
    );
    assert_eq!(
        receipts[0].fields.get(crate::receipt::FIELD_GRANT_REF),
        None,
        "there was no grant to name"
    );
    assert_eq!(
        vault
            .scope_stats(&scope)
            .expect("stats")
            .expect("row")
            .untouched_streak,
        0
    );
}

#[test]
fn a_per_scope_floor_overrides_the_compiled_default() {
    let (_dir, vault) = open_vault();
    let scope = eligible_scope();
    assert_eq!(
        vault.ramp_streak_floor(&scope).expect("floor"),
        DEFAULT_GRADUATION_STREAK_FLOOR
    );

    vault.set_ramp_streak_floor(&scope, 2).expect("set floor");
    vault
        .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)
        .expect("record");
    assert_eq!(
        vault.ramp_scope_state(&scope).expect("state"),
        RampState::Propose
    );
    let stats = vault
        .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)
        .expect("record");
    assert_eq!(stats.state, RampState::Offered);
}

#[test]
fn a_floor_survives_the_rebuild_that_drops_the_stats() {
    let (_dir, vault) = open_vault();
    let scope = eligible_scope();
    vault.set_ramp_streak_floor(&scope, 3).expect("set floor");
    vault.rebuild_ramp_stats_from_receipts().expect("rebuild");
    assert_eq!(vault.ramp_streak_floor(&scope).expect("floor"), 3);
}

#[test]
fn stats_persist_across_reopen_and_rebuild_reproduces_them_exactly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let survivor = crate::test_util::entity(0x21);
    let loser = crate::test_util::entity(0x22);
    let second_loser = crate::test_util::entity(0x23);
    let amended = crate::encode_identity_op_amendment(&merge_op(vec![second_loser], survivor))
        .expect("encode amendment");

    let before = {
        let vault =
            Vault::open(dir.path(), crate::test_util::embedding_test_config()).expect("open vault");
        put_person(&vault, 0x21);
        put_person(&vault, 0x22);
        put_person(&vault, 0x23);
        park_and_rule(&vault, survivor, loser, ProposalRuling::Approve, 200, 300);
        park_and_rule(
            &vault,
            survivor,
            second_loser,
            ProposalRuling::AmendThenApprove(&amended),
            400,
            500,
        );
        let before = all_stats(&vault);
        assert_eq!(before.len(), 1, "both rulings share one merge scope");
        assert_eq!(before[0].amended, 1);
        assert_eq!(before[0].untouched_streak, 0, "the amendment reset it");
        assert_eq!(
            before[0].last_outcome,
            Some(ProposalOutcome::ApprovedAmended)
        );
        before
    };

    let vault =
        Vault::open(dir.path(), crate::test_util::embedding_test_config()).expect("reopen vault");
    assert_eq!(all_stats(&vault), before, "stats must survive a reopen");

    vault
        .rebuild_ramp_stats_from_receipts()
        .expect("rebuild from receipts");
    assert_eq!(
        all_stats(&vault),
        before,
        "a receipts-alone refold must land byte-identically on incremental maintenance"
    );
}

#[test]
fn the_rebuild_folds_demotions_not_only_rulings() {
    let (_dir, vault) = open_vault();
    let scope = eligible_scope();
    vault.set_ramp_streak_floor(&scope, 1).expect("set floor");
    // A ruling that IS receipted, so the refold has a scope to rebuild.
    put_person(&vault, 0x21);
    put_person(&vault, 0x22);
    park_and_rule(
        &vault,
        crate::test_util::entity(0x21),
        crate::test_util::entity(0x22),
        ProposalRuling::Approve,
        200,
        300,
    );
    let merge_scope = all_stats(&vault)[0].scope.clone();
    assert_eq!(
        vault
            .scope_stats(&merge_scope)
            .expect("stats")
            .expect("row")
            .untouched_streak,
        1
    );

    vault
        .demote_scope_to_propose(&merge_scope, DemotionReason::AgentJudgment)
        .expect("demote");
    vault.rebuild_ramp_stats_from_receipts().expect("rebuild");
    assert_eq!(
        vault
            .scope_stats(&merge_scope)
            .expect("stats")
            .expect("row")
            .untouched_streak,
        0,
        "the rebuild must fold the demotion that zeroed the streak, not just the ruling"
    );
}

#[test]
fn identity_topology_op_kinds_never_graduate() {
    let (_dir, vault) = open_vault();
    let owner = owner(&vault);
    for op_kind in ["merge", "split", "facet", "assert_distinct", "undo"] {
        assert!(!op_kind_is_ramp_eligible(op_kind));
        let scope = RampScope::new(op_kind, "PERSON", "agent-a").expect("scope");
        assert!(!scope.is_graduatable());

        for _ in 0..DEFAULT_GRADUATION_STREAK_FLOOR * 2 {
            vault
                .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)
                .expect("record");
        }
        assert_eq!(
            vault.ramp_scope_state(&scope).expect("state"),
            RampState::Propose,
            "{op_kind} must never leave the inert state"
        );
        assert!(
            vault.graduation_offers().expect("offers").is_empty(),
            "{op_kind} must never surface an offer"
        );
        assert!(
            vault.accept_graduation_offer(&owner, &scope).is_err(),
            "{op_kind} has no propose lane to skip"
        );
    }
    assert!(
        vault
            .active_standing_consent_grants()
            .expect("grants")
            .is_empty()
    );
}

#[test]
fn an_ordinary_propose_lane_op_kind_is_eligible() {
    // The negative above is only meaningful if the predicate is not
    // universally false.
    for op_kind in ["send_email", "post_message", "schedule_meeting"] {
        assert!(op_kind_is_ramp_eligible(op_kind));
    }
}

#[test]
fn state_strings_round_trip() {
    for state in [RampState::Propose, RampState::Offered, RampState::Graduated] {
        assert_eq!(RampState::parse(state.as_str()), Some(state));
    }
    assert_eq!(RampState::Propose.as_str(), "proposed");
    assert_eq!(RampState::parse("nonsense"), None);

    for reason in [
        DemotionReason::Rejected,
        DemotionReason::Amended,
        DemotionReason::AgentJudgment,
    ] {
        assert_eq!(DemotionReason::parse(reason.as_str()), Some(reason));
    }
    assert_eq!(DemotionReason::parse("nonsense"), None);
}
