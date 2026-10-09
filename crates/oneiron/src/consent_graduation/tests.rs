//! ONE-1748 (MS-06) unit tests: the scope handle's keying, the
//! streak→offer→tap→grant path, receipted self-demotion, per-scope floors,
//! persistence across reopen, the CID-7 rebuild against the REAL proposal
//! resolution door, and the r7 §5 boundary that keeps identity-topology ops
//! off the ramp.

use super::*;
use crate::store::GateDecisionId;

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

fn all_stats(vault: &Vault) -> Vec<ScopeOutcomeStats> {
    let rtxn = vault.store.env.read_txn().expect("read txn");
    let mut rows = Vec::new();
    for (_, row) in RAMP_STATS.scan(&vault.store, &rtxn).expect("scan stats") {
        let (scope, counters) = stats_row_parts(row).expect("parts");
        let state = derive_state_in_txn(vault, &rtxn, &scope, counters).expect("state");
        rows.push(stats_view(scope, counters, state));
    }
    rows.sort_by(|left, right| left.scope.cmp(&right.scope));
    rows
}

/// Ramp receipts read back through the PUBLIC query surface, so a count also
/// witnesses that the projector is registered in the `Gate` family.
fn ramp_receipts_via_public_query(
    vault: &Vault,
    keep: fn(&crate::receipt::ReceiptRecord) -> bool,
) -> Vec<crate::receipt::ReceiptRecord> {
    let query = ReceiptQuery::default().with_kind(ReceiptKind::Gate);
    vault
        .receipts(query)
        .expect("gate receipts")
        .into_iter()
        .filter(keep)
        .collect()
}

fn demotion_receipts_via_public_query(vault: &Vault) -> Vec<crate::receipt::ReceiptRecord> {
    ramp_receipts_via_public_query(vault, is_ramp_demotion_receipt)
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
fn a_door_recorded_streak_is_witnessed_by_receipts_and_survives_the_rebuild() {
    let (_dir, vault) = open_vault();
    let scope = eligible_scope();
    for _ in 0..DEFAULT_GRADUATION_STREAK_FLOOR {
        vault
            .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)
            .expect("record");
    }
    assert_eq!(
        vault.graduation_offers().expect("offers"),
        vec![scope.clone()]
    );

    // Every counter the door moved names a durable receipt: an offer no
    // receipt can explain is trust the ledger never witnessed.
    let receipts = ramp_receipts_via_public_query(&vault, is_ramp_outcome_receipt);
    assert_eq!(
        receipts.len(),
        DEFAULT_GRADUATION_STREAK_FLOOR as usize,
        "one outcome receipt per recorded ruling"
    );
    assert_eq!(
        receipts[0].outcome,
        ProposalOutcome::ApprovedUntouched.as_str()
    );
    assert_eq!(
        receipts[0].fields.get(crate::receipt::FIELD_SCOPE_ACTOR),
        Some(&scope.actor)
    );

    vault.rebuild_ramp_stats_from_receipts().expect("rebuild");
    assert_eq!(
        vault
            .scope_stats(&scope)
            .expect("stats")
            .expect("row")
            .untouched_streak,
        DEFAULT_GRADUATION_STREAK_FLOOR,
        "a refold must reproduce the earned streak, not delete it"
    );
    assert_eq!(vault.graduation_offers().expect("offers"), vec![scope]);
}

#[test]
fn a_retracted_offer_cannot_be_taken_by_a_stale_tap() {
    let (_dir, vault) = open_vault();
    let scope = eligible_scope();
    let owner = owner(&vault);
    for _ in 0..DEFAULT_GRADUATION_STREAK_FLOOR {
        vault
            .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)
            .expect("record");
    }
    assert_eq!(
        vault.ramp_scope_state(&scope).expect("state"),
        RampState::Offered
    );

    // The ruling that retracts the offer lands while the tap is in flight.
    vault
        .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::Rejected)
        .expect("rejection");
    assert!(vault.graduation_offers().expect("offers").is_empty());

    assert!(
        vault.accept_graduation_offer(&owner, &scope).is_err(),
        "an offer the evidence retracted cannot still mint a grant"
    );
    assert!(
        vault
            .active_standing_consent_grants()
            .expect("grants")
            .is_empty()
    );
    assert_eq!(
        vault.ramp_scope_state(&scope).expect("state"),
        RampState::Propose
    );
}

#[test]
fn an_unbuildable_public_scope_never_commits_a_row() {
    let (_dir, vault) = open_vault();
    let owner = owner(&vault);
    // The tuple fields are public, so a caller can assemble what `new` would
    // have refused — including an un-normalized twin that keys to its own row.
    for scope in [
        RampScope {
            op_kind: "send_email".to_owned(),
            target_class: "client_followup".to_owned(),
            actor: String::new(),
        },
        RampScope {
            op_kind: " send_email".to_owned(),
            target_class: "client_followup".to_owned(),
            actor: "agent-a".to_owned(),
        },
    ] {
        assert!(
            vault
                .record_proposal_outcome_for_ramp(&scope, ProposalOutcome::ApprovedUntouched)
                .is_err()
        );
        assert!(
            vault
                .demote_scope_to_propose(&scope, DemotionReason::AgentJudgment)
                .is_err()
        );
        assert!(vault.set_ramp_streak_floor(&scope, 2).is_err());
        assert!(vault.accept_graduation_offer(&owner, &scope).is_err());
    }

    assert!(
        all_stats(&vault).is_empty(),
        "a rejected tuple must leave nothing behind"
    );
    // The all-scopes scan must still be readable: one poisoned row would fail
    // it globally for every honest scope.
    assert!(vault.graduation_offers().expect("offers").is_empty());
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
