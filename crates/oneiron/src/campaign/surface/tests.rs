//! Oracle-style membership and scoping tests.

use super::*;
use crate::EdgeActorClass;
use crate::campaign::claims::{CampaignMemberChannel, CampaignMemberState};
use crate::campaign::register_crm_pack;
use crate::config::VaultConfig;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::saved_query::{
    MembershipCause, MembershipCommitOutcome, MembershipWritePlan, commit_membership_plan,
    derived_member_value,
};

// Free dynamic slots in the compiled-product zone. 100-106 are statically
// allocated after byte-space v3, so the CRM pack registers above them.
const CAMPAIGN_BYTE: u8 = 107;
const SAVED_QUERY_BYTE: u8 = 108;

/// Unseeded, like CA-01's and CA-02's oracles: the default policy manifest
/// declares axes for `profile.`, `calendar.`, `booking.`, and `affect.vad`
/// only, so every CRM predicate falls to the manifest's `critical` default
/// and a `campaign.member` write is held PENDING at the criticality floor.
/// The projection under test reads heads CA-03 already wrote, so the
/// fixture writes them the way CA-02's own oracle does.
fn oracle_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open_unseeded_for_test(dir.path(), VaultConfig::device())
        .expect("open unseeded vault");
    register_crm_pack(&vault, CAMPAIGN_BYTE, SAVED_QUERY_BYTE).expect("register CRM pack");
    (dir, vault)
}

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; 16]).expect("seeded id")
}

fn put_person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"campaign surface person",
        )
        .expect("put person");
}

/// One `(query, campaign)` pair, so a fixture can spell a transition
/// without restating the two refs it never varies.
struct Cohort<'v> {
    vault: &'v Vault,
    query: EntityId,
    campaign: EntityId,
}

impl Cohort<'_> {
    fn commit(
        &self,
        person: EntityId,
        epoch: u64,
        transition: MembershipTransition,
        cause: MembershipCause,
        at: u64,
    ) {
        let event = MembershipEvent {
            query_ref: self.query,
            campaign_ref: self.campaign,
            entity_ref: person,
            epoch,
            valid_at: at,
            detected_at: at + 1,
            transition,
            cause,
            evidence_hash: [u8::try_from(epoch % 251).unwrap_or_default(); 32],
        };
        let state = match transition {
            MembershipTransition::Entered => CampaignMemberState::Enrolled,
            MembershipTransition::Exited => CampaignMemberState::Exited,
        };
        let plan = MembershipWritePlan {
            value: derived_member_value(
                &event,
                state,
                vec![CampaignMemberChannel {
                    channel: "email".to_owned(),
                    basis_evidence: test_id(0xE1),
                    sender_ref: test_id(0xE2),
                }],
            ),
            event,
        };
        assert_eq!(
            commit_membership_plan(self.vault, &plan, at + 1).expect("commit plan"),
            MembershipCommitOutcome::Applied
        );
    }
}

/// A minimal but REAL create request: the filter and matcher go through
/// CA-02's own `parse_filter_ast`, so the fixture cannot admit an
/// expression the engine would refuse.
fn saved_query_request() -> CreateSavedQueryRequest {
    let claim = |predicate: &str| {
        parse_filter_ast(&serde_json::json!({
            "op": "claim",
            "predicate": predicate,
            "cmp": "eq",
            "value": "vp",
        }))
        .expect("stage-1 filter")
    };
    CreateSavedQueryRequest {
        schema_version: SAVED_QUERY_SCHEMA_VERSION,
        scope: QueryScope::default(),
        filter: claim("profile.seniority"),
        matcher: MatcherSpec::Hard {
            expression: claim("profile.headcount"),
        },
        eval: EvalPolicy {
            mode: EvalMode::Manual,
            max_entities_per_wake: 8,
            max_judges_per_wake: 4,
        },
    }
}

fn request(owner: EntityId, limit: u32) -> MembershipReadRequest {
    MembershipReadRequest {
        owner_ref: owner,
        cursor: None,
        limit,
        at_epoch: None,
    }
}

/// Every entity in the vault, so "this read wrote nothing" is checkable
/// rather than asserted.
fn fingerprint(vault: &Vault) -> Vec<(u8, [u8; 16])> {
    let mut rows = Vec::new();
    for entity_type in u8::MIN..=u8::MAX {
        for id in vault.entities_by_type(entity_type).unwrap_or_default() {
            rows.push((entity_type, *id.as_bytes()));
        }
    }
    rows.sort_unstable();
    rows
}

/// Pages are stable, bounded, and gap-free across a cursor boundary.
#[test]
fn campaign_membership_reads_are_paginated_and_read_only() {
    let (_dir, vault) = oracle_vault();
    let (query, campaign) = (test_id(0x31), test_id(0x30));
    let cohort = Cohort {
        vault: &vault,
        query,
        campaign,
    };
    let people = [test_id(0x41), test_id(0x42), test_id(0x43)];
    for (index, person) in people.iter().enumerate() {
        put_person(&vault, *person);
        cohort.commit(
            *person,
            1,
            MembershipTransition::Entered,
            MembershipCause::DataChange,
            100 + index as u64,
        );
    }
    let ordered: Vec<EntityId> = people.to_vec();

    // A page wide enough for the cohort carries all of it, in entity order,
    // and reports no successor.
    let full = read_campaign_members(&vault, &request(campaign, 10)).expect("full page");
    assert_eq!(
        full.rows
            .iter()
            .map(|row| row.entity_ref)
            .collect::<Vec<_>>(),
        ordered
    );
    assert!(full.next_cursor.is_none());

    // Bitemporal fields are the committed event's, not the read's clock.
    assert_eq!(full.rows[0].state, "entered");
    assert_eq!(full.rows[0].cause.as_deref(), Some("data_change"));
    assert_eq!(full.rows[0].entered_valid, 100);
    assert_eq!(full.rows[0].entered_detected, 101);
    assert_eq!(full.rows[0].exited_valid, None);
    assert_eq!(full.rows[0].exited_detected, None);

    // limit=2 splits it; the cursor resumes exactly where page one stopped.
    let first = read_campaign_members(&vault, &request(campaign, 2)).expect("page one");
    assert_eq!(first.rows.len(), 2);
    let cursor = first.next_cursor.clone().expect("a successor page");
    let second = read_campaign_members(
        &vault,
        &MembershipReadRequest {
            cursor: Some(cursor),
            ..request(campaign, 2)
        },
    )
    .expect("page two");
    assert_eq!(second.rows.len(), 1);
    assert!(second.next_cursor.is_none());
    let paged: Vec<EntityId> = first
        .rows
        .iter()
        .chain(second.rows.iter())
        .map(|row| row.entity_ref)
        .collect();
    assert_eq!(paged, ordered, "paging must neither skip nor repeat a row");

    // Repeating a page is idempotent — the cursor is a position, not a
    // consumed token.
    assert_eq!(
        read_campaign_members(&vault, &request(campaign, 2)).expect("replay"),
        first
    );

    // `limit = 0` means the default, and an over-large limit is clamped
    // rather than refused.
    assert_eq!(
        read_campaign_members(&vault, &request(campaign, 0))
            .expect("default limit")
            .rows
            .len(),
        people.len()
    );
    assert_eq!(
        read_campaign_members(
            &vault,
            &request(campaign, MEMBERSHIP_PAGE_MAX_LIMIT + 10_000)
        )
        .expect("clamped limit")
        .rows
        .len(),
        people.len()
    );

    // A malformed cursor is a typed rejection, never a silent page one.
    for malformed in ["", "nonsense", &"a".repeat(95), &"g".repeat(96)] {
        assert!(
            read_campaign_members(
                &vault,
                &MembershipReadRequest {
                    cursor: Some(malformed.to_owned()),
                    ..request(campaign, 2)
                },
            )
            .is_err(),
            "{malformed:?} must not read as page one"
        );
    }

    // Another campaign's cohort is not this one's.
    assert!(
        read_campaign_members(&vault, &request(test_id(0x39), 10))
            .expect("empty cohort")
            .rows
            .is_empty()
    );

    // Nothing in any of that wrote a claim, an attempt row, or an entity.
    let before = fingerprint(&vault);
    let _ = read_campaign_members(&vault, &request(campaign, 1)).expect("read");
    let _ = read_saved_query_members(&vault, &request(query, 1)).expect("read");
    assert_eq!(fingerprint(&vault), before);
}

/// Causes survive verbatim, and an epoch ceiling reads the cohort as it
/// stood at that epoch.
#[test]
fn saved_query_membership_reads_preserve_causes() {
    let (_dir, vault) = oracle_vault();
    let (query, campaign, person) = (test_id(0x51), test_id(0x50), test_id(0x52));
    put_person(&vault, person);
    let cohort = Cohort {
        vault: &vault,
        query,
        campaign,
    };

    // One entity, three epochs, the closed cause set in full.
    cohort.commit(
        person,
        1,
        MembershipTransition::Entered,
        MembershipCause::DataChange,
        200,
    );
    cohort.commit(
        person,
        2,
        MembershipTransition::Exited,
        MembershipCause::ScopeChange,
        300,
    );
    cohort.commit(
        person,
        3,
        MembershipTransition::Entered,
        MembershipCause::DefinitionChange,
        400,
    );

    let at = |epoch: Option<u64>| {
        read_saved_query_members(
            &vault,
            &MembershipReadRequest {
                at_epoch: epoch,
                ..request(query, 10)
            },
        )
        .expect("membership page")
        .rows
        .first()
        .cloned()
        .expect("one row")
    };

    let now = at(None);
    assert_eq!(now.state, "entered");
    assert_eq!(now.cause.as_deref(), Some("definition_change"));
    assert_eq!(now.entered_valid, 400);
    assert_eq!(now.entered_detected, 401);
    assert_eq!(now.exited_valid, None);

    // As of epoch 2 the entity was OUT — and the row still reports when it
    // had entered, so a departure keeps its history instead of erasing it.
    let mid = at(Some(2));
    assert_eq!(mid.state, "exited");
    assert_eq!(mid.cause.as_deref(), Some("scope_change"));
    assert_eq!(mid.entered_valid, 200);
    assert_eq!(mid.exited_valid, Some(300));
    assert_eq!(mid.exited_detected, Some(301));

    let start = at(Some(1));
    assert_eq!(start.state, "entered");
    assert_eq!(start.cause.as_deref(), Some("data_change"));
    assert_eq!(start.exited_valid, None);

    // An epoch below the first transition has nothing to fold.
    assert!(
        read_saved_query_members(
            &vault,
            &MembershipReadRequest {
                at_epoch: Some(0),
                ..request(query, 10)
            },
        )
        .expect("page")
        .rows
        .is_empty()
    );

    // Every cause the projection can emit is one of CA-02's three tokens,
    // spelled by CA-02 rather than restated here.
    for cause in MembershipCause::ALL {
        assert!(["data_change", "scope_change", "definition_change"].contains(&cause.as_str()));
    }

    // The campaign axis of the same head projects identically: one fold,
    // two selectors.
    assert_eq!(
        read_campaign_members(&vault, &request(campaign, 10))
            .expect("campaign page")
            .rows,
        vec![now]
    );
}

/// One `(query, entity)` pair can hold heads in several campaigns. Each row
/// folds only the events of ITS campaign.
#[test]
fn membership_rows_fold_only_their_own_campaigns_events() {
    let (_dir, vault) = oracle_vault();
    let query = test_id(0x61);
    let (first, second) = (test_id(0x60), test_id(0x62));
    let person = test_id(0x63);
    put_person(&vault, person);
    let in_first = Cohort {
        vault: &vault,
        query,
        campaign: first,
    };
    let in_second = Cohort {
        vault: &vault,
        query,
        campaign: second,
    };

    // The event log is keyed `(query, entity)`, so these three transitions
    // share ONE history across two campaigns — and the epoch is monotonic
    // over that shared history, not per campaign.
    in_first.commit(
        person,
        1,
        MembershipTransition::Entered,
        MembershipCause::DataChange,
        100,
    );
    in_second.commit(
        person,
        2,
        MembershipTransition::Entered,
        MembershipCause::ScopeChange,
        200,
    );
    in_second.commit(
        person,
        3,
        MembershipTransition::Exited,
        MembershipCause::DefinitionChange,
        300,
    );

    // The first campaign never saw the exit: its member is still enrolled,
    // on its own entry's clock and its own cause.
    let still_in = read_campaign_members(&vault, &request(first, 10)).expect("first cohort");
    assert_eq!(still_in.rows.len(), 1);
    assert_eq!(still_in.rows[0].state, "entered");
    assert_eq!(still_in.rows[0].cause.as_deref(), Some("data_change"));
    assert_eq!(still_in.rows[0].entered_valid, 100);
    assert_eq!(still_in.rows[0].exited_valid, None);

    // The second did, and dates the entry from its OWN entry event rather
    // than from the first campaign's.
    let left = read_campaign_members(&vault, &request(second, 10)).expect("second cohort");
    assert_eq!(left.rows.len(), 1);
    assert_eq!(left.rows[0].state, "exited");
    assert_eq!(left.rows[0].cause.as_deref(), Some("definition_change"));
    assert_eq!(left.rows[0].entered_valid, 200);
    assert_eq!(left.rows[0].exited_valid, Some(300));

    // The query axis pages both heads, each folded against its own
    // campaign, so the derived cohort is not one campaign's state twice.
    let derived = read_saved_query_members(&vault, &request(query, 10)).expect("query cohort");
    let mut states: Vec<&str> = derived
        .rows
        .iter()
        .map(|row| row.state.as_str())
        .collect::<Vec<_>>();
    states.sort_unstable();
    assert_eq!(states, ["entered", "exited"]);
}

/// A membership page is the owner's cohort, not any admitted caller's.
#[test]
fn membership_reads_are_scoped_to_the_owning_principal() {
    let (_dir, vault) = oracle_vault();
    let (owner, intruder, person) = (test_id(0x71), test_id(0x72), test_id(0x73));
    for actor in [owner, intruder, person] {
        put_person(&vault, actor);
    }

    let owner_facade = vault.memory(owner, EdgeActorClass::Human);
    let campaign = owner_facade
        .campaign_create(
            &CreateCampaignRequest {
                schema_version: CAMPAIGN_SCHEMA_VERSION,
                name: "owned cohort".to_owned(),
            },
            10,
        )
        .expect("create campaign")
        .campaign_ref;
    let query = owner_facade
        .saved_query_create(&saved_query_request(), 10)
        .expect("create saved query")
        .query_ref;
    Cohort {
        vault: &vault,
        query,
        campaign,
    }
    .commit(
        person,
        1,
        MembershipTransition::Entered,
        MembershipCause::DataChange,
        100,
    );

    // The owner pages their own cohort on both axes.
    assert_eq!(
        owner_facade
            .campaign_members(&request(campaign, 10))
            .expect("owner campaign page")
            .rows
            .len(),
        1
    );
    assert_eq!(
        owner_facade
            .saved_query_members(&request(query, 10))
            .expect("owner query page")
            .rows
            .len(),
        1
    );

    // Another admitted principal holding the same well-formed refs pages
    // nothing: absent-or-not-yours is ONE answer here, exactly as it is for
    // the record reads.
    let intruder_facade = vault.memory(intruder, EdgeActorClass::Human);
    assert!(
        intruder_facade
            .campaign_members(&request(campaign, 10))
            .expect("foreign campaign page")
            .rows
            .is_empty(),
        "a campaign's cohort must not page for a principal that does not own it"
    );
    assert!(
        intruder_facade
            .saved_query_members(&request(query, 10))
            .expect("foreign query page")
            .rows
            .is_empty(),
        "a query's cohort must not page for a principal that does not own it"
    );
}

/// A `scope` that is not an object is a field error, never an unrestricted
/// query: every axis of [`QueryScope`] reads empty as "no restriction".
#[test]
fn scope_must_be_an_object() {
    for malformed in [
        serde_json::json!("sales"),
        serde_json::json!(7),
        serde_json::json!(["sales"]),
        serde_json::json!(true),
    ] {
        let body = serde_json::json!({ "scope": malformed });
        assert!(
            parse_scope(&body).is_err(),
            "{malformed} must not widen the query to every world and facet"
        );
    }
    // Absent and null still mean the default scope, which CA-02 documents.
    assert_eq!(
        parse_scope(&serde_json::json!({})).expect("absent scope"),
        QueryScope::default()
    );
    assert_eq!(
        parse_scope(&serde_json::json!({ "scope": Value::Null })).expect("null scope"),
        QueryScope::default()
    );
}
