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
    register_crm_pack(
        &vault,
        CAMPAIGN_BYTE,
        SAVED_QUERY_BYTE,
        crate::registry::TypeByteFamily::Productivity,
    )
    .expect("register CRM pack");
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

/// F13 H202: a membership page reads a bounded run of claims. 4,097 other
/// claims sort before the cohort's one head, so the first one-row page reads
/// its run, returns no row and a cursor; paging on reaches the member once.
#[test]
fn a_membership_page_reads_a_bounded_run_of_claims_and_pages_on() {
    let (_dir, vault) = oracle_vault();
    let (owner, person) = (test_id(0x71), test_id(0x73));
    for actor in [owner, person] {
        put_person(&vault, actor);
    }
    let facade = vault.memory(owner, EdgeActorClass::Human);
    let campaign = facade
        .campaign_create(
            &CreateCampaignRequest {
                schema_version: CAMPAIGN_SCHEMA_VERSION,
                name: "large vault".to_owned(),
            },
            10,
        )
        .expect("create campaign")
        .campaign_ref;
    let query = facade
        .saved_query_create(&saved_query_request(), 10)
        .expect("create saved query")
        .query_ref;
    let noise = crate::claim::encode_claim_body(
        &crate::claim::ClaimBody::new(
            "profile.noise",
            crate::claim::ClaimSubject::Entity(person),
            rmpv::Value::from("noise"),
            1.0,
            crate::claim::ClaimApprovalStatus::Approved,
            crate::claim::ClaimLifecycleStatus::Active,
        )
        .expect("noise body"),
    )
    .expect("noise claim");
    vault
        .with_write_txn(|wtxn| {
            for index in 0..4_097_u16 {
                let [hi, lo] = index.to_be_bytes();
                let id = crate::EntityId::from_bytes([
                    0, 0, 0, 0, hi, lo, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                ])?;
                let payload = crate::test_util::entity_record(
                    crate::registry::ENTITY_TYPE_CLAIM,
                    crate::TimeRange { start: 5, end: 5 },
                    5,
                    &noise,
                );
                vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
                let type_key =
                    crate::store::Store::encode_type_key(crate::registry::ENTITY_TYPE_CLAIM, &id);
                vault.store.type_index.put(wtxn, &type_key, &[])?;
            }
            Ok(())
        })
        .expect("seed other claims");
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

    let first = read_campaign_members(&vault, &request(campaign, 1)).expect("first page");
    assert!(first.rows.is_empty(), "the first page reads only its run");
    let mut cursor = first.next_cursor;
    assert!(
        cursor.is_some(),
        "a page that stopped early carries a cursor"
    );
    let mut members = Vec::new();
    for _ in 0..4 {
        let Some(after) = cursor.take() else { break };
        let page = read_campaign_members(
            &vault,
            &MembershipReadRequest {
                cursor: Some(after),
                ..request(campaign, 1)
            },
        )
        .expect("next page");
        members.extend(page.rows.into_iter().map(|row| row.entity_ref));
        cursor = page.next_cursor;
    }
    assert_eq!(members, vec![person]);
    assert_eq!(cursor, None);
}
