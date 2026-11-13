//! Census L3-28C (ARCH-0044 H202): a campaign's and a saved query's
//! membership pages nominate their heads from the campaign member index
//! instead of reading every CLAIM in the vault. The index changes no page:
//! after enter / exit / re-enter commits, a manual head that replaced a
//! derived one, two campaigns and two queries, every page (two rows at a
//! time, and at an epoch ceiling) reads as the scan reads it with the index
//! dropped, and as it reads after a reopen rebuilds the dropped index; the
//! index serves each read (no fallback). A timing line compares the two
//! reads beside 2,000 other claims.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test campaign_member_index -- --nocapture`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::Path;
use std::time::{Duration, Instant};

use oneiron::campaign::claims::{
    CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    decode_campaign_member_value, encode_campaign_member_value,
};
use oneiron::campaign::register_crm_pack;
use oneiron::campaign::surface::{
    CAMPAIGN_SCHEMA_VERSION, CreateCampaignRequest, MembershipPage, MembershipReadRequest,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, TypeByteFamily};
use oneiron::saved_query::{
    ClaimComparison, CreateSavedQueryRequest, EvalMode, EvalPolicy, FilterAst, MatcherSpec,
    MembershipCause, MembershipCommitOutcome, MembershipEvent, MembershipTransition,
    MembershipWritePlan, QueryScope, SAVED_QUERY_SCHEMA_VERSION, commit_membership_plan,
    derived_member_value,
};
use oneiron::test_doors::campaign_member_index as doors;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig,
};

// Free dynamic slots in the compiled-product zone, as the CA-01/CA-02
// oracles register the CRM pack.
const CAMPAIGN_BYTE: u8 = 107;
const SAVED_QUERY_BYTE: u8 = 108;

fn id(tag: u8, n: u16) -> EntityId {
    let [hi, lo] = n.to_be_bytes();
    EntityId::from_bytes([
        tag, hi, lo, 0x5c, 0x3d, 0x11, 0x42, 0x07, 0x19, 0x2e, 0x6b, 0x4f, 0x08, 0x73, 0x21, 0x9a,
    ])
    .expect("fixture id")
}

/// Unseeded, like the CA-01/CA-02 oracles: the heads under test are written
/// the way CA-02's own commit writes them.
fn open(dir: &Path) -> Vault {
    let vault =
        Vault::open_unseeded_for_test(dir, VaultConfig::device()).expect("open unseeded vault");
    register_crm_pack(
        &vault,
        CAMPAIGN_BYTE,
        SAVED_QUERY_BYTE,
        TypeByteFamily::Productivity,
    )
    .expect("register CRM pack");
    vault
}

fn put_person(vault: &Vault, person: EntityId) {
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"campaign member index person",
        )
        .expect("put person");
}

fn channel() -> CampaignMemberChannel {
    CampaignMemberChannel {
        channel: "email".to_owned(),
        basis_evidence: id(0xE1, 0),
        sender_ref: id(0xE2, 0),
    }
}

fn saved_query_request() -> CreateSavedQueryRequest {
    let claim = |predicate: &str| FilterAst::Claim {
        predicate: predicate.to_owned(),
        cmp: ClaimComparison::Exists,
        value: serde_json::Value::Null,
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

/// The owner, two campaigns and two saved queries the owner created.
struct Cohorts {
    owner: EntityId,
    campaigns: [EntityId; 2],
    queries: [EntityId; 2],
}

fn create_cohorts(vault: &Vault) -> Cohorts {
    let owner = id(0x71, 0);
    put_person(vault, owner);
    let facade = vault.memory(owner, EdgeActorClass::Human);
    let campaign = |name: &str| {
        facade
            .campaign_create(
                &CreateCampaignRequest {
                    schema_version: CAMPAIGN_SCHEMA_VERSION,
                    name: name.to_owned(),
                },
                10,
            )
            .expect("create campaign")
            .campaign_ref
    };
    let campaigns = [campaign("first cohort"), campaign("second cohort")];
    let query = || {
        facade
            .saved_query_create(&saved_query_request(), 10)
            .expect("create saved query")
            .query_ref
    };
    let queries = [query(), query()];
    Cohorts {
        owner,
        campaigns,
        queries,
    }
}

/// One CA-02 membership commit; every commit of a fixture takes the next
/// epoch, so no watermark refuses one.
fn commit(
    vault: &Vault,
    epoch: &mut u64,
    (query, campaign): (EntityId, EntityId),
    person: EntityId,
    transition: MembershipTransition,
) {
    *epoch += 1;
    let at = *epoch * 100;
    let event = MembershipEvent {
        query_ref: query,
        campaign_ref: campaign,
        entity_ref: person,
        epoch: *epoch,
        valid_at: at,
        detected_at: at + 1,
        transition,
        cause: MembershipCause::DataChange,
        evidence_hash: [u8::try_from(*epoch % 251).unwrap_or_default(); 32],
    };
    let state = match transition {
        MembershipTransition::Entered => CampaignMemberState::Enrolled,
        MembershipTransition::Exited => CampaignMemberState::Exited,
    };
    let plan = MembershipWritePlan {
        value: derived_member_value(&event, state, vec![channel()]),
        event,
    };
    assert_eq!(
        commit_membership_plan(vault, &plan, at + 1).expect("commit plan"),
        MembershipCommitOutcome::Applied
    );
}

/// The live `campaign.member` head on `person` scoped to `campaign`.
fn live_head(vault: &Vault, person: EntityId, campaign: EntityId) -> EntityId {
    vault
        .claims_for_subject(&person)
        .expect("claims for subject")
        .into_iter()
        .find(|claim| {
            vault
                .get_claim(claim)
                .expect("get claim")
                .is_some_and(|body| {
                    body.predicate == PREDICATE_CAMPAIGN_MEMBER
                        && body.lifecycle == ClaimLifecycleStatus::Active
                        && decode_campaign_member_value(&body.value)
                            .is_ok_and(|value| value.campaign == campaign)
                })
        })
        .expect("a live head")
}

/// A manual enrollment that replaces `derived`: the query that derived it
/// still pages the member through the lineage (FIX 9664).
fn replace_with_manual_head(
    vault: &Vault,
    manual: EntityId,
    derived: EntityId,
    person: EntityId,
    campaign: EntityId,
) {
    let value = CampaignMemberValue {
        campaign,
        state: CampaignMemberState::Enrolled,
        channels: vec![channel()],
        derivation: None,
    };
    let body = ClaimBody::new(
        PREDICATE_CAMPAIGN_MEMBER,
        ClaimSubject::Entity(person),
        encode_campaign_member_value(&value),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("manual member body");
    vault
        .put_claim(
            &manual,
            &body,
            TimeRange {
                start: 5_000,
                end: 5_000,
            },
            5_000,
        )
        .expect("put manual head");
    vault
        .supersede_claim(&manual, &derived, 5_001)
        .expect("manual head replaces the derived one");
}

/// Which page a read asks for.
#[derive(Clone, Copy, Debug)]
enum Axis {
    Campaign,
    SavedQuery,
}

/// Every page of one owner's membership, two rows at a time, then the
/// whole page at an epoch ceiling.
fn pages(vault: &Vault, owner: EntityId, axis: Axis, owner_ref: EntityId) -> Vec<MembershipPage> {
    let facade = vault.memory(owner, EdgeActorClass::Human);
    let read = |cursor: Option<String>, limit: u32, at_epoch: Option<u64>| {
        let request = MembershipReadRequest {
            owner_ref,
            cursor,
            limit,
            at_epoch,
        };
        let page = match axis {
            Axis::Campaign => facade.campaign_members(&request),
            Axis::SavedQuery => facade.saved_query_members(&request),
        };
        page.expect("membership page")
    };
    let mut out = Vec::new();
    let mut cursor = None;
    for _ in 0..64 {
        let page = read(cursor, 2, None);
        cursor = page.next_cursor.clone();
        out.push(page);
        if cursor.is_none() {
            break;
        }
    }
    assert!(cursor.is_none(), "paging ends");
    out.push(read(None, 0, Some(4)));
    out
}

/// Every page of every axis and owner, in a fixed order.
fn all_pages(vault: &Vault, cohorts: &Cohorts) -> Vec<Vec<MembershipPage>> {
    let mut out = Vec::new();
    for campaign in cohorts.campaigns {
        out.push(pages(vault, cohorts.owner, Axis::Campaign, campaign));
    }
    for query in cohorts.queries {
        out.push(pages(vault, cohorts.owner, Axis::SavedQuery, query));
    }
    out
}

fn row_count(pages: &[Vec<MembershipPage>]) -> usize {
    pages
        .iter()
        .flat_map(|owner| owner.iter().rev().skip(1))
        .map(|page| page.rows.len())
        .sum()
}

#[test]
fn membership_pages_read_the_same_from_the_index_and_from_the_scan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(dir.path());
    assert!(
        doors::index_complete(&vault).expect("flag"),
        "the open built the index"
    );
    let cohorts = create_cohorts(&vault);
    let [first, second] = cohorts.campaigns;
    let [query_a, query_b] = cohorts.queries;
    let people: Vec<EntityId> = (1..=6).map(|n| id(0x73, n)).collect();
    for person in &people {
        put_person(&vault, *person);
    }
    let mut epoch = 0;
    // Enter, exit and re-enter on one pair; one person in both campaigns
    // from one query; the other query feeding the first campaign.
    for transition in [
        MembershipTransition::Entered,
        MembershipTransition::Exited,
        MembershipTransition::Entered,
    ] {
        commit(&vault, &mut epoch, (query_a, first), people[0], transition);
    }
    commit(
        &vault,
        &mut epoch,
        (query_a, first),
        people[1],
        MembershipTransition::Entered,
    );
    commit(
        &vault,
        &mut epoch,
        (query_a, second),
        people[1],
        MembershipTransition::Entered,
    );
    for person in &people[2..4] {
        commit(
            &vault,
            &mut epoch,
            (query_b, first),
            *person,
            MembershipTransition::Entered,
        );
    }
    commit(
        &vault,
        &mut epoch,
        (query_b, second),
        people[4],
        MembershipTransition::Entered,
    );
    commit(
        &vault,
        &mut epoch,
        (query_b, second),
        people[4],
        MembershipTransition::Exited,
    );
    // A manual head replaces query A's head on the sixth person.
    commit(
        &vault,
        &mut epoch,
        (query_a, first),
        people[5],
        MembershipTransition::Entered,
    );
    let derived = live_head(&vault, people[5], first);
    let manual = id(0x7D, 1);
    replace_with_manual_head(&vault, manual, derived, people[5], first);

    // The index serves every axis, and nominates the manual head on the
    // query page through the lineage as well as on its campaign's.
    let campaign_claims = doors::indexed_campaign_claims(&vault, first).expect("index serves");
    assert!(campaign_claims.contains(&manual) && campaign_claims.contains(&derived));
    let query_claims = doors::indexed_saved_query_claims(&vault, query_a).expect("index serves");
    assert!(
        query_claims.contains(&manual),
        "the manual head that replaced a head query A derived is nominated"
    );
    assert!(
        !doors::indexed_saved_query_claims(&vault, query_b)
            .expect("index serves")
            .contains(&manual)
    );
    assert!(doors::indexed_campaign_claims(&vault, second).is_some());

    let indexed = all_pages(&vault, &cohorts);
    assert!(
        indexed[0].iter().any(|page| !page.rows.is_empty()),
        "the owner pages the first campaign's cohort"
    );

    doors::drop_index(&vault).expect("drop index");
    assert!(!doors::index_complete(&vault).expect("flag"));
    assert!(doors::indexed_campaign_claims(&vault, first).is_none());
    assert!(doors::indexed_saved_query_claims(&vault, query_a).is_none());
    let scanned = all_pages(&vault, &cohorts);
    assert_eq!(indexed, scanned, "the index changes no page");

    drop(vault);
    let vault = open(dir.path());
    assert!(
        doors::index_complete(&vault).expect("flag"),
        "the reopen rebuilt the dropped index"
    );
    assert_eq!(
        doors::indexed_saved_query_claims(&vault, query_a),
        Some(query_claims),
        "the rebuild nominates what the writer did"
    );
    let rebuilt = all_pages(&vault, &cohorts);
    assert_eq!(indexed, rebuilt, "the rebuilt index changes no page");
    eprintln!(
        "DIAG campaign-member-index pages={} rows={}",
        indexed.iter().map(Vec::len).sum::<usize>(),
        row_count(&indexed)
    );
}

#[test]
fn a_membership_page_beside_many_other_claims_reads_the_index() {
    const OTHER_CLAIMS: u16 = 2_000;
    const MEMBERS: u16 = 20;
    const READS: u32 = 20;
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = open(dir.path());
    let cohorts = create_cohorts(&vault);
    let pair = (cohorts.queries[0], cohorts.campaigns[0]);
    let mut epoch = 0;
    for n in 1..=MEMBERS {
        let person = id(0x74, n);
        put_person(&vault, person);
        commit(
            &vault,
            &mut epoch,
            pair,
            person,
            MembershipTransition::Entered,
        );
    }
    let noise = id(0x75, 0);
    put_person(&vault, noise);
    for n in 1..=OTHER_CLAIMS {
        let body = ClaimBody::new(
            "profile.timezone",
            ClaimSubject::Entity(noise),
            rmpv::Value::from(format!("zone {n}")),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
        .expect("other claim");
        vault
            .put_claim(&id(0x76, n), &body, TimeRange { start: 1, end: 1 }, 1)
            .expect("put other claim");
    }
    assert_eq!(
        doors::indexed_campaign_claims(&vault, pair.1)
            .expect("index serves")
            .len(),
        usize::from(MEMBERS)
    );
    let timed = |vault: &Vault| {
        let started = Instant::now();
        let mut last = Vec::new();
        for _ in 0..READS {
            last = pages(vault, cohorts.owner, Axis::Campaign, pair.1);
        }
        (started.elapsed(), last)
    };
    let (index_time, indexed) = timed(&vault);
    doors::drop_index(&vault).expect("drop index");
    let (scan_time, scanned) = timed(&vault);
    assert_eq!(indexed, scanned, "the index changes no page");
    let ms = |elapsed: Duration| elapsed.as_millis();
    eprintln!(
        "DIAG campaign-member-index claims={} members={} page_reads={} rows={} index_ms={} scan_ms={}",
        u32::from(OTHER_CLAIMS) + u32::from(MEMBERS),
        MEMBERS,
        READS,
        indexed
            .iter()
            .rev()
            .skip(1)
            .map(|page| page.rows.len())
            .sum::<usize>(),
        ms(index_time),
        ms(scan_time)
    );
}
