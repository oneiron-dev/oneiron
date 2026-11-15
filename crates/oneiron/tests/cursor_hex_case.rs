//! UC-13 PR 2: every hex page cursor reads in either case and resumes where
//! its lowercase spelling resumes (HEX-CASE-POLICY = A). Every list still
//! writes its cursor in lowercase.
//!
//! Red on main:
//! - `reaction_signal_cursor_reads_in_either_case`: main refuses upper case;
//! - `campaign_member_cursor_resumes_in_either_case`: main compares the raw
//!   text, so an upper-case cursor resumes at another row;
//! - `a_signed_digit_pair_is_refused`: main reads `+c` as a digit pair.
//!
//! The other parsers already took either case: green on main and on the head.
//!
//! Public paths only.

use oneiron::campaign::claims::{CampaignMemberChannel, CampaignMemberState};
use oneiron::campaign::register_crm_pack;
use oneiron::campaign::surface::{CAMPAIGN_SCHEMA_VERSION, CreateCampaignRequest};
use oneiron::inbox::{InboxGroupCursor, UnifiedInboxGroupCursor};
use oneiron::linear_sync::LinearProvenanceRequest;
use oneiron::memory::campaign_records::{MembershipPage, MembershipReadRequest};
use oneiron::memory::{Memory, MemoryResult};
use oneiron::reaction::ReactionSignalPaging;
use oneiron::registry::{ENTITY_TYPE_PERSON, TypeByteFamily};
use oneiron::saved_query::{
    CreateSavedQueryRequest, EvalMode, EvalPolicy, MatcherSpec, MembershipCause,
    MembershipCommitOutcome, MembershipEvent, MembershipTransition, MembershipWritePlan,
    QueryScope, SAVED_QUERY_SCHEMA_VERSION, commit_membership_plan, derived_member_value,
    parse_filter_ast,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_store::graph_fs::paging::CursorScope;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// 25 bytes (a reaction signal cursor), with letters in every part.
const SIGNAL_CURSOR: &str = "00000000000000ab0123456789abcdef0123456789abcdef01";
const ID: &str = "0123456789abcdef0123456789abcdef";
const LINEAR_REFUSAL: &str = "cursor is not a provenance page cursor";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn open_vault() -> Result<(tempfile::TempDir, Vault), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

fn put_person(vault: &Vault, id: EntityId) -> TestResult {
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"a person",
    )?;
    Ok(())
}

fn seeded_id(seed: u8) -> Result<EntityId, Box<dyn std::error::Error>> {
    Ok(EntityId::from_bytes([seed; 16])?)
}

/// The linear provenance read with `cursor`, for a TASK ref no vault holds:
/// the read takes the cursor before it looks the TASK up.
fn linear_read(memory: &Memory<'_>, cursor: &str) -> MemoryResult<()> {
    memory
        .linear_provenance(&LinearProvenanceRequest {
            task_ref: ID.to_owned(),
            cursor: Some(cursor.to_owned()),
            limit: None,
        })
        .map(|_| ())
}

fn linear_refused(result: &MemoryResult<()>) -> bool {
    result
        .as_ref()
        .err()
        .is_some_and(|error| error.message == LINEAR_REFUSAL)
}

#[test]
fn reaction_signal_cursor_reads_in_either_case() -> TestResult {
    let lower = ReactionSignalPaging::checked(Some(SIGNAL_CURSOR), 5)?;
    let upper_text = SIGNAL_CURSOR.to_uppercase();
    let mixed_text = SIGNAL_CURSOR.replace("ab", "aB");
    let upper = ReactionSignalPaging::checked(Some(upper_text.as_str()), 5)?;
    let mixed = ReactionSignalPaging::checked(Some(mixed_text.as_str()), 5)?;
    assert_eq!(
        upper, lower,
        "an upper-case cursor pages as its lowercase one"
    );
    assert_eq!(mixed, lower);
    assert!(ReactionSignalPaging::checked(Some(&SIGNAL_CURSOR[..48]), 5).is_err());
    let longer = format!("{SIGNAL_CURSOR}0");
    assert!(ReactionSignalPaging::checked(Some(longer.as_str()), 5).is_err());
    Ok(())
}

/// A minimal real saved query: its filter goes through `parse_filter_ast`.
fn saved_query_request() -> Result<CreateSavedQueryRequest, Box<dyn std::error::Error>> {
    let claim = |predicate: &str| {
        parse_filter_ast(&serde_json::json!({
            "op": "claim",
            "predicate": predicate,
            "cmp": "eq",
            "value": "vp",
        }))
    };
    Ok(CreateSavedQueryRequest {
        schema_version: SAVED_QUERY_SCHEMA_VERSION,
        scope: QueryScope::default(),
        filter: claim("profile.seniority")?,
        matcher: MatcherSpec::Hard {
            expression: claim("profile.headcount")?,
        },
        eval: EvalPolicy {
            mode: EvalMode::Manual,
            max_entities_per_wake: 8,
            max_judges_per_wake: 4,
        },
    })
}

/// `person` enters the cohort of `(query, campaign)` at `epoch`.
fn entered(
    query: EntityId,
    campaign: EntityId,
    person: EntityId,
    epoch: u64,
) -> Result<MembershipWritePlan, Box<dyn std::error::Error>> {
    let at = 100 + epoch;
    let event = MembershipEvent {
        query_ref: query,
        campaign_ref: campaign,
        entity_ref: person,
        epoch,
        valid_at: at,
        detected_at: at + 1,
        transition: MembershipTransition::Entered,
        cause: MembershipCause::DataChange,
        evidence_hash: [u8::try_from(epoch % 251)?; 32],
    };
    Ok(MembershipWritePlan {
        value: derived_member_value(
            &event,
            CampaignMemberState::Enrolled,
            vec![CampaignMemberChannel {
                channel: "email".to_owned(),
                basis_evidence: seeded_id(0xE1)?,
                sender_ref: seeded_id(0xE2)?,
            }],
        ),
        event,
    })
}

fn members_of(page: &MembershipPage) -> Vec<EntityId> {
    page.rows.iter().map(|row| row.entity_ref).collect()
}

#[test]
fn campaign_member_cursor_resumes_in_either_case() -> TestResult {
    // Unseeded, as the CRM oracles open it: the claim write door needs no
    // policy fixture there. The pack registers SAVED_QUERY and CAMPAIGN.
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_unseeded_for_test(dir.path(), VaultConfig::device())?;
    register_crm_pack(&vault, 107, 108, TypeByteFamily::Productivity)?;
    let owner = seeded_id(0x71)?;
    // Hex with letters, so an upper-case cursor differs from its lowercase.
    let members = [seeded_id(0xB1)?, seeded_id(0xB2)?, seeded_id(0xB3)?];
    put_person(&vault, owner)?;
    for member in members {
        put_person(&vault, member)?;
    }
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let campaign = memory
        .campaign_create(
            &CreateCampaignRequest {
                schema_version: CAMPAIGN_SCHEMA_VERSION,
                name: "re-cased cursor".to_owned(),
            },
            10,
        )?
        .campaign_ref;
    let query = memory
        .saved_query_create(&saved_query_request()?, 10)?
        .query_ref;
    for (epoch, member) in (1..).zip(members) {
        let plan = entered(query, campaign, member, epoch)?;
        assert_eq!(
            commit_membership_plan(&vault, &plan, 102 + epoch)?,
            MembershipCommitOutcome::Applied
        );
    }
    let page = |cursor: Option<String>| {
        memory.campaign_members(&MembershipReadRequest {
            owner_ref: campaign,
            cursor,
            limit: 1,
            at_epoch: None,
        })
    };

    let first = page(None)?;
    assert_eq!(members_of(&first), [members[0]]);
    let cursor = first
        .next_cursor
        .ok_or("a first page of three members has a next cursor")?;
    assert_ne!(cursor, cursor.to_uppercase());
    let lower = page(Some(cursor.clone()))?;
    assert_eq!(members_of(&lower), [members[1]]);
    let upper = page(Some(cursor.to_uppercase()))?;
    assert_eq!(
        members_of(&upper),
        members_of(&lower),
        "an upper-case cursor resumes where its lowercase one resumes"
    );
    assert_eq!(upper.next_cursor, lower.next_cursor);
    Ok(())
}

#[test]
fn linear_provenance_cursor_reads_in_either_case() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = EntityId::now();
    put_person(&vault, owner)?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    // 8 + 33 bytes.
    let cursor = format!("00000000000000ab{}", "cd".repeat(33));
    for taken in [cursor.clone(), cursor.to_uppercase()] {
        let read = linear_read(&memory, &taken);
        assert!(!linear_refused(&read), "{taken}: {:?}", read.err());
    }
    let refused: [String; 3] = [
        cursor[..80].to_owned(),
        format!("{cursor}cd"),
        cursor.replace('c', "g"),
    ];
    for text in &refused {
        assert!(linear_refused(&linear_read(&memory, text)), "{text}");
    }
    Ok(())
}

#[test]
fn own_rate_cursor_reads_in_either_case() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let cursor = format!("00000000000000ab{ID}");
    let upper = cursor.to_uppercase();
    assert!(
        vault
            .own_rate_checks_after(Some(cursor.as_str()), 10)?
            .is_empty()
    );
    assert!(
        vault
            .own_rate_checks_after(Some(upper.as_str()), 10)?
            .is_empty()
    );
    assert!(
        vault
            .own_rate_checks_after(Some(&cursor[..47]), 10)
            .is_err()
    );
    Ok(())
}

#[test]
fn inbox_group_cursors_read_in_either_case() -> TestResult {
    // 8 + 16 + 16 bytes.
    let token = format!("00000000000000ab{}{}", "cd".repeat(16), "ef".repeat(16));
    let cursor = InboxGroupCursor::parse(&token).ok_or("a tray token")?;
    assert_eq!(cursor.to_token(), token);
    assert_eq!(InboxGroupCursor::parse(&token.to_uppercase()), Some(cursor));
    assert_eq!(InboxGroupCursor::parse(&token[..78]), None);

    // 8 bytes of time, the kind (1 = shape), then the group key.
    let token = format!("00000000000000ab01{}", hex(b"group-key"));
    let cursor = UnifiedInboxGroupCursor::parse(&token).ok_or("a unified token")?;
    assert_eq!(cursor.to_token(), token);
    assert_eq!(
        UnifiedInboxGroupCursor::parse(&token.to_uppercase()),
        Some(cursor)
    );
    assert_eq!(UnifiedInboxGroupCursor::parse("00000000000000ab"), None);
    assert_eq!(UnifiedInboxGroupCursor::parse(&token[..17]), None);
    Ok(())
}

#[test]
fn graph_fs_sealed_cursor_opens_in_either_case() {
    let scope = CursorScope([7; 32]);
    let position = b"a graph-fs position".to_vec();
    let token = scope.seal_bytes(&position);
    assert_ne!(token, token.to_uppercase());
    assert_eq!(scope.open_bytes(&token), Some(position.clone()));
    assert_eq!(scope.open_bytes(&token.to_uppercase()), Some(position));
    assert_eq!(scope.open_bytes(&token[1..]), None);
}

/// `u8::from_str_radix` takes a sign before a digit pair, so the linear and
/// own-rate parsers read `+c` as `0c`. A cursor is hex digits only: both
/// now refuse it, as the other parsers did.
#[test]
fn a_signed_digit_pair_is_refused() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = EntityId::now();
    put_person(&vault, owner)?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let linear = format!("+c00000000000000{}", "cd".repeat(33));
    assert!(linear_refused(&linear_read(&memory, &linear)), "{linear}");
    let own_rate = format!("+00000000000000a{ID}");
    assert!(
        vault
            .own_rate_checks_after(Some(own_rate.as_str()), 10)
            .is_err()
    );
    Ok(())
}
