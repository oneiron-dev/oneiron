//! Pack key `campaign.sender.rotate_on_dead`: a dead sticky sender restarts by default,
//! and rotates to the proposed sender with one notice per vault owner once the
//! owner sets the key true.
//!
//! Red/green proof for OPUS-PACKWAVE-W3 W3-4 C06. On the base commit the key is
//! unknown (the owner's set fails) and `StickySenderOutcome::Rotated` does not
//! exist, so this file does not compile there. That is expected; it is the
//! proof the head adds both.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test pack_keys_campaign_sender`
#![cfg(feature = "test-support")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use oneiron::campaign::claims::{
    CampaignMemberChannel, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    decode_campaign_member_value, encode_campaign_member_value,
};
use oneiron::campaign::send_hygiene::{
    CAMPAIGN_SENDER_ROTATED_NOTIFICATION_PRODUCER, StickySenderOutcome, bind_sticky_sender,
};
use oneiron::inbox::{INBOX_PAGE_DEFAULT, NotificationKind, NotificationRow};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig,
};
use serde_json::json;

mod common;

use common::entity as test_id;

const CHANNEL: &str = "email";
const ROTATE_KEY: &str = "campaign.sender.rotate_on_dead";

const PERSON_SEED: u8 = 0x71;
const CAMPAIGN_SEED: u8 = 0x72;
const SENDER_A_SEED: u8 = 0x73;
const SENDER_B_SEED: u8 = 0x74;
const SENDER_C_SEED: u8 = 0x75;
const BASIS_SEED: u8 = 0x76;
const MEMBER_SEED: u8 = 0x77;

const BIND_AT: u64 = 50;
const ROTATE_AT: u64 = 60;
const REUSE_AT: u64 = 70;

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    config
}

/// One unseeded vault with a device keystore, its owner, one person, and the
/// campaign that person is enrolled in. The owner is created here, before any
/// rotation, so the rotation's owner census finds them.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    person: EntityId,
    campaign: EntityId,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open_unseeded_for_test(dir.path(), test_config()).unwrap();
    // The host installs this device's keystore after each open; the outbound
    // and claim doors load this install's keys from it (P6c).
    vault.install_device_keystore(std::sync::Arc::new(
        oneiron_keystore::MemoryKeystore::default(),
    ));
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner");
    let person = test_id(PERSON_SEED);
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"pack keys campaign sender fixture",
        )
        .unwrap();
    Fixture {
        _dir: dir,
        vault,
        owner,
        person,
        campaign: test_id(CAMPAIGN_SEED),
    }
}

fn owner_proof(vault: &Vault, owner: EntityId) -> oneiron::consent::AuthenticatedOwner {
    vault
        .authenticate_owner(
            owner,
            "principal:owner",
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner proof")
}

/// The cohort row every test starts from: enrolled, one email channel bound to
/// `sender`, no derivation.
fn enrolled_member(campaign: EntityId, sender: EntityId) -> CampaignMemberValue {
    CampaignMemberValue {
        campaign,
        state: CampaignMemberState::Enrolled,
        channels: vec![CampaignMemberChannel {
            channel: CHANNEL.to_owned(),
            basis_evidence: test_id(BASIS_SEED),
            sender_ref: sender,
        }],
        derivation: None,
    }
}

fn put_member(vault: &Vault, claim_id: EntityId, value: &CampaignMemberValue, subject: EntityId) {
    vault
        .put_claim(
            &claim_id,
            &ClaimBody::new(
                PREDICATE_CAMPAIGN_MEMBER,
                ClaimSubject::Entity(subject),
                encode_campaign_member_value(value),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            )
            .expect("fixture"),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .unwrap();
}

/// Every live `campaign.member` head on `person` scoped to `campaign`, as
/// (claim id, decoded value). The engine-internal
/// `live_campaign_member_head_in_txn` is not public, so this reads through
/// the public claim doors the way the send-hygiene oracle does.
fn live_member_heads(
    vault: &Vault,
    person: EntityId,
    campaign: EntityId,
) -> Vec<(EntityId, CampaignMemberValue)> {
    let mut heads = Vec::new();
    for id in vault.claims_for_subject(&person).unwrap() {
        let Some(body) = vault.get_claim(&id).unwrap() else {
            continue;
        };
        if body.predicate != PREDICATE_CAMPAIGN_MEMBER
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let value = decode_campaign_member_value(&body.value).unwrap();
        if value.campaign != campaign {
            continue;
        }
        heads.push((id, value));
    }
    heads
}

/// The email channel's sticky sender in `value`.
fn email_sender(value: &CampaignMemberValue) -> EntityId {
    value
        .channels
        .iter()
        .find(|row| row.channel == CHANNEL)
        .expect("the email channel row")
        .sender_ref
}

/// The owner's inbox rows produced by a sender rotation.
fn rotated_notices(vault: &Vault, owner: EntityId) -> Vec<NotificationRow> {
    vault
        .memory(owner, EdgeActorClass::Human)
        .inbox_list(None, INBOX_PAGE_DEFAULT)
        .expect("inbox read")
        .rows
        .into_iter()
        .filter(|row| row.source.producer == CAMPAIGN_SENDER_ROTATED_NOTIFICATION_PRODUCER)
        .collect()
}

#[test]
fn a_dead_sticky_sender_restarts_by_default_and_rotates_with_a_notice_once_the_owner_allows_it() {
    let fx = fixture();
    let sender_a = test_id(SENDER_A_SEED);
    let sender_b = test_id(SENDER_B_SEED);
    let sender_c = test_id(SENDER_C_SEED);
    let basis = test_id(BASIS_SEED);
    put_member(
        &fx.vault,
        test_id(MEMBER_SEED),
        &enrolled_member(fx.campaign, sender_a),
        fx.person,
    );

    // Default (the key unset reads false): the dead sender restarts, and
    // nothing is written.
    let restart = bind_sticky_sender(
        &fx.vault,
        fx.person,
        fx.campaign,
        CHANNEL,
        sender_b,
        false,
        basis,
        BIND_AT,
    )
    .unwrap();
    assert_eq!(
        restart,
        StickySenderOutcome::RestartRequired {
            previous_sender_ref: sender_a,
            proposed_sender_ref: sender_b,
        }
    );
    let heads = live_member_heads(&fx.vault, fx.person, fx.campaign);
    assert_eq!(heads.len(), 1, "one live member head");
    assert_eq!(
        heads[0].0,
        test_id(MEMBER_SEED),
        "a restart writes no replacement head"
    );
    assert_eq!(
        email_sender(&heads[0].1),
        sender_a,
        "the live head still names A"
    );
    assert!(
        rotated_notices(&fx.vault, fx.owner).is_empty(),
        "no rotation notice before the owner allows it"
    );

    // The owner allows rotation.
    let proof = owner_proof(&fx.vault, fx.owner);
    let outcome = fx
        .vault
        .set_setting(
            SettingCaller::Owner(&proof),
            SetSetting::vault_value(ROTATE_KEY, json!(true)),
        )
        .unwrap();
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's set applies: {outcome:?}"
    );

    // The same bind now rotates to B, with one notice per vault owner.
    let rotated = bind_sticky_sender(
        &fx.vault,
        fx.person,
        fx.campaign,
        CHANNEL,
        sender_b,
        false,
        basis,
        ROTATE_AT,
    )
    .unwrap();
    let (member_head_ref, notice_refs) = match rotated {
        StickySenderOutcome::Rotated {
            previous_sender_ref,
            sender_ref,
            member_head_ref,
            notice_refs,
        } => {
            assert_eq!(previous_sender_ref, sender_a);
            assert_eq!(sender_ref, sender_b);
            (member_head_ref, notice_refs)
        }
        other => panic!("a dead sender rotates once the owner allows it, got {other:?}"),
    };
    assert_ne!(
        member_head_ref,
        test_id(MEMBER_SEED),
        "the rotation mints a replacement head"
    );
    assert!(!notice_refs.is_empty(), "every vault owner gets one notice");
    let heads = live_member_heads(&fx.vault, fx.person, fx.campaign);
    assert_eq!(heads.len(), 1, "one live member head after the rotation");
    assert_eq!(
        heads[0].0, member_head_ref,
        "the live head is the rotation's receipt"
    );
    assert_eq!(email_sender(&heads[0].1), sender_b, "the live head names B");
    assert_eq!(
        heads[0].1.state,
        CampaignMemberState::Enrolled,
        "the rotation changes the sender, not the state"
    );
    let notices = rotated_notices(&fx.vault, fx.owner);
    assert_eq!(notices.len(), 1, "one vault owner gets one notice");
    let notice = &notices[0];
    assert_eq!(notice.kind, NotificationKind::Finding);
    assert_eq!(
        notice.source.result,
        Some(member_head_ref.to_hex()),
        "the notice's result is the new head"
    );
    assert_eq!(
        notice.source.detail,
        Some(sender_a.to_hex()),
        "the notice's detail is the dead sender"
    );
    assert_eq!(
        notice.subject_refs,
        vec![fx.person.to_hex()],
        "the notice names the person"
    );
    assert!(
        notice_refs.iter().any(|id| id.to_hex() == notice.id),
        "the inbox row is the returned notice ref"
    );

    // A live stored sender is reused even when a newer identity is proposed.
    let reused = bind_sticky_sender(
        &fx.vault,
        fx.person,
        fx.campaign,
        CHANNEL,
        sender_c,
        true,
        basis,
        REUSE_AT,
    )
    .unwrap();
    assert_eq!(
        reused,
        StickySenderOutcome::Reused {
            sender_ref: sender_b
        }
    );
}

#[test]
fn a_proposal_of_the_dead_sender_itself_still_restarts() {
    let fx = fixture();
    let sender_a = test_id(SENDER_A_SEED);
    put_member(
        &fx.vault,
        test_id(MEMBER_SEED),
        &enrolled_member(fx.campaign, sender_a),
        fx.person,
    );
    let proof = owner_proof(&fx.vault, fx.owner);
    let outcome = fx
        .vault
        .set_setting(
            SettingCaller::Owner(&proof),
            SetSetting::vault_value(ROTATE_KEY, json!(true)),
        )
        .unwrap();
    assert!(
        matches!(outcome, SetSettingOutcome::Applied { .. }),
        "the owner's set applies: {outcome:?}"
    );

    let restart = bind_sticky_sender(
        &fx.vault,
        fx.person,
        fx.campaign,
        CHANNEL,
        sender_a,
        false,
        test_id(BASIS_SEED),
        BIND_AT,
    )
    .unwrap();
    assert_eq!(
        restart,
        StickySenderOutcome::RestartRequired {
            previous_sender_ref: sender_a,
            proposed_sender_ref: sender_a,
        }
    );
    let heads = live_member_heads(&fx.vault, fx.person, fx.campaign);
    assert_eq!(heads.len(), 1, "one live member head");
    assert_eq!(
        heads[0].0,
        test_id(MEMBER_SEED),
        "a restart writes no replacement head"
    );
    assert_eq!(
        email_sender(&heads[0].1),
        sender_a,
        "the live head still names A"
    );
    assert!(
        rotated_notices(&fx.vault, fx.owner).is_empty(),
        "a restart writes no notice"
    );
}
