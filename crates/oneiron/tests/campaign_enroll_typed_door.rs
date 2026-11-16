// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Control for the Engine's RULING RESTRICTION-FIX-SCOPE = A, item 2 (15 Nov):
//! the generic claim doors refuse a `campaign.member` now
//! (`refuse_typed_claim_family`; the red is
//! `tests/restriction_removal_doors.rs`
//! `an_agents_generic_campaign_member_write_is_refused`), and
//! `vault.campaign.enroll`, the family's typed door, still writes one: the
//! owner enrolls a person in a campaign it launched, and the membership
//! lands enrolled.
//!
//! The vault is seeded (`Vault::open`), so the CRM pack takes the first free
//! product type bytes, as `oneiron-server`'s `campaign_surface_oracle`
//! registers it.
//!
//! Run: `cargo test --locked -p oneiron --all-features --test
//! campaign_enroll_typed_door`.

use oneiron::campaign::register_crm_pack;
use oneiron::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use oneiron::memory::campaign_records::{
    CAMPAIGN_SCHEMA_VERSION, CampaignEnrollRequest, CampaignEnrollmentState,
    CampaignMemberChannelSpec, CreateCampaignRequest,
};
use oneiron::registry::{
    ENTITY_TYPE_PERSON, TYPE_BYTE_ZONE_COMPILED_PRODUCT_END, TYPE_BYTE_ZONE_COMPILED_PRODUCT_START,
    TypeByteFamily, allocate_type_byte,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

mod common;

const NOW: u64 = 1_780_000_000;

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// The CRM pack at the first two free product type bytes.
fn register_crm_pack_at_free_bytes(vault: &Vault) {
    let family = TypeByteFamily::Productivity;
    let mut occupied: Vec<u8> = (TYPE_BYTE_ZONE_COMPILED_PRODUCT_START
        ..=TYPE_BYTE_ZONE_COMPILED_PRODUCT_END)
        .filter(|kind| vault.structural_kind_registration(*kind).is_some())
        .collect();
    let campaign = allocate_type_byte(family, &occupied).expect("a free campaign type byte");
    occupied.push(campaign);
    let saved_query = allocate_type_byte(family, &occupied).expect("a free saved-query type byte");
    register_crm_pack(vault, campaign, saved_query, family).expect("the CRM pack registers");
}

/// A live row of `kind`.
fn live_row(vault: &Vault, kind: u8, body: &[u8]) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(&id, kind, at(NOW), NOW, body)
        .expect("a live row");
    id
}

#[test]
fn the_owner_still_enrolls_a_person_through_the_typed_door() {
    let directory = tempfile::tempdir().expect("vault dir");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("open vault");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    register_crm_pack_at_free_bytes(&vault);
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let campaign = memory
        .campaign_create(
            &CreateCampaignRequest {
                schema_version: CAMPAIGN_SCHEMA_VERSION,
                name: "typed door campaign".to_owned(),
                reply_snooze_policy: None,
                voice_guide_ref: None,
                copy_review: None,
            },
            NOW,
        )
        .expect("the owner creates a campaign")
        .campaign_ref;
    memory
        .campaign_launch(campaign, 1, NOW + 1)
        .expect("the owner launches its draft");
    let person = live_row(&vault, ENTITY_TYPE_PERSON, b"human");
    let basis = live_row(&vault, ENTITY_TYPE_PERSON, b"basis");
    let sender = EntityId::now();
    vault
        .create_channel_identity(
            &sender,
            &common::self_held_identity_in_state(
                "email",
                "owen@example.com",
                SelfHeldShape::DedicatedAddress,
                ChannelIdentityBinding::actor(owner),
                ChannelIdentityState::Active,
                NOW,
            ),
        )
        .expect("a live email sender identity");

    let receipt = memory
        .campaign_enroll(&CampaignEnrollRequest {
            campaign_ref: campaign.to_hex(),
            person_ref: person.to_hex(),
            channels: vec![CampaignMemberChannelSpec {
                channel: "email".to_owned(),
                basis_evidence: basis.to_hex(),
                sender_ref: sender.to_hex(),
            }],
            evidence_refs: vec![basis.to_hex()],
        })
        .expect("the owner enrolls the person through vault.campaign.enroll");

    assert!(
        matches!(receipt.state, CampaignEnrollmentState::Enrolled),
        "the membership lands enrolled: {receipt:?}"
    );
    assert!(
        matches!(receipt.approval.as_str(), "auto" | "approved"),
        "the membership is admitted: {receipt:?}"
    );
}
