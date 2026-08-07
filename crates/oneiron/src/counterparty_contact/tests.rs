use super::*;
use crate::registry::{
    ENTITY_TYPE_COUNTERPARTY_CONTACT, EntityClassification, TypeByteZone,
    entity_type_registry_entry,
};

use crate::test_util::entity;

#[test]
fn counterparty_contact_codec_and_claim_family_round_trip() -> Result<()> {
    let record =
        CounterpartyContactRecord::user_introduction(entity(0x51), " kenji@example.com ", 10)?
            .with_promo_consent(true, 11)?
            .with_note("party invite", 12)?;

    let encoded = encode_counterparty_contact_body(&record)?;
    validate_counterparty_contact_body_bytes(&encoded)?;
    assert_eq!(decode_counterparty_contact_body(&encoded)?, record);

    let claims = record.claim_bodies(entity(0xC1));
    assert_eq!(claims.len(), COUNTERPARTY_CONTACT_CLAIM_PREDICATES.len());
    for claim in &claims {
        validate_counterparty_contact_claim_structure(claim)?;
    }
    Ok(())
}

#[test]
fn opt_out_and_owner_revocation_are_recorded_with_pinned_reasons() -> Result<()> {
    let record = CounterpartyContactRecord::inbound_first(entity(0x51), "+15551234567", 20)?
        .opted_out(CounterpartyOptOutReason::Stop, 30)?;
    let opt_out = record.opt_out.expect("opt-out stored");
    assert_eq!(opt_out.reason, CounterpartyOptOutReason::Stop);
    assert_eq!(opt_out.receipt_reason(), "counterparty_opt_out_stop");

    let revoked = record.revoked(40)?;
    assert_eq!(revoked.status, CounterpartyContactStatus::Revoked);
    assert_eq!(revoked.revoked_at, Some(40));
    assert!(revoked.is_opted_out());
    Ok(())
}

#[test]
fn malformed_counterparty_contact_bodies_fail_closed() {
    let err =
        decode_counterparty_contact_body(b"not-msgpack").expect_err("malformed msgpack rejected");
    assert_eq!(
        err.kind(),
        crate::error::ErrorKind::InvalidCounterpartyContactBody
    );

    let blank = CounterpartyContactRecord::public(entity(0x51), "   ", 20)
        .expect_err("blank counterparty rejected");
    assert_eq!(
        blank.kind(),
        crate::error::ErrorKind::InvalidCounterpartyContactBody
    );
}

#[test]
fn counterparty_contact_matches_identity_and_counterparty() -> Result<()> {
    let identity = entity(0x51);
    let record = CounterpartyContactRecord::public(identity, "public@example.com", 20)?;
    assert!(record.matches_counterparty(&identity, " public@example.com "));
    assert!(!record.matches_counterparty(&entity(0x52), "public@example.com"));
    assert!(!record.matches_counterparty(&identity, "other@example.com"));
    Ok(())
}

#[test]
fn counterparty_contact_type_registration_is_stable() {
    let entry = entity_type_registry_entry(ENTITY_TYPE_COUNTERPARTY_CONTACT)
        .expect("COUNTERPARTY_CONTACT registry row");
    assert_eq!(ENTITY_TYPE_COUNTERPARTY_CONTACT, 80);
    assert_eq!(entry.kind, "COUNTERPARTY_CONTACT");
    assert_eq!(entry.short_id_prefix, None);
    assert_eq!(entry.classification, EntityClassification::Maintenance);
    assert_eq!(entry.zone, TypeByteZone::System);
}
