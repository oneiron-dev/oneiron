//! CMT-5 read-side tests.
//!
//! The receipt-door and resolver cases live here rather than beside their
//! files: `commitment_trigger_ref` and `resolve_commitment_receipt_link` are
//! the same ticket's commitment read surface as the ledger, and a
//! commitment-door regression should surface from the commitment module's own
//! test name rather than from an unrelated projection or payload suite.

use std::collections::BTreeMap;

use rmpv::Value;

use super::*;
use crate::channel_identity::{ChannelIdentity, ChannelIdentityBinding, SelfHeldShape};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSubject, encode_claim_body};
use crate::commitment::{
    CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
    CommitmentStrength, encode_commitment_value,
};
use crate::counterparty_contact::CounterpartyContactRecord;
use crate::genui::{ReceiptDeepLinkKind, ViewTimeResolution, resolve_commitment_receipt_link};
use crate::outbound::OutboundIntentSource;
use crate::receipt::{ReceiptKind, ReceiptRecord, commitment_trigger_ref};
use crate::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use crate::store::Store;
use crate::test_util::{embedding_test_config, entity, entity_record, open_test_vault_with};

const IDENTITY: u8 = 0x51;
const CONTACT: u8 = 0xC1;
const OTHER_CONTACT: u8 = 0xC2;
const OWNER: u8 = 0x71;
const AGENT: u8 = 0x72;

/// A non-Nil opaque schedule payload.
///
/// CMT-5 never looks inside it and imports no schedule type to build it: the
/// ledger's whole claim is that a commitment's due order comes from the claim's
/// bitemporal valid-time, not from anything in here.
fn opaque_schedule() -> Value {
    Value::Map(vec![
        (Value::from("kind"), Value::from("opaque")),
        (Value::from("payload"), Value::Array(vec![Value::from(7)])),
    ])
}

fn at(instant: u64) -> TimeRange {
    TimeRange {
        start: instant,
        end: instant,
    }
}

fn due(start: u64, end: u64) -> TimeRange {
    TimeRange { start, end }
}

fn third_party(id: EntityId) -> CommitmentObligor {
    CommitmentObligor::new(CommitmentObligorKind::ThirdParty, id)
}

/// An `Auto` / `Active` / non-stale `commitment.record` body. Admission
/// negatives take this and move exactly one axis, so each negative names the
/// single reason it is excluded.
fn commitment_row(
    obligor: CommitmentObligor,
    beneficiary: EntityId,
    valid: TimeRange,
    status: CommitmentStatus,
) -> Result<ClaimBody> {
    let record = CommitmentRecord::new(
        obligor,
        beneficiary,
        CommitmentContent::new("return the countersigned lease", None)?,
        opaque_schedule(),
        CommitmentStrength::Commitment,
        status,
        CommitmentBirthProvenance::new(CommitmentBirthKind::Brief, "brief:lease-renewal")?,
    )?;
    let mut body = ClaimBody::new(
        PREDICATE_COMMITMENT_RECORD,
        ClaimSubject::Entity(obligor.entity_ref),
        encode_commitment_value(&record)?,
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.valid_from = Some(valid.start);
    body.valid_to = Some(valid.end);
    Ok(body)
}

fn put_row(vault: &Vault, seed: u8, body: &ClaimBody, learned_at: u64) -> Result<EntityId> {
    let id = entity(seed);
    vault.put_claim(&id, body, at(learned_at), learned_at)?;
    Ok(id)
}

/// Writes a CLAIM row straight to the store, bypassing every validating write
/// door. The only way to stage the rows this projection must survive: bodies no
/// public door would accept, because they came from an older writer, a damaged
/// page, or a foreign vault.
fn inject_raw_claim(vault: &Vault, seed: u8, body: &[u8]) -> Result<EntityId> {
    let id = entity(seed);
    let payload = entity_record(ENTITY_TYPE_CLAIM, at(1), 1, body);
    vault.with_write_txn(|wtxn| {
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_CLAIM, &id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })?;
    Ok(id)
}

struct LedgerVault {
    _tmp: tempfile::TempDir,
    vault: Vault,
}

/// A vault carrying the contact/identity join and the owner + agent entities
/// that Owner- and Agent-owed commitments hang off.
fn ledger_vault() -> Result<LedgerVault> {
    let (_tmp, vault) = open_test_vault_with(embedding_test_config());

    let identity = ChannelIdentity::requested(
        "email",
        "eiri@example.com",
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::vault(7),
        5,
    );
    vault.create_channel_identity(&entity(IDENTITY), &identity)?;
    vault.create_counterparty_contact(
        &entity(CONTACT),
        &CounterpartyContactRecord::user_introduction(entity(IDENTITY), "kenji@example.com", 10)?,
    )?;
    vault.create_counterparty_contact(
        &entity(OTHER_CONTACT),
        &CounterpartyContactRecord::user_introduction(entity(IDENTITY), "mika@example.com", 10)?,
    )?;
    vault.put_entity(&entity(OWNER), ENTITY_TYPE_PERSON, at(1), 1, b"owner")?;
    vault.put_entity(&entity(AGENT), ENTITY_TYPE_MACHINE, at(1), 1, b"agent")?;

    Ok(LedgerVault { _tmp, vault })
}

fn ids(entries: &[CommitmentLedgerEntry]) -> Vec<EntityId> {
    entries.iter().map(|entry| entry.commitment_id).collect()
}

fn learned(entries: &[CommitmentLedgerEntry]) -> Vec<u64> {
    entries.iter().map(|entry| entry.learned_at).collect()
}

#[test]
fn commitment_ledger_splits_open_commitments_by_direction_and_due_order() -> Result<()> {
    let fixture = ledger_vault()?;
    let vault = &fixture.vault;
    let contact = entity(CONTACT);
    let owner = entity(OWNER);

    // Owed BY the counterparty. `learned_at` runs strictly DOWN the expected
    // due order, so a projection that ordered on transaction-time instead of
    // valid-time would return this list exactly reversed.
    let self_ref = put_row(
        vault,
        0xD1,
        &commitment_row(
            third_party(contact),
            contact,
            due(50, 60),
            CommitmentStatus::Open,
        )?,
        900,
    )?;
    let early_close = put_row(
        vault,
        0xB3,
        &commitment_row(
            third_party(contact),
            owner,
            due(100, 150),
            CommitmentStatus::Open,
        )?,
        800,
    )?;
    let early_close_twin = put_row(
        vault,
        0xB4,
        &commitment_row(
            third_party(contact),
            owner,
            due(100, 150),
            CommitmentStatus::Open,
        )?,
        700,
    )?;
    let late_close = put_row(
        vault,
        0xB2,
        &commitment_row(
            third_party(contact),
            owner,
            due(100, 200),
            CommitmentStatus::Open,
        )?,
        600,
    )?;
    let latest = put_row(
        vault,
        0xB1,
        &commitment_row(
            third_party(contact),
            owner,
            due(300, 400),
            CommitmentStatus::Open,
        )?,
        500,
    )?;

    // Owed TO the counterparty: an Agent obligor and an Owner obligor.
    let agent_owed = put_row(
        vault,
        0x82,
        &commitment_row(
            CommitmentObligor::new(CommitmentObligorKind::Agent, entity(AGENT)),
            contact,
            due(200, 250),
            CommitmentStatus::Open,
        )?,
        400,
    )?;
    let owner_owed = put_row(
        vault,
        0x81,
        &commitment_row(
            CommitmentObligor::new(CommitmentObligorKind::Owner, owner),
            contact,
            due(500, 600),
            CommitmentStatus::Open,
        )?,
        300,
    )?;

    // An Owner-kind obligor whose entity_ref IS the contact, benefiting the
    // owner: directionless for this ledger, and skipped without error.
    put_row(
        vault,
        0x83,
        &commitment_row(
            CommitmentObligor::new(CommitmentObligorKind::Owner, contact),
            owner,
            due(120, 130),
            CommitmentStatus::Open,
        )?,
        200,
    )?;
    // Another counterparty's open obligation.
    put_row(
        vault,
        0xE7,
        &commitment_row(
            third_party(entity(OTHER_CONTACT)),
            owner,
            due(10, 20),
            CommitmentStatus::Open,
        )?,
        100,
    )?;
    // A CLAIM row this projection cannot decode at all.
    inject_raw_claim(vault, 0xF1, b"not a claim body")?;

    let ledger = vault.commitment_ledger_for_counterparty(&contact)?;

    assert_eq!(ledger.counterparty.contact_ref, contact);
    assert_eq!(ledger.counterparty.identity_ref, entity(IDENTITY));
    assert_eq!(ledger.counterparty.counterparty, "kenji@example.com");
    assert_eq!(ledger.counterparty.channel, "email");
    assert_eq!(ledger.counterparty.address_or_handle, "eiri@example.com");

    assert_eq!(
        ids(&ledger.owed_by_them),
        vec![self_ref, early_close, early_close_twin, late_close, latest],
        "owed_by_them must sort by (valid_from, valid_to, commitment_id)"
    );
    assert_eq!(
        learned(&ledger.owed_by_them),
        vec![900, 800, 700, 600, 500],
        "learned_at must be carried but never used as the due key"
    );
    assert_eq!(
        ids(&ledger.owed_to_them),
        vec![self_ref, agent_owed, owner_owed],
        "owed_to_them must sort independently by due window"
    );
    assert_eq!(learned(&ledger.owed_to_them), vec![900, 400, 300]);

    // The self-referential ThirdParty row is on BOTH sides: no precedence.
    assert_eq!(ledger.owed_by_them[0].commitment_id, self_ref);
    assert_eq!(ledger.owed_to_them[0].commitment_id, self_ref);
    assert_eq!(ledger.owed_by_them[0].valid_time, due(50, 60));

    // The schedule stays the opaque payload it was written as.
    assert_eq!(ledger.owed_by_them[0].record.schedule, opaque_schedule());
    Ok(())
}

#[test]
fn commitment_ledger_admits_only_open_surfaceable_commitments() -> Result<()> {
    let fixture = ledger_vault()?;
    let vault = &fixture.vault;
    let contact = entity(CONTACT);
    let owner = entity(OWNER);

    let admitted = put_row(
        vault,
        0xB1,
        &commitment_row(
            third_party(contact),
            owner,
            due(100, 200),
            CommitmentStatus::Open,
        )?,
        100,
    )?;

    // Consent axis: awaiting approval.
    let mut proposed = commitment_row(
        third_party(contact),
        owner,
        due(101, 200),
        CommitmentStatus::Open,
    )?;
    proposed.approval = ClaimApprovalStatus::Proposed;
    put_row(vault, 0xB2, &proposed, 101)?;

    // Staleness axis: derived content awaiting regeneration.
    let mut stale = commitment_row(
        third_party(contact),
        owner,
        due(102, 200),
        CommitmentStatus::Open,
    )?;
    stale.stale = true;
    put_row(vault, 0xB3, &stale, 102)?;

    // The two closed axes are independent: an ACTIVE claim head carrying a
    // FULFILLED commitment is out on status, and a SUPERSEDED claim head
    // carrying an OPEN commitment is out on lifecycle.
    put_row(
        vault,
        0xB4,
        &commitment_row(
            third_party(contact),
            owner,
            due(103, 200),
            CommitmentStatus::Fulfilled,
        )?,
        103,
    )?;
    let mut superseded_head = commitment_row(
        third_party(contact),
        owner,
        due(104, 200),
        CommitmentStatus::Open,
    )?;
    superseded_head.lifecycle = ClaimLifecycleStatus::Superseded;
    put_row(vault, 0xB5, &superseded_head, 104)?;

    let ledger = vault.commitment_ledger_for_counterparty(&contact)?;
    assert_eq!(
        ids(&ledger.owed_by_them),
        vec![admitted],
        "only surfaceable, lifecycle-active, non-stale, OPEN rows are obligations"
    );
    assert!(ledger.owed_to_them.is_empty());
    Ok(())
}

#[test]
fn commitment_ledger_reports_typed_errors_for_broken_contact_joins() -> Result<()> {
    let fixture = ledger_vault()?;
    let vault = &fixture.vault;

    let missing = vault
        .commitment_ledger_for_counterparty(&entity(0x33))
        .expect_err("absent contact row");
    assert!(
        matches!(missing, Error::EntityNotFound),
        "absent contact must be EntityNotFound, got {missing:?}"
    );

    let wrong_type = vault
        .commitment_ledger_for_counterparty(&entity(OWNER))
        .expect_err("PERSON id is not a contact");
    assert!(
        matches!(wrong_type, Error::InvalidEntityType(ENTITY_TYPE_PERSON)),
        "wrong entity type must stay typed, got {wrong_type:?}"
    );

    // A contact pointing at an identity row that does not exist is a broken
    // join, not a counterparty who happens to owe nothing.
    let dangling = entity(0xC3);
    vault.create_counterparty_contact(
        &dangling,
        &CounterpartyContactRecord::user_introduction(entity(0x34), "yuki@example.com", 10)?,
    )?;
    let broken = vault
        .commitment_ledger_for_counterparty(&dangling)
        .expect_err("dangling identity_ref");
    assert!(
        matches!(
            broken,
            Error::CorruptedIndex("counterparty contact channel identity")
        ),
        "dangling identity_ref must be a corrupted join, got {broken:?}"
    );
    Ok(())
}

#[test]
fn commitment_ledger_skips_undecodable_rows_and_fails_closed_on_commitment_rows() -> Result<()> {
    let fixture = ledger_vault()?;
    let vault = &fixture.vault;
    let contact = entity(CONTACT);

    let admitted = put_row(
        vault,
        0xB1,
        &commitment_row(
            third_party(contact),
            entity(OWNER),
            due(100, 200),
            CommitmentStatus::Open,
        )?,
        100,
    )?;
    inject_raw_claim(vault, 0xF1, b"not a claim body")?;
    let ledger = vault.commitment_ledger_for_counterparty(&contact)?;
    assert_eq!(
        ids(&ledger.owed_by_them),
        vec![admitted],
        "an undecodable unrelated CLAIM row must not take the ledger down"
    );

    // Same tolerance does NOT extend past the predicate filter: a row that
    // says it is a commitment and then will not decode is a typed error.
    let mut broken = ClaimBody::new(
        PREDICATE_COMMITMENT_RECORD,
        ClaimSubject::Entity(contact),
        Value::from("not a commitment record map"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    broken.valid_from = Some(100);
    broken.valid_to = Some(200);
    inject_raw_claim(vault, 0xF2, &encode_claim_body(&broken)?)?;

    let error = vault
        .commitment_ledger_for_counterparty(&contact)
        .expect_err("undecodable commitment.record row");
    assert!(
        matches!(error, Error::InvalidClaimBody(_)),
        "commitment-predicate rows fail closed, got {error:?}"
    );
    Ok(())
}

#[test]
fn commitment_ledger_valid_time_requires_both_bitemporal_bounds() -> Result<()> {
    // CMT-1's structural validator already refuses to STORE a half-bounded
    // commitment claim, so this guard is only reachable by a body that never
    // came through a validating door. Asserted directly for that reason.
    let mut body = commitment_row(
        third_party(entity(CONTACT)),
        entity(OWNER),
        due(100, 200),
        CommitmentStatus::Open,
    )?;
    assert_eq!(ledger_valid_time(&body)?, due(100, 200));

    body.valid_to = None;
    let error = ledger_valid_time(&body).expect_err("missing valid-time bound");
    assert!(
        matches!(
            error,
            Error::InvalidClaimBody("commitment claim missing valid-time bound")
        ),
        "half-bounded obligations must refuse rather than guess, got {error:?}"
    );
    Ok(())
}

fn receipt(intent_source: Option<&str>, trigger_ref: Option<&str>) -> ReceiptRecord {
    let mut fields = BTreeMap::new();
    if let Some(source) = intent_source {
        fields.insert("intent_source".to_owned(), source.to_owned());
    }
    ReceiptRecord {
        receipt_id: "outbound:intent:lease-reminder".to_owned(),
        receipt_kind: ReceiptKind::Outbound,
        occurred_at: 500,
        actor: None,
        on_behalf_of: None,
        outcome: "delivered_to_channel".to_owned(),
        job_ref: None,
        trigger_ref: trigger_ref.map(str::to_owned),
        policy_trace: Vec::new(),
        fields,
    }
}

#[test]
fn commitment_ledger_receipt_door_gates_on_intent_source_before_trigger_shape() -> Result<()> {
    let target = entity(0xB1).to_hex();
    let prefixed = format!("commitment:{target}");

    assert_eq!(
        OutboundIntentSource::parse("commitment"),
        Some(OutboundIntentSource::Commitment)
    );
    assert_eq!(
        OutboundIntentSource::parse("commitment_timer_wake"),
        Some(OutboundIntentSource::Commitment),
        "the landed timer-wake alias is the same source"
    );

    // Source gate is primary: a perfectly-shaped commitment trigger on a
    // non-commitment receipt is still not a commitment door.
    assert_eq!(
        commitment_trigger_ref(&receipt(Some("gap_queue"), Some(prefixed.as_str())))?,
        None
    );
    // The fields map is serde-defaulted; an absent or unknown source is a
    // valid receipt shape, not a read failure.
    assert_eq!(
        commitment_trigger_ref(&receipt(None, Some(prefixed.as_str())))?,
        None
    );
    assert_eq!(
        commitment_trigger_ref(&receipt(Some("not_a_source"), Some(prefixed.as_str())))?,
        None
    );

    // Commitment-sourced legacy rows: SPINE-COMM owns producer-side prefix
    // enforcement, so a missing or differently-prefixed trigger is tolerated.
    assert_eq!(
        commitment_trigger_ref(&receipt(Some("commitment"), None))?,
        None
    );
    assert_eq!(
        commitment_trigger_ref(&receipt(Some("commitment"), Some("intent:invite-kenji")))?,
        None
    );

    for source in ["commitment", "commitment_timer_wake"] {
        assert_eq!(
            commitment_trigger_ref(&receipt(Some(source), Some(prefixed.as_str())))?,
            Some(prefixed.clone()),
            "a commitment-sourced commitment: trigger must never collapse to None"
        );
    }
    // Case-insensitive hex reaches the same door.
    let upper = format!("commitment:{}", target.to_uppercase());
    assert_eq!(
        commitment_trigger_ref(&receipt(Some("commitment"), Some(upper.as_str())))?,
        Some(upper)
    );

    // A present-but-broken suffix is a producer bug, and never Ok(None).
    for broken in [
        "commitment:",
        "commitment:party-reminder",
        "commitment:00ff",
        &format!("commitment:commitment:{target}"),
    ] {
        let error = commitment_trigger_ref(&receipt(Some("commitment"), Some(broken)))
            .expect_err("malformed commitment trigger suffix");
        assert!(
            matches!(error, Error::InvalidKey),
            "{broken} must fail typed, got {error:?}"
        );
    }
    Ok(())
}

#[test]
fn commitment_ledger_receipt_link_maps_claim_lifecycle_to_view_time_resolution() -> Result<()> {
    let fixture = ledger_vault()?;
    let vault = &fixture.vault;
    let contact = entity(CONTACT);
    let owner = entity(OWNER);

    let open = put_row(
        vault,
        0xB1,
        &commitment_row(
            third_party(contact),
            owner,
            due(100, 200),
            CommitmentStatus::Open,
        )?,
        100,
    )?;
    // A CLOSED commitment on an active head: still readable, so still Active.
    let fulfilled = put_row(
        vault,
        0xB2,
        &commitment_row(
            third_party(contact),
            owner,
            due(100, 200),
            CommitmentStatus::Fulfilled,
        )?,
        101,
    )?;
    let mut superseded_body = commitment_row(
        third_party(contact),
        owner,
        due(100, 200),
        CommitmentStatus::Open,
    )?;
    superseded_body.lifecycle = ClaimLifecycleStatus::Superseded;
    let superseded = put_row(vault, 0xB3, &superseded_body, 102)?;

    let mut retracted_body = commitment_row(
        third_party(contact),
        owner,
        due(100, 200),
        CommitmentStatus::Open,
    )?;
    retracted_body.lifecycle = ClaimLifecycleStatus::Retracted;
    let retracted = put_row(vault, 0xB4, &retracted_body, 103)?;

    for (id, expected) in [
        (open, ViewTimeResolution::Active),
        (fulfilled, ViewTimeResolution::Active),
        (superseded, ViewTimeResolution::Active),
        (retracted, ViewTimeResolution::Revoked),
    ] {
        let target = format!("commitment:{}", id.to_hex());
        let link = resolve_commitment_receipt_link(
            vault,
            &receipt(Some("commitment"), Some(target.as_str())),
            "the commitment behind this message",
        )?
        .expect("commitment-sourced receipt resolves");
        assert_eq!(link.target_kind, ReceiptDeepLinkKind::Commitment);
        assert_eq!(link.target_ref, target);
        assert_eq!(link.label, "the commitment behind this message");
        assert_eq!(
            link.resolution, expected,
            "{target} resolved to the wrong view-time state"
        );
    }

    // Non-commitment sources stay Ok(None) at the resolver too.
    assert!(
        resolve_commitment_receipt_link(
            vault,
            &receipt(
                Some("gap_queue"),
                Some(&format!("commitment:{}", open.to_hex()))
            ),
            "label",
        )?
        .is_none()
    );

    // Everything past the source gate either links or fails typed. It never
    // panics, never returns Unavailable, and never quietly returns None.
    let absent = format!("commitment:{}", entity(0x35).to_hex());
    let missing = resolve_commitment_receipt_link(
        vault,
        &receipt(Some("commitment"), Some(absent.as_str())),
        "label",
    )
    .expect_err("no claim head under the referenced id");
    assert!(matches!(missing, Error::EntityNotFound), "got {missing:?}");

    let malformed = resolve_commitment_receipt_link(
        vault,
        &receipt(Some("commitment"), Some("commitment:not-hex")),
        "label",
    )
    .expect_err("malformed hex suffix");
    assert!(matches!(malformed, Error::InvalidKey), "got {malformed:?}");

    // A CLAIM that is not a commitment.record is a typed refusal.
    let stranger = entity(0x36);
    let mut stranger_body = ClaimBody::new(
        "profile.display_name",
        ClaimSubject::Entity(owner),
        Value::from("Kenji"),
        0.9,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    stranger_body.valid_from = Some(1);
    stranger_body.valid_to = Some(2);
    vault.put_claim(&stranger, &stranger_body, at(1), 1)?;
    let wrong_family = resolve_commitment_receipt_link(
        vault,
        &receipt(
            Some("commitment"),
            Some(&format!("commitment:{}", stranger.to_hex())),
        ),
        "label",
    )
    .expect_err("non-commitment CLAIM head");
    assert!(
        matches!(wrong_family, Error::InvalidClaimBody(_)),
        "got {wrong_family:?}"
    );

    // Label validation stays with the fallible ReceiptDeepLink constructor.
    let empty_label = resolve_commitment_receipt_link(
        vault,
        &receipt(
            Some("commitment"),
            Some(&format!("commitment:{}", open.to_hex())),
        ),
        "",
    )
    .expect_err("empty deep-link label");
    assert!(
        matches!(empty_label, Error::InvalidConfig(_)),
        "got {empty_label:?}"
    );
    Ok(())
}
