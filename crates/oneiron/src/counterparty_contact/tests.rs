use super::*;
use crate::config::VaultConfig;
use crate::disclosure::DisclosureScope;
use crate::interlocutor::{InterlocutorPartyInput, InterlocutorResolutionInput};
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

// ---------------------------------------------------------------------------
// ONE-1752 — type-132 is a claims-derived cache, not truth.
// ---------------------------------------------------------------------------

fn open_vault() -> (tempfile::TempDir, Vault) {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    crate::test_util::open_test_vault_with(config)
}

/// The live `counterparty_contact.*` head values for one contact, by predicate.
fn live_claim_heads(vault: &Vault, contact_id: &EntityId) -> Result<Vec<(String, Value)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut heads = Vec::new();
    for claim_id in vault.claims_for_subject_in_txn(&rtxn, contact_id)? {
        let Some(body) = vault.get_claim_in_txn(&rtxn, &claim_id)? else {
            continue;
        };
        if is_counterparty_contact_claim_predicate(&body.predicate)
            && body.lifecycle == ClaimLifecycleStatus::Active
            && !body.stale
        {
            heads.push((body.predicate.clone(), body.value.clone()));
        }
    }
    heads.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(heads)
}

/// Claims own the truth; the type-132 row is a cache that can be dropped and
/// rebuilt byte-for-byte from them.
#[test]
fn type_132_is_cache_not_truth() -> Result<()> {
    let (_tmp, vault) = open_vault();
    let identity = entity(0x51);
    let contact_id = entity(0x52);

    // Write contact + opt-out through the redirected writers.
    let record = CounterpartyContactRecord::user_introduction(identity, "kenji@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &record)?;
    vault.opt_out_counterparty_contact(&contact_id, CounterpartyOptOutReason::Unsubscribe, 20)?;

    // The heads and the cached row agree, one live head per predicate.
    let heads = live_claim_heads(&vault, &contact_id)?;
    assert_eq!(heads.len(), COUNTERPARTY_CONTACT_CLAIM_PREDICATES.len());
    let cached = vault
        .get_counterparty_contact(&contact_id)?
        .expect("cache row");
    assert!(cached.is_opted_out());
    let mut projected = cached
        .claim_bodies(contact_id)
        .into_iter()
        .map(|body| (body.predicate, body.value))
        .collect::<Vec<_>>();
    projected.sort_by(|left, right| left.0.cmp(&right.0));
    assert_eq!(heads, projected);

    let cached_bytes = encode_counterparty_contact_body(&cached)?;
    let index_key = counterparty_contact_index_key(&identity, "kenji@example.com")?;

    // Dropping the cache row takes the row and its index entries and NO claim.
    drop_contact_cache_row(&vault, &contact_id)?;
    assert_eq!(vault.get_counterparty_contact(&contact_id)?, None);
    assert_eq!(
        vault.find_counterparty_contact(&identity, "kenji@example.com")?,
        None
    );
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.vault_meta.get(&rtxn, &index_key)?.is_none());
    }
    assert_eq!(live_claim_heads(&vault, &contact_id)?, heads);

    // Rebuilding from the heads reproduces the row byte-for-byte, index and all.
    let rebuilt = rematerialize_contact_cache(&vault, &contact_id)?;
    assert_eq!(rebuilt, cached);
    assert_eq!(encode_counterparty_contact_body(&rebuilt)?, cached_bytes);
    assert_eq!(
        vault.find_counterparty_contact(&identity, "kenji@example.com")?,
        Some((contact_id, cached))
    );
    // And it is idempotent: a second rebuild changes nothing.
    let again = rematerialize_contact_cache(&vault, &contact_id)?;
    assert_eq!(encode_counterparty_contact_body(&again)?, cached_bytes);
    assert_eq!(live_claim_heads(&vault, &contact_id)?, heads);
    Ok(())
}

/// Every temporal index key that names `id`, across all four temporal indexes,
/// as `(index, stamp)` pairs.
fn temporal_keys_for(vault: &Vault, id: &EntityId) -> Result<Vec<(&'static str, u64)>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut found = Vec::new();
    for (index, db) in [
        ("learned", &vault.store.temporal_learned),
        ("long_intervals", &vault.store.temporal_long_intervals),
        ("occurred_end", &vault.store.temporal_occurred_end),
        ("occurred_start", &vault.store.temporal_occurred_start),
    ] {
        for entry in db.iter(&rtxn)? {
            let (key, _) = entry?;
            if key.ends_with(id.as_bytes()) {
                let stamp = u64::from_be_bytes(key[..8].try_into().expect("temporal key stamp"));
                found.push((index, stamp));
            }
        }
    }
    found.sort_unstable();
    Ok(found)
}

/// Dropping the cache row takes the engine index rows the PUT wrote with it.
///
/// The row is written through the normal put path, which indexes it by type and
/// by its write stamps. A drop that removed only the row and the family's own
/// lookup legs would leave every time-range reader answering with an id that no
/// longer resolves — and because each rebuild stamps the row afresh, the dead
/// keys would ACCUMULATE, one per cycle, all naming the same contact.
#[test]
fn dropping_the_cache_row_leaves_no_stale_temporal_keys() -> Result<()> {
    let (_tmp, vault) = open_vault();
    let identity = entity(0x64);
    let contact_id = entity(0x65);
    vault.create_counterparty_contact(
        &contact_id,
        &CounterpartyContactRecord::user_introduction(identity, "rin@example.com", 10)?,
    )?;
    let type_key =
        crate::store::Store::encode_type_key(ENTITY_TYPE_COUNTERPARTY_CONTACT, &contact_id);
    assert_eq!(
        temporal_keys_for(&vault, &contact_id)?,
        vec![("learned", 10), ("occurred_start", 10)],
        "the put path indexed the row under its own write stamp"
    );

    drop_contact_cache_row(&vault, &contact_id)?;
    assert!(
        temporal_keys_for(&vault, &contact_id)?.is_empty(),
        "a dropped row is named by no temporal index"
    );
    {
        let rtxn = vault.store.env.read_txn()?;
        assert!(vault.store.type_index.get(&rtxn, &type_key)?.is_none());
    }

    // Rebuilding stamps the row afresh, and the rebuilt row is indexed at that
    // stamp ALONE — the pre-drop stamp is not still there beside it.
    let mut wtxn = vault.store.env.write_txn()?;
    rematerialize_contact_cache_in_txn(&vault, &mut wtxn, &contact_id, 200)?;
    wtxn.commit()?;
    assert_eq!(
        temporal_keys_for(&vault, &contact_id)?,
        vec![("learned", 200), ("occurred_start", 200)]
    );

    // Repeating the cycle cannot pile up candidates: one live row, one stamp,
    // however many times the cache is dropped and rebuilt.
    for stamp in [300_u64, 400] {
        drop_contact_cache_row(&vault, &contact_id)?;
        let mut wtxn = vault.store.env.write_txn()?;
        rematerialize_contact_cache_in_txn(&vault, &mut wtxn, &contact_id, stamp)?;
        wtxn.commit()?;
    }
    assert_eq!(
        temporal_keys_for(&vault, &contact_id)?,
        vec![("learned", 400), ("occurred_start", 400)]
    );
    // The claims were never touched, so the row is still the same row.
    assert_eq!(
        vault
            .get_counterparty_contact(&contact_id)?
            .expect("cache row")
            .counterparty,
        "rin@example.com"
    );
    Ok(())
}

/// Disclosure and interlocutor consumers keep their stable type-132 read
/// surface: an explicit drop-and-rebuild leaves both reading identically.
///
/// Read-path self-heal is NOT asserted — the rebuild here is explicit.
#[test]
fn disclosure_and_interlocutor_reads_identical() -> Result<()> {
    let (_tmp, vault) = open_vault();
    let identity = entity(0x61);
    let contact_id = entity(0x62);
    let record = CounterpartyContactRecord::user_introduction(identity, "mika@example.com", 10)?;
    vault.create_counterparty_contact(&contact_id, &record)?;

    let scope = DisclosureScope::task_scoped("party", vec![entity(0x63)], 100)?;
    vault.set_counterparty_disclosure_scope(&contact_id, &scope)?;
    let input = InterlocutorResolutionInput {
        owner_session: true,
        parties: vec![InterlocutorPartyInput::ContactRef(contact_id)],
        voice_session_ref: None,
    };
    let before_scope = vault.counterparty_disclosure_scope(&contact_id)?;
    let before_set = vault.resolve_interlocutors(&input)?;

    drop_contact_cache_row(&vault, &contact_id)?;
    rematerialize_contact_cache(&vault, &contact_id)?;

    assert_eq!(
        vault.counterparty_disclosure_scope(&contact_id)?,
        before_scope
    );
    assert_eq!(vault.resolve_interlocutors(&input)?, before_set);
    // And the disclosure writer still accepts the rebuilt row.
    let mut wider = DisclosureScope::task_scoped("party and travel", vec![entity(0x63)], 100)?;
    wider.updated_at = 200;
    vault.set_counterparty_disclosure_scope(&contact_id, &wider)?;
    assert_eq!(
        vault.counterparty_disclosure_scope(&contact_id)?,
        Some(wider)
    );
    Ok(())
}

/// Seeds one ChannelIdentity so a contact recorded through it resolves to a
/// channel class.
fn put_identity(vault: &Vault, id: EntityId, channel: &str, address: &str) -> Result<()> {
    let identity = crate::channel_identity::ChannelIdentity {
        channel: channel.to_owned(),
        address_or_handle: address.to_owned(),
        shape: crate::channel_identity::ChannelIdentityShape::DedicatedAddress,
        binding: crate::channel_identity::ChannelIdentityBinding::agent(entity(0x6F)),
        state: crate::channel_identity::ChannelIdentityState::Active,
        pending_fulfillment: None,
        state_changed_at: 1,
        quarantine_until: None,
        reputation_ref: None,
        manifest_ref: None,
        grant: None,
    };
    vault.create_channel_identity(&id, &identity)
}

/// Party-scoped and channel-scoped opt-out truth reach exactly the rows they
/// cover, whichever contact the writer was handed.
///
/// A contact-level opt-out states a PARTY-WIDE fact — the party said it to the
/// owner, not to one mailbox — so every contact of that party re-derives, and a
/// sibling on another channel identity can never be left reading a stale "no"
/// for the gate to allow a send on. A channel-scoped STOP is the opposite
/// claim, and stays inside its class no matter which row is re-derived.
#[test]
fn party_wide_opt_out_reaches_every_contact_and_named_stop_stays_scoped() -> Result<()> {
    let (_tmp, vault) = open_vault();
    let email_identity = entity(0x71);
    let telegram_identity = entity(0x72);
    put_identity(&vault, email_identity, "email", "owner@example.com")?;
    put_identity(&vault, telegram_identity, "telegram", "@owner")?;

    // Two contacts for ONE party, on two different channel classes, both
    // written before any opt-out exists.
    let email_contact = entity(0x73);
    let telegram_contact = entity(0x74);
    vault.create_counterparty_contact(
        &email_contact,
        &CounterpartyContactRecord::user_introduction(email_identity, "kenji@example.com", 10)?,
    )?;
    vault.create_counterparty_contact(
        &telegram_contact,
        &CounterpartyContactRecord::user_introduction(telegram_identity, "kenji@example.com", 10)?,
    )?;

    // The opt-out is recorded on ONE of them and covers the party.
    vault.opt_out_counterparty_contact(
        &email_contact,
        CounterpartyOptOutReason::Unsubscribe,
        20,
    )?;
    assert!(
        vault
            .get_counterparty_contact(&telegram_contact)?
            .expect("sibling row")
            .is_opted_out(),
        "a party-wide head leaves no sibling contact reading not-opted-out"
    );

    // A channel-scoped STOP for a DIFFERENT party covers its class only. The
    // sibling row is re-derived explicitly, which is exactly the moment a
    // channel-blind fold would have dragged the email STOP onto telegram.
    let stopped_email = entity(0x75);
    let stopped_telegram = entity(0x76);
    vault.create_counterparty_contact(
        &stopped_email,
        &CounterpartyContactRecord::user_introduction(email_identity, "mika@example.com", 10)?,
    )?;
    vault.create_counterparty_contact(
        &stopped_telegram,
        &CounterpartyContactRecord::user_introduction(telegram_identity, "mika@example.com", 10)?,
    )?;
    crate::comm::record_comm_inbound_stop(&vault, "mika@example.com", "email", 30)
        .map_err(comm_fold_error)?;
    crate::comm::run_comm_projector(&vault).map_err(comm_fold_error)?;

    assert!(
        rematerialize_contact_cache(&vault, &stopped_email)?.is_opted_out(),
        "the STOPped class follows the head"
    );
    assert!(
        !rematerialize_contact_cache(&vault, &stopped_telegram)?.is_opted_out(),
        "a named STOP head never bleeds onto another class, whoever re-derives"
    );
    Ok(())
}

/// When EVERY covering head predates the contact, the newest head still wins.
///
/// CID-7 makes a stored `recorded_at` at least the contact's `created_at`, so a
/// head older than the contact lands on the row as `created_at`. Ranking the
/// next candidate against that stored stamp would rank it against `created_at`
/// instead of against the head that actually won: every remaining head predates
/// the contact too, so all of them lose, and the reason and receipt the row
/// carries become an artifact of claim iteration order. Here the party-wide
/// unsubscribe is the older head and the channel STOP is the newer one, and the
/// row must say STOP.
#[test]
fn newest_covering_head_wins_when_every_head_predates_the_contact() -> Result<()> {
    let (_tmp, vault) = open_vault();
    let first_identity = entity(0x81);
    let second_identity = entity(0x82);
    put_identity(&vault, first_identity, "email", "owner@example.com")?;
    put_identity(&vault, second_identity, "email", "ops@example.com")?;

    // Older head: a party-wide unsubscribe at 20.
    let early_contact = entity(0x83);
    vault.create_counterparty_contact(
        &early_contact,
        &CounterpartyContactRecord::user_introduction(first_identity, "kenji@example.com", 5)?,
    )?;
    vault.opt_out_counterparty_contact(
        &early_contact,
        CounterpartyOptOutReason::Unsubscribe,
        20,
    )?;

    // Newer head: a channel STOP for the same party at 30, in its own slot, so
    // both heads stand and both cover an email contact.
    crate::comm::record_comm_inbound_stop(&vault, "kenji@example.com", "email", 30)
        .map_err(comm_fold_error)?;
    crate::comm::run_comm_projector(&vault).map_err(comm_fold_error)?;

    // A contact created after BOTH heads: covered by both, newer than both.
    let late_contact = entity(0x84);
    vault.create_counterparty_contact(
        &late_contact,
        &CounterpartyContactRecord::user_introduction(second_identity, "kenji@example.com", 100)?,
    )?;

    let cached = vault
        .get_counterparty_contact(&late_contact)?
        .expect("cache row");
    let opt_out = cached.opt_out.expect("both heads cover this row");
    assert_eq!(
        opt_out.reason,
        CounterpartyOptOutReason::Stop,
        "the newest head by its OWN occurrence owns the reason"
    );
    assert_eq!(opt_out.receipt_reason(), "counterparty_opt_out_stop");
    // The clamp still applies, exactly once, to the head that won: the stored
    // stamp stays inside the record's window.
    assert_eq!(opt_out.recorded_at, cached.created_at);
    cached.validate()?;
    // And the choice is a property of the heads, not of one write: re-deriving
    // the row reaches the same one.
    assert_eq!(rematerialize_contact_cache(&vault, &late_contact)?, cached);
    Ok(())
}

/// A contact writer moves the contact family's OWN heads, never the party's.
///
/// After an inbound STOP the cache row is opted out by the fold, but that is
/// party truth on loan: a revoke must not copy it into a
/// `counterparty_contact.opt_out` head, or the family would be asserting a fact
/// it never learned and a contact-family CLEAR would appear to undo a
/// channel-scoped STOP.
#[test]
fn revoke_after_inbound_stop_keeps_stop_out_of_contact_claims() -> Result<()> {
    let (_tmp, vault) = open_vault();
    let identity = entity(0x77);
    let contact_id = entity(0x78);
    put_identity(&vault, identity, "email", "owner@example.com")?;
    vault.create_counterparty_contact(
        &contact_id,
        &CounterpartyContactRecord::user_introduction(identity, "sora@example.com", 10)?,
    )?;
    crate::comm::record_comm_inbound_stop(&vault, "sora@example.com", "email", 30)
        .map_err(comm_fold_error)?;
    crate::comm::run_comm_projector(&vault).map_err(comm_fold_error)?;
    assert!(
        vault
            .get_counterparty_contact(&contact_id)?
            .expect("cache row")
            .is_opted_out()
    );

    let revoked = vault.revoke_counterparty_contact(&contact_id, 40)?;
    assert_eq!(revoked.status, CounterpartyContactStatus::Revoked);
    assert!(
        revoked.is_opted_out(),
        "the cache still folds the standing STOP head"
    );

    let heads = live_claim_heads(&vault, &contact_id)?;
    let (_, opt_out_head) = heads
        .iter()
        .find(|(predicate, _)| predicate == PREDICATE_COUNTERPARTY_CONTACT_OPT_OUT)
        .expect("the family keeps a live opt-out head");
    assert_eq!(
        *opt_out_head,
        Value::Nil,
        "the STOP is party truth; the contact family never asserted it"
    );
    Ok(())
}

/// The reason vocabulary the cache stores is the RECEIPT vocabulary, and it
/// round-trips exactly.
#[test]
fn opt_out_receipt_reason_round_trips() {
    for reason in [
        CounterpartyOptOutReason::Stop,
        CounterpartyOptOutReason::Unsubscribe,
        CounterpartyOptOutReason::BlockOrFriendRemoval,
    ] {
        assert_eq!(
            CounterpartyOptOutReason::from_receipt_reason(reason.receipt_reason()),
            Some(reason)
        );
        // The `as_str()` spelling is a different vocabulary; it never decodes
        // as a receipt token.
        assert_eq!(
            CounterpartyOptOutReason::from_receipt_reason(reason.as_str()),
            None
        );
    }
    assert_eq!(
        CounterpartyOptOutReason::from_receipt_reason("counterparty_opt_out_unknown"),
        None
    );
}
