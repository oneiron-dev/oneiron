//! F06: an inbound STOP ends a projector pass as a durable, readable opt-out on
//! every vault shape, and a STOP the projector has not computed holds the send.

use super::*;

/// Opens a vault the production way, so the default policy manifest and its
/// critical floor stay in force (`open_vault` clears them).
fn open_production_vault(dir: &std::path::Path) -> Result<Vault> {
    let mut config = VaultConfig::device();
    config.map_size = 64 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    Vault::open(dir, config)
}

/// The `opt_out` entries the party's public contact view carries.
fn contact_view_opt_outs(vault: &Vault, party: &str) -> CommResult<usize> {
    let bytes = materialize_contact_record(vault, party)?;
    let Ok(rmpv::Value::Map(entries)) = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
    else {
        return Err(CommError::InvalidRecord);
    };
    Ok(entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("opt_out"))
        .and_then(|(_, value)| value.as_array())
        .map_or(0, Vec::len))
}

/// Source events still waiting for the projector.
fn pending_comm_events(vault: &Vault) -> CommResult<usize> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(comm_records_in_txn(vault, &rtxn)?
        .iter()
        .filter(|(_, record)| {
            matches!(
                record,
                CommRecord::Event {
                    projected: false,
                    ..
                }
            )
        })
        .count())
}

/// One email contact for `counterparty` under the owner identity `identity`.
fn email_contact(
    vault: &Vault,
    identity: EntityId,
    contact_id: EntityId,
    counterparty: &str,
) -> CommResult<()> {
    let contact = crate::counterparty_contact::CounterpartyContactRecord::user_introduction(
        identity,
        counterparty,
        1,
    )?;
    vault.create_counterparty_contact(&contact_id, &contact)?;
    Ok(())
}

/// H160: the default manifest's critical floor covers `comm.opt_out`, and the
/// projector wrote its STOP through the ordinary claim ladder, so on a vault
/// opened the production way the STOP was refused and stayed unprojected.
#[test]
fn production_policy_stop_projects_to_a_readable_opt_out() -> CommResult<()> {
    let dir = tempfile::tempdir().expect("tempdir");
    let contact_id = entity(0x92);
    {
        let vault = open_production_vault(dir.path())?;
        put_email_identity(&vault, entity(0x91), "owner@example.com")?;
        email_contact(&vault, entity(0x91), contact_id, "mika@example.com")?;
        record_comm_inbound_stop(&vault, "mika@example.com", "email", 30)?;
        run_comm_projector(&vault)?;
        assert_eq!(pending_comm_events(&vault)?, 0, "the STOP is consumed");
        assert_eq!(
            count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "mika@example.com", "email")?,
            1
        );
        assert!(contact_cache_opted_out(&vault, contact_id)?);
    }
    let vault = open_production_vault(dir.path())?;
    assert_eq!(
        count_active_comm_claims(&vault, PREDICATE_COMM_OPT_OUT, "mika@example.com", "email")?,
        1,
        "the opt-out survives a reopen"
    );
    assert!(contact_cache_opted_out(&vault, contact_id)?);
    Ok(())
}

/// H415: provider spellings (`email_ses`, `email_postmark`) normalize to one
/// slot. Two live last-touch heads there made a reply's projection return
/// `InvalidRecord` and abort the pass, so a later STOP for ANOTHER party never
/// projected; two live opt-out heads made that party's own STOP fail the same
/// way, leaving its contact row unrefreshed.
#[test]
fn provider_spelled_duplicate_heads_never_stall_a_stop() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    put_policy_manifest_bytes(&vault, entity(0x9D), &allow_email_send_manifest())?;
    put_email_identity(&vault, entity(0x91), "owner@example.com")?;
    email_contact(&vault, entity(0x91), entity(0x93), "stopped@example.com")?;
    email_contact(&vault, entity(0x91), entity(0x94), "victim@example.com")?;
    let noisy = resolve_or_create_comm_party(&vault, "noisy@example.com")?;
    let stopped = resolve_or_create_comm_party(&vault, "stopped@example.com")?;
    for (seed, class) in [(0x61, "email_ses"), (0x62, "email_postmark")] {
        let touch = CommClaimValue::LastTouch {
            party_ref: noisy,
            channel_class: class.to_owned(),
            occurred_at: 5,
        };
        let opt_out = CommClaimValue::OptOut {
            party_ref: stopped,
            channel_class: Some(class.to_owned()),
            reason: OPT_OUT_REASON_STOP.to_owned(),
            occurred_at: 5,
        };
        vault.try_with_write_txn(|wtxn| {
            put_comm_claim_with_id_in_txn(&vault, wtxn, entity(seed), &touch, 5)?;
            put_comm_claim_with_id_in_txn(&vault, wtxn, entity(seed + 0x10), &opt_out, 5)
        })?;
    }
    assert!(!contact_cache_opted_out(&vault, entity(0x93))?);

    record_comm_inbound_reply(&vault, "noisy@example.com", "email", 20)?;
    record_comm_inbound_stop(&vault, "stopped@example.com", "email", 30)?;
    record_comm_inbound_stop(&vault, "victim@example.com", "email", 40)?;
    run_comm_projector(&vault)?;

    assert_eq!(pending_comm_events(&vault)?, 0, "every event is consumed");
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_LAST_TOUCH,
            "noisy@example.com",
            "email"
        )?,
        1,
        "the reply leaves one live last-touch head on the slot"
    );
    assert!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "stopped@example.com",
            "email"
        )? >= 1
    );
    assert!(
        contact_cache_opted_out(&vault, entity(0x93))?,
        "a STOP on a slot that already stands refreshes the contact row"
    );
    assert!(gate_holds_for_counterparty_opt_out(
        &vault,
        "stopped@example.com"
    )?);
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "victim@example.com",
            "email"
        )?,
        1
    );
    assert!(gate_holds_for_counterparty_opt_out(
        &vault,
        "victim@example.com"
    )?);
    Ok(())
}

/// H415, isolation leg: an event the projector must still refuse (its derived
/// claim id is squatted by a foreign row) is reported, but it no longer stops
/// the pass, so a later STOP for another party still projects.
#[test]
fn a_refused_event_does_not_hold_back_a_later_stop() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    let party_ref = resolve_or_create_comm_party(&vault, "party-collide")?;
    let source_event = entity(0x77);
    let value = CommClaimValue::LastTouch {
        party_ref,
        channel_class: "email".to_owned(),
        occurred_at: 10,
    };
    let derived = projected_comm_claim_id(source_event, &value)?;
    vault.put_entity(
        &derived,
        ENTITY_TYPE_MACHINE,
        TimeRange { start: 1, end: 1 },
        1,
        b"machine",
    )?;
    let event = CommRecord::Event {
        sequence: 1,
        kind: CommEventKind::SendSucceeded,
        party_ref,
        channel_class: Some("email".to_owned()),
        thread_ref: None,
        occurred_at: 10,
        projected: false,
    };
    // The STOP sorts AFTER the refused event, so the pass reaches it only by
    // carrying on past the refusal.
    let victim = resolve_or_create_comm_party(&vault, "victim@example.com")?;
    let stop = CommRecord::Event {
        sequence: 2,
        kind: CommEventKind::InboundStop,
        party_ref: victim,
        channel_class: Some("email".to_owned()),
        thread_ref: None,
        occurred_at: 40,
        projected: false,
    };
    vault.try_with_write_txn(|wtxn| {
        put_comm_record_in_txn(&vault, wtxn, source_event, &event)?;
        put_comm_record_in_txn(&vault, wtxn, entity(0x7A), &stop)
    })?;

    let error = run_comm_projector(&vault).expect_err("the squatted event is still refused");
    assert!(matches!(error, CommError::InvalidRecord));
    assert!(!comm_event_is_projected(&vault, source_event)?);
    assert_eq!(vault.get_entity_type(&derived)?, Some(ENTITY_TYPE_MACHINE));
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "victim@example.com",
            "email"
        )?,
        1,
        "the later STOP projects past the refused event"
    );
    assert_eq!(
        pending_comm_events(&vault)?,
        1,
        "only the refused event waits"
    );
    Ok(())
}

/// H228: every join/leave re-read each snapshotted same-slot pending event, so
/// n thread events on one slot cost n(n-1) peer-candidate reads before a STOP
/// queued behind them could project. Those reads stay linear in the events.
#[test]
fn same_slot_peer_candidate_reads_stay_linear_before_a_stop() -> CommResult<()> {
    const EVENTS: u64 = 48;
    let (_dir, vault) = open_vault();
    for at in 0..EVENTS {
        record_comm_thread_event(
            &vault,
            "busy-thread",
            "busy@example.com",
            at % 2 == 0,
            10 + at,
        )?;
    }
    record_comm_inbound_stop(&vault, "victim@example.com", "email", 500)?;

    let reads_before = PEER_CANDIDATE_READS.with(std::cell::Cell::get);
    run_comm_projector(&vault)?;
    let reads = PEER_CANDIDATE_READS.with(std::cell::Cell::get) - reads_before;

    assert!(
        reads <= 2 * usize::try_from(EVENTS).expect("small"),
        "{reads} peer-candidate reads for {EVENTS} same-slot events"
    );
    assert_eq!(pending_comm_events(&vault)?, 0);
    assert_eq!(
        count_active_comm_claims(
            &vault,
            PREDICATE_COMM_OPT_OUT,
            "victim@example.com",
            "email"
        )?,
        1
    );
    Ok(())
}

/// H170: a twin merge keeps each claim on its own subject, but the opt-out
/// fold read only the survivor, so a STOP that projected onto the merged shell
/// was invisible to every contact row folded for the party: one existing
/// before the pass, and one created after the merge.
#[test]
fn stop_on_a_merged_twin_still_holds_the_survivors_sends() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    put_policy_manifest_bytes(&vault, entity(0x9D), &allow_email_send_manifest())?;
    put_email_identity(&vault, entity(0x91), "owner@example.com")?;
    let first = mint_comm_person(&vault, "twin@example.com")?;
    let second = mint_comm_person(&vault, "twin@example.com")?;
    let mut sorted = [first, second];
    sorted.sort_unstable();
    let [survivor, loser] = sorted;
    point_party_index(&vault, "twin@example.com", survivor)?;
    email_contact(&vault, entity(0x91), entity(0x95), "twin@example.com")?;

    let stop = CommRecord::Event {
        sequence: 0,
        kind: CommEventKind::InboundStop,
        party_ref: loser,
        channel_class: Some("email".to_owned()),
        thread_ref: None,
        occurred_at: 30,
        projected: false,
    };
    vault.try_with_write_txn(|wtxn| put_comm_record_in_txn(&vault, wtxn, entity(0x78), &stop))?;
    run_comm_projector(&vault)?;
    assert_eq!(
        vault.entity_lifecycle_state(&loser)?,
        EntityLifecycleState::Merged
    );
    assert!(comm_event_is_projected(&vault, entity(0x78))?);

    assert!(
        contact_cache_opted_out(&vault, entity(0x95))?,
        "a contact folded before the merge is folded again with the shell's STOP"
    );
    let identity = entity(0x96);
    put_email_identity(&vault, identity, "second@example.com")?;
    email_contact(&vault, identity, entity(0x97), "twin@example.com")?;
    assert!(
        contact_cache_opted_out(&vault, entity(0x97))?,
        "a contact created after the merge reads the shell's STOP through"
    );
    assert!(gate_holds_for_counterparty_opt_out(
        &vault,
        "twin@example.com"
    )?);
    assert_eq!(
        contact_view_opt_outs(&vault, "twin@example.com")?,
        1,
        "the party's public contact view reads the shell's STOP through"
    );
    Ok(())
}

/// H170, R1 F1: a delayed STOP naming a twin that an EARLIER pass already
/// merged projects onto the shell, and the party's contact rows must still be
/// refreshed: the refresh used to require an active subject.
#[test]
fn delayed_stop_on_an_already_merged_twin_refreshes_the_party() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    put_policy_manifest_bytes(&vault, entity(0x9D), &allow_email_send_manifest())?;
    put_email_identity(&vault, entity(0x91), "owner@example.com")?;
    let first = mint_comm_person(&vault, "late-twin@example.com")?;
    let second = mint_comm_person(&vault, "late-twin@example.com")?;
    let mut sorted = [first, second];
    sorted.sort_unstable();
    let [survivor, loser] = sorted;
    point_party_index(&vault, "late-twin@example.com", survivor)?;
    email_contact(&vault, entity(0x91), entity(0x98), "late-twin@example.com")?;
    run_comm_projector(&vault)?;
    assert_eq!(
        vault.entity_lifecycle_state(&loser)?,
        EntityLifecycleState::Merged
    );
    assert!(!contact_cache_opted_out(&vault, entity(0x98))?);

    let stop = CommRecord::Event {
        sequence: 0,
        kind: CommEventKind::InboundStop,
        party_ref: loser,
        channel_class: Some("email".to_owned()),
        thread_ref: None,
        occurred_at: 30,
        projected: false,
    };
    vault.try_with_write_txn(|wtxn| put_comm_record_in_txn(&vault, wtxn, entity(0x79), &stop))?;
    run_comm_projector(&vault)?;
    assert!(comm_event_is_projected(&vault, entity(0x79))?);
    assert!(contact_cache_opted_out(&vault, entity(0x98))?);
    assert!(gate_holds_for_counterparty_opt_out(
        &vault,
        "late-twin@example.com"
    )?);
    Ok(())
}

/// R1 F2: a contact created before its sending identity has no party-channel
/// index entry, and the STOP refresh enumerated only that index, so the row
/// stayed not opted out after the STOP projected.
#[test]
fn stop_refreshes_a_contact_missing_from_the_party_index() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    put_policy_manifest_bytes(&vault, entity(0x9D), &allow_email_send_manifest())?;
    email_contact(&vault, entity(0x91), entity(0x99), "unindexed@example.com")?;
    put_email_identity(&vault, entity(0x91), "owner@example.com")?;
    record_comm_inbound_stop(&vault, "unindexed@example.com", "email", 30)?;
    run_comm_projector(&vault)?;
    assert_eq!(pending_comm_events(&vault)?, 0);
    assert!(contact_cache_opted_out(&vault, entity(0x99))?);
    assert!(gate_holds_for_counterparty_opt_out(
        &vault,
        "unindexed@example.com"
    )?);
    Ok(())
}

/// Merges `source` into `survivor` read-through, through the identity door
/// that takes any two PERSON rows: nothing there requires their party keys to
/// agree.
fn merge_read_through(vault: &Vault, source: EntityId, survivor: EntityId) -> CommResult<()> {
    use crate::identity_topology::{
        IdentityOpEvidence, IdentityOpOutcome, IdentityOpWrite, IdentityTopologyOp, MergeOp,
        SurvivorshipPlan,
    };
    let outcome = vault.apply_identity_topology_op(
        &IdentityTopologyOp::Merge(MergeOp {
            sources: vec![source],
            survivor,
            evidence: IdentityOpEvidence {
                refs: vec![survivor, source],
                rationale: "one person, two addresses".to_owned(),
            },
            survivorship_plan: SurvivorshipPlan::ReadThrough,
        }),
        &IdentityOpWrite::auto(crate::claim::ClaimSource::Inferred),
        vault.store.clock.now_recorded_at(),
    )?;
    assert!(matches!(outcome, IdentityOpOutcome::Applied { .. }));
    Ok(())
}

/// An unprojected STOP naming `party_ref` directly, as a delayed or replicated
/// event still does after its party was merged away.
fn put_stop_naming(
    vault: &Vault,
    event_id: EntityId,
    party_ref: EntityId,
    channel_class: &str,
    sequence: u64,
    occurred_at: u64,
) -> CommResult<()> {
    let stop = CommRecord::Event {
        sequence,
        kind: CommEventKind::InboundStop,
        party_ref,
        channel_class: Some(channel_class.to_owned()),
        thread_ref: None,
        occurred_at,
        projected: false,
    };
    vault.try_with_write_txn(|wtxn| put_comm_record_in_txn(vault, wtxn, event_id, &stop))
}

/// R2-F1: a STOP on a merged twin holds the survivor's sends, so the human
/// clear must reach it. The request read only the survivor's own slot and
/// answered `ActiveOptOutNotFound`, leaving no way to lift the hold. The
/// restrictive-wins rule holds across the twins too: a STOP on the shell after
/// the request refuses the ruling. R3-F3: that STOP, and a twin's pending gate,
/// may carry a provider spelling of the channel. Both were compared raw, so the
/// stale request cleared the later STOP, and a ruling older than the shell's
/// gate went through.
#[test]
fn a_human_clear_reaches_a_merged_twins_stop() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    let party = "cleared-twin@example.com";
    put_policy_manifest_bytes(&vault, entity(0x9D), &allow_email_send_manifest())?;
    put_email_identity(&vault, entity(0x91), "owner@example.com")?;
    let first = mint_comm_person(&vault, party)?;
    let second = mint_comm_person(&vault, party)?;
    let mut sorted = [first, second];
    sorted.sort_unstable();
    let [survivor, loser] = sorted;
    point_party_index(&vault, party, survivor)?;
    email_contact(&vault, entity(0x91), entity(0x9A), party)?;
    put_stop_naming(&vault, entity(0x7B), loser, "email", 0, 30)?;
    run_comm_projector(&vault)?;
    assert_eq!(
        vault.entity_lifecycle_state(&loser)?,
        EntityLifecycleState::Merged
    );
    assert!(gate_holds_for_counterparty_opt_out(&vault, party)?);
    let human = WriteActor::new(survivor, EdgeActorClass::Human);

    assert_eq!(
        request_opt_out_clear(&vault, party, "email", 60)?,
        CommClearOptOutOutcome::PendingHumanRuling
    );
    put_stop_naming(&vault, entity(0x7C), loser, "email_ses", 1, 70)?;
    run_comm_projector(&vault)?;
    let error = approve_pending_opt_out_clear(&vault, party, "email", human, 71)
        .expect_err("a STOP on the shell after the request refuses the ruling");
    assert!(matches!(error, CommError::PendingClearSupersededByStop));
    assert!(gate_holds_for_counterparty_opt_out(&vault, party)?);

    assert_eq!(
        request_opt_out_clear(&vault, party, "email", 80)?,
        CommClearOptOutOutcome::PendingHumanRuling
    );
    let twin_gate = CommRecord::Gate {
        party_ref: loser,
        channel_class: "email_ses".to_owned(),
        claim_ref: entity(0x7E),
        created_at: 90,
        pending: true,
    };
    vault.try_with_write_txn(|wtxn| {
        put_comm_record_in_txn(&vault, wtxn, entity(0x7F), &twin_gate)
    })?;
    let error = approve_pending_opt_out_clear(&vault, party, "email", human, 85)
        .expect_err("a ruling older than the twin's gate is refused");
    assert!(matches!(error, CommError::RulingPredatesGate));
    approve_pending_opt_out_clear(&vault, party, "email", human, 91)?;
    assert!(!contact_cache_opted_out(&vault, entity(0x9A))?);
    assert!(!gate_holds_for_counterparty_opt_out(&vault, party)?);
    assert_eq!(contact_view_opt_outs(&vault, party)?, 0);
    assert_eq!(count_opt_out_clear_receipts(&vault, party)?, 1);
    assert_eq!(count_pending_comm_consent_gates(&vault)?, 0);
    Ok(())
}

/// R2-F3: a read-through merge may join two different party keys. A delayed
/// STOP naming the merged party projects onto its shell, and the survivor's
/// fold reads it through, but the refresh followed only the shell's own key,
/// so the survivor's contact row stayed not opted out and its send passed.
/// R3-F1: the refresh then took the survivor from the redirect table alone.
/// With the table dropped (a supported door; the fold still reads the shell
/// edges) it missed the survivor again, on the STOP and on the clear.
#[test]
fn delayed_stop_on_a_merged_alias_refreshes_the_survivors_contacts() -> CommResult<()> {
    for dropped in [false, true] {
        let (_dir, vault) = open_vault();
        put_policy_manifest_bytes(&vault, entity(0x9D), &allow_email_send_manifest())?;
        put_email_identity(&vault, entity(0x91), "owner@example.com")?;
        let alias = mint_comm_person(&vault, "old@example.com")?;
        let survivor = mint_comm_person(&vault, "new@example.com")?;
        point_party_index(&vault, "new@example.com", survivor)?;
        email_contact(&vault, entity(0x91), entity(0x9B), "new@example.com")?;
        merge_read_through(&vault, alias, survivor)?;
        if dropped {
            vault.drop_redirect_projection()?;
        }
        assert!(!contact_cache_opted_out(&vault, entity(0x9B))?);

        put_stop_naming(&vault, entity(0x7D), alias, "email", 0, 30)?;
        run_comm_projector(&vault)?;
        assert!(comm_event_is_projected(&vault, entity(0x7D))?);
        assert_eq!(
            contact_view_opt_outs(&vault, "new@example.com")?,
            1,
            "the survivor's view reads the alias's STOP (table dropped: {dropped})"
        );
        assert!(
            contact_cache_opted_out(&vault, entity(0x9B))?,
            "the survivor's contact row follows that STOP (table dropped: {dropped})"
        );
        assert!(gate_holds_for_counterparty_opt_out(
            &vault,
            "new@example.com"
        )?);

        assert_eq!(
            request_opt_out_clear(&vault, "new@example.com", "email", 60)?,
            CommClearOptOutOutcome::PendingHumanRuling
        );
        let human = WriteActor::new(survivor, EdgeActorClass::Human);
        approve_pending_opt_out_clear(&vault, "new@example.com", "email", human, 61)?;
        assert!(
            !contact_cache_opted_out(&vault, entity(0x9B))?,
            "the clear refreshes the survivor's contact row (table dropped: {dropped})"
        );
    }
    Ok(())
}

/// R3-F2: the refresh resolved the STOP's subject forward, and forward
/// resolution errors at 64 hops. Each merge of a chain is accepted on its own,
/// so a delayed STOP naming the chain's first link rolled back and was never
/// projected, while the head's fold still reads that link.
#[test]
fn a_stop_on_the_first_link_of_a_64_merge_chain_projects() -> CommResult<()> {
    let (_dir, vault) = open_vault();
    put_policy_manifest_bytes(&vault, entity(0x9D), &allow_email_send_manifest())?;
    put_email_identity(&vault, entity(0x91), "owner@example.com")?;
    let first = mint_comm_person(&vault, "link-0@example.com")?;
    let mut head = first;
    for link in 1..=64 {
        let next = mint_comm_person(&vault, &format!("link-{link}@example.com"))?;
        merge_read_through(&vault, head, next)?;
        head = next;
    }
    point_party_index(&vault, "link-64@example.com", head)?;
    email_contact(&vault, entity(0x91), entity(0x9C), "link-64@example.com")?;

    put_stop_naming(&vault, entity(0x7E), first, "email", 0, 30)?;
    run_comm_projector(&vault)?;
    assert!(comm_event_is_projected(&vault, entity(0x7E))?);
    assert!(contact_cache_opted_out(&vault, entity(0x9C))?);
    assert!(gate_holds_for_counterparty_opt_out(
        &vault,
        "link-64@example.com"
    )?);
    Ok(())
}
