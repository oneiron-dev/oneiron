use super::*;

use crate::config::VaultConfig;
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::registry::{
    EntityClassification, TypeByteBand, entity_type_registry_entry, short_id_prefix,
    validate_public_entity_type,
};

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

fn test_id(seed: u8) -> EntityId {
    EntityId::from_bytes([seed; ENTITY_ID_LEN]).expect("valid test id")
}

fn all_dimension_budgets() -> Vec<EffectorBudget> {
    vec![
        EffectorBudget::sends(
            20,
            EffectorBudgetWindow::Calendar {
                period: CalendarPeriod::Day,
                tz: None,
            },
            EffectorBudgetOnExhaust::Suspend,
        ),
        EffectorBudget {
            reserve_policy: Some(EffectorBudgetReservePolicy::SettleOnly),
            channel_class: Some("slack".to_owned()),
            ..EffectorBudget::spend(
                10_000,
                "USD",
                EffectorBudgetWindow::Calendar {
                    period: CalendarPeriod::Month,
                    tz: Some("UTC".to_owned()),
                },
                EffectorBudgetOnExhaust::Suspend,
            )
        },
        EffectorBudget::rate(5, 60),
    ]
}

#[test]
fn connector_key_codec_round_trips_all_dimensions() -> Result<()> {
    let actor_bound = ConnectorKeyRecord {
        actor_entity_ref: Some(test_id(0xA7)),
        ..ConnectorKeyRecord::active("slack", None, all_dimension_budgets(), 1_000)
    };
    let encoded = encode_connector_key_body(&actor_bound)?;
    assert_eq!(decode_connector_key_body(&encoded)?, actor_bound);

    let actor_agnostic = ConnectorKeyRecord::active("line", None, all_dimension_budgets(), 2_000);
    let encoded = encode_connector_key_body(&actor_agnostic)?;
    let decoded = decode_connector_key_body(&encoded)?;
    assert_eq!(decoded, actor_agnostic);
    assert!(decoded.charter.is_none());
    assert!(decoded.pending_charter.is_none());

    let suspended = ConnectorKeyRecord {
        status: ConnectorKeyStatus::Suspended,
        status_changed_at: Some(3_000),
        suspended_reason: Some("budget_exhausted:row:0".to_owned()),
        ..actor_agnostic
    };
    let encoded = encode_connector_key_body(&suspended)?;
    assert_eq!(decode_connector_key_body(&encoded)?, suspended);
    Ok(())
}

#[test]
fn charter_block_slots_round_trip_for_gov10() -> Result<()> {
    // GOV-01 mints records with both charter slots None, but the codec must
    // already round-trip filled blocks (GOV-10 relies on it).
    let compiled = CompiledConnectorPolicy {
        never_list: vec!["*:delete".to_owned(), "slack:call".to_owned()],
        channel_caps: vec![EffectorBudget::sends(
            3,
            EffectorBudgetWindow::Calendar {
                period: CalendarPeriod::Week,
                tz: None,
            },
            EffectorBudgetOnExhaust::Suspend,
        )],
    };
    let record = ConnectorKeyRecord {
        charter: Some(ConnectorCharterBlock {
            text: "never delete".to_owned(),
            text_hash: [0x11; 32],
            compiled: compiled.clone(),
            compiled_hash: [0x22; 32],
            stamped_aggregate: [0x33; 32],
            stamped_by: "owner:olety".to_owned(),
            stamped_at: 4_000,
        }),
        pending_charter: Some(PendingConnectorCharter {
            text: "never call".to_owned(),
            text_hash: [0x44; 32],
            compiled,
            compiled_hash: [0x55; 32],
            proposed_at: 4_100,
        }),
        ..ConnectorKeyRecord::active("slack", Some(test_id(0xB1)), Vec::new(), 1_000)
    };
    let encoded = encode_connector_key_body(&record)?;
    assert_eq!(decode_connector_key_body(&encoded)?, record);
    Ok(())
}

#[test]
fn connector_key_registry_entry_is_pinned() -> Result<()> {
    assert_eq!(ENTITY_TYPE_CONNECTOR_KEY, 135);
    let entry = entity_type_registry_entry(ENTITY_TYPE_CONNECTOR_KEY).expect("registered");
    assert_eq!(entry.kind, "CONNECTOR_KEY");
    assert_eq!(entry.type_byte, ENTITY_TYPE_CONNECTOR_KEY);
    assert_eq!(entry.short_id_prefix, Some("ck"));
    assert_eq!(entry.classification, EntityClassification::Maintenance);
    assert_eq!(entry.band, TypeByteBand::InducedDynamicMaintenance);
    assert_eq!(short_id_prefix(ENTITY_TYPE_CONNECTOR_KEY)?, "ck");
    assert!(matches!(
        validate_public_entity_type(ENTITY_TYPE_CONNECTOR_KEY),
        Err(Error::MaintenanceKindNotWritable(135))
    ));
    Ok(())
}

#[test]
fn register_then_get_returns_normalized_record() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xC1);
    let mut record = ConnectorKeyRecord::active(
        " Slack-Chat ",
        Some(test_id(0xC2)),
        all_dimension_budgets(),
        1_000,
    );
    record.budgets[1].channel_class = Some(" Slack-Chat ".to_owned());

    let registered = vault.register_connector_key(&id, record)?;
    assert_eq!(registered.connector, "slack_chat");
    assert_eq!(
        registered.budgets[1].channel_class.as_deref(),
        Some("slack_chat")
    );

    let fetched = vault.get_connector_key(&id)?.expect("stored record");
    assert_eq!(fetched, registered);

    // Wrong-type read fails closed with the header's type byte.
    let other = test_id(0xC3);
    vault.mint_standing_outbound_grant(
        &other,
        &crate::genui::GrantMintIntent {
            principal_ref: "owner".to_owned(),
            origin_component_id: "ask-1".to_owned(),
            origin_action_id: "escalate_always_this_verb_class".to_owned(),
            origin_receipt_ref: None,
            scope: crate::genui::GrantMintIntentScope::VerbClass {
                verb_class: "send".to_owned(),
            },
        },
        10,
    )?;
    assert!(matches!(
        vault.get_connector_key(&other),
        Err(Error::InvalidEntityType(_))
    ));
    Ok(())
}

#[test]
fn register_enforces_tuple_uniqueness_until_revoked() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0xD1);
    vault.register_connector_key(
        &test_id(0xD2),
        ConnectorKeyRecord::active("line", Some(actor), Vec::new(), 1_000),
    )?;

    // Same (connector, actor) tuple: rejected.
    assert!(matches!(
        vault.register_connector_key(
            &test_id(0xD3),
            ConnectorKeyRecord::active("line", Some(actor), Vec::new(), 1_001),
        ),
        Err(Error::ConnectorKeyAlreadyExists)
    ));
    // Reusing the same entity id: rejected.
    assert!(matches!(
        vault.register_connector_key(
            &test_id(0xD2),
            ConnectorKeyRecord::active("email", Some(actor), Vec::new(), 1_001),
        ),
        Err(Error::ConnectorKeyAlreadyExists)
    ));
    // Same connector, different actor: fine.
    vault
        .register_connector_key(
            &test_id(0xD4),
            ConnectorKeyRecord::active("line", Some(test_id(0xD5)), Vec::new(), 1_002),
        )
        .expect("different actor tuple");
    // Actor-agnostic sibling: a distinct tuple, fine.
    vault
        .register_connector_key(
            &test_id(0xD6),
            ConnectorKeyRecord::active("line", None, Vec::new(), 1_003),
        )
        .expect("actor-agnostic tuple");

    // After revoke, the tuple frees up. (Seed 0xD8: [0xD7; 16] is the seeded
    // DEFAULT_POLICY_MANIFEST_ID and would collide on the entity-id check.)
    vault.revoke_connector_key(&test_id(0xD2), 1_010)?;
    vault
        .register_connector_key(
            &test_id(0xD8),
            ConnectorKeyRecord::active("line", Some(actor), Vec::new(), 1_011),
        )
        .expect("revoked tuple re-register");
    Ok(())
}

#[test]
fn register_rejects_non_active_status_and_prestamped_charter() {
    let (_tmp, vault) = temp_vault();
    let suspended = ConnectorKeyRecord {
        status: ConnectorKeyStatus::Suspended,
        status_changed_at: Some(1_000),
        suspended_reason: Some("owner".to_owned()),
        ..ConnectorKeyRecord::active("line", None, Vec::new(), 1_000)
    };
    assert!(matches!(
        vault.register_connector_key(&test_id(0xE1), suspended),
        Err(Error::InvalidConnectorKeyBody(
            "registration requires status active"
        ))
    ));

    let pre_stamped = ConnectorKeyRecord {
        pending_charter: Some(PendingConnectorCharter {
            text: "never delete".to_owned(),
            text_hash: [0; 32],
            compiled: CompiledConnectorPolicy {
                never_list: vec!["*:delete".to_owned()],
                channel_caps: Vec::new(),
            },
            compiled_hash: [0; 32],
            proposed_at: 1_000,
        }),
        ..ConnectorKeyRecord::active("line", None, Vec::new(), 1_000)
    };
    assert!(matches!(
        vault.register_connector_key(&test_id(0xE2), pre_stamped),
        Err(Error::InvalidConnectorKeyBody(
            "registration must not carry a charter"
        ))
    ));
}

#[test]
fn validation_rejects_malformed_budget_rows() {
    let day = || EffectorBudgetWindow::Calendar {
        period: CalendarPeriod::Day,
        tz: None,
    };
    let record =
        |budgets: Vec<EffectorBudget>| ConnectorKeyRecord::active("line", None, budgets, 1_000);

    // Spend without a unit.
    let mut spend_without_unit =
        EffectorBudget::spend(100, "USD", day(), EffectorBudgetOnExhaust::Refuse);
    spend_without_unit.unit = None;
    assert!(matches!(
        encode_connector_key_body(&record(vec![spend_without_unit])),
        Err(Error::InvalidConnectorKeyBody("spend rows require a unit"))
    ));

    // Lowercase 3-letter unit is a malformed ISO-4217 code, not a provider token.
    assert!(matches!(
        encode_connector_key_body(&record(vec![EffectorBudget::spend(
            100,
            "usd",
            day(),
            EffectorBudgetOnExhaust::Refuse,
        )])),
        Err(Error::InvalidConnectorKeyBody(
            "spend unit currency code must be uppercase"
        ))
    ));
    // Provider-unit tokens are valid (M8 widening).
    assert!(
        encode_connector_key_body(&record(vec![EffectorBudget::spend(
            100,
            "credits",
            day(),
            EffectorBudgetOnExhaust::Refuse,
        )]))
        .is_ok()
    );

    // Zero limit.
    assert!(matches!(
        encode_connector_key_body(&record(vec![EffectorBudget::sends(
            0,
            day(),
            EffectorBudgetOnExhaust::Refuse,
        )])),
        Err(Error::InvalidConnectorKeyBody(
            "budget limit must be at least 1"
        ))
    ));

    // Zero rolling duration.
    assert!(matches!(
        encode_connector_key_body(&record(vec![EffectorBudget::rate(5, 0)])),
        Err(Error::InvalidConnectorKeyBody(
            "rolling window duration must be at least 1s"
        ))
    ));

    // Non-UTC tz is a v1 validation error (honest forward-compat).
    assert!(matches!(
        encode_connector_key_body(&record(vec![EffectorBudget::sends(
            5,
            EffectorBudgetWindow::Calendar {
                period: CalendarPeriod::Day,
                tz: Some("Asia/Tokyo".to_owned()),
            },
            EffectorBudgetOnExhaust::Refuse,
        )])),
        Err(Error::InvalidConnectorKeyBody("calendar tz must be UTC"))
    ));

    // 17 budget rows.
    let seventeen = (0..17)
        .map(|_| EffectorBudget::rate(5, 60))
        .collect::<Vec<_>>();
    assert!(matches!(
        encode_connector_key_body(&record(seventeen)),
        Err(Error::InvalidConnectorKeyBody("too many budget rows"))
    ));
}

#[test]
fn calendar_window_start_fixtures() {
    // 2024-02-29T12:00:00Z (leap February).
    let leap_noon = 1_709_208_000;
    assert_eq!(
        calendar_window_start(CalendarPeriod::Day, leap_noon),
        1_709_164_800 // 2024-02-29T00:00:00Z
    );
    assert_eq!(
        calendar_window_start(CalendarPeriod::Month, leap_noon),
        1_706_745_600 // 2024-02-01T00:00:00Z
    );

    // Monday boundary: 2024-01-01 is a Monday.
    let monday = 1_704_067_200;
    assert_eq!(calendar_window_start(CalendarPeriod::Week, monday), monday);
    assert_eq!(
        calendar_window_start(CalendarPeriod::Week, monday + 6 * 86_400 + 3_600),
        monday
    );
    // One second before that Monday belongs to the previous (Christmas) week.
    assert_eq!(
        calendar_window_start(CalendarPeriod::Week, monday - 1),
        1_703_462_400 // Monday 2023-12-25T00:00:00Z
    );
    // Pre-1970-01-05 clamps to the epoch instead of underflowing.
    assert_eq!(calendar_window_start(CalendarPeriod::Week, 2 * 86_400), 0);

    // Dec -> Jan rollover.
    assert_eq!(
        calendar_window_start(CalendarPeriod::Month, monday - 1),
        1_701_388_800 // 2023-12-01T00:00:00Z
    );
    assert_eq!(
        calendar_window_start(CalendarPeriod::Month, monday + 14 * 86_400),
        monday // 2024-01-01T00:00:00Z
    );
}

#[test]
fn rolling_window_liveness_boundary() {
    let window = EffectorBudgetWindow::Rolling { duration_s: 60 };
    let mut usage = ConnectorKeyUsage {
        window_start: 0,
        entries: vec![(1_000, 1)],
        fired: Vec::new(),
    };
    // Live at ts + duration_s - 1.
    usage.touch(&window, 5, 1_059);
    assert_eq!(usage.used(), 1);
    // Dead at ts + duration_s.
    usage.touch(&window, 5, 1_060);
    assert_eq!(usage.used(), 0);
}

#[test]
fn calendar_rollover_resets_entries_and_fired() {
    let window = EffectorBudgetWindow::Calendar {
        period: CalendarPeriod::Day,
        tz: None,
    };
    let mut usage = ConnectorKeyUsage {
        window_start: 0,
        entries: vec![(1_000, 3)],
        fired: vec!["silent50".to_owned()],
    };
    // Same bucket: state survives.
    usage.touch(&window, 5, 2_000);
    assert_eq!(usage.used(), 3);
    assert_eq!(usage.fired, vec!["silent50".to_owned()]);
    // Next day: fresh window, fresh ladder.
    usage.touch(&window, 5, 86_400 + 1);
    assert_eq!(usage.window_start, 86_400);
    assert_eq!(usage.used(), 0);
    assert!(usage.fired.is_empty());
}

#[test]
fn usage_codec_round_trips() -> Result<()> {
    let usage = ConnectorKeyUsage {
        window_start: 86_400,
        entries: vec![(86_500, 1), (86_600, 250)],
        fired: vec!["silent50".to_owned(), "plan80".to_owned()],
    };
    assert_eq!(ConnectorKeyUsage::decode(&usage.encode()?)?, usage);
    assert!(ConnectorKeyUsage::decode(b"garbage").is_err());
    Ok(())
}

#[test]
fn spend_settle_accumulates_and_suspends_on_crossing() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xF1);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active(
            "slack",
            None,
            vec![
                EffectorBudget::sends(
                    5,
                    EffectorBudgetWindow::Calendar {
                        period: CalendarPeriod::Day,
                        tz: None,
                    },
                    EffectorBudgetOnExhaust::Refuse,
                ),
                EffectorBudget::spend(
                    1_000,
                    "USD",
                    EffectorBudgetWindow::Calendar {
                        period: CalendarPeriod::Month,
                        tz: None,
                    },
                    EffectorBudgetOnExhaust::Suspend,
                ),
            ],
            1_000,
        ),
    )?;

    let read = vault.settle_connector_spend(&id, 1, 400, 1_100, "settle:one")?;
    assert_eq!(read.used, 400);
    assert_eq!(read.remaining, 600);
    assert_eq!(read.percent_used, 40);
    assert_eq!(
        vault.get_connector_key(&id)?.expect("record").status,
        ConnectorKeyStatus::Active
    );

    // Crossing the limit flips the key Suspended in the same txn; the row
    // reports zero remaining.
    let read = vault.settle_connector_spend(&id, 1, 700, 1_200, "settle:two")?;
    assert_eq!(read.used, 1_100);
    assert_eq!(read.remaining, 0);
    let record = vault.get_connector_key(&id)?.expect("record");
    assert_eq!(record.status, ConnectorKeyStatus::Suspended);
    assert_eq!(
        record.suspended_reason.as_deref(),
        Some("budget_exhausted:row:1")
    );

    // Settling a non-spend row / a missing row fails closed.
    assert!(matches!(
        vault.settle_connector_spend(&id, 0, 1, 1_300, "settle:three"),
        Err(Error::InvalidConnectorKeyBody(
            "spend settle on non-spend row"
        ))
    ));
    assert!(matches!(
        vault.settle_connector_spend(&id, 7, 1, 1_300, "settle:four"),
        Err(Error::InvalidConnectorKeyBody(
            "spend settle on missing row"
        ))
    ));
    Ok(())
}

#[test]
fn lifecycle_transitions_are_enforced() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xF5);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 1_000),
    )?;

    let suspended = vault.suspend_connector_key(&id, "owner", 1_010)?;
    assert_eq!(suspended.status, ConnectorKeyStatus::Suspended);
    assert_eq!(suspended.suspended_reason.as_deref(), Some("owner"));
    assert_eq!(suspended.status_changed_at, Some(1_010));
    // Suspend requires Active.
    assert!(matches!(
        vault.suspend_connector_key(&id, "owner", 1_011),
        Err(Error::InvalidConnectorKeyBody("illegal status transition"))
    ));

    let resumed = vault.resume_connector_key(&id, 1_020)?;
    assert_eq!(resumed.status, ConnectorKeyStatus::Active);
    assert!(resumed.suspended_reason.is_none());
    // Resume requires Suspended.
    assert!(matches!(
        vault.resume_connector_key(&id, 1_021),
        Err(Error::InvalidConnectorKeyBody("illegal status transition"))
    ));

    let revoked = vault.revoke_connector_key(&id, 1_030)?;
    assert_eq!(revoked.status, ConnectorKeyStatus::Revoked);
    // Revoked is terminal.
    assert!(matches!(
        vault.revoke_connector_key(&id, 1_031),
        Err(Error::InvalidConnectorKeyBody("illegal status transition"))
    ));
    assert!(matches!(
        vault.resume_connector_key(&id, 1_032),
        Err(Error::InvalidConnectorKeyBody("illegal status transition"))
    ));
    Ok(())
}

#[test]
fn receipted_ops_project_into_gate_receipts() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xF7);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 1_000),
    )?;
    vault.suspend_connector_key(&id, "owner", 1_010)?;
    vault.resume_connector_key(&id, 1_020)?;

    let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
    let grant_ref = format!("ckey:{}", id.to_hex());
    for op in [
        "gate.connector_key.register",
        "gate.connector_key.suspend",
        "gate.connector_key.resume",
    ] {
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.policy_trace.iter().any(|reason| reason == op))
            .unwrap_or_else(|| panic!("missing {op} receipt"));
        assert_eq!(
            receipt.fields.get("grant_ref").map(String::as_str),
            Some(grant_ref.as_str()),
            "{op} receipt must join the ckey lane"
        );
    }
    Ok(())
}

#[test]
fn connector_key_for_resolves_exact_actor_over_agnostic() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0xB1);
    let bound_id = test_id(0xB2);
    let agnostic_id = test_id(0xB3);
    vault.register_connector_key(
        &bound_id,
        ConnectorKeyRecord::active("line", Some(actor), Vec::new(), 1_000),
    )?;
    vault.register_connector_key(
        &agnostic_id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 1_001),
    )?;

    let (resolved, _) = vault
        .connector_key_for("line", Some(&actor))?
        .expect("actor-bound key governs");
    assert_eq!(resolved, bound_id);

    let (resolved, _) = vault
        .connector_key_for("line", None)?
        .expect("agnostic key governs");
    assert_eq!(resolved, agnostic_id);

    // An actor with no exact tuple falls back to the connector-wide key.
    let (resolved, _) = vault
        .connector_key_for("line", Some(&test_id(0xB4)))?
        .expect("agnostic fallback");
    assert_eq!(resolved, agnostic_id);

    // A revoked-only tuple still resolves (the status wall reports it).
    vault.revoke_connector_key(&bound_id, 1_010)?;
    vault.revoke_connector_key(&agnostic_id, 1_011)?;
    let (_, record) = vault
        .connector_key_for("line", Some(&actor))?
        .expect("revoked tuple still resolves");
    assert_eq!(record.status, ConnectorKeyStatus::Revoked);

    assert!(vault.connector_key_for("unknown", None)?.is_none());
    assert!(vault.connector_key_for("  ", None)?.is_none());
    Ok(())
}

#[test]
fn spend_settle_ledgers_on_the_engine_clock_and_records_cost_time() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xF9);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active(
            "slack",
            None,
            vec![
                EffectorBudget::spend(
                    1_000,
                    "USD",
                    EffectorBudgetWindow::Calendar {
                        period: CalendarPeriod::Day,
                        tz: None,
                    },
                    EffectorBudgetOnExhaust::Suspend,
                ),
                EffectorBudget::spend(
                    2_000,
                    "USD",
                    EffectorBudgetWindow::Calendar {
                        period: CalendarPeriod::Month,
                        tz: None,
                    },
                    EffectorBudgetOnExhaust::Suspend,
                ),
            ],
            1_000,
        ),
    )?;

    // Zero-amount settlements are rejected (nothing to record; keeps the
    // usage entry log bounded by the row limit).
    assert!(matches!(
        vault.settle_connector_spend(&id, 0, 0, 2_000, "settle:zero"),
        Err(Error::InvalidConnectorKeyBody(
            "settle amount must be at least 1"
        ))
    ));
    // Event identity is required and shape-checked.
    assert!(matches!(
        vault.settle_connector_spend(&id, 0, 10, 2_000, "  "),
        Err(Error::InvalidConnectorKeyBody(
            "settle event_ref must not be blank"
        ))
    ));
    assert!(matches!(
        vault.settle_connector_spend(&id, 0, 10, 2_000, "x".repeat(129).as_str()),
        Err(Error::InvalidConnectorKeyBody("settle event_ref too long"))
    ));

    // cost_occurred_at is a DECLARED fact, never a window selector: a
    // far-past, a far-future, a calendar-edge, and a first-touch-on-empty-row
    // declared time all debit the CURRENT engine-clock window and cannot
    // clear or shift prior usage.
    let now = crate::unix_seconds_now();
    let live_bucket = calendar_window_start(CalendarPeriod::Day, now);
    let day_edge = live_bucket + SECONDS_PER_DAY - 1;
    let declared_times = [
        (5_u64, "settle:first-touch-ancient"),
        (now + 10_000, "settle:far-future"),
        (day_edge, "settle:calendar-edge"),
        (1_100, "settle:far-past"),
    ];
    let mut expected_used = 0;
    for (declared, event_ref) in declared_times {
        expected_used += 100;
        let read = vault.settle_connector_spend(&id, 0, 100, declared, event_ref)?;
        assert_eq!(read.used, expected_used, "{event_ref} accumulates");
        assert!(
            read.window_start >= live_bucket && read.window_start <= crate::unix_seconds_now(),
            "{event_ref} landed in the live engine-clock bucket"
        );
    }
    assert_eq!(
        vault.get_connector_key(&id)?.expect("record").status,
        ConnectorKeyStatus::Active
    );

    // A replay of the SAME settlement is idempotent: nothing debits, the
    // current state echoes back.
    let replay = vault.settle_connector_spend(&id, 0, 100, 5, "settle:first-touch-ancient")?;
    assert_eq!(replay.used, expected_used, "replay settles nothing");
    // An honest retry whose DECLARED cost time drifted between attempts is
    // still the same settlement: idempotent, no second debit, and the first
    // write's recorded time stands (first-writer-wins).
    let drifted = vault.settle_connector_spend(&id, 0, 100, 6, "settle:first-touch-ancient")?;
    assert_eq!(
        drifted.used, expected_used,
        "drifted-time retry settles nothing"
    );
    let event_key = connector_key_settle_event_key(&id, "settle:first-touch-ancient");
    {
        let rtxn = vault.store.env.read_txn()?;
        let stored = vault
            .store
            .vault_meta
            .get(&rtxn, &event_key)?
            .expect("settlement event row");
        assert_eq!(
            &stored[stored.len() - 8..],
            &5_u64.to_be_bytes(),
            "first recorded cost time kept"
        );
    }
    // A replayed event id with different CONTENT (row or amount) fails
    // closed — a pre-claimed event_ref cannot force a silent no-op for a
    // different settlement.
    for (row, amount) in [(1_u16, 100_u64), (0, 999)] {
        assert!(
            matches!(
                vault.settle_connector_spend(&id, row, amount, 5, "settle:first-touch-ancient"),
                Err(Error::InvalidConnectorKeyBody(
                    "settle event replay with different settlement"
                ))
            ),
            "content-mismatched replay (row {row}, amount {amount}) must fail closed"
        );
    }
    Ok(())
}

#[test]
fn stored_form_must_be_canonical() -> Result<()> {
    // The read path (connector index, gate resolution, row matching) is
    // keyed on normalized channel strings, so validate rejects any record
    // whose STORED connector/channel_class is not already canonical — a
    // non-canonical stored key would exist but silently fail to govern.
    let non_canonical_connector =
        ConnectorKeyRecord::active(" Slack-Chat ", None, Vec::new(), 1_000);
    assert!(matches!(
        encode_connector_key_body(&non_canonical_connector),
        Err(Error::InvalidConnectorKeyBody(
            "connector must be stored normalized"
        ))
    ));

    let mut non_canonical_class = EffectorBudget::rate(5, 60);
    non_canonical_class.channel_class = Some("Slack-Chat".to_owned());
    let record = ConnectorKeyRecord::active("slack", None, vec![non_canonical_class], 1_000);
    assert!(matches!(
        encode_connector_key_body(&record),
        Err(Error::InvalidConnectorKeyBody(
            "channel_class must be stored normalized"
        ))
    ));

    // The Vault write door normalizes before validating, so messy owner
    // input still registers — stored canonical — and governs the normalized
    // effect (the AC15 gate test covers the governs half end-to-end).
    let (_tmp, vault) = temp_vault();
    let mut messy = ConnectorKeyRecord::active(" Slack-Chat ", None, Vec::new(), 1_000);
    messy.budgets = vec![EffectorBudget::rate(5, 60)];
    messy.budgets[0].channel_class = Some(" Slack-Chat ".to_owned());
    let registered = vault.register_connector_key(&test_id(0xE7), messy)?;
    assert_eq!(registered.connector, "slack_chat");
    assert_eq!(
        registered.budgets[0].channel_class.as_deref(),
        Some("slack_chat")
    );
    assert!(
        vault.connector_key_for("slack-chat", None)?.is_some(),
        "stored form == index form: the canonical lookup resolves the key"
    );
    Ok(())
}

// --- GOV-02 budget legibility + graceful wrap (ONE-1418) ---------------------

#[test]
fn effector_steering_templates_are_pinned_to_the_one_channel() {
    assert_eq!(
        EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE_ID,
        "effector_budget.plan.80"
    );
    assert_eq!(
        EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE_ID,
        "effector_budget.land.95"
    );
    assert!(effector_steering_signal(BudgetThreshold::Silent50).is_none());
    let plan = effector_steering_signal(BudgetThreshold::Plan80).expect("plan steering");
    assert_eq!(
        plan.channel,
        BudgetSignalDeliveryChannel::SteeringQueueNextTurn
    );
    assert_eq!(plan.template_id, EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE_ID);
    assert_eq!(plan.message, EFFECTOR_BUDGET_PLAN_PROMPT_TEMPLATE);
    let land = effector_steering_signal(BudgetThreshold::Land95).expect("land steering");
    assert_eq!(
        land.channel,
        BudgetSignalDeliveryChannel::SteeringQueueNextTurn
    );
    assert_eq!(land.template_id, EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE_ID);
    assert_eq!(land.message, EFFECTOR_BUDGET_LAND_PROMPT_TEMPLATE);
}

#[test]
fn rolling_partial_expiry_rearms_only_unsatisfied_thresholds() {
    let window = EffectorBudgetWindow::Rolling { duration_s: 100 };
    let mut usage = ConnectorKeyUsage {
        window_start: 0,
        entries: vec![(50, 4), (150, 6)],
        fired: vec![
            "silent50".to_owned(),
            "plan80".to_owned(),
            "land95".to_owned(),
        ],
    };
    // now = 200: the (50, 4) entry is dead; used falls 10 -> 6 of limit 10
    // (100% -> 60%), re-arming Land95 + Plan80 but NOT Silent50 (M5a).
    usage.touch(&window, 10, 200);
    assert_eq!(usage.used(), 6);
    assert_eq!(usage.fired, vec!["silent50".to_owned()]);

    // Full expiry re-arms everything.
    usage.touch(&window, 10, 400);
    assert_eq!(usage.used(), 0);
    assert!(usage.fired.is_empty());
}

#[test]
fn rolling_full_expiry_lets_the_ladder_refire_on_the_next_charge() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let key_id = test_id(0xE5);
    let mut record = vault.register_connector_key(
        &key_id,
        ConnectorKeyRecord::active("line", None, vec![EffectorBudget::rate(2, 60)], 1_000),
    )?;

    // Seed an exhausted usage row whose entries have expired by `now`
    // (sleep-free liveness expiry).
    let seeded = ConnectorKeyUsage {
        window_start: 0,
        entries: vec![(1_000, 2)],
        fired: vec![
            "silent50".to_owned(),
            "plan80".to_owned(),
            "land95".to_owned(),
        ],
    };
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(
            wtxn,
            &connector_key_usage_row_key(&key_id, 0),
            &seeded.encode()?,
        )?;
        Ok(())
    })?;

    // The next charge sees a fresh window and the ladder re-fires from the
    // bottom: 1 of 2 = 50% -> Silent50 again.
    let outcome = vault.with_write_txn(|wtxn| {
        charge_effector_budgets(
            &vault.store,
            wtxn,
            &key_id,
            &mut record,
            "line",
            false,
            2_000,
        )
    })?;
    let EffectorBudgetChargeOutcome::Charged(charge) = outcome else {
        panic!("expected a charged outcome");
    };
    let fired: Vec<_> = charge
        .ladder_events
        .iter()
        .map(|event| event.threshold)
        .collect();
    assert_eq!(fired, vec![BudgetThreshold::Silent50]);
    assert_eq!(
        charge.read.rows[0].fired_thresholds,
        vec![BudgetThreshold::Silent50]
    );
    assert_eq!(charge.matched_rows, vec![0]);
    Ok(())
}

#[test]
fn effector_budget_read_resolves_actor_and_reflects_suspension() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let actor = test_id(0xB2);
    let bound_id = test_id(0xB3);
    let wide_id = test_id(0xB4);
    vault.register_connector_key(
        &bound_id,
        ConnectorKeyRecord::active(
            "line",
            Some(actor),
            vec![EffectorBudget::rate(5, 60)],
            1_000,
        ),
    )?;
    vault.register_connector_key(
        &wide_id,
        ConnectorKeyRecord::active("line", None, vec![EffectorBudget::rate(9, 60)], 1_001),
    )?;

    // Exact-actor key wins over the connector-wide key.
    let read = vault
        .effector_budget_read("line", Some(&actor))?
        .expect("exact-actor key");
    assert_eq!(read.key_ref, bound_id);
    assert_eq!(read.rows.len(), 1);
    assert_eq!(read.rows[0].limit, 5);
    assert_eq!(read.rows[0].used, 0);
    assert_eq!(read.rows[0].remaining, 5);

    let read = vault
        .effector_budget_read("line", None)?
        .expect("connector-wide key");
    assert_eq!(read.key_ref, wide_id);

    // Unknown connector: no meter.
    assert!(vault.effector_budget_read("unknown", None)?.is_none());

    // The read reflects suspension status.
    vault.suspend_connector_key(&bound_id, "owner", 1_010)?;
    let read = vault
        .effector_budget_read("line", Some(&actor))?
        .expect("suspended key still reads");
    assert_eq!(read.status, ConnectorKeyStatus::Suspended);
    Ok(())
}

// --- GOV-10 charter -> compiled policy (ONE-1417) -----------------------------

const CHARTER_FIXTURE_LF: &str = "\
# Herald charter
never delete on slack

never call
cap 5 sends per day on slack
cap 3 sends per 3600s on line
cap spend 100 USD per month on slack
cap spend 5000 JPY per day on line
rate 10 per 60s on email
";

#[test]
fn charter_compile_is_deterministic_and_normalizes_crlf() {
    let crlf = CHARTER_FIXTURE_LF.replace('\n', "\r\n");
    let first = compile_connector_charter(&crlf).expect("compiles");
    let second = compile_connector_charter(&crlf).expect("compiles");
    assert_eq!(first, second);
    assert_eq!(first.text_hash, second.text_hash);
    assert_eq!(first.compiled_hash, second.compiled_hash);

    // CRLF normalization: the LF variant hashes identically.
    let lf = compile_connector_charter(CHARTER_FIXTURE_LF).expect("compiles");
    assert_eq!(lf.text_hash, first.text_hash);
    assert_eq!(lf.compiled_hash, first.compiled_hash);
    assert_eq!(lf.compiled, first.compiled);

    // never_list is sorted + deduped; caps keep charter order.
    assert_eq!(
        first.compiled.never_list,
        vec!["*:call".to_owned(), "slack:delete".to_owned()]
    );
    assert_eq!(first.compiled.channel_caps.len(), 5);
    let caps = &first.compiled.channel_caps;
    assert_eq!(caps[0].dimension, EffectorBudgetDimension::Sends);
    assert_eq!(caps[0].channel_class.as_deref(), Some("slack"));
    assert_eq!(caps[0].limit, 5);
    assert_eq!(
        caps[0].window,
        EffectorBudgetWindow::Calendar {
            period: CalendarPeriod::Day,
            tz: None,
        }
    );
    assert_eq!(caps[0].on_exhaust, EffectorBudgetOnExhaust::Suspend);
    assert_eq!(
        caps[1].window,
        EffectorBudgetWindow::Rolling { duration_s: 3_600 }
    );
    // ISO-4217 major -> minor via the pinned exponent table: USD exponent 2.
    assert_eq!(caps[2].dimension, EffectorBudgetDimension::Spend);
    assert_eq!(caps[2].limit, 10_000);
    assert_eq!(caps[2].unit.as_deref(), Some("USD"));
    // JPY is on the explicit exponent-0 list.
    assert_eq!(caps[3].limit, 5_000);
    assert_eq!(caps[3].unit.as_deref(), Some("JPY"));
    assert_eq!(caps[4].dimension, EffectorBudgetDimension::Rate);
    assert_eq!(caps[4].on_exhaust, EffectorBudgetOnExhaust::Refuse);
    assert_eq!(
        caps[4].window,
        EffectorBudgetWindow::Rolling { duration_s: 60 }
    );

    // Keyword case variants compile to the SAME struct and compiled_hash
    // (text_hash may differ — the stamp binds both).
    let shouty = "\
# Herald charter
NEVER delete ON slack

Never call
Cap 5 SENDS Per Day On slack
CAP 3 sends per 3600s on line
cap SPEND 100 USD PER month on slack
cap spend 5000 JPY per DAY on line
RATE 10 per 60s ON email
";
    let shouty = compile_connector_charter(shouty).expect("compiles");
    assert_eq!(shouty.compiled, first.compiled);
    assert_eq!(shouty.compiled_hash, first.compiled_hash);
    assert_ne!(shouty.text_hash, first.text_hash);
}

#[test]
fn charter_compile_fails_closed_with_line_numbers() {
    let unrecognized = "never delete on slack\n\nnever\n";
    let issue = compile_connector_charter(unrecognized).expect_err("fail closed");
    assert_eq!(issue.line_number, 3);
    assert_eq!(issue.message, "unrecognized charter directive");

    let zero_limit = "cap 0 sends per day on slack";
    let issue = compile_connector_charter(zero_limit).expect_err("fail closed");
    assert_eq!(issue.line_number, 1);
    assert_eq!(issue.message, "invalid sends cap limit");

    let lowercase_currency = "# ok\ncap spend 5 usd per day on slack";
    let issue = compile_connector_charter(lowercase_currency).expect_err("fail closed");
    assert_eq!(issue.line_number, 2);
    assert_eq!(issue.message, "spend unit currency code must be uppercase");

    let zero_window = "rate 5 per 0s on slack";
    let issue = compile_connector_charter(zero_window).expect_err("fail closed");
    assert_eq!(issue.line_number, 1);
    assert_eq!(issue.message, "invalid window duration");

    // Provider-unit spend caps pass through opaque (M8).
    let provider = compile_connector_charter("cap spend 500 credits per day on slack")
        .expect("provider units compile");
    assert_eq!(provider.compiled.channel_caps[0].limit, 500);
    assert_eq!(
        provider.compiled.channel_caps[0].unit.as_deref(),
        Some("credits")
    );
}

#[test]
fn charter_never_list_matching_forms() {
    let block = |entries: &[&str]| ConnectorCharterBlock {
        text: "fixture".to_owned(),
        text_hash: [0; 32],
        compiled: CompiledConnectorPolicy {
            never_list: entries.iter().map(|entry| (*entry).to_owned()).collect(),
            channel_caps: Vec::new(),
        },
        compiled_hash: [0; 32],
        stamped_aggregate: [0; 32],
        stamped_by: "owner".to_owned(),
        stamped_at: 1,
    };
    // "*:{verb}" matches the verb on any channel.
    let any_channel = block(&["*:delete"]);
    assert!(charter_never_list_matches(&any_channel, "slack", "delete"));
    assert!(charter_never_list_matches(&any_channel, "line", " Delete "));
    assert!(!charter_never_list_matches(&any_channel, "slack", "send"));
    // "{channel}:*" matches every verb on the channel.
    let any_verb = block(&["slack:*"]);
    assert!(charter_never_list_matches(&any_verb, "slack", "send"));
    assert!(!charter_never_list_matches(&any_verb, "line", "send"));
    // Exact pair.
    let exact = block(&["slack:call"]);
    assert!(charter_never_list_matches(&exact, "slack", "call"));
    assert!(!charter_never_list_matches(&exact, "slack", "send"));
    assert!(!charter_never_list_matches(&exact, "line", "call"));
}

#[test]
fn charter_propose_approve_discard_lifecycle() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xC5);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("slack", None, Vec::new(), 1_000),
    )?;

    // Approve/discard without a staged proposal fail closed.
    assert!(matches!(
        vault.approve_connector_charter(&id, [0; 32], "owner", 1_001),
        Err(Error::ConnectorCharterMissing)
    ));
    assert!(matches!(
        vault.discard_connector_charter(&id, 1_001),
        Err(Error::ConnectorCharterMissing)
    ));

    // Propose stages the compile and NEVER changes enforcement state.
    let pending = vault.propose_connector_charter(&id, "never delete on slack", 1_002)?;
    let record = vault.get_connector_key(&id)?.expect("record");
    assert!(record.charter.is_none());
    assert_eq!(record.pending_charter.as_ref(), Some(&pending));

    // A malformed charter is rejected fail-closed and does not clobber the
    // staged proposal.
    assert!(matches!(
        vault.propose_connector_charter(&id, "cap 0 sends per day on slack", 1_003),
        Err(Error::ConnectorCharterCompile { line_number: 1, .. })
    ));
    assert_eq!(
        vault
            .get_connector_key(&id)?
            .expect("record")
            .pending_charter
            .as_ref(),
        Some(&pending)
    );

    // The human gate demands the out-of-band re-presented hash.
    assert!(matches!(
        vault.approve_connector_charter(&id, [0xAB; 32], "owner", 1_004),
        Err(Error::ConnectorCharterApprovalMismatch)
    ));
    assert!(matches!(
        vault.approve_connector_charter(&id, pending.compiled_hash, "  ", 1_004),
        Err(Error::InvalidConnectorKeyBody(
            "stamped_by must not be blank"
        ))
    ));
    let stamped =
        vault.approve_connector_charter(&id, pending.compiled_hash, "owner:olety", 1_005)?;
    let block = stamped.charter.as_ref().expect("stamped charter");
    assert!(stamped.pending_charter.is_none());
    assert_eq!(block.stamped_by, "owner:olety");
    assert_eq!(block.stamped_at, 1_005);
    assert_eq!(
        block.stamped_aggregate,
        charter_stamped_aggregate(&block.text_hash, &block.compiled_hash)
    );
    assert!(!charter_block_drifted(block)?);

    // Discard clears a re-staged proposal without touching the stamped block.
    vault.propose_connector_charter(&id, "never call", 1_006)?;
    let discarded = vault.discard_connector_charter(&id, 1_007)?;
    assert!(discarded.pending_charter.is_none());
    assert_eq!(discarded.charter, stamped.charter);

    // Every charter op is receipted with the ckey grant ref.
    let receipts = vault.receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::Gate))?;
    let grant_ref = format!("ckey:{}", id.to_hex());
    for op in [
        "gate.connector_key.charter_propose",
        "gate.connector_key.charter_approve",
        "gate.connector_key.charter_discard",
    ] {
        let receipt = receipts
            .iter()
            .find(|receipt| receipt.policy_trace.iter().any(|reason| reason == op))
            .unwrap_or_else(|| panic!("missing {op} receipt"));
        assert_eq!(
            receipt.fields.get("grant_ref").map(String::as_str),
            Some(grant_ref.as_str())
        );
    }

    // Charter ops on a revoked key fail closed.
    vault.revoke_connector_key(&id, 1_010)?;
    assert!(matches!(
        vault.propose_connector_charter(&id, "never call", 1_011),
        Err(Error::InvalidConnectorKeyBody("charter op on revoked key"))
    ));
    Ok(())
}

#[test]
fn cap_and_rate_reject_wildcard_channel_but_never_keeps_it() -> Result<()> {
    // (a) The gate matches a cap row's `channel_class` by EXACT equality, so a
    // stored `"*"` never matches a real channel (slack/email) and would debit 0
    // forever. Every cap/rate arm must fail closed on the wildcard with a
    // line-numbered compile error.
    for line in [
        "cap 10 sends per day on *",
        "cap spend 100 USD per month on *",
        "rate 10 per 60s on *",
    ] {
        let issue = compile_connector_charter(line).expect_err("wildcard cap fails closed");
        assert_eq!(issue.line_number, 1, "{line}");
        assert_eq!(
            issue.message, "cap channel must not be the wildcard '*'",
            "{line}"
        );
    }

    // (b) `never <verb> on *` STILL compiles — "*" is a legitimate wildcard on
    // the never arm — and matches every real channel.
    let never_wild = compile_connector_charter("never send on *").expect("never wildcard compiles");
    assert_eq!(never_wild.compiled.never_list, vec!["*:send".to_owned()]);
    let block = ConnectorCharterBlock {
        text: "never send on *".to_owned(),
        text_hash: [0; 32],
        compiled: never_wild.compiled,
        compiled_hash: [0; 32],
        stamped_aggregate: [0; 32],
        stamped_by: "owner".to_owned(),
        stamped_at: 1,
    };
    assert!(charter_never_list_matches(&block, "slack", "send"));
    assert!(charter_never_list_matches(&block, "email", "send"));

    // (c) A real-channel cap still compiles and narrows to that channel.
    let real =
        compile_connector_charter("cap 10 sends per day on slack").expect("real channel compiles");
    assert_eq!(
        real.compiled.channel_caps[0].channel_class.as_deref(),
        Some("slack")
    );
    Ok(())
}

#[test]
fn revoked_key_charter_ops_fail_closed_and_revoke_clears_pending() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xCA);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("slack", None, Vec::new(), 1_000),
    )?;
    let pending = vault.propose_connector_charter(&id, "never delete on slack", 1_001)?;

    // Revoke drops any staged pending_charter — a revoked key carries no
    // mutable charter state.
    let revoked = vault.revoke_connector_key(&id, 1_002)?;
    assert_eq!(revoked.status, ConnectorKeyStatus::Revoked);
    assert!(revoked.pending_charter.is_none());
    assert!(
        vault
            .get_connector_key(&id)?
            .expect("record")
            .pending_charter
            .is_none()
    );

    // Approve on a revoked key now errors (propose -> revoke -> approve).
    assert!(matches!(
        vault.approve_connector_charter(&id, pending.compiled_hash, "owner", 1_003),
        Err(Error::InvalidConnectorKeyBody("charter op on revoked key"))
    ));
    // Discard on a revoked key errors too.
    assert!(matches!(
        vault.discard_connector_charter(&id, 1_004),
        Err(Error::InvalidConnectorKeyBody("charter op on revoked key"))
    ));
    Ok(())
}

#[test]
fn malformed_never_list_entry_fails_closed_at_validation() {
    let charter = |never: Vec<String>| ConnectorKeyRecord {
        charter: Some(ConnectorCharterBlock {
            text: "fixture".to_owned(),
            text_hash: [0; 32],
            compiled: CompiledConnectorPolicy {
                never_list: never,
                channel_caps: Vec::new(),
            },
            compiled_hash: [0; 32],
            stamped_aggregate: [0; 32],
            stamped_by: "owner".to_owned(),
            stamped_at: 1,
        }),
        ..ConnectorKeyRecord::active("slack", None, Vec::new(), 1_000)
    };

    // No ':' — `charter_never_list_matches` silently skips it, so a stored
    // entry lacking a separator would fail OPEN (deny nothing).
    assert!(matches!(
        encode_connector_key_body(&charter(vec!["delete".to_owned()])),
        Err(Error::InvalidConnectorKeyBody(
            "never_list entry must be channel:verb"
        ))
    ));
    // More than one ':'.
    assert!(matches!(
        encode_connector_key_body(&charter(vec!["slack:call:x".to_owned()])),
        Err(Error::InvalidConnectorKeyBody(
            "never_list entry must be channel:verb"
        ))
    ));
    // Empty channel part.
    assert!(matches!(
        encode_connector_key_body(&charter(vec![":delete".to_owned()])),
        Err(Error::InvalidConnectorKeyBody(
            "never_list entry channel invalid"
        ))
    ));
    // Verb part carries a byte outside `[a-z0-9_]`.
    assert!(matches!(
        encode_connector_key_body(&charter(vec!["slack:call!".to_owned()])),
        Err(Error::InvalidConnectorKeyBody(
            "never_list entry verb invalid"
        ))
    ));
    // Well-formed entries (both wildcards) still validate.
    assert!(
        encode_connector_key_body(&charter(vec!["*:delete".to_owned(), "slack:*".to_owned()]))
            .is_ok()
    );
}
