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
    usage.touch(&window, 1_059);
    assert_eq!(usage.used(), 1);
    // Dead at ts + duration_s.
    usage.touch(&window, 1_060);
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
    usage.touch(&window, 2_000);
    assert_eq!(usage.used(), 3);
    assert_eq!(usage.fired, vec!["silent50".to_owned()]);
    // Next day: fresh window, fresh ladder.
    usage.touch(&window, 86_400 + 1);
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
    let actor = test_id(0xA1);
    let bound_id = test_id(0xA2);
    let agnostic_id = test_id(0xA3);
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
        .connector_key_for("line", Some(&test_id(0xA4)))?
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
    // A replayed event id with ANY differing field fails closed — a
    // pre-claimed event_ref cannot force a silent no-op for a different
    // settlement.
    for (row, amount, declared) in [(1_u16, 100_u64, 5_u64), (0, 999, 5), (0, 100, 6)] {
        assert!(
            matches!(
                vault.settle_connector_spend(
                    &id,
                    row,
                    amount,
                    declared,
                    "settle:first-touch-ancient"
                ),
                Err(Error::InvalidConnectorKeyBody(
                    "settle event replay with different settlement"
                ))
            ),
            "mismatched replay (row {row}, amount {amount}, declared {declared}) must fail closed"
        );
    }
    Ok(())
}
