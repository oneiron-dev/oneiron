use super::*;

use crate::config::VaultConfig;
use crate::receipt::{ReceiptKind, ReceiptQuery};
use crate::registry::{
    EntityClassification, TypeByteZone, entity_type_registry_entry, short_id_prefix,
    validate_public_entity_type,
};

fn register_catalog(
    vault: &Vault,
    entry: ConnectorCatalogEntry,
    mut spec: ConnectorKeySpec,
    registered_at: u64,
) -> Result<(EntityId, ConnectorKeyRecord)> {
    use super::{SlateDataClass, SlateToolManifest, draft_connector_slate};
    let manifest: Vec<_> = entry
        .verbs
        .iter()
        .map(|name| SlateToolManifest {
            name: name.clone(),
            data_class: SlateDataClass::Personal,
            header_parameters: Vec::new(),
            resolved_input_schema: Some(serde_json::json!({"type":"object"})),
            trigger: None,
            destroys: false,
            spends: false,
            sends_outward: false,
            legacy_ask: false,
        })
        .collect();
    let manifest = if manifest.is_empty() {
        vec![SlateToolManifest {
            name: "read".into(),
            data_class: SlateDataClass::Personal,
            header_parameters: Vec::new(),
            resolved_input_schema: Some(serde_json::json!({"type":"object"})),
            trigger: None,
            destroys: false,
            spends: false,
            sends_outward: false,
            legacy_ask: false,
        }]
    } else {
        manifest
    };
    let slate = vault.store_connector_slate(
        &manifest,
        &serde_json::to_string(&draft_connector_slate(&manifest))
            .map_err(|_| Error::InvariantViolation("test slate encoding"))?,
    )?;
    spec.slate_ref = Some(slate);
    spec.protocol_revision = Some("2026-09-01".into());
    vault.register_connector(entry, spec, registered_at)
}

fn temp_vault() -> (tempfile::TempDir, Vault) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(tmp.path(), VaultConfig::default()).expect("open vault");
    (tmp, vault)
}

use crate::error::{RecordError, RegistryError};
use crate::test_util::entity as test_id;

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

fn connector_key_op_receipt_count(vault: &Vault) -> Result<usize> {
    let receipts = vault.receipts(ReceiptQuery::new(20).with_kind(ReceiptKind::Gate))?;
    Ok(receipts
        .iter()
        .filter(|receipt| {
            receipt
                .policy_trace
                .iter()
                .any(|reason| reason.starts_with("gate.connector_key."))
        })
        .count())
}

#[test]
fn connector_key_codec_rejects_an_unsupported_version() -> Result<()> {
    let record = ConnectorKeyRecord::active("peer_link", None, Vec::new(), 1_000);
    let encoded = encode_connector_key_body(&record)?;
    let mut cursor = std::io::Cursor::new(encoded);
    let mut value = rmpv::decode::read_value(&mut cursor).expect("decode fixture");
    let rmpv::Value::Map(entries) = &mut value else {
        panic!("connector key body must be a map");
    };
    let (_, schema_version) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("schema_version"))
        .expect("schema_version key");
    // One past the current ceiling, expressed against the const so a future
    // additive bump cannot silently turn this into a no-op assertion.
    *schema_version = rmpv::Value::from(CONNECTOR_KEY_SCHEMA_VERSION + 1);
    let mut unsupported_body = Vec::new();
    rmpv::encode::write_value(&mut unsupported_body, &value).expect("encode unsupported fixture");

    assert!(matches!(
        decode_connector_key_body(&unsupported_body),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
    Ok(())
}

#[test]
fn connector_key_codec_rejects_missing_required_body_key() -> Result<()> {
    let record = ConnectorKeyRecord::active("peer_link", None, Vec::new(), 1_000);
    let encoded = encode_connector_key_body(&record)?;
    let mut cursor = std::io::Cursor::new(encoded);
    let mut value = rmpv::decode::read_value(&mut cursor).expect("decode fixture");
    let rmpv::Value::Map(entries) = &mut value else {
        panic!("connector key body must be a map");
    };
    entries.retain(|(key, _)| key.as_str() != Some("connector"));
    let mut missing_connector = Vec::new();
    rmpv::encode::write_value(&mut missing_connector, &value).expect("encode malformed fixture");

    assert!(matches!(
        decode_connector_key_body(&missing_connector),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
    Ok(())
}

// --- ONE-1875: the engine clock owns admission accounting --------------------

#[test]
fn connector_key_registry_entry_is_pinned() -> Result<()> {
    assert_eq!(ENTITY_TYPE_CONNECTOR_KEY, 80);
    let entry = entity_type_registry_entry(ENTITY_TYPE_CONNECTOR_KEY).expect("registered");
    assert_eq!(entry.kind, "CONNECTOR_KEY");
    assert_eq!(entry.type_byte, ENTITY_TYPE_CONNECTOR_KEY);
    assert_eq!(entry.short_id_prefix, Some("ck"));
    assert_eq!(entry.classification, EntityClassification::Maintenance);
    assert_eq!(entry.zone, TypeByteZone::System);
    assert_eq!(short_id_prefix(ENTITY_TYPE_CONNECTOR_KEY)?, "ck");
    assert!(matches!(
        validate_public_entity_type(ENTITY_TYPE_CONNECTOR_KEY),
        Err(Error::Registry(RegistryError::MaintenanceKindNotWritable(
            80
        )))
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
        Err(Error::Record(RecordError::ConnectorKeyAlreadyExists))
    ));
    // Reusing the same entity id: rejected.
    assert!(matches!(
        vault.register_connector_key(
            &test_id(0xD2),
            ConnectorKeyRecord::active("email", Some(actor), Vec::new(), 1_001),
        ),
        Err(Error::Record(RecordError::ConnectorKeyAlreadyExists))
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
        vault.register_connector_key(&test_id(0x5E), suspended),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
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
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
}

#[test]
fn lifecycle_transitions_are_enforced() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xF5);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 1_000),
    )?;

    let old_pin = vault.pin_entity_revision(&id)?;
    let old_raw = vault.get_raw_with_mode(&id, crate::vault::entity_revision::ReadMode::Live)?;
    let suspended = vault.suspend_connector_key(&id, "owner", 1_010)?;
    assert_eq!(suspended.status, ConnectorKeyStatus::Suspended);
    let new_pin = vault.pin_entity_revision(&id)?;
    assert_ne!(old_pin, new_pin);
    assert_eq!(vault.pin_entity_revision(&id)?, new_pin);
    assert_eq!(
        vault.get_raw_with_mode(
            &id,
            crate::vault::entity_revision::ReadMode::Pinned(old_pin)
        )?,
        old_raw
    );
    assert_eq!(
        vault.get_raw_with_mode(
            &id,
            crate::vault::entity_revision::ReadMode::Pinned(new_pin)
        )?,
        vault.get_raw_with_mode(&id, crate::vault::entity_revision::ReadMode::Live)?
    );
    assert_eq!(suspended.suspended_reason.as_deref(), Some("owner"));
    assert!(matches!(suspended.status_changed_at, Some(at) if (1_010..1_011).contains(&at)));
    // Suspend requires Active.
    assert!(matches!(
        vault.suspend_connector_key(&id, "owner", 1_011),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));

    let resumed = vault.resume_connector_key(&id, 1_020)?;
    assert_eq!(resumed.status, ConnectorKeyStatus::Active);
    assert!(resumed.suspended_reason.is_none());
    // Resume requires Suspended.
    assert!(matches!(
        vault.resume_connector_key(&id, 1_021),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));

    let revoked = vault.revoke_connector_key(&id, 1_030)?;
    assert_eq!(revoked.status, ConnectorKeyStatus::Revoked);
    // Revoked is terminal.
    assert!(matches!(
        vault.revoke_connector_key(&id, 1_031),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
    assert!(matches!(
        vault.resume_connector_key(&id, 1_032),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
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
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(
            "settle amount must be at least 1"
        )))
    ));
    // Event identity is required and shape-checked.
    assert!(matches!(
        vault.settle_connector_spend(&id, 0, 10, 2_000, "  "),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(
            "settle event_ref must not be blank"
        )))
    ));
    assert!(matches!(
        vault.settle_connector_spend(&id, 0, 10, 2_000, "x".repeat(129).as_str()),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(
            "settle event_ref too long"
        )))
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
    {
        let rtxn = vault.store.env.read_txn()?;
        let stored = SETTLE_EVENT
            .get(
                &vault.store,
                &rtxn,
                &(id, "settle:first-touch-ancient".to_owned()),
            )?
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
                Err(Error::Record(RecordError::InvalidConnectorKeyBody(
                    "settle event replay with different settlement"
                )))
            ),
            "content-mismatched replay (row {row}, amount {amount}) must fail closed"
        );
    }
    Ok(())
}

#[test]
fn stored_form_must_be_canonical() -> Result<()> {
    // Stored strings must already be canonical for lookup and matching.
    let non_canonical_connector =
        ConnectorKeyRecord::active(" Slack-Chat ", None, Vec::new(), 1_000);
    assert!(matches!(
        encode_connector_key_body(&non_canonical_connector),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));

    let mut non_canonical_class = EffectorBudget::rate(5, 60);
    non_canonical_class.channel_class = Some("Slack-Chat".to_owned());
    let record = ConnectorKeyRecord::active("slack", None, vec![non_canonical_class], 1_000);
    assert!(matches!(
        encode_connector_key_body(&record),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));

    // The public write door normalizes messy owner input before validation.
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

// --- GOV-10 charter -> compiled policy (ONE-1417) -----------------------------

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
        Err(Error::Record(RecordError::ConnectorCharterMissing))
    ));
    assert!(matches!(
        vault.discard_connector_charter(&id, 1_001),
        Err(Error::Record(RecordError::ConnectorCharterMissing))
    ));

    // Propose stages the compile and NEVER changes enforcement state.
    let pending = vault.propose_connector_charter(&id, "never delete on slack", 1_002)?;
    let record = vault.get_connector_key(&id)?.expect("record");
    assert!(record.charter.is_none());
    assert_eq!(
        record
            .pending_charter
            .as_ref()
            .expect("pending")
            .compiled_hash,
        pending.compiled_hash
    );

    // A malformed charter does not clobber the staged proposal.
    assert!(matches!(
        vault.propose_connector_charter(&id, "cap 0 sends per day on slack", 1_003),
        Err(Error::Record(RecordError::ConnectorCharterCompile {
            line_number: 1,
            ..
        }))
    ));
    let record = vault.get_connector_key(&id)?.expect("record");
    assert!(record.charter.is_none());
    assert_eq!(
        record
            .pending_charter
            .as_ref()
            .expect("pending")
            .compiled_hash,
        pending.compiled_hash
    );

    // The human gate demands the out-of-band re-presented hash.
    assert!(matches!(
        vault.approve_connector_charter(&id, [0xAB; 32], "owner", 1_004),
        Err(Error::Record(RecordError::ConnectorCharterApprovalMismatch))
    ));
    assert!(matches!(
        vault.approve_connector_charter(&id, pending.compiled_hash, "  ", 1_004),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
    let stamped =
        vault.approve_connector_charter(&id, pending.compiled_hash, "owner:olety", 1_005)?;
    let block = stamped.charter.as_ref().expect("stamped charter");
    assert!(stamped.pending_charter.is_none());
    assert_eq!(block.stamped_by, "owner:olety");
    assert_eq!(block.compiled_hash, pending.compiled_hash);
    assert_eq!(
        block.stamped_aggregate,
        charter_stamped_aggregate(&block.text_hash, &block.compiled_hash)
    );
    assert!(!charter_block_drifted(block)?);

    // Discard clears a re-staged proposal without touching approved policy.
    vault.propose_connector_charter(&id, "never call", 1_006)?;
    let discarded = vault.discard_connector_charter(&id, 1_007)?;
    assert!(discarded.pending_charter.is_none());
    let retained = discarded.charter.as_ref().expect("retained charter");
    assert_eq!(retained.stamped_aggregate, block.stamped_aggregate);
    assert_eq!(retained.stamped_by, block.stamped_by);
    assert!(!charter_block_drifted(retained)?);
    let persisted = vault.get_connector_key(&id)?.expect("record");
    assert!(persisted.pending_charter.is_none());
    let retained = persisted.charter.as_ref().expect("persisted charter");
    assert_eq!(retained.stamped_aggregate, block.stamped_aggregate);
    assert!(!charter_block_drifted(retained)?);

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
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
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
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
    // Discard on a revoked key errors too.
    assert!(matches!(
        vault.discard_connector_charter(&id, 1_004),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
    Ok(())
}

#[test]
fn never_list_entry_must_be_canonical_form() {
    let policy = |entry: &str| CompiledConnectorPolicy {
        never_list: vec![entry.to_owned()],
        channel_caps: Vec::new(),
    };

    // A merely well-SHAPED but non-canonical entry passes a shape-only check
    // yet at enforcement `charter_never_list_matches` compares the STORED
    // channel/verb by EXACT string against the effect's normalized channel and
    // lowercased verb — a non-canonical stored part never equals it, so the
    // prohibition fails OPEN. Every such entry MUST fail closed at validation.
    for entry in [
        "Slack:send",  // mixed-case channel
        "slack:SEND",  // mixed-case verb (parses to "send", but non-canonical)
        "SLACK:SEND",  // both non-canonical
        " slack:send", // leading-whitespace channel
        "slack :send", // trailing-whitespace channel
        "slack:send ", // trailing-whitespace verb
        // A colon-bearing ordinary channel carries the same canonicality duty:
        // enforcement compares the stored channel by exact string.
        "mcp:Acme:grant:ab12",
        "mcp:acme:grant:ab12 ",
        "mcp:my-server:grant:x",
        "Mcp:acme:grant:ab12",
    ] {
        assert!(
            matches!(
                validate_compiled_policy(&policy(entry)),
                Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
            ),
            "non-canonical never_list entry {entry:?} must fail closed"
        );
    }

    // The canonical forms the compiler emits still validate: the ordinary pair,
    // both wildcards, a colon-bearing ordinary channel, and one exact tagged
    // capability rule (ONE-1885).
    let capability_entry = format!(
        "capability-key:{}",
        ScopedCapabilityProvenance::mint("acme", &test_id(0xB4))
            .expect("safe canonical server")
            .connector()
    );
    for entry in [
        "slack:send",
        "*:send",
        "slack:*",
        "*:*",
        "mcp:acme:grant:ab12cd34",
        "mcp:*",
        "mcp:my_server:grant:x",
        "scoped-channel:mcp:my-server:*",
        capability_entry.as_str(),
    ] {
        assert!(
            validate_compiled_policy(&policy(entry)).is_ok(),
            "canonical never_list entry {entry:?} must validate"
        );
    }

    // An ordinary rule's verb is its LAST segment and its channel is everything
    // before it: a missing separator, an empty part, or a partial wildcard may
    // never reach a stored policy. A tagged rule must be one real capability
    // identity — nothing wildcard, truncated, or unsafe.
    for entry in [
        "send",
        ":send",
        "slack:",
        "",
        "mcp*:acme:grant:ab12",
        "mcp:acme*",
        "capability-key:mcp:acme:grant:*",
        "capability-key:mcp:acme:grant",
        "capability-key:mcp:*:grant:ab12cd34ab12cd34ab12cd34ab12cd34",
        "capability-key:mcp:acme:grant:ab12",
        "capability-key:",
        "scoped-channel:",
        "scoped-channel:mcp:Acme:*",
        "scoped-channel:mcp:acme:extra:*",
        "scoped-channel:mcp:acme*:send",
    ] {
        assert!(
            matches!(
                validate_compiled_policy(&policy(entry)),
                Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
            ),
            "malformed never_list entry {entry:?} must fail closed"
        );
    }
}

#[test]
fn crlf_imported_charter_block_does_not_false_drift() -> Result<()> {
    // The compiler stamps over the CRLF-normalized (LF) text. An imported block
    // that carries raw CRLF in `text` but whose stamp was computed over the LF
    // form must NOT read as drifted (which would degrade it to proposed-only).
    let crlf_text = "never delete on slack\r\nnever call\r\n";
    let compiled = compile_connector_charter(crlf_text).expect("compiles");
    let text_hash = compiled.text_hash;
    let compiled_hash = compiled.compiled_hash;
    let stamped_aggregate = charter_stamped_aggregate(&text_hash, &compiled_hash);
    let block = ConnectorCharterBlock {
        text: crlf_text.to_owned(),
        text_hash,
        compiled: compiled.compiled,
        compiled_hash,
        stamped_aggregate,
        stamped_by: "owner".to_owned(),
        stamped_at: 1,
    };
    assert!(
        !charter_block_drifted(&block)?,
        "CRLF block stamped over LF must not false-drift"
    );

    // Sanity: genuine text tampering with a stale stamp still drifts.
    let mut tampered = block;
    tampered.text = "never delete on slack\r\nnever send\r\n".to_owned();
    assert!(
        charter_block_drifted(&tampered)?,
        "mutated text must still drift"
    );
    Ok(())
}

// --- ONE-1885 first-colon never-list grammar ----------------------------------

#[test]
fn scoped_capability_identity_requires_one_safe_server() {
    let grant_id = test_id(0xAB);
    let hex = grant_id.to_hex();

    let minted = ScopedCapabilityProvenance::mint("files", &grant_id).expect("safe server");
    assert_eq!(minted.server(), "files");
    assert_eq!(minted.connector(), format!("mcp:files:grant:{hex}"));
    assert_eq!(minted.grant_id(), grant_id);
    assert_eq!(minted.ordinary_channel(), "mcp:files");

    // Hyphen and underscore are both canonical identity bytes. Neither the
    // producer nor connector-key canonicalization may alias one to the other.
    let hyphen = ScopedCapabilityProvenance::mint("my-server", &grant_id)
        .expect("canonical hyphenated server");
    let underscore = ScopedCapabilityProvenance::mint("my_server", &grant_id)
        .expect("canonical underscored server");
    assert_eq!(hyphen.server(), "my-server");
    assert_eq!(hyphen.connector(), format!("mcp:my-server:grant:{hex}"));
    assert_eq!(hyphen.ordinary_channel(), "mcp:my-server");
    assert_eq!(underscore.server(), "my_server");
    assert_eq!(underscore.connector(), format!("mcp:my_server:grant:{hex}"));
    assert_ne!(hyphen, underscore);
    assert_eq!(
        normalize_connector_key(hyphen.connector()),
        hyphen.connector()
    );
    assert_eq!(
        normalize_connector_key(underscore.connector()),
        underscore.connector()
    );
    let (_tmp, vault) = temp_vault();
    let hyphen_key_id = test_id(0xAD);
    let underscore_key_id = test_id(0xAE);
    vault
        .register_connector_key(
            &hyphen_key_id,
            ConnectorKeyRecord::active(hyphen.connector(), None, Vec::new(), 10),
        )
        .expect("register hyphenated capability connector");
    vault
        .register_connector_key(
            &underscore_key_id,
            ConnectorKeyRecord::active(underscore.connector(), None, Vec::new(), 10),
        )
        .expect("register underscored capability connector");
    assert_eq!(
        vault
            .connector_key_for(hyphen.connector(), None)
            .expect("lookup hyphenated connector")
            .expect("hyphenated connector key")
            .0,
        hyphen_key_id
    );
    assert_eq!(
        vault
            .connector_key_for(underscore.connector(), None)
            .expect("lookup underscored connector")
            .expect("underscored connector key")
            .0,
        underscore_key_id
    );

    // Non-canonical and unsafe segments mint NOTHING. Admission never trims or
    // case-folds a server identifier into another authority.
    for unsafe_server in [
        "My-Server",
        "MY_SERVER",
        "FILES",
        "acme:extra",
        "acme:grant:ff",
        ":",
        " acme",
        "acme ",
        "ac me",
        "ac\tme",
        "ac\u{00a0}me",
        "\u{3000}acme",
        "*",
        "ac*",
        "*me",
        "acme?",
        "acme[1]",
        "",
        "   ",
        "acme/../etc",
        "acme\u{0000}",
    ] {
        assert!(
            ScopedCapabilityProvenance::mint(unsafe_server, &grant_id).is_none(),
            "unsafe scoped server {unsafe_server:?} must not mint a capability key"
        );
        assert!(
            canonical_scoped_server_segment(unsafe_server).is_none(),
            "unsafe scoped server {unsafe_server:?} must fail the shared rule"
        );
    }

    // Persisted parts are re-derived, never trusted, and retain the exact
    // admitted server punctuation through the round trip.
    assert_eq!(
        ScopedCapabilityProvenance::from_persisted_parts(
            &grant_id,
            "my-server",
            &format!("mcp:my-server:grant:{hex}")
        )
        .expect("consistent hyphenated parts"),
        hyphen
    );
    for (server, connector) in [
        ("My-Server", format!("mcp:my-server:grant:{hex}")),
        ("my-server", format!("mcp:my_server:grant:{hex}")),
        ("files", format!("mcp:other:grant:{hex}")),
        (
            "files",
            format!("mcp:files:grant:{}", test_id(0xAC).to_hex()),
        ),
        ("files", "mcp:files:grant:ab12".to_owned()),
        ("files:x", format!("mcp:files:x:grant:{hex}")),
    ] {
        assert!(
            ScopedCapabilityProvenance::from_persisted_parts(&grant_id, server, &connector)
                .is_none(),
            "inconsistent persisted provenance {server:?}/{connector} must fail closed"
        );
    }
}

// --- ONE-1886 registration lifecycle (pre-live-transport) ---------------------

/// A custody record whose value is a distinctive fixture: no connector-key
/// path may ever surface these bytes.
const CUSTODY_VALUE_FIXTURE: &[u8] = b"custody-value-never-read-here";

fn register_test_secret(vault: &Vault, name: &str) -> Result<EntityId> {
    vault.register_secret(crate::secret_custody::SecretCustodyRecord {
        schema_version: crate::secret_custody::SECRET_CUSTODY_SCHEMA_VERSION,
        name: name.to_owned(),
        class: crate::secret_custody::CustodyClass::CustodyPortable,
        device_only: false,
        value_bytes: CUSTODY_VALUE_FIXTURE.to_vec(),
        status: crate::secret_custody::SecretCustodyStatus::Active,
        registered_at: 1,
        rotated_at: None,
        rotation_generation: 0,
        bindings: Vec::new(),
        manifest_ref: "secrets.toml".to_owned(),
        declared_paths: Vec::new(),
        policy_floor_snapshot: crate::secret_custody::SecretCustodyFloor::default(),
    })
}

fn catalog_entry(name: &str, connector: &str) -> ConnectorCatalogEntry {
    ConnectorCatalogEntry {
        name: name.to_owned(),
        connector: connector.to_owned(),
        summary: "Herald's outbound workspace".to_owned(),
        verbs: vec!["send".to_owned()],
        call_class: ConnectorCallClass::CounterpartyComm,
        // Deliberately stale: the registration door overwrites it.
        registered_at: 7,
    }
}

fn connector_key_op_reasons(vault: &Vault) -> Result<Vec<String>> {
    let receipts = vault.receipts(ReceiptQuery::new(50).with_kind(ReceiptKind::Gate))?;
    Ok(receipts
        .iter()
        .flat_map(|receipt| receipt.policy_trace.iter())
        .filter(|reason| reason.starts_with("gate.connector_key."))
        .cloned()
        .collect())
}

fn catalog_name_index_row(vault: &Vault, name: &str) -> Result<Option<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    CATALOG_NAME_INDEX.get(&vault.store, &rtxn, &name.to_owned())
}

#[test]
fn secret_ref_round_trip_additive() -> Result<()> {
    let record = ConnectorKeyRecord {
        secret_ref: Some("slack/bot_token".to_owned()),
        key_generation: 7,
        catalog: Some(ConnectorCatalogEntry {
            registered_at: 1_000,
            ..catalog_entry("herald_slack", "slack")
        }),
        status: ConnectorKeyStatus::Pending,
        ..ConnectorKeyRecord::active("slack", None, all_dimension_budgets(), 1_000)
    };
    let encoded = encode_connector_key_body(&record)?;
    assert_eq!(decode_connector_key_body(&encoded)?, record);

    // The append is POSITIONAL: positions 0-10 are byte-identical to the
    // pinned v1/v2 key set, and the three new keys sit at 11-13.
    assert_eq!(
        CONNECTOR_KEY_BODY_KEYS[..11],
        [
            "schema_version",
            "connector",
            "actor_entity_ref",
            "status",
            "budgets",
            "registered_at",
            "status_changed_at",
            "suspended_reason",
            "charter",
            "pending_charter",
            "suggested_budgets",
        ]
    );
    let mut cursor = std::io::Cursor::new(encoded);
    let value = rmpv::decode::read_value(&mut cursor).expect("decode body");
    let rmpv::Value::Map(entries) = &value else {
        panic!("connector key body must be a map");
    };
    let keys: Vec<&str> = entries
        .iter()
        .map(|(key, _)| key.as_str().expect("string key"))
        .collect();
    assert_eq!(keys, CONNECTOR_KEY_BODY_KEYS.to_vec());

    // A stored 11-key legacy body decodes at the pre-live-transport defaults
    // and is otherwise unchanged — no bulk rewrite, no re-versioning.
    let legacy = ConnectorKeyRecord::active("peer_link", None, Vec::new(), 1_000);
    let encoded = encode_connector_key_body(&legacy)?;
    let mut cursor = std::io::Cursor::new(encoded);
    let mut value = rmpv::decode::read_value(&mut cursor).expect("decode fixture");
    let rmpv::Value::Map(entries) = &mut value else {
        panic!("connector key body must be a map");
    };
    let (_, schema_version) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("schema_version"))
        .expect("schema_version key");
    *schema_version = rmpv::Value::from(2);
    entries.retain(|(key, _)| {
        !matches!(
            key.as_str(),
            Some(
                "secret_ref"
                    | "key_generation"
                    | "catalog"
                    | "slate_ref"
                    | "protocol_revision"
                    | "slate_revision"
                    | "admission_epoch"
                    | "consent_required"
                    | "retained_manifest"
                    | "pending_manifest"
            )
        )
    });
    assert_eq!(entries.len(), 11);
    let mut old_body = Vec::new();
    rmpv::encode::write_value(&mut old_body, &value).expect("encode v2 fixture");

    let decoded = decode_connector_key_body(&old_body)?;
    assert_eq!(decoded.secret_ref, None);
    assert_eq!(decoded.key_generation, 0);
    assert_eq!(decoded.catalog, None);
    assert_eq!(decoded, legacy);
    Ok(())
}

#[test]
fn registration_fails_on_unresolved_secret_ref() -> Result<()> {
    let (_tmp, vault) = temp_vault();

    // Legacy door.
    let id = test_id(0x21);
    assert!(matches!(
        vault.register_connector_key(
            &id,
            ConnectorKeyRecord {
                secret_ref: Some("missing_secret".to_owned()),
                ..ConnectorKeyRecord::active("slack", None, Vec::new(), 1_000)
            },
        ),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
    assert!(vault.get_connector_key(&id)?.is_none());
    assert!(vault.connector_key_for("slack", None)?.is_none());

    // Composed door: unresolved custody must not reserve catalog state.
    assert!(matches!(
        register_catalog(
            &vault,
            catalog_entry("herald_slack", "slack"),
            ConnectorKeySpec {
                secret_ref: Some("missing_secret".to_owned()),
                ..ConnectorKeySpec::new("slack")
            },
            1_000,
        ),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
    assert!(vault.describe_connector("herald_slack")?.is_none());
    assert!(catalog_name_index_row(&vault, "herald_slack")?.is_none());
    assert_eq!(connector_key_op_receipt_count(&vault)?, 0);

    // With the custody record live, both doors accept the same reference.
    register_test_secret(&vault, "live_secret")?;
    let registered = vault.register_connector_key(
        &id,
        ConnectorKeyRecord {
            secret_ref: Some("live_secret".to_owned()),
            ..ConnectorKeyRecord::active("slack", None, Vec::new(), 1_000)
        },
    )?;
    assert_eq!(registered.secret_ref.as_deref(), Some("live_secret"));
    let (composed_id, composed) = register_catalog(
        &vault,
        catalog_entry("herald_line", "line"),
        ConnectorKeySpec {
            secret_ref: Some("live_secret".to_owned()),
            ..ConnectorKeySpec::new("line")
        },
        1_001,
    )?;
    assert_eq!(composed.secret_ref.as_deref(), Some("live_secret"));
    assert_eq!(
        vault
            .get_connector_key(&composed_id)?
            .expect("stored composed key")
            .secret_ref
            .as_deref(),
        Some("live_secret"),
    );
    Ok(())
}

#[test]
fn replicated_existing_pending_key_cannot_activate() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (id, pending) = register_catalog(
        &vault,
        catalog_entry("peer", "peer"),
        ConnectorKeySpec::new("peer"),
        1_000,
    )?;
    let original = vault.get_connector_key(&id)?.expect("pending key");
    let forged = ConnectorKeyRecord {
        status: ConnectorKeyStatus::Active,
        slate_revision: Some(1),
        consent_required: false,
        ..pending
    };
    let data = encode_connector_key_body(&forged)?;
    assert!(
        vault
            .batch()
            .put_replicated(
                &id,
                ENTITY_TYPE_CONNECTOR_KEY,
                crate::TimeRange {
                    start: 2_000,
                    end: 2_000
                },
                2_000,
                &data
            )
            .commit()
            .is_err()
    );
    assert_eq!(vault.get_connector_key(&id)?, Some(original));
    assert!(vault.route_connector_call("peer")?.is_none());
    Ok(())
}

#[test]
fn register_connector_is_atomic() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    register_test_secret(&vault, "slack_token")?;

    // Hyphen/underscore are the same registration.
    let (id, record) = register_catalog(
        &vault,
        catalog_entry("My-Connector", "My-Connector"),
        ConnectorKeySpec {
            secret_ref: Some("slack_token".to_owned()),
            ..ConnectorKeySpec::new("my_connector")
        },
        1_000,
    )?;
    assert_eq!(record.connector, "my_connector");
    assert_eq!(record.key_generation, 0);
    assert_eq!(record.secret_ref.as_deref(), Some("slack_token"));
    let stored = vault.get_connector_key(&id)?.expect("stored key");
    assert_eq!(stored.connector, "my_connector");
    assert_eq!(stored.key_generation, 0);
    assert_eq!(stored.secret_ref.as_deref(), Some("slack_token"));
    let entry = stored.catalog.expect("catalog embedded on the key");
    assert_eq!(entry.name, "my_connector");
    assert_eq!(entry.connector, "my_connector");

    // Permanent name index + generation-0 log row, both in the same commit.
    assert_eq!(catalog_name_index_row(&vault, "my_connector")?, Some(id),);
    let generation = vault
        .connector_key_generation(&id, 0)?
        .expect("generation 0");
    assert_eq!(generation.generation, 0);
    assert_eq!(generation.secret_ref.as_deref(), Some("slack_token"));
    assert_eq!(
        connector_key_op_reasons(&vault)?,
        vec!["gate.connector_key.register".to_owned()],
    );

    // The name is taken across vault history.
    assert!(matches!(
        register_catalog(
            &vault,
            catalog_entry("my-connector", "other"),
            ConnectorKeySpec::new("other"),
            1_010,
        ),
        Err(Error::Record(RecordError::ConnectorKeyAlreadyExists))
    ));

    // Blank / NUL names fail pre-write.
    for bad in ["   ", "bad\u{0}name"] {
        assert!(matches!(
            register_catalog(
                &vault,
                catalog_entry(bad, "line"),
                ConnectorKeySpec::new("line"),
                1_011,
            ),
            Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
        ));
    }
    assert!(vault.connector_key_for("line", None)?.is_none());

    // A forced leg failure (the tuple is already governed) reserves NOTHING.
    assert!(matches!(
        register_catalog(
            &vault,
            catalog_entry("second_name", "my_connector"),
            ConnectorKeySpec::new("my_connector"),
            1_020,
        ),
        Err(Error::Record(RecordError::ConnectorKeyAlreadyExists))
    ));
    assert!(catalog_name_index_row(&vault, "second_name")?.is_none());
    assert!(vault.describe_connector("second_name")?.is_none());

    // Legacy door rejects a carried catalog before writing.
    let legacy_id = test_id(0x31);
    assert!(matches!(
        vault.register_connector_key(
            &legacy_id,
            ConnectorKeyRecord {
                catalog: Some(catalog_entry("legacy", "line")),
                ..ConnectorKeyRecord::active("line", None, Vec::new(), 1_030)
            },
        ),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
    assert!(vault.get_connector_key(&legacy_id)?.is_none());
    assert!(catalog_name_index_row(&vault, "legacy")?.is_none());

    let legacy = vault.register_connector_key(
        &legacy_id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 1_030),
    )?;
    assert!(legacy.catalog.is_none());
    assert_eq!(legacy.key_generation, 0);
    let generation = vault
        .connector_key_generation(&legacy_id, 0)?
        .expect("legacy generation 0");
    assert_eq!(generation.generation, 0);
    assert!(generation.secret_ref.is_none());
    Ok(())
}

#[test]
fn rotate_connector_key_receipted_and_value_free() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    register_test_secret(&vault, "token_v1")?;
    register_test_secret(&vault, "token_v2")?;

    let (id, _) = register_catalog(
        &vault,
        catalog_entry("herald_slack", "slack"),
        ConnectorKeySpec {
            secret_ref: Some("token_v1".to_owned()),
            ..ConnectorKeySpec::new("slack")
        },
        1_000,
    )?;
    assert_eq!(
        vault
            .connector_key_generation(&id, 0)?
            .expect("generation 0 is point-readable at registration")
            .secret_ref
            .as_deref(),
        Some("token_v1"),
    );

    let rotated = vault.rotate_connector_key(&id, "token_v2", 2_000)?;
    assert_eq!(rotated.secret_ref.as_deref(), Some("token_v2"));
    assert_eq!(rotated.key_generation, 1);
    let stored = vault.get_connector_key(&id)?.expect("stored key");
    assert_eq!(stored.secret_ref.as_deref(), Some("token_v2"));
    assert_eq!(stored.key_generation, 1);
    let generation = vault
        .connector_key_generation(&id, 1)?
        .expect("generation 1");
    assert_eq!(generation.generation, 1);
    assert_eq!(generation.secret_ref.as_deref(), Some("token_v2"));
    assert_eq!(
        connector_key_op_reasons(&vault)?
            .iter()
            .filter(|reason| *reason == "gate.connector_key.rotate")
            .count(),
        1,
    );

    // Value-free: no rotation surface carries the custody value bytes.
    let leaked = format!("{rotated:?}");
    assert!(!leaked.contains(std::str::from_utf8(CUSTODY_VALUE_FIXTURE).expect("utf8 fixture")));

    // An unresolved reference is a ruled error and writes nothing.
    assert!(matches!(
        vault.rotate_connector_key(&id, "ghost_token", 3_000),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
    let stored = vault.get_connector_key(&id)?.expect("stored key");
    assert_eq!(stored.secret_ref.as_deref(), Some("token_v2"));
    assert_eq!(stored.key_generation, 1);
    assert!(vault.connector_key_generation(&id, 2)?.is_none());
    assert_eq!(
        connector_key_op_reasons(&vault)?
            .iter()
            .filter(|reason| *reason == "gate.connector_key.rotate")
            .count(),
        1,
    );

    // A pre-log record backfills its current generation on first rotation.
    let legacy_id = test_id(0x41);
    vault.register_connector_key(
        &legacy_id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 1_500),
    )?;
    {
        let mut wtxn = vault.store.env.write_txn()?;
        GENERATION_LOG.delete(&vault.store, &mut wtxn, &(legacy_id, 0_u32.to_be_bytes()))?;
        wtxn.commit()?;
    }
    assert!(
        vault.connector_key_generation(&legacy_id, 0)?.is_none(),
        "fixture: the record now looks pre-log"
    );

    let rotated_legacy = vault.rotate_connector_key(&legacy_id, "token_v2", 2_500)?;
    assert_eq!(rotated_legacy.key_generation, 1);
    let generation = vault
        .connector_key_generation(&legacy_id, 0)?
        .expect("generation 0 backfilled");
    assert_eq!(generation.generation, 0);
    assert!(generation.secret_ref.is_none());
    assert_eq!(
        vault
            .connector_key_generation(&legacy_id, 1)?
            .expect("generation 1")
            .secret_ref
            .as_deref(),
        Some("token_v2"),
    );

    // A terminal key does not rotate.
    vault.revoke_connector_key(&legacy_id, 3_500)?;
    assert!(matches!(
        vault.rotate_connector_key(&legacy_id, "token_v1", 3_600),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));
    let stored = vault.get_connector_key(&legacy_id)?.expect("revoked key");
    assert_eq!(stored.status, ConnectorKeyStatus::Revoked);
    assert_eq!(stored.key_generation, 1);
    assert_eq!(stored.secret_ref.as_deref(), Some("token_v2"));
    assert!(vault.connector_key_generation(&legacy_id, 2)?.is_none());
    Ok(())
}

#[test]
fn remove_connector_key_is_revoke_plus_permanent_catalog_history() -> Result<()> {
    let (_tmp, vault) = temp_vault();
    let (id, _) = register_catalog(
        &vault,
        catalog_entry("herald_slack", "slack"),
        ConnectorKeySpec::new("slack"),
        1_000,
    )?;

    let removed = vault.remove_connector_key(&id, 2_000)?;
    assert_eq!(removed.status, ConnectorKeyStatus::Revoked);

    let ops = connector_key_op_reasons(&vault)?;
    assert_eq!(
        ops.iter()
            .filter(|reason| *reason == "gate.connector_key.remove")
            .count(),
        1,
        "removal appends exactly one remove record"
    );
    assert!(
        !ops.iter()
            .any(|reason| reason == "gate.connector_key.revoke"),
        "removal is its own op, never a revoke"
    );

    // The name-index row survives: the catalog keeps HISTORY.
    assert_eq!(catalog_name_index_row(&vault, "herald_slack")?, Some(id),);
    assert!(
        vault.search_connector_catalog("herald")?.is_empty(),
        "the discovery lens is live-only"
    );
    assert!(vault.route_connector_call("herald_slack")?.is_none());
    let described = vault
        .describe_connector("herald_slack")?
        .expect("the history lens resolves a removed connector");
    assert_eq!(described.status, ConnectorKeyStatus::Revoked);
    assert_eq!(described.key_ref, id);

    // The name can never be recycled onto a different connector.
    assert!(matches!(
        register_catalog(
            &vault,
            catalog_entry("herald_slack", "line"),
            ConnectorKeySpec::new("line"),
            3_000,
        ),
        Err(Error::Record(RecordError::ConnectorKeyAlreadyExists))
    ));

    // Removing an already-terminal key inherits the illegal-transition error.
    assert!(matches!(
        vault.remove_connector_key(&id, 4_000),
        Err(Error::Record(RecordError::InvalidConnectorKeyBody(_)))
    ));

    // The public revoke path still appends its own revoke record.
    let other = test_id(0x51);
    vault.register_connector_key(
        &other,
        ConnectorKeyRecord::active("email", None, Vec::new(), 1_000),
    )?;
    vault.revoke_connector_key(&other, 5_000)?;
    let ops = connector_key_op_reasons(&vault)?;
    assert_eq!(
        ops.iter()
            .filter(|reason| *reason == "gate.connector_key.revoke")
            .count(),
        1,
    );
    Ok(())
}

#[test]
fn budget_rider_send_is_counterparty_only() -> Result<()> {
    // ARCH-0054: the Send class is counterparty communications ONLY.
    assert!(ConnectorCallClass::CounterpartyComm.debits_sends());
    assert!(!ConnectorCallClass::ReadOnly.debits_sends());
    assert!(!ConnectorCallClass::ScopedMcp.debits_sends());
    for class in [
        ConnectorCallClass::CounterpartyComm,
        ConnectorCallClass::ReadOnly,
        ConnectorCallClass::ScopedMcp,
    ] {
        assert_eq!(ConnectorCallClass::parse(class.as_str()), Some(class));
    }
    assert!(ConnectorCallClass::parse("send").is_none());

    let (_tmp, vault) = temp_vault();
    // A mixed-verb counterparty connector budgets its read-only verbs as
    // sends too: the classification is entry-wide, and over-budgeting is the
    // safe direction.
    register_catalog(
        &vault,
        ConnectorCatalogEntry {
            verbs: vec!["send".to_owned(), "search".to_owned()],
            ..catalog_entry("herald_slack", "slack")
        },
        ConnectorKeySpec::new("slack"),
        1_000,
    )?;
    let described = vault.describe_connector("herald_slack")?.expect("history");
    assert!(described.budgeted_as_sends);
    assert_eq!(
        described.entry.verbs.len(),
        2,
        "no verb narrows the classification"
    );
    assert!(vault.route_connector_call("herald_slack")?.is_none());

    // A scoped-MCP connector stays unbudgeted for Sends.
    register_catalog(
        &vault,
        ConnectorCatalogEntry {
            call_class: ConnectorCallClass::ScopedMcp,
            ..catalog_entry("mcp_tools", "mcp")
        },
        ConnectorKeySpec::new("mcp"),
        1_001,
    )?;
    assert!(
        !vault
            .describe_connector("mcp_tools")?
            .expect("history")
            .budgeted_as_sends
    );
    assert!(vault.route_connector_call("mcp_tools")?.is_none());

    // UNCLASSIFIED is unbudgeted: a catalog-free key has no route, so the
    // executor keeps the canon default. This says nothing about the
    // production scoped-MCP path, which is still wired to the existing
    // charger — that rewire is a named follow-on.
    let legacy_id = test_id(0x61);
    vault.register_connector_key(
        &legacy_id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 1_002),
    )?;
    assert!(
        vault
            .get_connector_key(&legacy_id)?
            .expect("stored key")
            .catalog
            .is_none()
    );
    assert!(vault.route_connector_call("line")?.is_none());
    Ok(())
}

#[test]
fn manifest_stage_retains_prior_and_revision_halts_until_owner() -> Result<()> {
    use serde_json::json;
    use std::collections::BTreeSet;
    struct Suite;
    impl ConnectorManifestQualifier for Suite {
        fn qualify(&self, manifest: &ResolvedConnectorManifest, revision: &str) -> Result<String> {
            assert_eq!(manifest.tools().len(), 1);
            assert!(!revision.is_empty());
            Ok("a".repeat(64))
        }
    }
    let (_tmp, vault) = temp_vault();
    let id = test_id(0xB9);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("mcp", None, Vec::new(), 100),
    )?;
    let source = || {
        ResolvedConnectorManifest::resolve(vec![ConnectorToolSchema {
        name: "read".into(), permissions: ["read".into()].into(),
        triggers: BTreeSet::new(), input_schema: json!({"type":"object","properties":{"limit":{"type":"integer","default":10}}}),
    }]).unwrap()
    };
    let first = vault
        .stage_connector_manifest(&id, source(), "2026-07-28", &Suite, 101)?
        .unwrap();
    assert!(first.kinds.contains(&ConnectorDriftKind::Permission));
    assert!(vault.connector_tool_requires_confirmation(&id, "read")?);
    let initial = vault.get_connector_key(&id)?.unwrap();
    assert_eq!(initial.status, ConnectorKeyStatus::Pending);
    assert!(initial.retained_manifest.is_none());
    assert!(initial.pending_manifest.is_some());
    let candidate_id = initial.pending_manifest.as_ref().unwrap().candidate_id;
    let mut staged = initial;
    staged.retained_manifest = Some(source());
    assert!(staged.validate().is_err());
    let owner = test_id(0xB8);
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let auth = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::from_bytes(*test_id(0xBA).as_bytes()),
    )?;
    assert!(
        vault
            .approve_connector_manifest(
                &auth,
                &id,
                candidate_id,
                source().hash()?,
                &"f".repeat(64),
                102
            )
            .is_err()
    );
    assert!(
        vault
            .approve_connector_manifest(&auth, &id, candidate_id, [0; 32], &"a".repeat(64), 102)
            .is_err()
    );
    let approved = vault.approve_connector_manifest(
        &auth,
        &id,
        candidate_id,
        source().hash()?,
        &"a".repeat(64),
        102,
    )?;
    assert_eq!(approved.status, ConnectorKeyStatus::Active);
    assert_eq!(vault.get_connector_key(&id)?, Some(approved));
    assert!(!vault.connector_tool_requires_confirmation(&id, "read")?);
    let revision = vault
        .stage_connector_manifest(&id, source(), "2026-09-01", &Suite, 102)?
        .unwrap();
    assert!(revision.requires_reregistration);
    let pending = vault.get_connector_key(&id)?.unwrap();
    assert_eq!(pending.status, ConnectorKeyStatus::Pending);
    assert_eq!(pending.protocol_revision.as_deref(), Some("2026-07-28"));
    assert_eq!(pending.retained_manifest.as_ref(), Some(&source()));
    assert!(vault.connector_tool_requires_confirmation(&id, "read")?);
    assert!(vault.resume_connector_key(&id, 103).is_err());
    let mut changed = source().tools()[0].clone();
    changed.input_schema["properties"]["limit"]["default"] = json!(20);
    let new_manifest = ResolvedConnectorManifest::resolve(vec![changed])?;
    assert!(
        vault
            .stage_connector_manifest(&id, new_manifest.clone(), "2026-07-28", &Suite, 104)
            .is_err()
    );
    let change = vault
        .stage_connector_manifest(&id, new_manifest, "2026-09-01", &Suite, 104)?
        .unwrap();
    assert!(change.kinds.contains(&ConnectorDriftKind::ParameterDefault));
    assert!(change.requires_reregistration);
    Ok(())
}

fn drift_fixture_manifest(permission: &str, schema_bytes: usize) -> ResolvedConnectorManifest {
    use serde_json::json;
    ResolvedConnectorManifest::resolve(vec![ConnectorToolSchema {
        name: "send".into(), permissions: [permission.into()].into(),
        triggers: ["manual".into()].into(),
        input_schema: json!({"type":"object", "properties":{"value":{"type":"string", "description":"x".repeat(schema_bytes)}}}),
    }]).unwrap()
}

#[test]
fn failed_suite_retains_hold_revert_clears_candidate_and_revision_is_exact() -> Result<()> {
    struct Suite(bool);
    impl ConnectorManifestQualifier for Suite {
        fn qualify(&self, _: &ResolvedConnectorManifest, _: &str) -> Result<String> {
            if self.0 {
                Ok("a".repeat(64))
            } else {
                Err(Error::InvalidConfig("qualification failed".into()))
            }
        }
    }
    let (_dir, vault) = temp_vault();
    let id = test_id(0xC0);
    vault.register_connector_key(
        &id,
        ConnectorKeyRecord::active("line", None, Vec::new(), 10),
    )?;
    let a = drift_fixture_manifest("read", 1);
    let b = drift_fixture_manifest("write", 1);
    vault.stage_connector_manifest(&id, a.clone(), "R1", &Suite(true), 11)?;
    let owner = test_id(0xC1);
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let auth = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::from_bytes(*test_id(0xC2).as_bytes()),
    )?;
    let pending = vault
        .get_connector_key(&id)?
        .unwrap()
        .pending_manifest
        .unwrap();
    vault.approve_connector_manifest(
        &auth,
        &id,
        pending.candidate_id,
        a.hash()?,
        &"a".repeat(64),
        12,
    )?;
    assert!(
        vault
            .stage_connector_manifest(&id, b.clone(), "R1", &Suite(false), 13)
            .is_err()
    );
    let failed = vault.get_connector_key(&id)?.unwrap();
    assert_eq!(failed.retained_manifest.as_ref(), Some(&a));
    assert!(
        failed
            .pending_manifest
            .as_ref()
            .unwrap()
            .qualification_report_hash
            .is_none()
    );
    assert!(failed.tool_requires_confirmation("send"));
    let failed_id = failed.pending_manifest.unwrap().candidate_id;
    assert!(
        vault
            .approve_connector_manifest(&auth, &id, failed_id, b.hash()?, &"a".repeat(64), 14)
            .is_err()
    );
    vault.stage_connector_manifest(&id, b.clone(), "R1", &Suite(true), 15)?;
    let b_id = vault
        .get_connector_key(&id)?
        .unwrap()
        .pending_manifest
        .unwrap()
        .candidate_id;
    assert_eq!(
        vault.stage_connector_manifest(&id, a.clone(), "R1", &Suite(true), 16)?,
        None
    );
    let reverted = vault.get_connector_key(&id)?.unwrap();
    assert!(reverted.pending_manifest.is_none());
    assert!(!reverted.tool_requires_confirmation("send"));
    assert!(
        vault
            .approve_connector_manifest(&auth, &id, b_id, b.hash()?, &"a".repeat(64), 17)
            .is_err()
    );
    vault.stage_connector_manifest(&id, a.clone(), "R2", &Suite(true), 18)?;
    let r2 = vault
        .get_connector_key(&id)?
        .unwrap()
        .pending_manifest
        .unwrap()
        .candidate_id;
    vault.stage_connector_manifest(&id, a.clone(), "R3", &Suite(true), 19)?;
    let r3_record = vault.get_connector_key(&id)?.unwrap();
    let r3 = r3_record.pending_manifest.as_ref().unwrap().candidate_id;
    assert_ne!(r2, r3);
    assert_eq!(r3_record.status, ConnectorKeyStatus::Pending);
    assert!(
        vault
            .approve_connector_manifest(&auth, &id, r2, a.hash()?, &"a".repeat(64), 20)
            .is_err()
    );
    let approved =
        vault.approve_connector_manifest(&auth, &id, r3, a.hash()?, &"a".repeat(64), 20)?;
    assert_eq!(approved.protocol_revision.as_deref(), Some("R3"));
    assert_eq!(approved.status, ConnectorKeyStatus::Active);
    assert!(
        vault
            .stage_connector_manifest(&id, a, "R4", &Suite(false), 21)
            .is_err()
    );
    let failed_revision = vault.get_connector_key(&id)?.unwrap();
    assert_eq!(failed_revision.status, ConnectorKeyStatus::Pending);
    assert_eq!(failed_revision.protocol_revision.as_deref(), Some("R3"));
    assert!(
        failed_revision
            .pending_manifest
            .unwrap()
            .qualification_report_hash
            .is_none()
    );
    Ok(())
}

#[test]
fn catalog_key_manifest_stays_on_its_pinned_revision() -> Result<()> {
    struct Suite;
    impl ConnectorManifestQualifier for Suite {
        fn qualify(&self, _: &ResolvedConnectorManifest, _: &str) -> Result<String> {
            Ok("a".repeat(64))
        }
    }
    let (_dir, vault) = temp_vault();
    let (id, _) = register_catalog(
        &vault,
        catalog_entry("herald", "herald"),
        ConnectorKeySpec::new("herald"),
        1_000,
    )?;
    let registered = vault.get_connector_key(&id)?.expect("pending key");
    // A catalog revision change re-binds the owner slate through
    // `revise_connector_protocol`, never through manifest staging.
    assert!(
        vault
            .stage_connector_manifest(&id, drift_fixture_manifest("read", 0), "R2", &Suite, 1_001)
            .is_err()
    );
    assert_eq!(vault.get_connector_key(&id)?, Some(registered));
    vault.stage_connector_manifest(
        &id,
        drift_fixture_manifest("read", 0),
        "2026-09-01",
        &Suite,
        1_002,
    )?;
    let staged = vault.get_connector_key(&id)?.expect("staged key");
    assert_eq!(staged.status, ConnectorKeyStatus::Pending);
    assert_eq!(staged.protocol_revision.as_deref(), Some("2026-09-01"));
    assert!(staged.retained_manifest.is_none());
    assert!(staged.pending_manifest.is_some());
    Ok(())
}

#[test]
fn strict_permission_narrow_and_tool_removal_qualify_without_reconsent() -> Result<()> {
    use std::cell::Cell;
    struct Suite(Cell<usize>);
    impl ConnectorManifestQualifier for Suite {
        fn qualify(&self, _: &ResolvedConnectorManifest, _: &str) -> Result<String> {
            self.0.set(self.0.get() + 1);
            Ok("a".repeat(64))
        }
    }
    let (_dir, vault) = temp_vault();
    let id = test_id(0xC3);
    let suite = Suite(Cell::new(0));
    vault.register_connector_key(&id, ConnectorKeyRecord::active("line", None, vec![], 10))?;
    let tool = |name: &str, permissions: &[&str]| ConnectorToolSchema {
        name: name.into(),
        permissions: permissions
            .iter()
            .map(|permission| (*permission).to_owned())
            .collect(),
        triggers: Default::default(),
        input_schema: serde_json::json!({"properties":{}}),
    };
    let full = ResolvedConnectorManifest::resolve(vec![
        tool("send", &["read", "write"]),
        tool("other", &["read"]),
    ])?;
    vault.stage_connector_manifest(&id, full.clone(), "R1", &suite, 11)?;
    let owner = test_id(0xC4);
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let auth = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::from_bytes(*test_id(0xC5).as_bytes()),
    )?;
    let pending = vault
        .get_connector_key(&id)?
        .unwrap()
        .pending_manifest
        .unwrap();
    vault.approve_connector_manifest(
        &auth,
        &id,
        pending.candidate_id,
        full.hash()?,
        &"a".repeat(64),
        12,
    )?;
    let narrowed = ResolvedConnectorManifest::resolve(vec![
        tool("send", &["read"]),
        tool("other", &["read"]),
    ])?;
    let change = vault
        .stage_connector_manifest(&id, narrowed.clone(), "R1", &suite, 13)?
        .unwrap();
    assert!(change.kinds.contains(&ConnectorDriftKind::Permission));
    assert!(!change.needs_reconsent());
    assert!(change.reconsent_tools.is_empty());
    let record = vault.get_connector_key(&id)?.unwrap();
    assert_eq!(record.retained_manifest.as_ref(), Some(&narrowed));
    assert!(record.pending_manifest.is_none());
    assert!(!record.tool_requires_confirmation("send"));
    let removed = ResolvedConnectorManifest::resolve(vec![tool("send", &["read"])])?;
    let change = vault
        .stage_connector_manifest(&id, removed.clone(), "R1", &suite, 14)?
        .unwrap();
    assert!(!change.needs_reconsent());
    assert_eq!(
        vault.get_connector_key(&id)?.unwrap().retained_manifest,
        Some(removed.clone())
    );
    assert!(vault.connector_tool_requires_confirmation(&id, "other")?);
    let expansion = vault
        .stage_connector_manifest(&id, full, "R1", &suite, 15)?
        .unwrap();
    assert!(expansion.needs_reconsent());
    assert!(expansion.reconsent_tools.contains("send"));
    assert!(expansion.reconsent_tools.contains("other"));
    assert_eq!(
        vault.get_connector_key(&id)?.unwrap().retained_manifest,
        Some(removed)
    );
    assert_eq!(suite.0.get(), 4);
    Ok(())
}

#[test]
fn failed_or_malformed_revision_revert_keeps_the_qualified_hold() -> Result<()> {
    use std::cell::Cell;
    struct Suite<'a> {
        calls: &'a Cell<usize>,
        result: Option<&'a str>,
    }
    impl ConnectorManifestQualifier for Suite<'_> {
        fn qualify(&self, _: &ResolvedConnectorManifest, _: &str) -> Result<String> {
            self.calls.set(self.calls.get() + 1);
            self.result
                .map(str::to_owned)
                .ok_or_else(|| Error::InvalidConfig("probe failed".into()))
        }
    }
    let calls = Cell::new(0);
    let (_dir, vault) = temp_vault();
    let id = test_id(0xC6);
    let manifest = drift_fixture_manifest("read", 0);
    vault.register_connector_key(&id, ConnectorKeyRecord::active("line", None, vec![], 10))?;
    vault.stage_connector_manifest(
        &id,
        manifest.clone(),
        "R1",
        &Suite {
            calls: &calls,
            result: Some(&"a".repeat(64)),
        },
        11,
    )?;
    let owner = test_id(0xC7);
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        crate::TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let auth = vault.authenticate_owner(
        owner,
        &owner.to_hex(),
        true,
        crate::store::GateDecisionId::from_bytes(*test_id(0xC8).as_bytes()),
    )?;
    let initial = vault
        .get_connector_key(&id)?
        .unwrap()
        .pending_manifest
        .unwrap();
    vault.approve_connector_manifest(
        &auth,
        &id,
        initial.candidate_id,
        manifest.hash()?,
        &"a".repeat(64),
        12,
    )?;
    assert!(
        vault
            .stage_connector_manifest(
                &id,
                manifest.clone(),
                "R2",
                &Suite {
                    calls: &calls,
                    result: None
                },
                13
            )
            .is_err()
    );
    let held = vault.get_connector_key(&id)?.unwrap();
    let candidate = held.pending_manifest.as_ref().unwrap().candidate_id;
    assert_eq!(held.status, ConnectorKeyStatus::Pending);
    assert!(
        vault
            .stage_connector_manifest(
                &id,
                manifest.clone(),
                "R1",
                &Suite {
                    calls: &calls,
                    result: None
                },
                14
            )
            .is_err()
    );
    assert!(
        vault
            .stage_connector_manifest(
                &id,
                manifest.clone(),
                "R1",
                &Suite {
                    calls: &calls,
                    result: Some("bad")
                },
                15
            )
            .is_err()
    );
    let still_held = vault.get_connector_key(&id)?.unwrap();
    assert_eq!(still_held.status, ConnectorKeyStatus::Pending);
    assert_eq!(
        still_held.pending_manifest.as_ref().unwrap().candidate_id,
        candidate
    );
    assert!(vault.connector_tool_requires_confirmation(&id, "send")?);
    assert!(
        vault
            .approve_connector_manifest(
                &auth,
                &id,
                candidate,
                manifest.hash()?,
                &"a".repeat(64),
                16
            )
            .is_err()
    );
    assert_eq!(calls.get(), 4);
    assert_eq!(
        vault.stage_connector_manifest(
            &id,
            manifest,
            "R1",
            &Suite {
                calls: &calls,
                result: Some(&"a".repeat(64))
            },
            17
        )?,
        None
    );
    let recovered = vault.get_connector_key(&id)?.unwrap();
    assert_eq!(recovered.status, ConnectorKeyStatus::Active);
    assert!(recovered.pending_manifest.is_none());
    assert_eq!(calls.get(), 5);
    Ok(())
}

#[test]
fn connector_admission_quota_policy_vault_and_holder_rows_narrow_without_poisoning_old_keys()
-> Result<()> {
    use rmpv::Value;
    struct Suite;
    impl ConnectorManifestQualifier for Suite {
        fn qualify(&self, _: &ResolvedConnectorManifest, _: &str) -> Result<String> {
            Ok("a".repeat(64))
        }
    }
    let (_dir, vault) = temp_vault();
    let holder = test_id(0xC9);
    let mut cursor = std::io::Cursor::new(crate::gate::default_policy_manifest().unwrap());
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).unwrap() else {
        panic!("policy map")
    };
    entries.retain(|(key, _)| key.as_str() != Some("connector_admission"));
    let quotas = |scope: &str, max_tools: u64, holder: Option<EntityId>| {
        let mut fields = vec![
            (Value::from("scope"), Value::from(scope)),
            (Value::from("max_tools"), Value::from(max_tools)),
            (Value::from("max_permissions_per_tool"), Value::from(10)),
            (Value::from("max_triggers_per_tool"), Value::from(10)),
        ];
        if let Some(holder) = holder {
            fields.push((Value::from("holder_ref"), Value::from(holder.to_hex())));
        }
        Value::Map(fields)
    };
    entries.push((
        Value::from("connector_admission"),
        Value::Array(vec![
            Value::Map(vec![
                (Value::from("scope"), Value::from("precedence")),
                (
                    Value::from("mode"),
                    Value::from("nested_narrow_holder_override_vault_cap"),
                ),
            ]),
            quotas("vault", 300, None),
            quotas("holder", 2, Some(holder)),
        ]),
    ));
    let mut raw = Vec::new();
    rmpv::encode::write_value(&mut raw, &Value::Map(entries)).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &raw,
    )?;
    let tools = |count: usize| -> ResolvedConnectorManifest {
        ResolvedConnectorManifest::resolve(
            (0..count)
                .map(|n| ConnectorToolSchema {
                    name: format!("tool_{n:03}"),
                    permissions: ["read".to_owned()].into(),
                    triggers: Default::default(),
                    input_schema: serde_json::json!({"properties":{}}),
                })
                .collect(),
        )
        .unwrap()
    };
    let general = test_id(0xCA);
    vault.register_connector_key(
        &general,
        ConnectorKeyRecord::active("general", None, vec![], 10),
    )?;
    vault.stage_connector_manifest(&general, tools(257), "R1", &Suite, 11)?;
    assert_eq!(
        vault
            .get_connector_key(&general)?
            .unwrap()
            .pending_manifest
            .as_ref()
            .unwrap()
            .manifest
            .tools()
            .len(),
        257
    );
    assert!(
        vault
            .stage_connector_manifest(&general, tools(301), "R1", &Suite, 12)
            .is_err()
    );
    let bounded = test_id(0xCB);
    vault.register_connector_key(
        &bounded,
        ConnectorKeyRecord::active("bounded", Some(holder), vec![], 10),
    )?;
    assert!(
        vault
            .stage_connector_manifest(&bounded, tools(3), "R1", &Suite, 13)
            .is_err()
    );
    vault.stage_connector_manifest(&bounded, tools(2), "R1", &Suite, 14)?;
    assert_eq!(
        vault
            .get_connector_key(&bounded)?
            .unwrap()
            .pending_manifest
            .unwrap()
            .manifest
            .tools()
            .len(),
        2
    );
    // A later policy decrease refuses NEW admissions, but the already stored
    // 257-tool candidate stays decodable and available for its owner decision.
    let mut reduced: Value = rmpv::decode::read_value(&mut raw.as_slice()).unwrap();
    let Value::Map(ref mut reduced_entries) = reduced else {
        panic!("policy map")
    };
    let (_, admission) = reduced_entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("connector_admission"))
        .unwrap();
    let Value::Array(rows) = admission else {
        panic!("quota rows")
    };
    let Value::Map(vault_row) = &mut rows[1] else {
        panic!("vault row")
    };
    let (_, limit) = vault_row
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("max_tools"))
        .unwrap();
    *limit = Value::from(100);
    let mut reduced_bytes = Vec::new();
    rmpv::encode::write_value(&mut reduced_bytes, &reduced).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &reduced_bytes,
    )?;
    assert!(
        vault
            .stage_connector_manifest(&general, tools(101), "R1", &Suite, 15)
            .is_err()
    );
    assert_eq!(
        vault
            .get_connector_key(&general)?
            .unwrap()
            .pending_manifest
            .unwrap()
            .manifest
            .tools()
            .len(),
        257
    );
    Ok(())
}
