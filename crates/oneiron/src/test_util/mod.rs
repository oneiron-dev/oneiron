//! Shared test helpers. Centralized to avoid drift between per-module
//! copies of `open_test_vault`, seed-id, policy-manifest, and config
//! fixtures.
//!
//! Config carve-out: [`embedding_test_config`] is the canonical
//! embedding-enabled config. A module keeps a LOCAL `test_config()` only
//! when its values genuinely diverge (map size, dimensions, embedding
//! model, HNSW params); a copy that is value-identical to the shared
//! helper is a drift hazard and must route through it.

pub(crate) mod row_dump;
/// Test-only-file classification for the source-scanning fences. The
/// integration binaries mount the same file through `tests/common`.
pub(crate) mod source_scan;

mod channel_identity;
pub(crate) use channel_identity::self_held_identity_in_state;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::error::{Error, GateError};
use crate::registry::ENTITY_TYPE_POLICY_MANIFEST;
use crate::store::Store;
use crate::temporal::TimeRange;
use crate::vault::Vault;

/// Id bytes pinned by production code. `entity` refuses them so a generic
/// fixture can never alias a system identity. Any byte NOT listed here is
/// safe for test seeds. A new production id pin must be added to this list
/// in the same change that mints it.
///
/// - `0x00`, `0xFF`: reserved sentinels (`entity_id::is_reserved_entity_id_bytes`)
/// - `0x11`: dreamer consolidation probe actor
/// - `0x42`: code-run replay canonical request actor
/// - `0x47`: gate local-write actor ref
/// - `0xA1..=0xA6`: seeded system-agent row/actor ids (canonical manifest).
///   ONE-1709's `sys.team_lead` row is deliberately NOT a repeated byte
///   (`aaaa…aaaa1709`): every free byte in the roster's `0xA*` range was
///   already in `[seed; 16]` fixture use, and a non-repeating id is
///   unreachable from that whole class of seed.
/// - `0xD7`: default policy manifest id
/// - `0xE1`: first-party connector actor id
pub(crate) const PINNED_ID_BYTES: [u8; 13] = [
    0x00, 0x11, 0x42, 0x47, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xD7, 0xE1, 0xFF,
];

/// Canonical test entity id: `[seed; 16]`.
///
/// Panics when `seed` is production-pinned (see [`PINNED_ID_BYTES`]) —
/// including `entity(0)`, whose bytes are the reserved zero sentinel.
/// Tests that *intend* a pinned identity must construct it explicitly
/// (a seeded roster row id resolved through
/// `Vault::get_seeded_agent_definition_by_logical_id`,
/// `crate::gate::default_policy_manifest_id()`, or
/// `EntityId::from_bytes` with an intent comment), never through this
/// helper.
pub(crate) fn entity(seed: u8) -> EntityId {
    assert!(
        !PINNED_ID_BYTES.contains(&seed),
        "test seed {seed:#04x} collides with a production-pinned id byte; \
         pick a byte outside PINNED_ID_BYTES or construct the pinned id explicitly"
    );
    EntityId::from_bytes([seed; 16]).expect("non-pinned seed byte forms a valid entity id")
}

/// Seeds a minimal, VALID AGENT_DEF entity at `id` and returns it.
///
/// Centralized because an AGENT_DEF body is validated on write: the
/// obvious `put_entity(id, ENTITY_TYPE_AGENT_DEF, b"fixture")` is rejected
/// with `InvalidAgentDefBody`, so every test needing "an actor that is a
/// real agent" would otherwise grow its own copy of this constructor.
pub(crate) fn seed_agent_definition(vault: &Vault, id: EntityId, label: &str) -> EntityId {
    use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
    use rmpv::Value;

    let def = AgentDefinition::new(
        format!("{label}-{}", id.to_hex()),
        "test_util agent fixture",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        Value::Map(vec![(Value::from("fixture"), Value::from(label))]),
        None,
        true,
        None,
    );
    vault
        .put_agent_definition(
            &id,
            &def,
            TimeRange {
                start: 100,
                end: 100,
            },
            100,
        )
        .expect("seed agent definition");
    id
}

/// Raw stored-entity record: the 25-byte metadata header (type byte,
/// occurred start/end, learned_at — all big-endian u64s, per the
/// `batch::ENTITY_*_OFFSET` layout) followed by `body`.
pub(crate) fn entity_record(
    entity_type: u8,
    occurred: TimeRange,
    learned_at: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    out.push(entity_type);
    out.extend_from_slice(&occurred.start.to_be_bytes());
    out.extend_from_slice(&occurred.end.to_be_bytes());
    out.extend_from_slice(&learned_at.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Stores `data` as a policy-manifest entity at `id` via a raw store put
/// (occurred `1..1`, learned_at `1`), bypassing the batch write path.
/// Seeding the *default* manifest slot must pass
/// `crate::gate::default_policy_manifest_id()` so the intent is explicit.
/// The `graph_fs` test copy deliberately stays local: it exercises the
/// real `apply_ops` write path instead of a raw put.
pub(crate) fn put_policy_manifest_bytes(
    vault: &Vault,
    id: EntityId,
    data: &[u8],
) -> crate::Result<()> {
    let payload = entity_record(
        ENTITY_TYPE_POLICY_MANIFEST,
        TimeRange { start: 1, end: 1 },
        1,
        data,
    );
    vault.with_write_txn(|wtxn| {
        // This fixture represents local authoring, not replay. Preserve that
        // origin even though it bypasses batch to isolate the tested gate.
        crate::gate::stamp_manifest_origin(&vault.store, wtxn, &id, data, false)?;
        vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
        let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
        vault.store.type_index.put(wtxn, &type_key, &[])?;
        Ok(())
    })
}

/// Pin a test model manifest with a passing teacher-probe receipt, the way
/// the bench publishes one; a bare `set_model_manifest` refuses a new teacher.
pub(crate) fn pin_model_manifest(
    vault: &crate::Vault,
    manifest: &crate::llm::manifest::ModelManifest,
) -> crate::Result<()> {
    let policy = vault.teacher_probe_policy(None)?;
    let approval = crate::llm::manifest::TeacherProbeApproval::for_scored_checkpoint(
        manifest, &policy, 1_000_000,
    )?;
    vault.set_model_manifest_with_teacher_approval(manifest, &approval)
}

/// Re-appends every live claim-bound gate decision as if created at
/// `created_at`, so a test can age real receipts past a retention horizon.
pub(crate) fn backdate_claim_gate_decisions(vault: &Vault, created_at: u64) -> crate::Result<()> {
    vault.with_write_txn(|txn| {
        let mut rows = Vec::new();
        vault.store.for_each_gate_decision_in_txn(txn, |record| {
            if record.claim_id.is_some() && record.redacted_at.is_none() {
                rows.push(record);
            }
            Ok(())
        })?;
        for mut row in rows {
            vault
                .store
                .delete_gate_decision_in_txn(txn, row.decision_id)?;
            row.created_at = created_at;
            vault.store.append_gate_decision_in_txn(txn, &row)?;
        }
        Ok(())
    })
}

/// Copy the shipped teacher-probe policy row into a custom test policy. Tests
/// that replace the seeded default must preserve this floor before pinning a
/// teacher, without accidentally replacing their own Gate policy rows.
pub(crate) fn add_default_teacher_probe_policy(entries: &mut Vec<(rmpv::Value, rmpv::Value)>) {
    let default = crate::gate::default_policy_manifest().unwrap();
    let rmpv::Value::Map(default_entries) =
        rmpv::decode::read_value(&mut default.as_slice()).expect("seeded policy map")
    else {
        panic!("seeded policy map");
    };
    entries.push(
        default_entries
            .into_iter()
            .find(|(key, _)| key.as_str() == Some("teacher_probe"))
            .expect("seeded teacher probe row"),
    );
}

/// Installs the shipped default policy manifest carrying one unrestricted
/// schema-1.2 `core:read` grant per reader. A plain scoped-read key reads
/// nothing until a trusted manifest grants it.
pub(crate) fn authorize_readers(vault: &Vault, readers: &[&str]) {
    let authority = crate::federation::scope_codec::encode_scope_value(
        &crate::federation::scope_codec::read_preset(),
    )
    .expect("read preset encodes");
    let grants: Vec<rmpv::Value> = readers
        .iter()
        .map(|reader| {
            rmpv::Value::Map(vec![
                (rmpv::Value::from("actor_ref"), rmpv::Value::from(*reader)),
                (
                    rmpv::Value::from("effector"),
                    rmpv::Value::from("core:read"),
                ),
                (rmpv::Value::from("scope"), authority.clone()),
                (
                    rmpv::Value::from("receipt_required"),
                    rmpv::Value::Boolean(false),
                ),
            ])
        })
        .collect();
    let bytes = crate::gate::default_policy_manifest().unwrap();
    let rmpv::Value::Map(mut entries) =
        rmpv::decode::read_value(&mut bytes.as_slice()).expect("default manifest")
    else {
        panic!("manifest map");
    };
    entries.retain(|(key, _)| key.as_str() != Some("scoped_grants"));
    entries.push((
        rmpv::Value::from("scoped_grants"),
        rmpv::Value::Array(grants),
    ));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(entries)).expect("manifest encodes");
    put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id().expect("manifest id"),
        &bytes,
    )
    .expect("install read grants");
}

/// Canonical embedding-enabled test config: 16 MiB map, 4 dimensions,
/// `test/model@v1` embedding model, 16 readers. Everything else is the
/// `VaultConfig::device()` preset — HNSW and text-analyzer defaults
/// included, so do NOT re-assign defaults here.
pub(crate) fn embedding_test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config
}

/// Opens a temporary vault with the supplied config. Returns the
/// `TempDir` so callers keep the directory alive for the vault's lifetime.
pub(crate) fn open_test_vault_with(cfg: VaultConfig) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), cfg).expect("open vault");
    clear_default_policy_manifest_for_legacy_tests(&vault);
    (dir, vault)
}

/// The unit-test host root. Each test vault is its own trust domain, so one
/// fixed secret lets any fixture rebuild the issuer that rooted its vault.
pub(crate) fn test_host_issuer() -> crate::authority::HostSlipIssuer {
    crate::authority::HostSlipIssuer::from_secret(b"oneiron unit test host root")
        .expect("host issuer")
}

/// Roots the vault under the test host and provisions the engine's MACHINE
/// writers, as a host does at bootstrap. Returns the host issuer so a test can
/// provision its own MACHINE actors with `provision_host_machine_identity`.
pub(crate) fn provision_engine_machines(vault: &Vault) -> crate::authority::HostSlipIssuer {
    let issuer = test_host_issuer();
    vault.ensure_host_root_slip(&issuer).expect("host root");
    vault
        .provision_engine_machine_identities(&issuer)
        .expect("engine machine identities");
    issuer
}

/// Binds `owner` as the rooted test vault's human owner, so owner verbs keep
/// working after a fixture roots its vault.
pub(crate) fn bind_test_owner(vault: &Vault, owner: EntityId) {
    vault
        .bind_host_owner_for_test(&test_host_issuer(), owner)
        .expect("owner binding");
}

/// First open seeds the bootstrap skills, whose activation edits wait for
/// idle publication like any other revision. Publishes them through the
/// model-free drain so an idle-refresh law observes only its own entities.
/// Leaves the loop-owned idle delay at zero.
pub(crate) fn publish_seeded_revisions(vault: &Vault) {
    vault.set_indexed_idle_delay_ms(0).expect("idle delay");
    let seeded = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("seeded idle publication");
    assert!(seeded.failed.is_empty(), "seeded revisions need no model");
    assert!(seeded.superseded.is_empty());
}

/// Asserts `error` is the Gate secret-scan denial: [`GateError::GateWriteRejected`](crate::error::GateError::GateWriteRejected)
/// with outcome `"deny"` and reason codes exactly
/// `["gate.secret_scan.detected", expected_reason]`. Call sites pass the
/// expected leaf reason explicitly (e.g. `"gate.secret_scan.github_token"`)
/// so the asserted detector is visible at the test.
pub(crate) fn assert_secret_scan_rejected(error: Error, expected_reason: &'static str) {
    match error {
        Error::Gate(GateError::GateWriteRejected {
            outcome,
            reason_codes,
        }) => {
            assert_eq!(outcome, "deny");
            assert_eq!(
                reason_codes.as_slice(),
                &["gate.secret_scan.detected", expected_reason]
            );
        }
        other => panic!("expected GateWriteRejected, got {other:?}"),
    }
}

fn clear_default_policy_manifest_for_legacy_tests(vault: &Vault) {
    let id = crate::gate::default_policy_manifest_id().expect("default policy manifest id");
    vault
        .with_write_txn(|wtxn| {
            crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
            Ok(())
        })
        .expect("clear default policy manifest for legacy test fixture");
}
