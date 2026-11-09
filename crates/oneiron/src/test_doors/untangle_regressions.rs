//! Doors for the untangle regression tests (`tests/untangle_regressions.rs`;
//! lead 19:05 9 Nov, TESTS-MUST-RUN): each is a thin door over one
//! crate-private item, or a port of a seed helper of the `#[cfg(test)]`
//! fixtures, so the ruled behaviour tests of X01, X02, CONSENT-RAMP and the
//! repeat revoke (#6874) run from an integration target while the lib test
//! target does not compile. Compiled only under `--cfg oneiron_test_support`
//! (`test_doors`); the existing `test_support` doors they call are on in every
//! test build through the crate's self dev-dependency. Hidden; never API.
//! Every assertion stays in the test file: these return plain values.

use std::sync::Arc;

use rmpv::Value;

use crate::config::VaultConfig;
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::{Error, Result};

// ─── vaults ─────────────────────────────────────────────────────────────

/// A temporary vault opened with `cfg`, with a process-memory device keystore
/// installed, as the crate's legacy test opener
/// (`test_util::open_test_vault_with`) opens it, except that it keeps the
/// seeded default policy manifest. The legacy opener deletes that row
/// through the stale `#[cfg(test)]` helper `batch::deindex_entity_for_test`,
/// so its tests read the shipped default by fallback. The seeded row holds
/// those same bytes (`gate::default_policy_manifest`), so the policy every
/// door reads is unchanged.
#[doc(hidden)]
#[must_use]
pub fn open_test_vault_with(cfg: VaultConfig) -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), cfg).expect("open vault");
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    (dir, vault)
}

/// The crate's embedding test config (`test_util::embedding_test_config`).
#[doc(hidden)]
#[must_use]
pub fn embedding_test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config
}

// ─── Dreamer fixtures ───────────────────────────────────────────────────

/// The Dreamer tests' vault (`dreamer_consolidation::tests::open_vault`): the
/// legacy opener, the engine's MACHINE writers, owner-pinned test egress and
/// the shipped policy.
#[doc(hidden)]
#[must_use]
pub fn open_dreamer_vault() -> (tempfile::TempDir, Vault) {
    let (dir, vault) = open_test_vault_with(VaultConfig::device());
    let _issuer = crate::test_support::provision_engine_machines(&vault);
    authorize_test_inference(&vault).expect("owner-pinned test egress");
    install_shipped_policy(&vault).expect("shipped policy");
    (dir, vault)
}

/// Installs the shipped default policy manifest, which the legacy opener
/// clears; the Dreamer's read row (ARCH-0026) is in it.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn install_shipped_policy(vault: &Vault) -> Result<()> {
    crate::test_support::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &crate::gate::default_policy_manifest()?,
    )
}

/// Pins extraction to the owner's own server, as the Dreamer tests' egress
/// fixture does.
///
/// # Errors
/// The store's, or a purpose table with no extraction row.
#[doc(hidden)]
pub fn authorize_test_inference(vault: &Vault) -> Result<()> {
    let mut policy = vault.purpose_default_table()?;
    policy.extraction_max_locality = crate::ModelLocality::OwnServer;
    policy
        .purposes
        .get_mut(&crate::CallPurpose::Extraction)
        .ok_or_else(|| Error::InvalidConfig("missing extraction row".into()))?
        .locality = crate::ModelLocality::OwnServer;
    vault.set_purpose_default_table(&policy)?;
    Ok(())
}

/// This device's stable client id (`identity::load_or_mint_client_id`).
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn load_or_mint_client_id(vault: &Vault) -> Result<u64> {
    crate::identity::load_or_mint_client_id(vault)
}

// ─── seed rows ──────────────────────────────────────────────────────────

fn occurred(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

/// A SESSION row at `[seed; 16]`.
#[doc(hidden)]
#[must_use]
pub fn seed_session(vault: &Vault, seed: u8, at: u64) -> EntityId {
    let id = EntityId::from_bytes([seed; 16]).expect("session id");
    vault
        .put_entity(
            &id,
            crate::registry::ENTITY_TYPE_SESSION,
            occurred(at),
            at,
            b"session",
        )
        .expect("seed session");
    id
}

/// A TURN carrying its own words, `ChildOf` its conversation, in one batch.
#[doc(hidden)]
#[must_use]
pub fn seed_turn(
    vault: &Vault,
    conversation: &EntityId,
    speaker: &str,
    text: &str,
    learned_at: u64,
) -> EntityId {
    let id = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![
            (Value::from("txt"), Value::from(text)),
            (Value::from("spkr"), Value::from(speaker)),
        ]),
    )
    .expect("turn body encode");
    vault
        .batch()
        .put(
            &id,
            crate::registry::ENTITY_TYPE_TURN,
            occurred(learned_at),
            learned_at,
            &body,
        )
        .edge(&id, crate::EdgeKind::ChildOf, conversation, 1.0)
        .commit()
        .expect("seed turn");
    id
}

/// A PERSON row at `id`.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn seed_person(vault: &Vault, id: &EntityId, at: u64) -> Result<()> {
    vault.put_entity(
        id,
        crate::registry::ENTITY_TYPE_PERSON,
        occurred(at),
        at,
        b"person",
    )
}

// ─── policy rows ────────────────────────────────────────────────────────

/// Whether a manifest row names the Dreamer as its actor.
fn names_actor(row: &Value, actor: &str) -> bool {
    row.as_map().is_some_and(|fields| {
        fields
            .iter()
            .any(|(key, value)| key.as_str() == Some("actor_ref") && value.as_str() == Some(actor))
    })
}

/// Removes the Dreamer's read row from the vault's default policy
/// (`test_util::withhold_dreamer_read`), as a vault seeded before
/// ARCH-0026's warm default, or whose owner removed the row, holds it. Every
/// other row, the Dreamer's ceiling and permit included, stays.
///
/// # Errors
/// No stored default manifest, or the store's.
#[doc(hidden)]
pub fn withhold_dreamer_read(vault: &Vault) -> Result<()> {
    let id = crate::gate::default_policy_manifest_id()?;
    let body = vault.get(&id)?.ok_or(Error::EntityNotFound)?;
    let Value::Map(mut entries) =
        rmpv::decode::read_value(&mut body.as_slice()).expect("default policy map")
    else {
        unreachable!("default policy manifest is a map");
    };
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?.to_hex();
    for (key, table) in &mut entries {
        if let (Some("scoped_grants"), Value::Array(rows)) = (key.as_str(), table) {
            rows.retain(|row| !names_actor(row, &dreamer));
        }
    }
    entries.retain(|(key, table)| {
        key.as_str() != Some("scoped_grants")
            || table.as_array().is_some_and(|rows| !rows.is_empty())
    });
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries)).expect("encode policy");
    crate::test_support::put_policy_manifest_bytes(vault, id, &data)
}

/// One of the two rows that let the Dreamer land Auto (X02).
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamerLandingRow {
    /// Its Auto actor ceiling.
    ActorCeiling,
    /// Its `Generated` source-trust permit.
    GeneratedPermit,
}

/// The owner narrowed the Dreamer's landing
/// (`test_util::seeded_without_dreamer_landing_row`): the seeded default
/// without `row`, its read grant and its other landing row kept, and still
/// the untouched seed.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn seeded_without_dreamer_landing_row(vault: &Vault, row: DreamerLandingRow) -> Result<()> {
    let dreamer = crate::dreamer_runner::authority::dreamer_actor_id()?.to_hex();
    let manifest = crate::gate::default_policy_manifest()?;
    let Value::Map(mut entries) = rmpv::decode::read_value(&mut &manifest[..]).expect("map") else {
        panic!("policy manifest is a map");
    };
    for (key, value) in &mut entries {
        match (key.as_str(), row) {
            (Some("actor_ceilings"), DreamerLandingRow::ActorCeiling) => {
                if let Value::Array(rows) = value {
                    rows.retain(|ceiling| !names_actor(ceiling, &dreamer));
                }
            }
            (Some("source_trust"), DreamerLandingRow::GeneratedPermit) => {
                if let Value::Map(sources) = value {
                    for (source, rows) in sources.iter_mut() {
                        if source.as_str() == Some("generated")
                            && let Value::Array(list) = rows
                        {
                            list.retain(|permit| !names_actor(permit, &dreamer));
                        }
                    }
                    // A permit that was the Dreamer's alone leaves no row.
                    sources.retain(|(source, rows)| {
                        source.as_str() != Some("generated")
                            || !(names_actor(rows, &dreamer)
                                || rows.as_array().is_some_and(Vec::is_empty))
                    });
                }
            }
            _ => {}
        }
    }
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &Value::Map(entries)).expect("encode");
    let id = crate::gate::default_policy_manifest_id()?;
    crate::test_support::put_policy_manifest_bytes(vault, id, &data)?;
    vault.with_write_txn(|txn| {
        vault.store.sync_state.put(
            txn,
            &oneiron_store::manifest_origin_keys::seeded_manifest_key(&id),
            blake3::hash(&data).as_bytes(),
        )?;
        Ok(())
    })
}

// ─── X01: the Dreamer's side doors ──────────────────────────────────────

/// A TURN record one of the Dreamer's side doors (gap scan, owner intent,
/// retrieval shadow) read, held so its writer's re-check can run after a
/// policy change (X01).
#[doc(hidden)]
pub struct SideDoorTurnText(crate::dreamer_consolidation::TurnText);

impl SideDoorTurnText {
    /// The TURN's words as the side door read them; `None` when it gave none.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        self.0.text()
    }

    /// The writer's re-check of this record (`TurnText::check_live_in`),
    /// read as the Dreamer in a fresh snapshot.
    ///
    /// # Errors
    /// The re-check's refusal.
    pub fn recheck_as_dreamer(&self, vault: &Vault, turn: &EntityId) -> Result<()> {
        crate::dreamer_consolidation::side_door_recheck_for_test(&self.0, vault, turn)
    }
}

/// The side doors' read of one TURN (`turn_text::read_turn_text`).
///
/// # Errors
/// The read's.
#[doc(hidden)]
pub fn side_door_turn_text(vault: &Vault, turn: &EntityId) -> Result<SideDoorTurnText> {
    crate::dreamer_consolidation::side_door_turn_text_for_test(vault, turn).map(SideDoorTurnText)
}

/// The retrieval tagger's shadow read of one TURN's words.
///
/// # Errors
/// Not a TURN, a TURN with no text the Dreamer may read, or the read's.
#[doc(hidden)]
pub fn turn_text_for_shadow(vault: &Vault, turn: &EntityId) -> Result<String> {
    crate::dreamer_consolidation::turn_text_for_shadow(vault, turn)
}
