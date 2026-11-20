//! Stored workspace rows in the shape written before one-vault mode, for
//! `tests/workspace_one_vault_mode.rs`.
#![cfg(oneiron_test_support)]

use std::io::Cursor;

use rmpv::Value;

use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// The three roster tables, read and written as their stored bytes through the
/// typed side-table door, so the fixture rows are the bytes main stored.
const MEMBER_BYTES: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::WORKSPACE_ROSTER_MEMBER);
const PRESET_BYTES: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::WORKSPACE_ROSTER_PRESET);
const ONBOARDING_BYTES: SideTable<Vec<u8>, Vec<u8>, Raw> =
    SideTable::new(&side_table::WORKSPACE_ONBOARDING);

/// Rewrites one member, its workspace preset and its completed onboarding
/// journal with only the version-1 keys written before one-vault mode.
/// The rows keep their keys and every retained value except `schema_version`.
///
/// # Errors
///
/// A fixture row is missing, is not a complete MessagePack map, or the store
/// refuses the write.
pub fn rewrite_workspace_rows_before_one_vault(
    vault: &Vault,
    workspace_ref: &str,
    member: EntityId,
    onboarding_id: &str,
) -> Result<()> {
    // The member key after its prefix: workspace, NUL, the person id in hex
    // (workspace_roster::records::RosterMemberKey).
    let mut member_key = workspace_ref.as_bytes().to_vec();
    member_key.push(0);
    member_key.extend_from_slice(member.to_hex().as_bytes());
    let preset_key = workspace_ref.as_bytes().to_vec();
    let journal_key = onboarding_id.as_bytes().to_vec();

    vault.with_write_txn(|txn| {
        rewrite_stored_row(
            vault,
            txn,
            &MEMBER_BYTES,
            &member_key,
            &[
                "schema_version",
                "person_ref",
                "actor_ref",
                "companion_person_ref",
                "companion_actor_ref",
                "companion_facet_ref",
                "identity_ref",
            ],
        )?;
        rewrite_stored_row(
            vault,
            txn,
            &PRESET_BYTES,
            &preset_key,
            &[
                "schema_version",
                "workspace_ref",
                "workspace_vault_id",
                "org_ref",
                "venture_name",
                "house_display_name",
                "house_actor_ref",
                "house_identity_ref",
                "work_companion",
            ],
        )?;
        rewrite_stored_row(
            vault,
            txn,
            &ONBOARDING_BYTES,
            &journal_key,
            &[
                "schema_version",
                "onboarding_id",
                "intent_digest",
                "step",
                "completed_at",
            ],
        )
    })
}

fn rewrite_stored_row(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    table: &SideTable<Vec<u8>, Vec<u8>, Raw>,
    key: &[u8],
    stored_keys: &[&str],
) -> Result<()> {
    let key = key.to_vec();
    let mut entries = {
        let bytes = table
            .get(&vault.store, txn, &key)?
            .ok_or(Error::InvariantViolation(
                "workspace fixture row is missing",
            ))?;
        let mut cursor = Cursor::new(bytes.as_slice());
        let value = rmpv::decode::read_value(&mut cursor)
            .map_err(|_| Error::InvalidClaimBody("workspace fixture MessagePack decode failed"))?;
        if cursor.position() != bytes.len() as u64 {
            return Err(Error::InvalidClaimBody(
                "workspace fixture body has trailing bytes",
            ));
        }
        match value {
            Value::Map(entries) => entries,
            _ => {
                return Err(Error::InvalidClaimBody(
                    "workspace fixture body must be a map",
                ));
            }
        }
    };
    entries.retain(|(name, _)| {
        name.as_str()
            .is_some_and(|name| stored_keys.contains(&name))
    });
    let (_, version) = entries
        .iter_mut()
        .find(|(name, _)| name.as_str() == Some("schema_version"))
        .ok_or(Error::InvalidClaimBody(
            "workspace fixture schema_version is missing",
        ))?;
    *version = Value::from(1_u64);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(entries))
        .map_err(|_| Error::InvalidClaimBody("workspace fixture MessagePack encode failed"))?;
    table.put(&vault.store, txn, &key, &bytes)
}
