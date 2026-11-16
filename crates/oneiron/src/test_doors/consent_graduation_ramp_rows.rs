//! The raw rows of every table the consent-graduation ramp keeps
//! (RAMP-SCOPE-ACTOR-ERASE, Engine RULING NEXT-ROW-18 = A1, 14 Nov), so the
//! `ramp_scope_actor_erase` test proves that no row spells an erased actor's
//! id after the erase. Read-only: each table's declared keyspace, its key and
//! value bytes undecoded. One writer: a streak-floor row in the layout written
//! before a floor row carried its scope (RAMP-FLOOR-ORPHAN-ERASE), so the
//! test proves such a row still reads.

use crate::consent_graduation::RampScope;
use crate::error::{Error, Result};
use crate::side_table::{self, CodecError, Raw, RawValue, SideTable, SideTableDbs, SideTableDecl};
use crate::vault::Vault;

/// One ramp table: how many rows it holds, and how many of them spell the
/// text asked for in their key or value bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RampTableRows {
    /// The table, by its keyspace's name.
    pub table: &'static str,
    /// Every row it holds.
    pub rows: usize,
    /// The rows whose key (past the table prefix) or value spells the text.
    pub spelling: usize,
}

/// Each ramp table's row count and how many of its rows spell `text`.
///
/// # Errors
///
/// Storage errors.
pub fn ramp_rows_spelling(vault: &Vault, text: &str) -> Result<Vec<RampTableRows>> {
    let needle = text.as_bytes();
    let spells = |bytes: &[u8]| {
        !needle.is_empty() && bytes.windows(needle.len()).any(|window| window == needle)
    };
    // The tables a ramp scope's actor may be spelled in: the ramp's own four
    // and ED-05's offer answers and threshold overrides.
    let ramp_tables: [(&'static str, &SideTableDecl); 6] = [
        ("ramp_demotion", &side_table::RAMP_DEMOTION),
        ("ramp_floor", &side_table::RAMP_FLOOR),
        ("ramp_outcome", &side_table::RAMP_OUTCOME),
        ("ramp_stats", &side_table::RAMP_STATS),
        (
            "graduation_answer",
            &side_table::EDIT_DISTANCE_GRADUATION_ANSWER,
        ),
        (
            "graduation_threshold",
            &side_table::EDIT_DISTANCE_GRADUATION_THRESHOLD,
        ),
    ];
    let rtxn = vault.store.env.read_txn()?;
    let mut tables = Vec::new();
    for (table, decl) in ramp_tables {
        let mut counted = RampTableRows {
            table,
            rows: 0,
            spelling: 0,
        };
        for row in vault
            .store
            .side_vault_meta()
            .prefix_iter(&rtxn, decl.prefix)?
        {
            let (key, value) = row?;
            counted.rows += 1;
            if spells(&key[decl.prefix.len()..]) || spells(&value) {
                counted.spelling += 1;
            }
        }
        tables.push(counted);
    }
    Ok(tables)
}

/// A streak floor in the layout written before a floor row carried its scope:
/// four little-endian bytes and nothing after them.
struct FourByteFloor(u32);

impl RawValue for FourByteFloor {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, CodecError> {
        Ok(self.0.to_le_bytes().to_vec())
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, CodecError> {
        let bytes: [u8; 4] = bytes
            .try_into()
            .map_err(|_| Error::CorruptedIndex("ramp streak floor row"))?;
        Ok(Self(u32::from_le_bytes(bytes)))
    }
}

/// The streak-floor table, read and written in its four-byte layout.
const FOUR_BYTE_FLOOR: SideTable<[u8; 16], FourByteFloor, Raw> =
    SideTable::new(&side_table::RAMP_FLOOR);

/// Writes `floor` as `scope`'s streak-floor row in the four-byte layout, which
/// names no scope.
///
/// # Errors
///
/// Storage errors.
pub fn put_four_byte_ramp_floor(vault: &Vault, scope: &RampScope, floor: u32) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        FOUR_BYTE_FLOOR.put(&vault.store, wtxn, &scope.key(), &FourByteFloor(floor))
    })
}
