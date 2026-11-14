//! The raw rows of every table the consent-graduation ramp keeps
//! (RAMP-SCOPE-ACTOR-ERASE, Engine RULING NEXT-ROW-18 = A1, 14 Nov), so the
//! `ramp_scope_actor_erase` test proves that no row spells an erased actor's
//! id after the erase. Read-only: each table's declared keyspace, its key and
//! value bytes undecoded.

use crate::error::Result;
use crate::side_table::{self, SideTableDbs, SideTableDecl};
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
    let spells = |bytes: &[u8]| bytes.windows(needle.len()).any(|window| window == needle);
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
