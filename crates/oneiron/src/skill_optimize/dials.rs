//! The N dial over vault_meta, and the two text helpers every child in this module uses.

use crate::Vault;
use crate::error::{Error, Result};

/// `vault_meta` key holding N, the attributed outcomes a skill must carry
/// before it can be optimized.
///
/// A per-feature engine dial over `vault_meta` — the `INBOX_REVIEW_DIAL_KEY`
/// house pattern, the same one `SKILL_RELIABILITY_FLOOR_KEY` and
/// `MINER_K_SETTINGS_KEY` follow. `settings.rs` is UI customization and owns
/// nothing here.
pub const SKILL_OPTIMIZE_MIN_OUTCOMES_KEY: &[u8] = b"settings:skill_optimize:v1:min_outcomes";

/// N when the dial has never been set.
///
/// Five, matching `SKILL_RELIABILITY_FLOOR_MIN_OUTCOMES`: the two gates ask
/// the same underlying question ("is there evidence, or only a prior?") of the
/// same posterior, and answering it with two different numbers would mean a
/// skill could be evidenced enough to retire but not enough to repair.
pub const DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES: u32 = 5;

/// Page size of the SKILL type-index sweep.
pub(super) const SKILL_SCAN_PAGE: usize = 1024;

pub(super) const fn invalid(reason: &'static str) -> Error {
    Error::InvalidSkillBody(reason)
}

pub(super) fn validate_text(value: &str, max_bytes: usize, reason: &'static str) -> Result<()> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(invalid(reason));
    }
    Ok(())
}

/// Reads the N dial (default [`DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES`]).
///
/// # Errors
///
/// Storage errors; [`Error::CorruptedIndex`] on an undecodable row.
pub fn skill_optimize_min_outcomes(vault: &Vault) -> Result<u32> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(raw) = vault
        .store
        .vault_meta
        .get(&rtxn, SKILL_OPTIMIZE_MIN_OUTCOMES_KEY)?
    else {
        return Ok(DEFAULT_SKILL_OPTIMIZE_MIN_OUTCOMES);
    };
    let bytes: [u8; 4] = raw
        .as_ref()
        .try_into()
        .map_err(|_| Error::CorruptedIndex("skill optimize min outcomes"))?;
    Ok(u32::from_be_bytes(bytes))
}

/// Sets the N dial.
///
/// # Errors
///
/// [`Error::InvalidSkillBody`] when `min_outcomes` is zero — a job that may
/// rewrite a skill on no evidence at all is the thing N exists to prevent.
pub fn set_skill_optimize_min_outcomes(vault: &Vault, min_outcomes: u32) -> Result<()> {
    if min_outcomes == 0 {
        return Err(invalid(
            "skill optimize min_outcomes must be > 0: evidence is the point",
        ));
    }
    vault.with_write_txn(|wtxn| {
        vault.store.vault_meta.put(
            wtxn,
            SKILL_OPTIMIZE_MIN_OUTCOMES_KEY,
            &min_outcomes.to_be_bytes(),
        )?;
        Ok(())
    })
}
