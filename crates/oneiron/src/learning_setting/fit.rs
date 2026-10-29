//! A learned knob's fit (ARCH-0003 #learning-settings, FIX 6038): the checks
//! that fit it, the key each scope's fit is cached under, and the owner seed
//! a fit starts from. A fit is keyed by its project, its subject and its type
//! node, so a project's fit is its own and never the vault's.

use super::{SETTING, SettingMode, SettingSpec, invalid, scoped_row_key, setting_spec, subject};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::LearningCell;

/// The key a setting cell's fit is cached under
/// (`learning::project::SETTING_FIT`): the knob's key alone for its vault
/// fit; with the cell's project when it is scoped to one; with its `subject`
/// when that is not the knob's [`global_setting_subject`]; with its task
/// type's node when that is not the root. A type names its node only, as a
/// type row does, so it matches at any tree version.
pub(crate) fn setting_fit_key(
    key: &str,
    project: Option<EntityId>,
    subject: Option<EntityId>,
    type_node: Option<&str>,
) -> String {
    let mut out = key.to_owned();
    if let Some(project) = project {
        out.push_str("\0project\0");
        out.push_str(&project.to_hex());
    }
    if let Some(subject) = subject {
        out.push_str("\0subject\0");
        out.push_str(&subject.to_hex());
    }
    if let Some(node) = type_node {
        out.push_str("\0type\0");
        out.push_str(node);
    }
    out
}

/// [`setting_fit_key`] read back: the knob's key, the project, the subject
/// and the type node. `None` for a key this codec does not write.
pub(super) fn parse_setting_fit_key(
    stored: &str,
) -> Option<(&str, Option<EntityId>, Option<EntityId>, Option<&str>)> {
    let parts: Vec<&str> = stored.split('\0').collect();
    let (key, tail) = parts.split_first()?;
    let mut fit = (*key, None, None, None);
    // The coordinates come in the writer's order, each at most once.
    let mut rank = 0;
    for pair in tail.chunks(2) {
        let [tag, value] = pair else {
            return None;
        };
        let id = || EntityId::from_hex(value).ok();
        rank = match *tag {
            "project" if rank < 1 => {
                fit.1 = Some(id()?);
                1
            }
            "subject" if rank < 2 => {
                fit.2 = Some(id()?);
                2
            }
            "type" if rank < 3 => {
                fit.3 = Some(*value);
                3
            }
            _ => return None,
        };
    }
    (!key.is_empty()).then_some(fit)
}

/// The cached fit for one scope, once it has own runs.
pub(super) fn cached_fit(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    project: Option<EntityId>,
    subject: Option<EntityId>,
    type_node: Option<&str>,
) -> Result<Option<f64>> {
    Ok(crate::learning::project::SETTING_FIT
        .get(
            store,
            txn,
            &setting_fit_key(spec.key, project, subject, type_node),
        )?
        .filter(|fit| fit.runs > 0.0 && fit.value.is_finite())
        // A fit never leaves the catalog's bounds, so it never widens a floor.
        .map(|fit| fit.value.clamp(spec.min, spec.max)))
}

/// The owner's seed over `spec` and its weight in runs for `cell`, if one
/// stands: the prior a `learning.setting` fit starts from. The cell's
/// project names the scope, never its subject: the project's goal's seed
/// comes first, then the project's, then a non-root type's, then the
/// vault's.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn owner_seed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    spec: &SettingSpec,
    cell: &LearningCell,
) -> Result<Option<(f64, f64)>> {
    let type_ref = cell
        .type_ref
        .as_ref()
        .filter(|type_ref| !type_ref.is_root());
    for scope in super::read_scopes_in_txn(vault, txn, cell.project, type_ref)? {
        if let Some(seed) = SETTING
            .get(
                &vault.store,
                txn,
                &scoped_row_key(spec.key, SettingMode::Seed, &scope),
            )?
            .filter(|row| (spec.min..=spec.max).contains(&row.value))
            .and_then(|row| row.weight_runs.map(|weight| (row.value, weight)))
        {
            return Ok(Some(seed));
        }
    }
    Ok(None)
}

/// One check that fits a named knob: the value the check found best, on the
/// receipt that ran it.
#[derive(Debug, Clone, PartialEq)]
pub struct SettingCheck {
    /// The skill that uses the knob, or the knob's [`global_setting_subject`].
    pub subject: EntityId,
    /// The project the check ran under; `None`, the vault (FIX 6038).
    pub project: Option<EntityId>,
    /// The catalog key.
    pub key: String,
    /// The task type the check ran under; the vault-scope fit is the root.
    pub type_ref: crate::learning::TypeRef,
    pub observed: f64,
    pub receipt: String,
    pub at: u64,
    /// A fitting check, an audit (with its rate) or a held-out run.
    pub anchor: crate::learning::Anchor,
}

/// Records one fitting check into `learning.setting` and refits.
///
/// # Errors
///
/// [`crate::error::Error::InvalidClaimBody`] for a key outside the catalog,
/// an observed value outside its bounds, or an anchor that does not fit
/// settings; the evidence door's errors.
pub fn record_setting_check(
    vault: &Vault,
    check: &SettingCheck,
    now: u64,
) -> Result<Option<crate::learning::Estimate>> {
    vault.with_write_txn_grouped(|wtxn| record_setting_check_in_txn(vault, wtxn, check, now))
}

/// The one subject `key`'s vault-wide fit is learned on: an id derived from
/// the key, since a vault-wide knob has no one skill that uses it. Only a
/// root-typed check on this subject with no project fits the vault
/// (OF-542); a project's check fits that project, a skill's that skill.
///
/// # Errors
///
/// The derivation's refusal of a reserved id.
pub fn global_setting_subject(key: &str) -> Result<EntityId> {
    EntityId::derive(
        crate::entity_id::derived_domains::GLOBAL_SETTING_SUBJECT,
        &[key.as_bytes()],
    )
}

/// [`record_setting_check`] inside `wtxn`, for a writer whose own row and
/// the check commit together: a random audit's outcome and the audit rate it
/// fits (OF-542).
///
/// # Errors
///
/// As [`record_setting_check`].
pub(crate) fn record_setting_check_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    check: &SettingCheck,
    now: u64,
) -> Result<Option<crate::learning::Estimate>> {
    let spec = setting_spec(&check.key).ok_or(invalid("no learned setting has this key"))?;
    if !check.observed.is_finite() || check.observed < spec.min || check.observed > spec.max {
        return Err(invalid(
            "a fitting check's value lies within its catalog bounds",
        ));
    }
    // A vault-wide fit is learned on its knob's ASSET (FIX 8079). One not
    // ready passes the check over, and the write that carries it goes on.
    if check.subject == global_setting_subject(spec.key)?
        && let Err(reason) =
            subject::ensure_global_setting_subject_in_txn(vault, wtxn, spec.key, &check.subject)
    {
        tracing::warn!(
            ?reason,
            key = spec.key,
            "a vault-wide setting check was not recorded: its subject is not ready"
        );
        return Ok(None);
    }
    let cell = LearningCell::new(crate::learning::LearningPredicate::Setting, check.subject)
        .setting_key(spec.key)
        .type_ref(check.type_ref.clone())
        .project(check.project);
    let evidence = crate::learning::LearningEvidence::anchored(
        check.receipt.clone(),
        check.at,
        check.anchor,
        crate::learning::Observation::Magnitude(check.observed),
    );
    crate::learning::record_evidence_in_txn(vault, wtxn, &cell, &evidence, now)
}
