//! OF-542: `audit_rate` learned from audit checks (ARCH-0003 settings
//! catalog: "Learned from audit checks. Each draw records the rate in
//! force"). Each completed random audit is one fitting check on the vault's
//! audit rate, recorded in the transaction that admits the audit's outcome,
//! on the knob's global subject at the root type, anchored on the audit at
//! the rate its draw stamped. The draw itself is no check: only a finished
//! audit observes anything.

use crate::learning::{Anchor, TypeRef};
use crate::learning_setting::{
    AUDIT_RATE, SettingCheck, global_setting_subject, record_setting_check_in_txn,
};
use crate::self_heal::audit::{SealCheckKind, SealedAttemptReceipt};
use crate::{Result, Vault};

/// The rate one completed random audit argues for: every attempt, when it
/// found a flaw the attempt did not disclose; the catalog floor, when it
/// found none. Their mean over audits is the share of audited attempts that
/// hid a flaw, so the rate rises with the hiding audits find and falls
/// toward the floor, never zero, while they find none.
#[must_use]
pub(crate) fn audit_rate_target(hidden: bool) -> f64 {
    if hidden {
        AUDIT_RATE.max
    } else {
        AUDIT_RATE.min
    }
}

/// The fitting check `receipt.checks[index]` makes on the vault's audit
/// rate; `None` unless it is a completed random audit.
///
/// # Errors
///
/// The global subject's derivation.
pub(crate) fn audit_rate_check(
    receipt: &SealedAttemptReceipt,
    index: usize,
) -> Result<Option<SettingCheck>> {
    let Some(check) = receipt.checks.get(index) else {
        return Ok(None);
    };
    let Some(outcome) = check
        .outcome
        .as_ref()
        .filter(|_| check.request.kind == SealCheckKind::RandomAudit)
    else {
        return Ok(None);
    };
    // A flaw on an objective the confession neither named nor doubted.
    let hidden = outcome.findings.iter().any(|finding| {
        finding.flaw_present
            && receipt.confession.objectives.iter().any(|objective| {
                objective.objective == finding.objective && !objective.needs_recheck()
            })
    });
    Ok(Some(SettingCheck {
        subject: global_setting_subject(AUDIT_RATE.key)?,
        key: AUDIT_RATE.key.to_owned(),
        // The vault-wide fit, whichever tree version the work was typed in.
        type_ref: TypeRef::root(0),
        observed: audit_rate_target(hidden),
        receipt: check.request.reference.clone(),
        at: outcome.checked_at,
        anchor: Anchor::Audit {
            rate: check.request.rate,
        },
    }))
}

/// Records [`audit_rate_check`] in the outcome's own transaction `txn`, so
/// the finding and the fit commit together.
///
/// # Errors
///
/// As [`audit_rate_check`] and [`record_setting_check_in_txn`].
pub(crate) fn fit_audit_rate_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    receipt: &SealedAttemptReceipt,
    index: usize,
    now: u64,
) -> Result<()> {
    if let Some(check) = audit_rate_check(receipt, index)? {
        record_setting_check_in_txn(vault, txn, &check, now)?;
    }
    Ok(())
}
