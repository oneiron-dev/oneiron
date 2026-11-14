//! An actor's erase takes the actor out of the offer-answer log and the
//! threshold overrides (RAMP-SCOPE-ACTOR-ERASE, Engine RULING NEXT-ROW-18 =
//! A1, 14 Nov), as part of the ramp's own erase
//! ([`crate::consent_graduation::erase_ramp_actor_in_txn`]).
//!
//! An answer is the owner's act: it stays, with its answer, answerer and
//! times, and its scope actor reads [`ERASED_CALL_IDENTITY`]. Its key derives
//! from the scope, so it is deleted and re-put under the erased scope's digest
//! with its own row id, as the escalation rows are (FIX 4700). A threshold
//! override whose pattern names the actor is that scope's policy, and it goes.

use super::pattern::pattern_axes;
use super::{ANSWER, THRESHOLD};
use crate::consent_graduation::RampScope;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::store::Store;

/// Rewrites the scope actor of every answer whose scope names `actor_hex` to
/// [`ERASED_CALL_IDENTITY`], re-keyed under the erased scope's digest, and
/// deletes every threshold override whose pattern's actor axis is
/// `actor_hex`. Returns the scopes whose answers it rewrote, still naming
/// `actor_hex`, so the ramp's erase drops their floor rows too.
///
/// # Errors
///
/// Storage errors, or a row that cannot be read.
pub(crate) fn erase_scope_actor_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    actor_hex: &str,
) -> Result<Vec<RampScope>> {
    let mut answers = Vec::new();
    for ((scope_key, id), row) in ANSWER.scan(store, wtxn)? {
        if row.actor == actor_hex {
            answers.push((scope_key, id, row));
        }
    }
    let mut scopes = Vec::new();
    for (scope_key, id, mut row) in answers {
        let erased = RampScope {
            op_kind: row.op_kind.clone(),
            target_class: row.target_class.clone(),
            actor: ERASED_CALL_IDENTITY.to_owned(),
        };
        scopes.push(RampScope {
            op_kind: row.op_kind.clone(),
            target_class: row.target_class.clone(),
            actor: std::mem::replace(&mut row.actor, ERASED_CALL_IDENTITY.to_owned()),
        });
        ANSWER.delete(store, wtxn, &(scope_key, id))?;
        ANSWER.put(store, wtxn, &(erased.key(), id), &row)?;
    }
    let mut thresholds = Vec::new();
    for (key, row) in THRESHOLD.scan(store, wtxn)? {
        if pattern_axes(&row.scope_pattern).is_some_and(|[_, _, actor]| actor == actor_hex) {
            thresholds.push(key);
        }
    }
    for key in thresholds {
        THRESHOLD.delete(store, wtxn, &key)?;
    }
    Ok(scopes)
}
