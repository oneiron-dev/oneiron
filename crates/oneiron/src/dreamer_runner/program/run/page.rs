//! One page of a program run's STEP rows, for its reads (moved out of the
//! run module whole; FIX 9391 names its erased steps).
//!
//! Each row is read before it decodes: the explicit erased marker of a
//! retired body that never decoded (FIX 6227) is an erased step, named by
//! its ref, as its single read answers it `ResponseErased`, never an
//! undecodable row (FIX 5736) and never a step made up. An erased step takes
//! its slot in the page and moves the cursor past it, so a page of erased
//! steps alone still moves on.

use super::{STEP, TurnProgramStep};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::{ResponseFamily, ResponseRead};

/// One page of a program run's STEP rows, for its reads.
pub(in crate::dreamer_runner::program) struct ProgramStepPage {
    /// Each step by its ref, in key order.
    pub(in crate::dreamer_runner::program) steps: Vec<(EntityId, TurnProgramStep)>,
    /// Each step whose row holds the erased marker of a retired body that
    /// never decoded, by its ref, in key order (FIX 9391).
    pub(in crate::dreamer_runner::program) erased: Vec<EntityId>,
    /// Rows of the page that do not decode (FIX 5736): skipped, never a
    /// refusal of the page.
    pub(in crate::dreamer_runner::program) undecodable: u64,
    /// The last step the page names, decoded or erased: where the next page
    /// starts.
    pub(in crate::dreamer_runner::program) last: Option<EntityId>,
    /// Whether a row follows the page.
    pub(in crate::dreamer_runner::program) more: bool,
}

/// Up to `limit` of `code_run`'s steps in key order, after the step `after`
/// when one is named, each a decoded step or an erased one. Every step id
/// lies between the least and the greatest id that is not reserved, so only
/// this run's rows in that range are read.
pub(in crate::dreamer_runner::program) fn program_steps_page_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    code_run: EntityId,
    after: Option<EntityId>,
    limit: usize,
) -> Result<ProgramStepPage> {
    let mut least = [0_u8; 16];
    least[15] = 1;
    let mut greatest = [u8::MAX; 16];
    greatest[15] = u8::MAX - 1;
    let mut page = ProgramStepPage {
        steps: Vec::new(),
        erased: Vec::new(),
        undecodable: 0,
        last: None,
        more: false,
    };
    for row in STEP.iter_raw_from(vault, txn, code_run.as_bytes())? {
        let (key, raw) = row?;
        let Some(step) = key
            .get(16..)
            .and_then(|step| <[u8; 16]>::try_from(step).ok())
            .filter(|step| *step >= least && *step <= greatest)
        else {
            continue;
        };
        if after.is_some_and(|after| step <= *after.as_bytes()) {
            continue;
        }
        if page.steps.len() + page.erased.len() >= limit {
            page.more = true;
            break;
        }
        let Ok(step) = EntityId::from_bytes(step) else {
            page.undecodable += 1;
            continue;
        };
        let full = STEP.key_bytes(&(code_run, step));
        match ResponseRead::of(ResponseFamily::ProgramStep, &full, &raw) {
            ResponseRead::ErasedOpaque(_) => {
                page.erased.push(step);
                page.last = Some(step);
            }
            ResponseRead::Present(raw) => match STEP.decode_value(raw) {
                Ok(held) => {
                    page.steps.push((step, held));
                    page.last = Some(step);
                }
                Err(_) => page.undecodable += 1,
            },
        }
    }
    Ok(page)
}
