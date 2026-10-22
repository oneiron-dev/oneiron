//! A public model-step submission's kept copies under body custody (FIX 9929).
//!
//! The submission row keeps the owner's request and the step's result beside
//! the receipt's metadata. Its owners are the submitting actor and, once the
//! step finished, the terminal `dreamer.step` claim that logged its answer.
//! The erase of either, at both delete doors, takes the request, the parsed
//! JSON, the response and any failure text out of the live row in the erase's
//! own transaction; a row written after its owner is gone is kept erased.
//! A checkpoint carries the row as a row-held response bound to those owners,
//! so their erase retires every image's copy too. The erased row keeps the
//! receipt's metadata (actor, step hash, key, retry policy and model) and
//! answers `Erased`: the step is over and is never asked again.

use serde::{Deserialize, Serialize};

use super::super::ResponseFormat;
use super::public::{ModelStepResult, ModelStepSubmit};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, Named, SideKey, SideTable};
use crate::store::{ResponseCarriage, ResponseScan, Store};

pub(super) const SUBMISSIONS: SideTable<AttemptId, Submission, Named> =
    SideTable::new(&side_table::MODEL_STEP_SUBMISSION);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Submission {
    pub(super) actor: EntityId,
    pub(super) input: ModelStepSubmit,
    pub(super) step_hash: [u8; 32],
    pub(super) result: Option<ModelStepResult>,
}

/// Whether an erase already took the row's copies.
pub(super) fn erased(row: &Submission) -> bool {
    matches!(row.result, Some(ModelStepResult::Erased))
}

/// Whose the row's copies are: its actor, and a finished step's terminal
/// claim. A claim ref that does not parse names no owner.
fn owners(row: &Submission) -> Vec<EntityId> {
    let mut owners = vec![row.actor];
    if let Some(ModelStepResult::Finished { claim_ref, .. }) = &row.result
        && let Ok(claim) = EntityId::from_hex(claim_ref)
        && claim != row.actor
    {
        owners.push(claim);
    }
    owners
}

/// The row's erased form: the request's content, its schema included, and
/// the result go together; its metadata stays.
fn scrub(row: &mut Submission) {
    let request = &mut row.input.request;
    request.messages.clear();
    request.tools.clear();
    request.params.clear();
    request.provider_options.clear();
    request.host_segments = None;
    if let ResponseFormat::Json { schema } = &mut request.envelope.response_format {
        *schema = serde_json::Value::Null;
    }
    row.result = Some(ModelStepResult::Erased);
}

/// Writes `row` at `id` in `wtxn`, the public door's one write: a row whose
/// owner is already gone is kept in its erased form, so a terminal written
/// after its claim's erase never outlives it. `row` becomes what was kept.
///
/// # Errors
///
/// Storage errors.
pub(super) fn put_submission_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &AttemptId,
    row: &mut Submission,
) -> Result<()> {
    if !erased(row) && super::owner_gone_in_txn(vault, &*wtxn, &owners(row))? {
        scrub(row);
    }
    SUBMISSIONS.put(vault, wtxn, id, row)
}

/// What a checkpoint carries of the submission row `value`: the whole row,
/// whose erased form is the stub a retired instance keeps. No response for
/// a row already erased; a row that does not decode, or whose stub does not
/// encode, is carried whole as an opaque response (FIX 6227).
pub(crate) fn submission_carriage(value: &[u8]) -> ResponseScan {
    let Ok(mut row) = SUBMISSIONS.decode_value(value) else {
        return ResponseScan::opaque_row();
    };
    if erased(&row) {
        return ResponseScan::NotResponse;
    }
    scrub(&mut row);
    let Ok(stub) = SUBMISSIONS.encode_value(&row) else {
        return ResponseScan::opaque_row();
    };
    ResponseScan::Decoded(ResponseCarriage {
        keep: 0,
        retired: stub.len(),
        stub,
    })
}

/// Who owns the submission row `value`'s copies: none for a row that does
/// not decode.
pub(crate) fn submission_owners(value: &[u8]) -> Vec<EntityId> {
    SUBMISSIONS
        .decode_value(value)
        .map(|row| owners(&row))
        .unwrap_or_default()
}

/// The erase of `owner` takes the copies out of every submission row it
/// owns, in the erase's own transaction, at both delete doors. The row stays
/// in its erased form. A row that does not decode names no owner and stays
/// as it is (FIX 5736); images' copies retire through the rows' obligations.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn erase_submissions_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    owner: &EntityId,
) -> Result<()> {
    let needle = owner.to_hex();
    let mut owned = Vec::new();
    for row in SUBMISSIONS.iter_raw_from(store, wtxn, &[])? {
        let (key, bytes) = row?;
        // An owner's id rests in its row as its hex text: a row without it
        // is not decoded.
        if !bytes
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
        {
            continue;
        }
        let Ok(mut submission) = SUBMISSIONS.decode_value(&bytes) else {
            continue;
        };
        if erased(&submission) || !owners(&submission).contains(owner) {
            continue;
        }
        scrub(&mut submission);
        owned.push((key, submission));
    }
    for (key, submission) in owned {
        let Some(key) = <AttemptId as SideKey>::decode_key(&key) else {
            continue;
        };
        SUBMISSIONS.put(store, wtxn, &key, &submission)?;
    }
    Ok(())
}
