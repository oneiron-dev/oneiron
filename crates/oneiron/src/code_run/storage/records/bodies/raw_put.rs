//! The raw output put (OF-597, SECRET-04): a complete body held whole,
//! stored under its content handle with the taint refs of the action that
//! made it, and the descriptor its owner publishes (moved out of the result
//! bodies module whole).

use super::*;

impl Vault {
    /// Stores a complete body held whole under its content handle; `output`
    /// must be its manifest, and `owner` the run that holds it, if one does.
    pub fn put_code_run_raw_output(
        &self,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
        raw: &[u8],
    ) -> Result<()> {
        self.put_code_run_raw_output_tainted(owner, output, raw, &[])
    }

    /// Stores a complete body ALONGSIDE the taint refs of the action that
    /// produced them (SECRET-04, ONE-1922), on the occurrence `owner` holds
    /// (or the bytes' own, with none). With an `owner`, the same writer
    /// publishes the descriptor `raw_put_descriptor_in_txn` names, so
    /// erasing the owner releases the body, and the row takes no hold of
    /// its own; a hold its row kept before stays (FIX 7283, FIX 7364).
    /// With none, no descriptor is published and the row holds its body on
    /// its own (FIX 5399b).
    ///
    /// One write transaction carries the sidecar and the body row, so
    /// tainted exhaust can never survive a half-failed write wearing no
    /// mark. An empty ref list is exactly the untainted put (the sidecar is
    /// cleared, not written empty); it clears this occurrence's sidecar only,
    /// never another's of the same bytes.
    pub fn put_code_run_raw_output_tainted(
        &self,
        owner: Option<EntityId>,
        output: &CodeRunRawOutput,
        raw: &[u8],
        taint_refs: &[SecretTaintRef],
    ) -> Result<()> {
        validate_taint_refs(taint_refs)?;
        let at = ResultOccurrence::of(owner, output)?;
        let mut sink = self.code_run_output_sink()?;
        sink.write(raw)?;
        let mut finished = finish_output_sourced(
            output.path.clone(),
            sink,
            true,
            output.input_rows.clone(),
            self.limit_watch(),
            |digest| self.pin_result_body(digest),
        )?;
        finished.output.producing_step_start = output.producing_step_start;
        if finished.output != *output {
            return Err(invalid_code_run_replay(
                "raw output metadata does not match bytes",
            ));
        }
        let key = at.mark_key(&output.handle);
        let mut wtxn = self.store.env.write_txn()?;
        if taint_refs.is_empty() {
            RAW_OUTPUT_TAINTS.delete(&self.store, &mut wtxn, &key)?;
        } else {
            RAW_OUTPUT_TAINTS.put(&self.store, &mut wtxn, &key, &taint_refs.to_vec())?;
        }
        let descriptor = match owner {
            Some(owner) => {
                raw_put_descriptor_in_txn(&self.store, &wtxn, owner, output, &finished.body)?
            }
            None => None,
        };
        self.put_code_run_output_row_in_txn(&mut wtxn, &finished, output, at, owner.is_none())?;
        if let Some(descriptor) = descriptor {
            crate::provenance::body::publish_body_in_txn(&self.store, &mut wtxn, &descriptor)?;
        }
        Ok(wtxn.commit()?)
    }
}

/// The descriptor a raw put of `output` by run `owner` publishes, in the
/// put's transaction (FIX 7364, FIX 7430). It is the owner/path
/// occurrence's own where [`raw_put_publishes_descriptor`] lets that
/// occurrence take the bytes. Elsewhere it is the raw hold
/// `ResultOccurrence::raw` names, published beside the occurrence's
/// descriptor, which stays as it is; the hold's marks stay on the
/// owner/path occurrence the put marked. `None` when that raw hold holds
/// these bytes already and would let them go if replaced: the repeat put
/// publishes nothing. A canonical raw put and a routed Base row both ask
/// it.
///
/// # Errors
///
/// Storage errors, and a raw hold's descriptor that does not decode.
pub(in crate::code_run::storage) fn raw_put_descriptor_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    owner: EntityId,
    output: &CodeRunRawOutput,
    body: &StoredBody,
) -> Result<Option<crate::provenance::body::OwnedBody>> {
    use crate::provenance::body::{OwnedBody, owned_body_in_txn};
    let slot = owned_body(owner, output, body)?;
    let prior = owned_body_in_txn(store, txn, &owner, &slot.occurrence);
    if raw_put_publishes_descriptor(&prior, &slot) {
        return Ok(Some(slot));
    }
    let hold = OwnedBody {
        occurrence: ResultOccurrence::raw(owner, &output.path, &output.raw_blake3)?.id(),
        ..slot
    };
    let hold_prior = owned_body_in_txn(store, txn, &owner, &hold.occurrence)?;
    Ok(raw_put_publishes_descriptor(&Ok(hold_prior), &hold).then_some(hold))
}

/// Whether a raw output put publishes `body`, its owner's descriptor of the
/// bytes, over `prior`, the one that occurrence has now (FIX 7283): only
/// where the owned publisher neither refuses nor lets other bytes go. A
/// complete descriptor is final, so one naming other bytes would refuse the
/// put; an incomplete one holding bytes would release them; a prior that
/// does not read would fail it. Where the owner/path occurrence declines,
/// the put publishes a raw hold instead ([`raw_put_descriptor_in_txn`], FIX
/// 7364), so no raw put that lands today is refused or costs another body
/// its hold.
fn raw_put_publishes_descriptor(
    prior: &Result<Option<crate::provenance::body::OwnedBody>>,
    body: &crate::provenance::body::OwnedBody,
) -> bool {
    use crate::provenance::body::BodyState;
    match prior {
        Ok(None) => true,
        Ok(Some(prior)) => {
            prior == body || matches!(prior.state, BodyState::Incomplete { retained: None })
        }
        Err(_) => false,
    }
}
