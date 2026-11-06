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
    /// publishes the body as that owner's occurrence, so erasing the owner
    /// releases it, and the row takes no hold of its own; a hold its row
    /// kept before stays (FIX 7283). With none, or where
    /// `raw_put_publishes_descriptor` keeps the put as it was, no
    /// descriptor is published and the row holds its body on its own (FIX
    /// 5399b).
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
        let finished = finish_output_sourced(
            output.path.clone(),
            sink,
            true,
            output.input_rows.clone(),
            self.limit_watch(),
            |digest| self.pin_result_body(digest),
        )?;
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
        let publishes = match owner {
            Some(owner) => {
                let body = owned_body(owner, output, &finished.body)?;
                let prior = crate::provenance::body::owned_body_in_txn(
                    &self.store,
                    &wtxn,
                    &owner,
                    &body.occurrence,
                );
                raw_put_publishes_descriptor(&prior, &body)
            }
            None => false,
        };
        if publishes {
            self.put_code_run_output_in_txn(&mut wtxn, &finished, output, owner)?;
        } else {
            self.put_code_run_output_row_in_txn(&mut wtxn, &finished, output, at, true)?;
        }
        Ok(wtxn.commit()?)
    }
}

/// Whether a raw output put publishes `body`, its owner's descriptor of the
/// bytes, over `prior`, the one that occurrence has now (FIX 7283): only
/// where the owned publisher neither refuses nor lets other bytes go. A
/// complete descriptor is final, so one naming other bytes would refuse the
/// put; an incomplete one holding bytes would release them; a prior that
/// does not read would fail it. There the put stays as it was, its row
/// holding its body on its own with no descriptor (FIX 5399b), so no raw
/// put that lands today is refused or costs another body its hold. A
/// session row an on-record route writes in base asks it too (FIX 7363).
pub(in crate::code_run::storage) fn raw_put_publishes_descriptor(
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
