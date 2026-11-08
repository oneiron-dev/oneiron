//! The seal's input is built inside its original admitted host call.

use super::observe::{call_size, read_sized_call};
use super::*;
use crate::host::{CallMeasure, Lent, LentRegion};
use oneiron::blob_artifact::esign::render::PdfPreparationError;
use oneiron::blob_artifact::esign::{EsignSealError, EsignSealProducer};
use oneiron_docedit::resource::RESERVE_STEP;

impl HostedSealer<'_> {
    pub(super) fn seal_produced(
        &self,
        request: &EsignSealRequest,
        producer: &mut dyn EsignSealProducer,
    ) -> Result<EsignSealed, EsignSealError> {
        self.asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        // Freeze the original checked header and normal moving clock once.
        let start = self
            .host
            .start_producer(self.call(VERB_SEAL, SEAL_SCHEMA, Value::Nil))
            .map_err(host_failure)?;
        let now_ms = self.now_ms();
        let mut lent_bytes = producer.source_bytes();
        let mut planned = 0;
        let mut measured = 0;
        loop {
            let mut witness = None;
            let mut dispatched = false;
            // Every resource clone belongs to this lexical phase. They all
            // drop BEFORE the next full admission joins its FIFO tail.
            let result = {
                let mut size = call_size(lent_bytes);
                // Book the complete producer pool at the same class FIFO
                // admission, not by growing a smaller live permit later.
                size.booking = size.booking.max(planned);
                let mut admitted = Some(start.admit(size).map_err(host_failure)?);
                let resources = admitted
                    .as_ref()
                    .expect("new admission")
                    .resources()
                    .clone();
                producer.with_input(&resources, planned, measured, &mut |input, budget| {
                    let actual_lent = input
                        .revisions
                        .iter()
                        .try_fold(input.pdf.len() as u64, |total, revision| {
                            total.checked_add(revision.suffix.len() as u64)
                        })
                        .ok_or(PdfPreparationError::Limit)?;
                    if actual_lent > lent_bytes {
                        return Err(EsignSealError::ProducerBooking {
                            lent_bytes: actual_lent,
                        });
                    }
                    let call = SealCall::new(self.keys, &request.operation_id, input)?;
                    let identity = Identity { call: &call };
                    let sign = Sign { call: &call };
                    let fetch = TimedFetch {
                        timeout: self.settings.fetch_timeout,
                        vault: self.vault,
                    };
                    let memory = MemoryGrow;
                    let handlers = AskHandlers::none()
                        .with(ASK_IDENTITY, &identity)
                        .with(ASK_SIGN, &sign)
                        .with(ASK_NET_FETCH, &fetch)
                        .with(ASK_MEMORY_GROW, &memory);
                    let _publish = Publish {
                        asked: &self.asked,
                        handlers: &handlers,
                    };
                    let args = to_value(&SealArgs {
                        operation_id: request.operation_id.clone(),
                        profile: request.profile,
                        now_ms,
                        config: self.config(true)?,
                        signature_revisions: call.revision_args(),
                    })
                    .map_err(|_| reply_invalid())?;
                    measure_operation_id(self.vault, &request.operation_id);
                    measure_input(self.vault, &input.pdf);

                    // No PDF Vec clone and no cached input survives the call.
                    // Each actual region/copy is admitted before allocation.
                    let suffix_len = actual_lent - input.pdf.len() as u64;
                    budget.take(suffix_len)?;
                    let suffixes = call.suffixes();
                    budget.allocated(suffix_len, suffixes.capacity() as u64)?;
                    budget.take(input.pdf.len() as u64)?;
                    let pdf = LentRegion::copy_from(&input.pdf, PDF)
                        .map_err(|error| host_failure(HostError::Io(error)))?;
                    budget.take(suffixes.len() as u64)?;
                    let revisions = LentRegion::copy_from(&suffixes, REVISIONS)
                        .map_err(|error| host_failure(HostError::Io(error)))?;
                    let capacity = suffixes.capacity() as u64;
                    drop(suffixes);
                    budget.release(capacity);
                    budget.materialized()?;
                    let lent = vec![Lent::Region(pdf), Lent::Region(revisions)];
                    let mut measure = CallMeasure::default();
                    let phase = admitted.take().ok_or_else(|| EsignSealerError::Fatal {
                        stage: "input_validation".to_owned(),
                        code: "producer_already_dispatched".to_owned(),
                    })?;
                    // From this point even a failed key attempt is
                    // irreversible. No later error enters the rebuild arm.
                    dispatched = true;
                    let called =
                        phase.dispatch(self.vault, args, lent, &handlers, size, &mut measure);
                    measure_asks(self.vault, &handlers.asked());
                    let (reply, outcome) = read_sized_call(
                        self.vault,
                        called.map(|(outcome, _deadline)| outcome),
                        &measure,
                    )?;
                    let (evidence_sha256, requested, achieved, degraded, self_verify) =
                        match from_value(&reply)? {
                            SealReply::Failed(failure) => {
                                return Err(failure.into_error(self.vault).into());
                            }
                            SealReply::Sealed {
                                evidence_sha256,
                                requested,
                                achieved,
                                degraded,
                                self_verify,
                            } => (evidence_sha256, requested, achieved, degraded, self_verify),
                        };
                    measure_report(self.vault, &self_verify.report_json);
                    let sealed = outcome
                        .outputs
                        .iter()
                        .find(|output| output.name == SEALED_OUTPUT && output.media_type == PDF)
                        .ok_or_else(reply_invalid)?;
                    let admitted_revision =
                        call.admit(sealed, request.profile >= SealProfile::BaselineLt)?;
                    let evidence: [u8; 32] = Sha256::digest(&sealed[..]).into();
                    if evidence_sha256.as_slice() != evidence {
                        return Err(reply_invalid().into());
                    }
                    let bytes = sealed.to_vec();
                    drop(outcome);
                    measure_output(self.vault, &input.pdf, &bytes);
                    witness = Some(admitted_revision);
                    Ok(EsignSealed {
                        bytes,
                        evidence_sha256: evidence,
                        requested,
                        achieved,
                        degraded,
                        self_verify: self_verify.into_verdict(),
                    })
                })
            };
            match result {
                Err(EsignSealError::Prepare(PdfPreparationError::InputReservation {
                    needed,
                    measured: actual,
                })) if !dispatched => {
                    planned = needed.max(RESERVE_STEP);
                    measured = actual;
                }
                Err(EsignSealError::ProducerBooking { lent_bytes: actual }) if !dispatched => {
                    lent_bytes = actual;
                }
                result => {
                    let sealed = result?;
                    let witness = witness.ok_or_else(reply_invalid)?;
                    // All producer input/region/model/room reservations are
                    // now free, before the independent verifier books room.
                    self.admit_fresh(&sealed.bytes, &witness, sealed.achieved, request.profile)?;
                    return Ok(sealed);
                }
            }
        }
    }
}
