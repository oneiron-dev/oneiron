//! The immutable prepared PDF and the unissued phase of one seal item.

use super::producer_input::EsignInputBudget;
use super::render::PdfPreparationError;
use super::seal::EsignSealError;
use super::sealer::{EsignSealInput, EsignSealProducer, EsignSealed};
use super::signature_revision::SEAL_CONTENTS_LADDER;
use oneiron_docedit::resource::Resources;

pub(super) struct SealInputProducer<'a> {
    vault: &'a crate::Vault,
    pdf: Vec<u8>,
    operation_id: &'a str,
    now_ms: u64,
    codec_bytes: u64,
    capacities: Vec<usize>,
    observed_stream: bool,
}

impl<'a> SealInputProducer<'a> {
    pub(super) fn new(
        vault: &'a crate::Vault,
        pdf: Vec<u8>,
        operation_id: &'a str,
        now_ms: u64,
        codec_bytes: u64,
    ) -> Self {
        Self {
            vault,
            pdf,
            operation_id,
            now_ms,
            codec_bytes,
            capacities: SEAL_CONTENTS_LADDER.to_vec(),
            observed_stream: false,
        }
    }

    /// The existing ContentsShort policy, not a memory retry. No completed
    /// signature or failed key attempt is inferred to be absent here.
    pub(super) fn rewrite_larger(&mut self, needed: u64) -> Result<bool, PdfPreparationError> {
        let largest = self.capacities.iter().copied().max().unwrap_or(0) as u64;
        if needed <= largest {
            return Ok(false);
        }
        let doubled = largest.checked_mul(2).ok_or(PdfPreparationError::Limit)?;
        let next = needed
            .checked_next_power_of_two()
            .ok_or(PdfPreparationError::Limit)?;
        let capacity = doubled.max(next);
        // The SAME classic xref format bound used by rewrite_larger.
        if capacity > super::signature_revision::MAX_CLASSIC_XREF_OFFSET / 2 {
            return Err(PdfPreparationError::Limit);
        }
        self.capacities = vec![usize::try_from(capacity).map_err(|_| PdfPreparationError::Limit)?];
        Ok(true)
    }
}

impl EsignSealProducer for SealInputProducer<'_> {
    fn source_bytes(&self) -> u64 {
        self.pdf.len() as u64
    }

    fn with_input(
        &mut self,
        resources: &Resources,
        planned_bytes: u64,
        measured_bytes: u64,
        dispatch: &mut dyn FnMut(
            &EsignSealInput,
            &EsignInputBudget,
        ) -> Result<EsignSealed, EsignSealError>,
    ) -> Result<EsignSealed, EsignSealError> {
        let budget = EsignInputBudget::new(resources, planned_bytes, measured_bytes)?;
        let (revisions, stream_bytes) = EsignSealInput::producer_revisions(
            &self.pdf,
            self.operation_id,
            self.now_ms,
            self.codec_bytes,
            &self.capacities,
            &budget,
        )?;
        if !self.observed_stream {
            self.vault.measure_limit(
                crate::limit_ask::EngineLimit::SealPreparedStreamBytes,
                stream_bytes,
            );
            self.observed_stream = true;
        }
        // Only move the immutable source once the entire build succeeded.
        // Any earlier error leaves it intact for the pre-dispatch rebuild.
        let mut input = EsignSealInput {
            pdf: std::mem::take(&mut self.pdf),
            revisions,
        };
        let result = dispatch(&input, &budget);
        self.pdf = std::mem::take(&mut input.pdf);
        drop(input);
        // The callback's handlers/regions and this input have all unwound
        // before budget drops and the host may join a fresh FIFO ticket.
        result
    }
}
