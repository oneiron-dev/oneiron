//! What one seal or verification call measured, against the engine's
//! `[limits]` rows (OF-520, Rule 5). Nothing here refuses: past a row the
//! vault asks whether everything is okay, and the call is served whole. The
//! organ's own size checks are format bounds only, and its call runs at a
//! size taken from what it is lent, never a fixed grant the input must fit.

use oneiron::Vault;
use oneiron::blob_artifact::esign::EsignSealerError;
use oneiron::limit_ask::EngineLimit;
use serde::Deserialize;

use oneiron_organ_protocol::seal::backend_operation_id;
use oneiron_organ_protocol::{ASK_MEMORY_GROW, ASK_NET_FETCH, ByteBuf};

use super::{ASK_IDENTITY, ASK_SIGN, HostedSealer};
use crate::handlers::AskHandlers;
use crate::host::{CallMeasure, CallSize};
use crate::outcome::OrganOutcome;
use crate::receipt::AskReceipt;
use crate::spec::{LentInput, OrganCall};

impl HostedSealer<'_> {
    /// One seal-organ call, in a process of its own sized by what it lends.
    /// Its frames and the organ's counts are measured before its outcome is
    /// read, a native failure's included; the report returned holds only
    /// the outcome.
    pub(super) fn sized_call(
        &self,
        call: OrganCall,
        lent: Vec<LentInput>,
        handlers: &AskHandlers<'_>,
    ) -> Result<(rmpv::Value, OrganOutcome), EsignSealerError> {
        let lent_bytes = lent.iter().map(|input| input.bytes.len() as u64).sum();
        let mut measure = CallMeasure::default();
        let called = self.host.call_sized_with(
            self.vault,
            call,
            lent,
            handlers,
            call_size(lent_bytes),
            &mut measure,
        );
        measure_frames(self.vault, &measure);
        let mut outcome = called.map_err(super::host_failure)?;
        let report = std::mem::replace(&mut outcome.report, rmpv::Value::Nil);
        let (reply, observed) = Observed::split(report);
        observed.measure(self.vault);
        Ok((reply, outcome))
    }
}

/// What a seal or verification call books, and the memory grant of its
/// own process, per byte it lends: its input lent once, the parsed
/// revisions and their copies beside it, the output and the verifier's
/// parse of it. One pair sizes every seal call (CALLS: seal call size).
const CALL_BYTES_PER_LENT_BYTE: u64 = 8;
/// What a seal or verification call books before its first lent byte:
/// the old fixed booking.
const CALL_BASE_BYTES: u64 = 256 << 20;

/// The size of a call that lends `lent` bytes. The host never gives it
/// less than the install grant.
fn call_size(lent: u64) -> CallSize {
    let bytes = lent
        .saturating_mul(CALL_BYTES_PER_LENT_BYTE)
        .saturating_add(CALL_BASE_BYTES);
    CallSize {
        booking: bytes,
        process: bytes,
    }
}

/// What the organ's native analysis counted, beside its report's outcome
/// (`observed`). A report without one counted nothing.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Observed {
    pdf_objects: u64,
    raw_definitions: u64,
    structural_work: u64,
    revisions: u64,
    prefix_bytes: u64,
    dss_decode_bytes: u64,
    stream_decode_bytes: u64,
    stream_header_tokens: u64,
    pdf_depth: u64,
    security_name_hops: u64,
    reference_hops: u64,
    dss_reference_work: u64,
    field_tree_work: u64,
    contents_bytes: u64,
}

impl Observed {
    /// The report's outcome, with the `observed` entry beside it taken out.
    fn split(report: rmpv::Value) -> (rmpv::Value, Self) {
        match report {
            rmpv::Value::Map(entries) => {
                let (observed, outcome): (Vec<_>, Vec<_>) = entries
                    .into_iter()
                    .partition(|(key, _)| key.as_str() == Some("observed"));
                let observed = observed
                    .into_iter()
                    .find_map(|(_, value)| super::from_value(&value).ok())
                    .unwrap_or_default();
                (rmpv::Value::Map(outcome), observed)
            }
            other => (other, Self::default()),
        }
    }

    /// Asks each row the counts crossed.
    fn measure(&self, vault: &Vault) {
        for (row, measured) in [
            (EngineLimit::SealPdfObjects, self.pdf_objects),
            (EngineLimit::SealRawDefinitions, self.raw_definitions),
            (EngineLimit::SealStructuralWork, self.structural_work),
            (EngineLimit::SealRevisions, self.revisions),
            (EngineLimit::SealPrefixBytes, self.prefix_bytes),
            (EngineLimit::SealDssDecodeBytes, self.dss_decode_bytes),
            (EngineLimit::SealStreamDecodeBytes, self.stream_decode_bytes),
            (
                EngineLimit::SealStreamHeaderTokens,
                self.stream_header_tokens,
            ),
            (EngineLimit::SealPdfDepth, self.pdf_depth),
            (EngineLimit::SealSecurityNameHops, self.security_name_hops),
            (EngineLimit::SealReferenceHops, self.reference_hops),
            (EngineLimit::SealDssReferenceWork, self.dss_reference_work),
            (EngineLimit::SealFieldTreeWork, self.field_tree_work),
            (EngineLimit::SealContentsBytes, self.contents_bytes),
        ] {
            vault.measure_limit(row, measured);
        }
    }
}

/// Asks the frame rows what the call's frames carried, as encoded: the
/// largest the host sent, and the largest the organ sent back.
fn measure_frames(vault: &Vault, measure: &CallMeasure) {
    vault.measure_limit(EngineLimit::SealCallFrameBytes, measure.largest_sent_frame);
    vault.measure_limit(
        EngineLimit::SealReplyFrameBytes,
        measure.largest_received_frame,
    );
}

/// Asks the seal's ask rows what one seal call asked, by its receipt
/// lines: the identity, signatures and fetches, all of them, and the
/// answer bytes it was lent. None of them was refused for its count. Its
/// memory asks, the organ reserving its own buffers, are resource control:
/// they have a row of their own, and neither the functional asks nor their
/// answer bytes count them (FIX 8453).
pub(super) fn measure_asks(vault: &Vault, asked: &[AskReceipt]) {
    let count = |verb: &str| asked.iter().filter(|line| line.verb == verb).count() as u64;
    let functional = || asked.iter().filter(|line| line.verb != ASK_MEMORY_GROW);
    let lent = functional().map(|line| line.answer_len).sum::<u64>();
    for (row, measured) in [
        (EngineLimit::SealIdentityAsks, count(ASK_IDENTITY)),
        (EngineLimit::SealSignAsks, count(ASK_SIGN)),
        (EngineLimit::SealFetchAsks, count(ASK_NET_FETCH)),
        (EngineLimit::SealAsks, functional().count() as u64),
        (EngineLimit::SealAnswerBytes, lent),
        (EngineLimit::SealMemoryAsks, count(ASK_MEMORY_GROW)),
    ] {
        vault.measure_limit(row, measured);
    }
}

/// Asks the report row what one verdict's report JSON holds: it came whole.
pub(super) fn measure_report(vault: &Vault, report_json: &ByteBuf) {
    vault.measure_limit(EngineLimit::SealReportJsonBytes, report_json.len() as u64);
}

/// Bytes the seal's own suffix takes on a backend operation id
/// (`:{16 hex}:{phase}:{capacity}`).
const OPERATION_ID_SUFFIX_BYTES: u64 = 32;

/// Asks the operation id rows what one seal's caller id holds, and what the
/// longest id the seal sends its backend for it holds, its suffix counted
/// (FIX 6271). Neither refuses: a long id reaches the backend as its alias.
pub(super) fn measure_operation_id(vault: &Vault, operation_id: &str) {
    vault.measure_limit(EngineLimit::SealOperationIdBytes, operation_id.len() as u64);
    vault.measure_limit(
        EngineLimit::SealBackendOperationIdBytes,
        backend_operation_id(operation_id).len() as u64 + OPERATION_ID_SUFFIX_BYTES,
    );
}

/// Asks the input row what one lent PDF holds.
pub(super) fn measure_input(vault: &Vault, pdf: &[u8]) {
    vault.measure_limit(EngineLimit::EsignPdfBytes, pdf.len() as u64);
}

/// Asks the output rows what a sealed PDF the host accepted holds, and what
/// it grew by over the prepared one.
pub(super) fn measure_output(vault: &Vault, prepared: &[u8], sealed: &[u8]) {
    let len = sealed.len() as u64;
    vault.measure_limit(EngineLimit::SealOutputBytes, len);
    vault.measure_limit(
        EngineLimit::SealGrowthBytes,
        len.saturating_sub(prepared.len() as u64),
    );
}
