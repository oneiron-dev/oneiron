//! The `vault.gpu.jobs.*` verbs' inputs and answers: plain fields the SDK
//! spells, converted at the door to and from the engine's own types. A quote
//! goes out as [`GpuJobQuoteTerms`] and comes back on start; the start checks
//! it against the offer again, so a changed term is a changed quote.
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::llm::run_admission::LeaseUnit;

use super::{
    GpuEndReason, GpuJob, GpuJobAllowance, GpuJobError, GpuJobQuote, GpuJobRequest, GpuJobState,
    PriceShape,
};

/// `vault.gpu.jobs.quote`: what to run, on which of the host's offers. A
/// missing maximum takes the host's default.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuJobQuoteRequest {
    pub offer: String,
    pub job_type: String,
    pub image: String,
    #[serde(default)]
    pub maximum_secs: Option<u64>,
    #[serde(default)]
    pub inputs: serde_json::Value,
    /// The stopped job (its id, hex) this quotes one more chunk of.
    #[serde(default)]
    pub resume_job: Option<String>,
}

impl GpuJobQuoteRequest {
    /// The engine's request.
    #[must_use]
    pub fn request(&self) -> GpuJobRequest {
        GpuJobRequest {
            job_type: self.job_type.clone(),
            image: self.image.clone(),
            maximum_secs: self.maximum_secs,
            inputs: self.inputs.clone(),
        }
    }
}

/// One chunk's price as the customer sees it: the rate times the maximum plus
/// startup, teardown and rounding, frozen until `valid_until_ms`. Starting
/// on it reserves `units` whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuJobQuoteTerms {
    /// The job it starts (hex): a new one, or the stopped job it resumes.
    pub job: String,
    pub offer: String,
    pub job_type: String,
    pub image: String,
    #[serde(default)]
    pub inputs: serde_json::Value,
    pub maximum_secs: u64,
    pub overhead_secs: u64,
    /// The seconds reserved: the maximum plus the overhead.
    pub quantity: u64,
    /// The price of one second, in `unit`.
    pub unit_cost: u64,
    /// The most this chunk is ever billed.
    pub units: u64,
    pub unit: String,
    pub catalog_revision: Option<String>,
    pub price_shape: PriceShape,
    /// The provider's list price for the same seconds, when the host knows
    /// it.
    pub list_cost: Option<u64>,
    pub quoted_at_ms: u64,
    pub valid_until_ms: u64,
    pub digest: String,
}

impl From<&GpuJobQuote> for GpuJobQuoteTerms {
    fn from(quote: &GpuJobQuote) -> Self {
        Self {
            job: quote.job.to_hex(),
            offer: quote.offer.clone(),
            job_type: quote.job_type.clone(),
            image: quote.image.clone(),
            inputs: quote.inputs.clone(),
            maximum_secs: quote.maximum_secs,
            overhead_secs: quote.overhead_secs,
            quantity: quote.quantity,
            unit_cost: quote.unit_cost,
            units: quote.units,
            unit: quote.unit.as_str().to_owned(),
            catalog_revision: quote.catalog_revision.clone(),
            price_shape: quote.price_shape,
            list_cost: quote.list_cost,
            quoted_at_ms: quote.quoted_at_ms,
            valid_until_ms: quote.valid_until_ms,
            digest: quote.digest.clone(),
        }
    }
}

impl TryFrom<GpuJobQuoteTerms> for GpuJobQuote {
    type Error = GpuJobError;

    /// A term that does not parse is a quote the offer never made: quote
    /// again.
    fn try_from(terms: GpuJobQuoteTerms) -> Result<Self, GpuJobError> {
        let job = EntityId::from_hex(&terms.job).map_err(|_| GpuJobError::QuoteChanged)?;
        let unit = LeaseUnit::new(terms.unit).map_err(|_| GpuJobError::QuoteChanged)?;
        Ok(Self {
            job,
            offer: terms.offer,
            job_type: terms.job_type,
            image: terms.image,
            inputs: terms.inputs,
            maximum_secs: terms.maximum_secs,
            overhead_secs: terms.overhead_secs,
            quantity: terms.quantity,
            unit_cost: terms.unit_cost,
            units: terms.units,
            unit,
            catalog_revision: terms.catalog_revision,
            price_shape: terms.price_shape,
            list_cost: terms.list_cost,
            quoted_at_ms: terms.quoted_at_ms,
            valid_until_ms: terms.valid_until_ms,
            digest: terms.digest,
        })
    }
}

/// `vault.gpu.jobs.start`: the quote the customer saw. With `resume`, it
/// starts the next chunk of the stopped job the quote names, from the
/// checkpoint its stop kept; that works once per stop.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuJobStartRequest {
    pub quote: GpuJobQuoteTerms,
    #[serde(default)]
    pub resume: bool,
}

/// `vault.gpu.jobs.status` and `vault.gpu.jobs.cancel`: one job, by id (hex).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuJobRef {
    pub job: String,
}

impl GpuJobRef {
    /// The job's id.
    ///
    /// # Errors
    ///
    /// [`GpuJobError::NotFound`] for an id that does not parse.
    pub fn id(&self) -> Result<EntityId, GpuJobError> {
        EntityId::from_hex(&self.job).map_err(|_| GpuJobError::NotFound)
    }
}

/// `vault.gpu.jobs.list` takes no input.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuJobListRequest {}

/// The add-funds notice of a stop at the maximum, while its resume stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobStopView {
    pub used_secs: u64,
    pub maximum_secs: u64,
    /// The checkpoint the resume starts from.
    pub checkpoint: String,
    /// The one-tap resume: one more chunk of the job's first maximum,
    /// priced when it stopped. `vault.gpu.jobs.start` takes it with
    /// `resume` while the stop stands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_quote: Option<GpuJobQuoteTerms>,
}

/// `vault.gpu.jobs.allow`: the longest run time, in seconds, one GPU job an
/// agent starts under the Grant `grant` (hex) may declare over all its
/// chunks. 0 removes it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuJobAllowRequest {
    pub grant: String,
    pub maximum_secs: u64,
}

impl GpuJobAllowRequest {
    /// The Grant's id.
    ///
    /// # Errors
    ///
    /// A bad request for an id that does not parse.
    pub fn grant_id(&self) -> Result<EntityId, GpuJobError> {
        EntityId::from_hex(&self.grant).map_err(|_| {
            GpuJobError::Caller(crate::memory::MemoryError::new(
                crate::memory::MEMORY_CODE_BAD_REQUEST,
                "grant must be a Grant id (32 hex)",
                &[],
            ))
        })
    }
}

/// What `vault.gpu.jobs.allow` left beside the Grant: its agent and per-job
/// maximum, or none once removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobAllowanceView {
    pub grant: String,
    /// The agent the Grant names; `None` once removed.
    pub agent: Option<String>,
    /// 0 once removed.
    pub maximum_secs: u64,
    pub set_at_ms: Option<u64>,
}

impl GpuJobAllowanceView {
    /// The view of `allowance` as `vault.gpu.jobs.allow` left it for `grant`.
    #[must_use]
    pub fn of(grant: &EntityId, allowance: Option<&GpuJobAllowance>) -> Self {
        Self {
            grant: grant.to_hex(),
            agent: allowance.map(|row| row.agent.to_hex()),
            maximum_secs: allowance.map_or(0, |row| row.maximum_secs),
            set_at_ms: allowance.map(|row| row.set_at_ms),
        }
    }
}

/// Where one job stands: its state, its run time and spend against its
/// maximum, the checkpoint signals it was sent, the warning and checkpoint
/// that make a stop lawful, and its stop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobStatus {
    pub job: String,
    /// `reserved`, `running`, `ending`, `stopped`, `ended` or `held`.
    pub state: String,
    /// Why it ended or is ending: `exited`, `at_maximum`, `cancelled` or
    /// `gone`.
    pub end_reason: Option<String>,
    /// Why the provider refused its chunk, for a held job.
    pub held_reason: Option<String>,
    pub offer: String,
    pub class: String,
    pub provider: String,
    pub region: String,
    pub job_type: String,
    pub image: String,
    /// The job's maximum run time over all its chunks.
    pub maximum_secs: u64,
    /// Its run time over all its chunks.
    pub used_secs: u64,
    pub chunks: u32,
    /// The money unit of its quotes.
    pub unit: String,
    /// The most its chunks can be billed: the sum of their quotes.
    pub quoted_units: u64,
    /// What its ended chunks were billed.
    pub settled_units: u64,
    /// The checkpoint percents the running chunk was told, in order.
    pub signalled_percents: Vec<u8>,
    /// The 95 percent warning reached the customer's inbox.
    pub warning_delivered: bool,
    /// The checkpoint a stop at the maximum would keep.
    pub checkpoint: Option<String>,
    pub stop: Option<GpuJobStopView>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

impl From<&GpuJob> for GpuJobStatus {
    fn from(job: &GpuJob) -> Self {
        let (state, end_reason, held_reason) = match &job.state {
            GpuJobState::Reserved => ("reserved", None, None),
            GpuJobState::Running => ("running", None, None),
            GpuJobState::Ending { reason } => ("ending", Some(*reason), None),
            GpuJobState::Stopped => ("stopped", Some(GpuEndReason::AtMaximum), None),
            GpuJobState::Ended { reason } => ("ended", Some(*reason), None),
            GpuJobState::Held { reason } => ("held", None, Some(reason.clone())),
        };
        let chunk = job.chunk();
        Self {
            job: job.id.to_hex(),
            state: state.to_owned(),
            end_reason: end_reason.map(|reason| end_reason_name(reason).to_owned()),
            held_reason,
            offer: job.offer.name.clone(),
            class: job.offer.class.clone(),
            provider: job.offer.provider.clone(),
            region: job.offer.region.clone(),
            job_type: job.job_type.clone(),
            image: job.image.clone(),
            maximum_secs: job.maximum.maximum().units,
            used_secs: job.maximum.used_units(),
            chunks: u32::try_from(job.chunks.len()).unwrap_or(u32::MAX),
            unit: chunk
                .map(|chunk| chunk.quote.unit.as_str().to_owned())
                .unwrap_or_default(),
            quoted_units: job
                .chunks
                .iter()
                .fold(0, |sum: u64, chunk| sum.saturating_add(chunk.quote.units)),
            settled_units: job.chunks.iter().fold(0, |sum: u64, chunk| {
                sum.saturating_add(chunk.settled_units.unwrap_or(0))
            }),
            signalled_percents: chunk
                .map(|chunk| chunk.signalled_percents.clone())
                .unwrap_or_default(),
            warning_delivered: job.maximum.warning_delivered(),
            checkpoint: job
                .maximum
                .counted_checkpoint()
                .map(|checkpoint| checkpoint.0.clone()),
            stop: job.stop.as_ref().map(|stop| GpuJobStopView {
                used_secs: stop.notice.used_units,
                maximum_secs: stop.notice.maximum.units,
                checkpoint: stop.notice.checkpoint.0.clone(),
                resume_quote: job.resume_quote.as_ref().map(GpuJobQuoteTerms::from),
            }),
            created_at_ms: job.created_at_ms,
            updated_at_ms: job.updated_at_ms,
        }
    }
}

/// The wire name of an end reason, as the record spells it.
fn end_reason_name(reason: GpuEndReason) -> &'static str {
    match reason {
        GpuEndReason::Exited => "exited",
        GpuEndReason::AtMaximum => "at_maximum",
        GpuEndReason::Cancelled => "cancelled",
        GpuEndReason::Gone => "gone",
    }
}

/// `vault.gpu.jobs.list`: every GPU job of the vault, newest first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobList {
    pub jobs: Vec<GpuJobStatus>,
}
