//! The offer a host posts for one GPU class and the quote a job starts on
//! (CROSS-ARCH-0023 lifecycle 01, C3).
use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::llm::run_admission::{JobStartRefused, LeaseUnit, PaidConnector};

use super::GpuJobError;

/// How long a quote may be started on after it was made.
pub const GPU_QUOTE_VALID_MS: u64 = 10 * 60 * 1000;

/// How an offer's price is set (CROSS-ARCH-0023 C3). A GPU class takes one
/// posted price whichever provider serves it, so a GPU offer is
/// [`PriceShape::AtOneironList`]; the quote refuses the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceShape {
    AtOneironList,
    AtVendorList,
    CostPlus,
}

/// One GPU class at a provider and region, as the host's config binds it.
/// `connector.unit_cost` is our posted price for one second of the class, in
/// `connector.cost_unit`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GpuOffer {
    pub name: String,
    pub class: String,
    pub provider: String,
    pub region: String,
    pub connector: PaidConnector,
    pub price_shape: PriceShape,
    /// The provider's list price for one second, when the host knows it. It is
    /// shown beside our price; it never sets it.
    pub list_cost_per_second: Option<u64>,
    pub startup_secs: u64,
    pub teardown_secs: u64,
    pub rounding_secs: u64,
}

/// What a customer asks to run. A missing maximum takes the host's default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobRequest {
    pub job_type: String,
    pub image: String,
    #[serde(default)]
    pub maximum_secs: Option<u64>,
    #[serde(default)]
    pub inputs: serde_json::Value,
}

/// The price of one chunk of a job: the rate times its maximum run time plus
/// startup, teardown and billing rounding. The revision, unit and price freeze
/// here; starting on it reserves `units` whole. A quote names the job it
/// starts, a new one or, for a resume, the stopped job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuJobQuote {
    pub job: EntityId,
    pub offer: String,
    pub job_type: String,
    pub image: String,
    pub inputs: serde_json::Value,
    pub maximum_secs: u64,
    /// Startup, teardown and rounding, in seconds.
    pub overhead_secs: u64,
    /// The seconds reserved: the maximum plus the overhead.
    pub quantity: u64,
    /// The price of one second, in `unit`.
    pub unit_cost: u64,
    /// `quantity` times `unit_cost`: the most this chunk is ever billed.
    pub units: u64,
    pub unit: LeaseUnit,
    pub catalog_revision: Option<String>,
    pub price_shape: PriceShape,
    /// The provider's list price for the same seconds, when known.
    pub list_cost: Option<u64>,
    pub quoted_at_ms: u64,
    pub valid_until_ms: u64,
    /// blake3 over the offer and every term above, hex.
    pub digest: String,
}

/// The digest's input: every term of the quote and the whole offer.
#[derive(Serialize)]
struct QuoteTerms<'a> {
    offer: &'a GpuOffer,
    job: &'a EntityId,
    request: &'a GpuJobRequest,
    maximum_secs: u64,
    quoted_at_ms: u64,
}

impl GpuOffer {
    /// Quotes one chunk of `request` on this offer: a new job, or the next
    /// chunk of the stopped job `resume` names. It writes nothing.
    ///
    /// # Errors
    ///
    /// [`GpuJobError::PriceShape`] for an offer not at our list price,
    /// [`GpuJobError::Start`] for a zero maximum, and
    /// [`GpuJobError::QuoteOverflow`] when the price does not fit.
    pub fn quote(
        &self,
        request: &GpuJobRequest,
        resume: Option<EntityId>,
        default_maximum_secs: u64,
        now_ms: u64,
    ) -> Result<GpuJobQuote, GpuJobError> {
        let job = resume.unwrap_or_else(EntityId::now);
        self.quote_for(job, request, default_maximum_secs, now_ms)
    }

    pub(super) fn quote_for(
        &self,
        job: EntityId,
        request: &GpuJobRequest,
        default_maximum_secs: u64,
        quoted_at_ms: u64,
    ) -> Result<GpuJobQuote, GpuJobError> {
        if self.price_shape != PriceShape::AtOneironList {
            return Err(GpuJobError::PriceShape(self.price_shape));
        }
        let maximum_secs = request.maximum_secs.unwrap_or(default_maximum_secs);
        if maximum_secs == 0 {
            return Err(GpuJobError::Start(JobStartRefused::ZeroMaximum));
        }
        let overhead_secs = self
            .startup_secs
            .checked_add(self.teardown_secs)
            .and_then(|secs| secs.checked_add(self.rounding_secs))
            .ok_or(GpuJobError::QuoteOverflow)?;
        let quantity = maximum_secs
            .checked_add(overhead_secs)
            .ok_or(GpuJobError::QuoteOverflow)?;
        let units = quantity
            .checked_mul(self.connector.unit_cost)
            .ok_or(GpuJobError::QuoteOverflow)?;
        let list_cost = self
            .list_cost_per_second
            .map(|rate| rate.checked_mul(quantity).ok_or(GpuJobError::QuoteOverflow))
            .transpose()?;
        // The digest covers the request with its maximum stated, so a quote
        // on the host's default checks against itself.
        let stated = GpuJobRequest {
            maximum_secs: Some(maximum_secs),
            ..request.clone()
        };
        let terms = QuoteTerms {
            offer: self,
            job: &job,
            request: &stated,
            maximum_secs,
            quoted_at_ms,
        };
        let bytes = crate::llm::canonical_json_bytes(&terms).map_err(|_| {
            GpuJobError::Vault(crate::Error::InvariantViolation("gpu quote encode"))
        })?;
        Ok(GpuJobQuote {
            job,
            offer: self.name.clone(),
            job_type: request.job_type.clone(),
            image: request.image.clone(),
            inputs: request.inputs.clone(),
            maximum_secs,
            overhead_secs,
            quantity,
            unit_cost: self.connector.unit_cost,
            units,
            unit: self.connector.cost_unit.clone(),
            catalog_revision: self.connector.catalog_revision.clone(),
            price_shape: self.price_shape,
            list_cost,
            quoted_at_ms,
            valid_until_ms: quoted_at_ms.saturating_add(GPU_QUOTE_VALID_MS),
            digest: blake3::hash(&bytes).to_hex().to_string(),
        })
    }
}

impl GpuJobQuote {
    /// The request this quote prices, with its maximum stated.
    #[must_use]
    pub fn request(&self) -> GpuJobRequest {
        GpuJobRequest {
            job_type: self.job_type.clone(),
            image: self.image.clone(),
            maximum_secs: Some(self.maximum_secs),
            inputs: self.inputs.clone(),
        }
    }

    /// Checks this quote against `offer` as it stands at `now_ms`: the same
    /// terms quoted again give the same digest, and the quote has not
    /// expired.
    pub(super) fn check(&self, offer: &GpuOffer, now_ms: u64) -> Result<(), GpuJobError> {
        let again = offer.quote_for(
            self.job,
            &self.request(),
            self.maximum_secs,
            self.quoted_at_ms,
        )?;
        if again != *self {
            return Err(GpuJobError::QuoteChanged);
        }
        if now_ms > self.valid_until_ms {
            return Err(GpuJobError::QuoteExpired);
        }
        Ok(())
    }
}
