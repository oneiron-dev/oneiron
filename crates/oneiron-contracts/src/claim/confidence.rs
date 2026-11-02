//! What a claim's confidence means beyond its number (ARCH-0003, FIX 7761):
//! the hedge band it is read in and the basis that band came from. The
//! number stays the claim's one `conf`; the band and basis are kept beside
//! it, so a reader compares bands and never derives one from a cutoff.

/// The hedge band a confidence is read in, lowest first.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ConfidenceBand {
    Low,
    Medium,
    High,
    Certain,
}

/// The lowest confidence the house table reads as each band above `Low`
/// (the hedge words claim recall has always used: tentative from 0.4,
/// likely from 0.7, confident from 0.9). An open call in
/// engine-calls-review/CALLS.md ("FIX 7761 C1 house confidence band").
const HOUSE_BAND_FLOORS: [(f32, ConfidenceBand); 3] = [
    (0.9, ConfidenceBand::Certain),
    (0.7, ConfidenceBand::High),
    (0.4, ConfidenceBand::Medium),
];

impl ConfidenceBand {
    /// The band a model verdict's confidence, in millionths, falls in by the
    /// verdict table (Medium from 0.5, High from 0.8, Certain from 0.98);
    /// `None` past one.
    #[must_use]
    pub const fn for_verdict_millionths(value: u32) -> Option<Self> {
        match value {
            0..=499_999 => Some(Self::Low),
            500_000..=799_999 => Some(Self::Medium),
            800_000..=979_999 => Some(Self::High),
            980_000..=1_000_000 => Some(Self::Certain),
            _ => None,
        }
    }

    /// The house band of a confidence given as a number alone, by
    /// [`HOUSE_BAND_FLOORS`]. A band from this table has the basis
    /// [`VerdictBasis::DeterministicFallback`]: it says how the number reads,
    /// not that a model was calibrated.
    #[must_use]
    pub fn house(confidence: f32) -> Self {
        HOUSE_BAND_FLOORS
            .iter()
            .find(|(floor, _)| confidence >= *floor)
            .map_or(Self::Low, |(_, band)| *band)
    }

    /// The pinned on-disk string for this band.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Certain => "certain",
        }
    }

    /// Engine seam: `pub` only so `oneiron` can call it across the crate split.
    #[doc(hidden)]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            "certain" => Some(Self::Certain),
            _ => None,
        }
    }
}

/// Where a confidence band came from.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum VerdictBasis {
    /// A calibrated decider gave the band with its number.
    CalibratedModel,
    /// The house table read the band off the number; no model was calibrated.
    DeterministicFallback,
}

impl VerdictBasis {
    /// The pinned on-disk string for this basis.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CalibratedModel => "calibrated_model",
            Self::DeterministicFallback => "deterministic_fallback",
        }
    }

    /// Engine seam: `pub` only so `oneiron` can call it across the crate split.
    #[doc(hidden)]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "calibrated_model" => Some(Self::CalibratedModel),
            "deterministic_fallback" => Some(Self::DeterministicFallback),
            _ => None,
        }
    }
}

const BAND_NAMES: &str = "confidence_band must be one of low|medium|high|certain";
const BASIS_NAMES: &str = "confidence_basis must be one of calibrated_model|deterministic_fallback";

/// The band and basis a producer gives a confidence, beside its number.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ConfidenceDetails {
    /// The band the confidence is read in.
    pub band: ConfidenceBand,
    /// Where the band came from.
    pub basis: VerdictBasis,
}

impl ConfidenceDetails {
    /// The house details of a confidence given as a number alone.
    #[must_use]
    pub fn house(confidence: f32) -> Self {
        Self {
            band: ConfidenceBand::house(confidence),
            basis: VerdictBasis::DeterministicFallback,
        }
    }

    /// The details a binding's two optional names give: both or neither.
    ///
    /// # Errors
    ///
    /// The reason, when only one is given or one names no band or basis.
    pub fn from_names(
        band: Option<&str>,
        basis: Option<&str>,
    ) -> Result<Option<Self>, &'static str> {
        match (band, basis) {
            (None, None) => Ok(None),
            (Some(band), Some(basis)) => Ok(Some(Self {
                band: ConfidenceBand::parse(band).ok_or(BAND_NAMES)?,
                basis: VerdictBasis::parse(basis).ok_or(BASIS_NAMES)?,
            })),
            _ => Err("confidence_band and confidence_basis are given together"),
        }
    }
}
