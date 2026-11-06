//! Retrieval-telemetry record, trace, signal, and blend-weight types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::retrieval_signal::Signal;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_base::retrieval_quality::ConfidenceAdjustment;
use oneiron_base::retrieval_quality::RetrievalDegradation;
use oneiron_base::retrieval_quality::RetrievalQuality;
use oneiron_base::retrieval_quality::RetrievalQualityReport;
use oneiron_contracts::entity_id::bytes_to_hex_lower;

// The signal and blend-weight vocabulary is defined in `oneiron-contracts` (retrieval's
// fusion scores with it); `From<Signal>` stays here with the pipeline's channel enum.
pub use oneiron_contracts::retrieval_telemetry::{
    RetrievalBlendSignal, RetrievalBlendWeights, RetrievalScoreComponent, RetrievalSignal,
};

impl From<Signal> for RetrievalSignal {
    fn from(signal: Signal) -> Self {
        match signal {
            Signal::Vector => Self::Vector,
            Signal::Text => Self::Text,
            Signal::Phonetic => Self::Phonetic,
            Signal::Temporal => Self::Temporal,
            Signal::Ppr => Self::Ppr,
            Signal::Hyde => Self::Hyde,
        }
    }
}
