//! The per-route calibration report and the fitted maps it carries. Each fitted value it shows
//! stands beside the raw probability it came from.

use crate::EntityId;
use crate::llm::decision::ProviderPin;
use crate::llm::decision::questions::{DecisionRoute, RoutingPolicy};
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::llm::decision::questions::route_calibration::report::{
    AcceptanceAtCut, CalibrationMetrics, CalibrationPairRef, MapKnot, RouteCalibrationGroup,
    RouteCalibrationMap, RouteCalibrationReport, RouteFit, RouteFitRefusal, RouteGroupKey,
};
