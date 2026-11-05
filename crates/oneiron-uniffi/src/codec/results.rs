//! Owned result-card shapes and off-record result pages.

use oneiron::memory::result_doors::ResultCard;
use oneiron::task_verb::sdk::OffRecordResultRead;
use serde_json::Value;

use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<ResultCard> for crate::ResultCard {
    fn lift(mut value: ResultCard) -> Result<Self, OneironError> {
        let shape = match value.shape.take() {
            None | Some(Value::Null) => None,
            Some(shape) => Some(WireJson::lift(shape)?),
        };
        let mut output: Self = lift_record("result card", &value)?;
        output.shape = shape;
        Ok(output)
    }
}

impl Lift<OffRecordResultRead> for crate::OffRecordResultRead {
    fn lift(value: OffRecordResultRead) -> Result<Self, OneironError> {
        Ok(match value {
            OffRecordResultRead::Card { card } => Self::Card {
                card: Lift::lift(card)?,
            },
            OffRecordResultRead::Page { facet, page } => {
                let page = WireJson::lift(page)?;
                Self::Page {
                    facet: lift_record("self.off_record.results.read", &facet)?,
                    page,
                }
            }
            OffRecordResultRead::Denied { refusal } => Self::Denied {
                refusal: lift_record("self.off_record.results.read", &refusal)?,
            },
        })
    }
}
