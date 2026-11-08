//! Owned result-card shapes and off-record result pages.

use oneiron::memory::result_doors::{ResultCard, ResultReadView};
use oneiron::task_verb::sdk::{OffRecordResultCards, OffRecordResultRead};
use serde_json::Value;

use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<ResultCard> for crate::ResultCard {
    fn lift(mut value: ResultCard) -> Result<Self, OneironError> {
        let shape = take_shape(&mut value)?;
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

impl Lift<OffRecordResultCards> for crate::OffRecordResultCards {
    fn lift(mut value: OffRecordResultCards) -> Result<Self, OneironError> {
        let shapes = value.cards.iter_mut().map(take_shape).collect::<Vec<_>>();
        let shapes = shapes.into_iter().collect::<Result<Vec<_>, _>>()?;
        let mut output: Self = lift_record("self.off_record.results.list", &value)?;
        for (card, shape) in output.cards.iter_mut().zip(shapes) {
            card.shape = shape;
        }
        Ok(output)
    }
}

impl Lift<ResultReadView> for crate::ResultReadView {
    fn lift(value: ResultReadView) -> Result<Self, OneironError> {
        Ok(match value {
            ResultReadView::Available { manifest, card } => {
                let card = Lift::lift(card)?;
                Self::Available {
                    manifest: lift_record("vault.results.read", &manifest)?,
                    card,
                }
            }
            ResultReadView::Denied { refusal } => Self::Denied {
                refusal: lift_record("vault.results.read", &refusal)?,
            },
        })
    }
}

fn take_shape(card: &mut ResultCard) -> Result<Option<WireJson>, OneironError> {
    match card.shape.take() {
        None | Some(Value::Null) => Ok(None),
        Some(shape) => WireJson::lift(shape).map(Some),
    }
}
