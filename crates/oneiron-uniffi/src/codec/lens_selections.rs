//! Owned entity bodies in inspection and frame-bound selection replies.

use oneiron::lens::{InspectionResolved, LensSelectionResolved};
use serde_json::Value;

use super::{Lift, OneironError, WireJson, lift_record};

impl Lift<InspectionResolved> for crate::InspectionResolved {
    fn lift(mut value: InspectionResolved) -> Result<Self, OneironError> {
        let body = value.item.as_mut().and_then(|item| item.body.take());
        let body = match body {
            None | Some(Value::Null) => None,
            Some(body) => Some(WireJson::lift(body)?),
        };
        let mut output: Self = lift_record("vault.inspection.resolve", &value)?;
        if let Some(item) = &mut output.item {
            item.body = body;
        }
        Ok(output)
    }
}

impl Lift<LensSelectionResolved> for crate::LensSelectionResolved {
    fn lift(value: LensSelectionResolved) -> Result<Self, OneironError> {
        let LensSelectionResolved { selection, source } = value;
        // The source body is consumed before either finite wrapper can fail.
        let source = crate::InspectionResolved::lift(source)?;
        Ok(Self {
            selection: lift_record("vault.lenses.resolve.selection", &selection)?,
            source,
        })
    }
}
