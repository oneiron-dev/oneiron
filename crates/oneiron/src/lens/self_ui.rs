//! The `self.ui` control family: the [`SelfUiControl`] enum, its six control
//! payloads, and the action/value types they embed. Controls are the only atoms
//! that can carry an action declaration or a `$bind` descriptor, so the
//! interactivity rules in [`super::generated_ui`] resolve against this file.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::{Error, Result};

use super::atom::{FiniteF64, LensText};
use super::generated_ui::{SelfUiBindableProperty, SelfUiStateValue};
use super::validate::{
    LensBudget, validate_lens_collection_len, validate_selected_option, validate_self_ui_options,
};
use super::wire_ids::{LensHandleName, SelfUiActionId, SelfUiControlId, SelfUiOptionValue};
use super::wire_limits::{deserialize_limited_vec, serialize_tagged};

/// Fraction of one slider step a value may sit off the grid before it is rejected.
const SLIDER_STEP_TOLERANCE: f64 = 1e-6;

#[derive(Debug, Clone, PartialEq)]
pub enum SelfUiControl {
    Button(ButtonControl),
    Toggle(ToggleControl),
    Segmented(SegmentedControl),
    Select(SelectControl),
    Slider(SliderControl),
    TextInput(TextInputControl),
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "control",
    content = "props",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum SelfUiControlWire {
    Button(ButtonControl),
    Toggle(ToggleControl),
    Segmented(SegmentedControl),
    Select(SelectControl),
    Slider(SliderControl),
    TextInput(TextInputControl),
}

impl From<SelfUiControlWire> for SelfUiControl {
    fn from(value: SelfUiControlWire) -> Self {
        match value {
            SelfUiControlWire::Button(control) => Self::Button(control),
            SelfUiControlWire::Toggle(control) => Self::Toggle(control),
            SelfUiControlWire::Segmented(control) => Self::Segmented(control),
            SelfUiControlWire::Select(control) => Self::Select(control),
            SelfUiControlWire::Slider(control) => Self::Slider(control),
            SelfUiControlWire::TextInput(control) => Self::TextInput(control),
        }
    }
}

impl<'de> Deserialize<'de> for SelfUiControl {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let control = Self::from(SelfUiControlWire::deserialize(deserializer)?);
        control.validate().map_err(de::Error::custom)?;

        let mut budget = LensBudget::default();
        control
            .count_collection_items(&mut budget)
            .map_err(de::Error::custom)?;

        Ok(control)
    }
}

impl Serialize for SelfUiControl {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Button(props) => {
                serialize_tagged(serializer, "control", "button", "props", props)
            }
            Self::Toggle(props) => {
                serialize_tagged(serializer, "control", "toggle", "props", props)
            }
            Self::Segmented(props) => {
                serialize_tagged(serializer, "control", "segmented", "props", props)
            }
            Self::Select(props) => {
                serialize_tagged(serializer, "control", "select", "props", props)
            }
            Self::Slider(props) => {
                serialize_tagged(serializer, "control", "slider", "props", props)
            }
            Self::TextInput(props) => {
                serialize_tagged(serializer, "control", "text_input", "props", props)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ButtonControl {
    pub id: SelfUiControlId,
    pub label: LensText,
    pub action: SelfUiAction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToggleControl {
    pub id: SelfUiControlId,
    pub label: LensText,
    pub checked: bool,
    pub action: SelfUiAction,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SegmentedControl {
    pub id: SelfUiControlId,
    pub label: LensText,
    pub options: Vec<SelfUiOption>,
    #[serde(default)]
    pub selected: Option<SelfUiOptionValue>,
    pub action: SelfUiAction,
}

impl<'de> Deserialize<'de> for SegmentedControl {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SegmentedControlWire {
            id: SelfUiControlId,
            label: LensText,
            #[serde(deserialize_with = "deserialize_limited_vec")]
            options: Vec<SelfUiOption>,
            #[serde(default)]
            selected: Option<SelfUiOptionValue>,
            action: SelfUiAction,
        }

        let wire = SegmentedControlWire::deserialize(deserializer)?;
        let control = Self {
            id: wire.id,
            label: wire.label,
            options: wire.options,
            selected: wire.selected,
            action: wire.action,
        };
        control.validate().map_err(de::Error::custom)?;
        Ok(control)
    }
}

impl SegmentedControl {
    fn validate(&self) -> Result<()> {
        validate_self_ui_options("segmented control options", &self.options)?;
        validate_selected_option(
            "segmented control selected value",
            &self.options,
            self.selected.as_ref(),
        )?;
        self.action.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SelectControl {
    pub id: SelfUiControlId,
    pub label: LensText,
    pub options: Vec<SelfUiOption>,
    #[serde(default)]
    pub selected: Option<SelfUiOptionValue>,
    pub action: SelfUiAction,
}

impl<'de> Deserialize<'de> for SelectControl {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SelectControlWire {
            id: SelfUiControlId,
            label: LensText,
            #[serde(deserialize_with = "deserialize_limited_vec")]
            options: Vec<SelfUiOption>,
            #[serde(default)]
            selected: Option<SelfUiOptionValue>,
            action: SelfUiAction,
        }

        let wire = SelectControlWire::deserialize(deserializer)?;
        let control = Self {
            id: wire.id,
            label: wire.label,
            options: wire.options,
            selected: wire.selected,
            action: wire.action,
        };
        control.validate().map_err(de::Error::custom)?;
        Ok(control)
    }
}

impl SelectControl {
    fn validate(&self) -> Result<()> {
        validate_self_ui_options("select control options", &self.options)?;
        validate_selected_option(
            "select control selected value",
            &self.options,
            self.selected.as_ref(),
        )?;
        self.action.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SliderControl {
    pub id: SelfUiControlId,
    pub label: LensText,
    pub min: FiniteF64,
    pub max: FiniteF64,
    pub step: FiniteF64,
    pub value: FiniteF64,
    pub action: SelfUiAction,
}

impl SliderControl {
    fn validate(&self) -> Result<()> {
        if self.min.get() > self.max.get() {
            return Err(Error::InvalidConfig(
                "self.ui slider min must be less than or equal to max".to_string(),
            ));
        }
        if self.step.get() <= 0.0 {
            return Err(Error::InvalidConfig(
                "self.ui slider step must be positive".to_string(),
            ));
        }
        if !self.admits(self.value.get()) {
            return Err(Error::InvalidConfig(
                "self.ui slider value must be within min and max and land on the step grid"
                    .to_string(),
            ));
        }
        self.action.validate()
    }

    /// Whether a number is one this slider can actually hold: inside the declared range
    /// and on the declared step grid. The grid residual is measured against a millionth
    /// of one step so decimal steps such as `0.1` survive binary rounding.
    ///
    /// Only meaningful once `validate` has established `min <= max` and `step > 0`.
    fn admits(&self, value: f64) -> bool {
        if value < self.min.get() || value > self.max.get() {
            return false;
        }
        let step = self.step.get();
        let offset = value - self.min.get();
        let steps = offset / step;
        steps.is_finite() && (offset - steps.round() * step).abs() <= step * SLIDER_STEP_TOLERANCE
    }
}

impl<'de> Deserialize<'de> for SliderControl {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SliderControlWire {
            id: SelfUiControlId,
            label: LensText,
            min: FiniteF64,
            max: FiniteF64,
            step: FiniteF64,
            value: FiniteF64,
            action: SelfUiAction,
        }

        let wire = SliderControlWire::deserialize(deserializer)?;
        let slider = Self {
            id: wire.id,
            label: wire.label,
            min: wire.min,
            max: wire.max,
            step: wire.step,
            value: wire.value,
            action: wire.action,
        };
        slider.validate().map_err(de::Error::custom)?;
        Ok(slider)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextInputControl {
    pub id: SelfUiControlId,
    pub label: LensText,
    #[serde(default)]
    pub placeholder: Option<LensText>,
    #[serde(default)]
    pub value: Option<LensText>,
    pub action: SelfUiAction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfUiOption {
    pub value: SelfUiOptionValue,
    pub label: LensText,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfUiAction {
    pub command: SelfUiActionId,
    #[serde(default, deserialize_with = "deserialize_limited_vec")]
    pub args: Vec<SelfUiValue>,
}

impl<'de> Deserialize<'de> for SelfUiAction {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct SelfUiActionWire {
            command: SelfUiActionId,
            #[serde(default, deserialize_with = "deserialize_limited_vec")]
            args: Vec<SelfUiValue>,
        }

        let wire = SelfUiActionWire::deserialize(deserializer)?;
        let action = Self {
            command: wire.command,
            args: wire.args,
        };
        action.validate().map_err(de::Error::custom)?;
        Ok(action)
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(
    tag = "type",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SelfUiValue {
    Bool(bool),
    Number(FiniteF64),
    Text(LensText),
    Token(SelfUiOptionValue),
    Handle(LensHandleName),
}

impl Serialize for SelfUiValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Bool(value) => serialize_tagged(serializer, "type", "bool", "value", value),
            Self::Number(value) => serialize_tagged(serializer, "type", "number", "value", value),
            Self::Text(value) => serialize_tagged(serializer, "type", "text", "value", value),
            Self::Token(value) => serialize_tagged(serializer, "type", "token", "value", value),
            Self::Handle(value) => serialize_tagged(serializer, "type", "handle", "value", value),
        }
    }
}

impl SelfUiControl {
    /// The single engine-declared action embedded in this control.
    #[must_use]
    pub fn action(&self) -> &SelfUiAction {
        match self {
            Self::Button(control) => &control.action,
            Self::Toggle(control) => &control.action,
            Self::Segmented(control) => &control.action,
            Self::Select(control) => &control.action,
            Self::Slider(control) => &control.action,
            Self::TextInput(control) => &control.action,
        }
    }

    /// The value domain a `$bind` may drive on *this* control. Type agreement is not
    /// enough: a bound token has to name one of the control's own options, and a bound
    /// slider value has to satisfy the same range and step rule the slider declares for
    /// itself. Every other control property is fully described by its type.
    pub(super) fn accepts_bound_value(
        &self,
        property: SelfUiBindableProperty,
        value: &SelfUiStateValue,
    ) -> Result<()> {
        match (self, property, value) {
            (
                Self::Select(SelectControl { options, .. })
                | Self::Segmented(SegmentedControl { options, .. }),
                SelfUiBindableProperty::Selected,
                SelfUiStateValue::Token(token),
            ) => {
                validate_selected_option("generated-ui $bind selected value", options, Some(token))
            }
            (
                Self::Slider(slider),
                SelfUiBindableProperty::Value,
                SelfUiStateValue::Number(number),
            ) => {
                if slider.admits(number.get()) {
                    Ok(())
                } else {
                    Err(Error::InvalidConfig(
                        "generated-ui $bind must keep a slider value inside its declared min, max, and step"
                            .to_string(),
                    ))
                }
            }
            (Self::Slider(_), SelfUiBindableProperty::Value, _) => Err(Error::InvalidConfig(
                "generated-ui $bind must drive a slider value with a number".to_string(),
            )),
            _ => Ok(()),
        }
    }

    pub(super) fn fallback_text(&self) -> String {
        match self {
            Self::Button(control) => control.label.as_str().to_string(),
            Self::Toggle(control) => control.label.as_str().to_string(),
            Self::Segmented(control) => control.label.as_str().to_string(),
            Self::Select(control) => control.label.as_str().to_string(),
            Self::Slider(control) => control.label.as_str().to_string(),
            Self::TextInput(control) => control.label.as_str().to_string(),
        }
    }

    pub(super) fn validate(&self) -> Result<()> {
        match self {
            Self::Button(control) => control.action.validate(),
            Self::Toggle(control) => control.action.validate(),
            Self::Segmented(control) => control.validate(),
            Self::Select(control) => control.validate(),
            Self::Slider(control) => control.validate(),
            Self::TextInput(control) => control.action.validate(),
        }
    }

    pub(super) fn count_collection_items(&self, budget: &mut LensBudget) -> Result<()> {
        match self {
            Self::Button(control) => {
                budget.add_collection("self.ui action args", control.action.args.len())
            }
            Self::Toggle(control) => {
                budget.add_collection("self.ui action args", control.action.args.len())
            }
            Self::Segmented(control) => {
                budget.add_collection("segmented control options", control.options.len())?;
                budget.add_collection("self.ui action args", control.action.args.len())
            }
            Self::Select(control) => {
                budget.add_collection("select control options", control.options.len())?;
                budget.add_collection("self.ui action args", control.action.args.len())
            }
            Self::Slider(control) => {
                budget.add_collection("self.ui action args", control.action.args.len())
            }
            Self::TextInput(control) => {
                budget.add_collection("self.ui action args", control.action.args.len())
            }
        }
    }
}

impl SelfUiAction {
    pub(super) fn validate(&self) -> Result<()> {
        validate_lens_collection_len("self.ui action args", self.args.len())
    }
}
