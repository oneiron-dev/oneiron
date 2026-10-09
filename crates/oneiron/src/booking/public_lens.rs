//! Public booking model and projection onto the existing lens atom kit.
//!
//! This module does not publish pages, solve availability, or mint credentials.
//! Callers supply the final disclosure projection and host-owned presentation.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::booking::{
    BookingError, BookingLandingContent, BookingSlotPreview, BookingVerb, DisclosureRung,
    EventTypeKey, OpaqueLifecycleToken, RungProjection, SurfaceClass, booking_slot_preview,
    project_at_rung,
};
use crate::lens::{
    ButtonControl, CollectionAtom, GeneratedLens, GeneratedUiActionDeclaration,
    GeneratedUiActionTier, GeneratedUiCard, LensAtom, LensAtomId, LensNode, LensRenderId, LensText,
    MetaLineAtom, SelfUiAction, SelfUiActionId, SelfUiControl, SelfUiControlId, SelfUiOptionValue,
    SelfUiValue,
};
use crate::{Error, Result};

pub const PUBLIC_BOOKING_ROUTE_PREFIX: &str = "/public/booking";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EventTypeCard {
    pub key: EventTypeKey,
    pub title: String,
    pub duration_min: u32,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintFieldConfig {
    pub enabled: bool,
    pub placeholder: String,
}

/// Transport only. No token names, defaults, or visual rules belong here.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ThemeTokens(pub JsonValue);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingPageModel {
    pub owner_display: String,
    pub event_types: Vec<EventTypeCard>,
    pub slots: RungProjection,
    pub constraint_field: ConstraintFieldConfig,
    pub theme: ThemeTokens,
    pub landing: BookingLandingContent,
    pub preview: BookingSlotPreview,
    pub visitor_tz: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BookingPageModelError {
    NonSlotsProjection,
    InvalidSlotMask,
    EmptyOwnerDisplay,
    EmptyEventTypes,
    UnlistedEventType,
    FieldTooLarge,
    InvalidLanding,
    InvalidPreview,
    InvalidTimeZone,
}

impl BookingPageModel {
    pub fn new(
        owner_display: String,
        event_types: Vec<EventTypeCard>,
        slots: RungProjection,
        constraint_field: ConstraintFieldConfig,
        theme: ThemeTokens,
        landing: BookingLandingContent,
        visitor_tz: String,
    ) -> core::result::Result<Self, BookingPageModelError> {
        let preview = match &slots {
            RungProjection::Slots(mask) => booking_slot_preview(mask),
            _ => return Err(BookingPageModelError::NonSlotsProjection),
        };
        let model = Self {
            owner_display,
            event_types,
            slots,
            constraint_field,
            theme,
            landing,
            preview,
            visitor_tz,
        };
        validate_booking_page_model(&model)?;
        Ok(model)
    }
}

/// Assembly assertion, not a second disclosure policy or a substitute solver.
pub fn validate_booking_page_model(
    model: &BookingPageModel,
) -> core::result::Result<(), BookingPageModelError> {
    let RungProjection::Slots(mask) = &model.slots else {
        return Err(BookingPageModelError::NonSlotsProjection);
    };
    // Reuse the seam's half-open-mask validator. Never coerce another rung.
    project_at_rung(&[], DisclosureRung::Slots, SurfaceClass::Public, Some(mask))
        .map_err(|_| BookingPageModelError::InvalidSlotMask)?;
    validate_presentation_fields(
        &model.owner_display,
        &model.event_types,
        &model.constraint_field,
        &model.theme,
    )?;
    validate_model_field(&model.slots)?;
    model
        .landing
        .validate()
        .map_err(|_| BookingPageModelError::InvalidLanding)?;
    validate_model_field(&model.landing)?;
    validate_model_field(&model.preview)?;
    if model.preview != booking_slot_preview(mask) {
        return Err(BookingPageModelError::InvalidPreview);
    }
    if model.visitor_tz.len() > 64
        || crate::calendar::tz::utc_to_wall(mask.window_start_utc, &model.visitor_tz).is_err()
    {
        return Err(BookingPageModelError::InvalidTimeZone);
    }
    if model.owner_display.trim().is_empty() {
        return Err(BookingPageModelError::EmptyOwnerDisplay);
    }
    if model.event_types.is_empty() {
        return Err(BookingPageModelError::EmptyEventTypes);
    }
    if !model
        .event_types
        .iter()
        .any(|event| event.key == mask.event_type)
    {
        return Err(BookingPageModelError::UnlistedEventType);
    }
    Ok(())
}

fn validate_model_field(value: &impl Serialize) -> core::result::Result<(), BookingPageModelError> {
    let json = serde_json::to_string(value).map_err(|_| BookingPageModelError::FieldTooLarge)?;
    LensText::new(json).map_err(|_| BookingPageModelError::FieldTooLarge)?;
    Ok(())
}

pub(super) fn validate_presentation_fields(
    owner: &str,
    events: &[EventTypeCard],
    constraint: &ConstraintFieldConfig,
    theme: &ThemeTokens,
) -> core::result::Result<(), BookingPageModelError> {
    validate_model_field(&owner)?;
    validate_model_field(&events)?;
    validate_model_field(constraint)?;
    validate_model_field(theme)
}

/// Bounded ranked prefix for the public lens. Query a narrower window for more
/// choices. Never truncate a serialized JSON string or change a slot interval.
pub fn bounded_public_slots(
    mut mask: crate::booking::SlotMask,
) -> core::result::Result<RungProjection, BookingError> {
    mask.slots.truncate(128);
    loop {
        let projection = RungProjection::Slots(mask.clone());
        if validate_model_field(&projection).is_ok() {
            return project_at_rung(
                &[],
                DisclosureRung::Slots,
                SurfaceClass::Public,
                Some(&mask),
            );
        }
        if mask.slots.pop().is_none() {
            return Err(BookingError::Surface(
                "public booking slot metadata exceeds lens bounds".to_owned(),
            ));
        }
    }
}

/// A handle supplied by the published-page capability resolver, never an entity id.
/// This envelope does not mint, resolve, or grant authority to a token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicBookingPageToken(pub String);

impl PublicBookingPageToken {
    /// Derive the existing opaque page address. This grants no authority:
    /// public serving still requires a live owner-authored publication claim.
    #[must_use]
    pub fn for_page(page_ref: crate::EntityId) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"oneiron.booking.agent_api.page_token.v1\0");
        hasher.update(page_ref.as_bytes());
        let hex = hasher.finalize().to_hex();
        Self(format!("bkp_{}", &hex.as_str()[..32]))
    }
}

/// Closed action vocabulary. Credentials come from the shared lifecycle only.
/// Labels and input presentation belong to the host, not to this descriptor.
#[derive(Clone, Debug, PartialEq)]
pub enum PublicBookingAction {
    Hold,
    Confirm(OpaqueLifecycleToken),
    Reschedule(OpaqueLifecycleToken),
    Cancel(OpaqueLifecycleToken),
}

impl PublicBookingAction {
    #[must_use]
    pub const fn verb(&self) -> BookingVerb {
        match self {
            Self::Hold => BookingVerb::Hold,
            Self::Confirm(_) => BookingVerb::Confirm,
            Self::Reschedule(_) => BookingVerb::Reschedule,
            Self::Cancel(_) => BookingVerb::Cancel,
        }
    }

    fn credential(&self) -> Option<&OpaqueLifecycleToken> {
        match self {
            Self::Hold => None,
            Self::Confirm(token) | Self::Reschedule(token) | Self::Cancel(token) => Some(token),
        }
    }
}

pub struct BookingPageLens;

impl BookingPageLens {
    pub fn card(model: &BookingPageModel) -> Result<GeneratedUiCard> {
        GeneratedUiCard::card(LensRenderId::new("public-booking")?, Self::root(model)?)
    }

    pub fn assemble(model: BookingPageModel) -> Result<GeneratedLens> {
        GeneratedLens::new(Self::root(&model)?)
    }

    /// Add only canonical booking controls. The host adapts user input to the
    /// typed booking request; the descriptor never carries a URL or generic tool.
    pub fn card_with_actions(
        model: &BookingPageModel,
        page_token: &PublicBookingPageToken,
        actions: &[PublicBookingAction],
    ) -> Result<GeneratedUiCard> {
        let mut root = Self::root(model)?;
        // Shape checks prevent an internal identifier or URL from being emitted
        // as an action argument. They do not resolve or authorize credentials.
        if !page_token
            .0
            .strip_prefix("bkp_")
            .is_some_and(|value| opaque_hex(value, 32))
        {
            return Err(Error::InvalidConfig(
                "public booking page token shape".to_owned(),
            ));
        }
        let mut declarations = Vec::with_capacity(actions.len());
        for (index, descriptor) in actions.iter().enumerate() {
            let verb = descriptor.verb();
            let element_id = LensAtomId::new(format!("booking-action-{index}"))?;
            let action_id = SelfUiActionId::new(verb.as_str())?;
            let mut args = vec![SelfUiValue::Token(SelfUiOptionValue::new(&page_token.0)?)];
            if let Some(token) = descriptor.credential() {
                if !opaque_hex(&token.0, 64) {
                    return Err(Error::InvalidConfig(
                        "public booking action token shape".to_owned(),
                    ));
                }
                args.push(SelfUiValue::Token(SelfUiOptionValue::new(&token.0)?));
            }
            let action = SelfUiAction {
                command: action_id.clone(),
                args,
            };
            root.children.push(LensNode::new(
                element_id.clone(),
                LensAtom::SelfUi(SelfUiControl::Button(ButtonControl {
                    id: SelfUiControlId::new(format!("booking-control-{index}"))?,
                    label: LensText::new(verb.as_str())?,
                    action: action.clone(),
                })),
            ));
            declarations.push(GeneratedUiActionDeclaration {
                element_id,
                action_id,
                tier: GeneratedUiActionTier::DeterministicTool,
                action,
            });
        }
        GeneratedUiCard::card(LensRenderId::new("public-booking")?, root)?
            .with_interactivity(declarations, Default::default())
    }

    fn root(model: &BookingPageModel) -> Result<LensNode> {
        validate_booking_page_model(model).map_err(|defect| {
            tracing::error!(?defect, "public booking page assembly invariant failed");
            Error::InvalidConfig(format!("public booking page invariant: {defect:?}"))
        })?;
        let mut root = LensNode::new(
            LensAtomId::new("booking-page")?,
            LensAtom::Sheet(CollectionAtom {
                title: LensText::new(&model.owner_display)?,
                rows: Vec::new(),
            }),
        );
        // Named seam data stays structured JSON in existing meta-line atoms.
        // In particular, theme serialization is the only operation on its bag.
        root.children
            .push(model_field("event_types", &model.event_types)?);
        root.children.push(model_field("slots", &model.slots)?);
        root.children
            .push(model_field("constraint_field", &model.constraint_field)?);
        root.children.push(model_field("theme", &model.theme)?);
        root.children.push(model_field("landing", &model.landing)?);
        root.children.push(model_field("preview", &model.preview)?);
        root.children
            .push(model_field("visitor_tz", &model.visitor_tz)?);
        Ok(root)
    }
}

fn opaque_hex(value: &str, width: usize) -> bool {
    value.len() == width
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn model_field(name: &str, value: &impl Serialize) -> Result<LensNode> {
    let json = serde_json::to_string(value)
        .map_err(|error| Error::InvalidConfig(format!("booking model serialization: {error}")))?;
    Ok(LensNode::new(
        LensAtomId::new(format!("booking-{name}"))?,
        LensAtom::MetaLine(MetaLineAtom {
            label: LensText::new(name)?,
            value: LensText::new(json)?,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::booking::{RankedSlot, SolveRequest, SolveResult, slot_mask};
    use crate::temporal::TimeRange;
    use serde_json::json;

    fn model() -> BookingPageModel {
        let request = SolveRequest {
            event_type: EventTypeKey("intro".to_owned()),
            window: TimeRange {
                start: 100,
                end: 699,
            },
            constraint: None,
            visitor_tz: "UTC".to_owned(),
        };
        let mask = slot_mask(
            &request,
            SolveResult {
                slots: vec![RankedSlot {
                    start_utc: 100,
                    end_utc: 700,
                    rank: 0.5,
                }],
                flex_used: false,
                host_bindings: Vec::new(),
            },
        );
        BookingPageModel::new(
            "Fixture host".to_owned(),
            vec![EventTypeCard {
                key: request.event_type,
                title: "Introduction".to_owned(),
                duration_min: 10,
                description: "Fixture description".to_owned(),
            }],
            project_at_rung(&[], DisclosureRung::Full, SurfaceClass::Public, Some(&mask))
                .expect("public clamp"),
            ConstraintFieldConfig {
                enabled: false,
                placeholder: String::new(),
            },
            ThemeTokens(json!({"unknown": {"nested": [null, 7, "opaque"]}})),
            BookingLandingContent::default(),
            "UTC".to_owned(),
        )
        .expect("model")
    }

    #[test]
    fn bounded_public_slots_rejects_oversized_metadata_as_surface_error() {
        let RungProjection::Slots(mut mask) = model().slots else {
            panic!("slots");
        };
        mask.event_type = EventTypeKey("x".repeat(16 * 1024 + 1));
        assert!(matches!(
            bounded_public_slots(mask),
            Err(BookingError::Surface(_)),
        ));
    }

    #[test]
    fn public_slot_projection_caps_large_solver_output_and_still_renders() {
        let mut model = model();
        let RungProjection::Slots(mut mask) = model.slots.clone() else {
            panic!("slots");
        };
        mask.window_end_utc = 1_000_000;
        mask.slots = (0..2_000)
            .map(|i| RankedSlot {
                start_utc: 100 + i * 60,
                end_utc: 700 + i * 60,
                rank: 0.5,
            })
            .collect();
        assert!(
            BookingPageModel::new(
                model.owner_display.clone(),
                model.event_types.clone(),
                RungProjection::Slots(mask.clone()),
                model.constraint_field.clone(),
                model.theme.clone(),
                model.landing.clone(),
                model.visitor_tz.clone()
            )
            .is_err()
        );
        model.slots = bounded_public_slots(mask).expect("bounded projection");
        let RungProjection::Slots(projected) = &model.slots else {
            panic!("slots");
        };
        model.preview = booking_slot_preview(projected);
        let RungProjection::Slots(mask) = &model.slots else {
            panic!("slots");
        };
        assert!(!mask.slots.is_empty() && mask.slots.len() <= 128);
        assert_eq!(mask.slots[0].start_utc, 100);
        assert!(
            BookingPageLens::card(&model)
                .expect("card")
                .render()
                .is_ok()
        );
    }
}
