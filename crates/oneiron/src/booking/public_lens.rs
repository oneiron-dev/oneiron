//! Public booking model and projection onto the existing lens atom kit.
//!
//! This module does not publish pages, solve availability, or mint credentials.
//! Callers supply the final disclosure projection and host-owned presentation.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::booking::{
    BookingVerb, DisclosureRung, EventTypeKey, OpaqueLifecycleToken, RungProjection, SurfaceClass,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BookingPageModelError {
    NonSlotsProjection,
    InvalidSlotMask,
    EmptyOwnerDisplay,
    EmptyEventTypes,
    UnlistedEventType,
}

impl BookingPageModel {
    pub fn new(
        owner_display: String,
        event_types: Vec<EventTypeCard>,
        slots: RungProjection,
        constraint_field: ConstraintFieldConfig,
        theme: ThemeTokens,
    ) -> core::result::Result<Self, BookingPageModelError> {
        let model = Self {
            owner_display,
            event_types,
            slots,
            constraint_field,
            theme,
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
    use crate::booking::{
        BOOKING_VERBS, RankedSlot, SlotMask, SolveRequest, SolveResult, slot_mask,
    };
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
        )
        .expect("model")
    }

    fn keys(value: &JsonValue) -> Vec<&str> {
        let mut keys: Vec<_> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys
    }

    #[test]
    fn booking_page_model_serializes_exact_seam_fields() {
        let value = serde_json::to_value(model()).expect("serialize");
        assert_eq!(
            keys(&value),
            [
                "constraint_field",
                "event_types",
                "owner_display",
                "slots",
                "theme"
            ]
        );
        assert_eq!(
            keys(&value["event_types"][0]),
            ["description", "duration_min", "key", "title"]
        );
        assert_eq!(keys(&value["constraint_field"]), ["enabled", "placeholder"]);
        let restored: BookingPageModel = serde_json::from_value(value).expect("round trip");
        assert_eq!(restored, model());
    }

    #[test]
    fn booking_page_model_rejects_non_slots_projection() {
        for projection in [
            RungProjection::Full(Vec::new()),
            RungProjection::Titles(Vec::new()),
            RungProjection::Busy(Vec::new()),
            RungProjection::Nothing,
        ] {
            let mut model = model();
            model.slots = projection;
            assert_eq!(
                validate_booking_page_model(&model),
                Err(BookingPageModelError::NonSlotsProjection)
            );
            assert!(BookingPageLens::card(&model).is_err());
            assert!(BookingPageLens::assemble(model.clone()).is_err());
            assert_eq!(
                BookingPageModel::new(
                    model.owner_display,
                    model.event_types,
                    model.slots,
                    model.constraint_field,
                    model.theme
                ),
                Err(BookingPageModelError::NonSlotsProjection)
            );
        }
        assert!(serde_json::from_value::<RungProjection>(json!({"rung": "slots"})).is_err());
        assert!(
            serde_json::from_value::<RungProjection>(json!({"rung": "slots", "rows": null}))
                .is_err()
        );
    }

    #[test]
    fn booking_page_model_accepts_slots_projection() {
        assert_eq!(validate_booking_page_model(&model()), Ok(()));
        assert!(BookingPageLens::assemble(model()).is_ok());
    }

    #[test]
    fn booking_page_slots_use_final_half_open_mask_schema() {
        let model = model();
        let RungProjection::Slots(mask) = &model.slots else {
            panic!("slots")
        };
        let _: &SlotMask = mask;
        let value = serde_json::to_value(mask).expect("mask");
        assert_eq!(
            keys(&value),
            [
                "event_type",
                "flex_used",
                "slots",
                "window_end_utc",
                "window_start_utc"
            ]
        );
        assert_eq!(mask.window_end_utc, 700);
        assert_eq!(mask.slots[0].end_utc, mask.window_end_utc);
        for (start, end) in [(100, 100), (99, 700), (100, 701), (700, 701)] {
            let mut invalid = model.clone();
            let RungProjection::Slots(mask) = &mut invalid.slots else {
                panic!("slots")
            };
            mask.slots[0].start_utc = start;
            mask.slots[0].end_utc = end;
            assert_eq!(
                validate_booking_page_model(&invalid),
                Err(BookingPageModelError::InvalidSlotMask)
            );
        }
        let mut invalid = model;
        let RungProjection::Slots(mask) = &mut invalid.slots else {
            panic!("slots")
        };
        mask.window_end_utc = mask.window_start_utc;
        assert!(BookingPageLens::card(&invalid).is_err());
    }

    #[test]
    fn theme_tokens_are_opaque_to_machinery() {
        for bag in [
            json!({"never_known": {"x": [null, false, 0.5, "</script>"]}}),
            json!(null),
            json!([1, "x"]),
        ] {
            let mut model = model();
            model.theme = ThemeTokens(bag.clone());
            let bytes = serde_json::to_vec(&bag).expect("bag bytes");
            assert_eq!(
                serde_json::to_vec(&model.theme).expect("theme bytes"),
                bytes
            );
            let restored: ThemeTokens = serde_json::from_slice(&bytes).expect("round trip");
            assert_eq!(restored, model.theme);
            let lens = BookingPageLens::assemble(model).expect("assemble");
            let LensAtom::MetaLine(theme) = &lens.root().children[3].atom else {
                panic!("meta line")
            };
            assert_eq!(theme.value.as_str().as_bytes(), bytes);
        }
    }

    #[test]
    fn booking_page_lens_uses_existing_generated_lens_atoms() {
        let card: GeneratedUiCard = BookingPageLens::card(&model()).expect("card");
        let lens: GeneratedLens = BookingPageLens::assemble(model()).expect("lens");
        assert_eq!(card.tree, lens);
        assert!(matches!(lens.root().atom, LensAtom::Sheet(_)));
        assert!(
            lens.root()
                .children
                .iter()
                .all(|node| matches!(node.atom, LensAtom::MetaLine(_)))
        );
        assert!(card.render().is_ok());
        let bytes = serde_json::to_vec(&card).expect("card bytes");
        assert_eq!(
            serde_json::from_slice::<GeneratedUiCard>(&bytes).expect("existing decoder"),
            card
        );
    }

    #[test]
    fn booking_page_lens_contains_only_booking_pack_actions() {
        let page_token = PublicBookingPageToken(format!("bkp_{}", "ab".repeat(16)));
        let credential = OpaqueLifecycleToken("cd".repeat(32));
        let actions = [
            PublicBookingAction::Cancel(credential.clone()),
            PublicBookingAction::Confirm(credential.clone()),
            PublicBookingAction::Hold,
            PublicBookingAction::Reschedule(credential),
        ];
        let card =
            BookingPageLens::card_with_actions(&model(), &page_token, &actions).expect("actions");
        assert_eq!(card.actions.len(), BOOKING_VERBS.len());
        for (declaration, expected) in card.actions.iter().zip(BOOKING_VERBS) {
            assert_eq!(declaration.action.command.as_str(), expected);
            assert!(BookingVerb::parse(declaration.action.command.as_str()).is_some());
            assert!(
                declaration
                    .action
                    .args
                    .iter()
                    .all(|arg| matches!(arg, SelfUiValue::Token(_)))
            );
        }
        let mut pending = vec![card.tree.root()];
        let mut controls = 0;
        while let Some(node) = pending.pop() {
            assert!(node.bindings.is_empty());
            match &node.atom {
                LensAtom::SelfUi(SelfUiControl::Button(button)) => {
                    controls += 1;
                    assert!(BOOKING_VERBS.contains(&button.action.command.as_str()));
                    assert!(
                        button
                            .action
                            .args
                            .iter()
                            .all(|arg| matches!(arg, SelfUiValue::Token(_)))
                    );
                }
                LensAtom::Sheet(_) | LensAtom::MetaLine(_) => {}
                other => panic!("unexpected public atom: {other:?}"),
            }
            pending.extend(&node.children);
        }
        assert_eq!(controls, 4);
        assert!(card.render().is_ok());
        for invalid in [
            "ab".repeat(16),
            "https://invalid.example/".to_owned(),
            "shell.run".to_owned(),
        ] {
            assert!(
                BookingPageLens::card_with_actions(
                    &model(),
                    &PublicBookingPageToken(invalid.clone()),
                    &[PublicBookingAction::Hold]
                )
                .is_err()
            );
            assert!(
                BookingPageLens::card_with_actions(
                    &model(),
                    &page_token,
                    &[PublicBookingAction::Cancel(OpaqueLifecycleToken(invalid))]
                )
                .is_err()
            );
        }
    }
}
