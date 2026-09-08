//! Policy claim parsing and per-claim restriction gating.

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, claim_generated_origin,
};
use crate::error::Result;

use super::context::DeliveryWindowEvaluationContext;
use super::evaluate::{default_reason, normalize_channel_key};
use super::types::{
    DeliveryWindowAppliesTo, DeliveryWindowContextCondition, DeliveryWindowVerbClass,
    KEY_APPLIES_TO, KEY_CHANNEL, KEY_REASON, KEY_WHEN, KEY_WINDOW,
    PREDICATE_DELIVERY_WINDOW_CHANNEL, PREDICATE_DELIVERY_WINDOW_CONTEXT,
    PREDICATE_DELIVERY_WINDOW_QUIET,
};
use super::validate::{
    invalid_claim, optional_str, optional_value, required_str, required_value,
    validate_delivery_window_claim_structure, value_map,
};
use super::window::{DeliveryWindowTimeWindow, decode_time_window};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryWindowPolicyClaim {
    pub predicate: String,
    pub applies_to: DeliveryWindowAppliesTo,
    pub channel: Option<String>,
    pub window: Option<DeliveryWindowTimeWindow>,
    pub context: Option<DeliveryWindowContextCondition>,
    pub reason: String,
    pub approval: ClaimApprovalStatus,
    pub lifecycle: ClaimLifecycleStatus,
    pub source: Option<ClaimSource>,
    pub generated_origin: bool,
    pub valid_from: Option<u64>,
    pub valid_to: Option<u64>,
    pub stale: bool,
}

impl DeliveryWindowPolicyClaim {
    pub fn from_claim_body(body: &ClaimBody) -> Result<Self> {
        validate_delivery_window_claim_structure(body)?;
        let entries = value_map(&body.value)?;
        let applies_to = DeliveryWindowAppliesTo::parse(required_str(entries, KEY_APPLIES_TO)?)
            .ok_or_else(|| invalid_claim("delivery_window applies_to must be interrupt"))?;
        let reason = optional_str(entries, KEY_REASON)?
            .map_or_else(|| default_reason(&body.predicate).to_owned(), str::to_owned);
        let (channel, window, context) = match body.predicate.as_str() {
            PREDICATE_DELIVERY_WINDOW_QUIET => (
                None,
                Some(decode_time_window(required_value(entries, KEY_WINDOW)?)?),
                None,
            ),
            PREDICATE_DELIVERY_WINDOW_CONTEXT => (
                None,
                None,
                Some(
                    DeliveryWindowContextCondition::parse(required_str(entries, KEY_WHEN)?)
                        .ok_or_else(|| invalid_claim("delivery_window when value is unknown"))?,
                ),
            ),
            PREDICATE_DELIVERY_WINDOW_CHANNEL => (
                Some(normalize_channel_key(required_str(entries, KEY_CHANNEL)?)),
                optional_value(entries, KEY_WINDOW)?
                    .map(decode_time_window)
                    .transpose()?,
                None,
            ),
            _ => unreachable!("predicate membership checked above"),
        };

        Ok(Self {
            predicate: body.predicate.clone(),
            applies_to,
            channel,
            window,
            context,
            reason,
            approval: body.approval,
            lifecycle: body.lifecycle,
            source: body.source,
            generated_origin: claim_generated_origin(body),
            valid_from: body.valid_from,
            valid_to: body.valid_to,
            stale: body.stale,
        })
    }

    pub(super) fn restriction_at(
        &self,
        context: &DeliveryWindowEvaluationContext,
    ) -> Option<Restriction> {
        if !matches!(
            self.approval,
            ClaimApprovalStatus::Auto | ClaimApprovalStatus::Approved
        ) || self.lifecycle != ClaimLifecycleStatus::Active
            || self.stale
        {
            return None;
        }
        if self.approval == ClaimApprovalStatus::Auto && self.generated_origin {
            return None;
        }
        if self.applies_to != DeliveryWindowAppliesTo::Interrupt {
            return None;
        }
        if context.verb_class != DeliveryWindowVerbClass::Interrupt {
            return None;
        }
        if let Some(valid_from) = self.valid_from
            && context.delivery_epoch_secs < valid_from
        {
            return None;
        }
        if let Some(valid_to) = self.valid_to
            && context.delivery_epoch_secs >= valid_to
        {
            return None;
        }
        if let Some(channel) = self.channel.as_deref()
            && context.channel.as_deref() != Some(channel)
        {
            return None;
        }
        if let Some(condition) = self.context
            && !context.active_contexts.contains(&condition)
        {
            return None;
        }
        let retry_at = if let Some(window) = self.window {
            window.retry_at_after(context.delivery_epoch_secs, context.local_minute_of_day)?
        } else {
            0
        };
        Some(Restriction {
            predicate: self.predicate.clone(),
            reason: self.reason.clone(),
            retry_at: if self.window.is_some() {
                Some(retry_at)
            } else {
                None
            },
            source: self.source,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Restriction {
    pub(super) predicate: String,
    pub(super) reason: String,
    pub(super) retry_at: Option<u64>,
    pub(super) source: Option<ClaimSource>,
}
