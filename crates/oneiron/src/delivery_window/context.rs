//! Frozen execute-time evaluation context and its builder.

use crate::error::Result;

use super::evaluate::normalize_channel_key;
use super::types::{
    DeliveryWindowApnsInterruptionLevel, DeliveryWindowContextCondition, DeliveryWindowVerbClass,
    MINUTES_PER_DAY,
};
use super::validate::invalid_claim;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryWindowEvaluationContext {
    pub delivery_epoch_secs: u64,
    pub(super) local_minute_of_day: u16,
    pub verb_class: DeliveryWindowVerbClass,
    pub channel: Option<String>,
    pub active_contexts: Vec<DeliveryWindowContextCondition>,
    pub interrupt_surface: Option<String>,
    pub degrade_to: Option<String>,
    pub apns_interruption_level: Option<DeliveryWindowApnsInterruptionLevel>,
    /// A human chose this exact instant. Policy is still evaluated and
    /// retained as evidence; only the effective action is lifted.
    pub human_explicit_instant: bool,
}

impl DeliveryWindowEvaluationContext {
    pub fn new(
        delivery_epoch_secs: u64,
        local_minute_of_day: u16,
        verb_class: DeliveryWindowVerbClass,
    ) -> Result<Self> {
        if local_minute_of_day >= MINUTES_PER_DAY {
            return Err(invalid_claim(
                "delivery_window local minute of day must be < 1440",
            ));
        }
        Ok(Self {
            delivery_epoch_secs,
            local_minute_of_day,
            verb_class,
            channel: None,
            active_contexts: Vec::new(),
            interrupt_surface: None,
            degrade_to: None,
            apns_interruption_level: None,
            human_explicit_instant: false,
        })
    }

    #[must_use]
    pub const fn local_minute_of_day(&self) -> u16 {
        self.local_minute_of_day
    }

    #[must_use]
    pub fn channel(mut self, channel: impl Into<String>) -> Self {
        let channel = channel.into();
        self.channel = Some(normalize_channel_key(&channel));
        self
    }

    #[must_use]
    pub fn active_context(mut self, condition: DeliveryWindowContextCondition) -> Self {
        if !self.active_contexts.contains(&condition) {
            self.active_contexts.push(condition);
        }
        self
    }

    #[must_use]
    pub fn interrupt_surface(mut self, surface: impl Into<String>) -> Self {
        self.interrupt_surface = Some(surface.into());
        self
    }

    #[must_use]
    pub fn degrade_to(mut self, surface: impl Into<String>) -> Self {
        self.degrade_to = Some(surface.into());
        self
    }

    #[must_use]
    pub fn apns_interruption_level(mut self, level: DeliveryWindowApnsInterruptionLevel) -> Self {
        self.apns_interruption_level = Some(level);
        self
    }

    /// Marks the top ladder rung: a human explicitly chose this instant.
    #[must_use]
    pub fn human_explicit_instant(mut self) -> Self {
        self.human_explicit_instant = true;
        self
    }
}
