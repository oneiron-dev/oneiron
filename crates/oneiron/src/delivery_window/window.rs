//! Quiet-window time arithmetic and time-window decoding.

use rmpv::Value;

use crate::error::Result;

use super::types::{KEY_END_MINUTE, KEY_START_MINUTE, MINUTES_PER_DAY};
use super::validate::{invalid_claim, required_u16, value_map};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryWindowTimeWindow {
    pub start_minute: u16,
    pub end_minute: u16,
}

impl DeliveryWindowTimeWindow {
    pub fn new(start_minute: u16, end_minute: u16) -> Result<Self> {
        if start_minute >= MINUTES_PER_DAY || end_minute >= MINUTES_PER_DAY {
            return Err(invalid_claim(
                "delivery_window window minutes must be < 1440",
            ));
        }
        if start_minute == end_minute {
            return Err(invalid_claim(
                "delivery_window window start and end must differ",
            ));
        }
        Ok(Self {
            start_minute,
            end_minute,
        })
    }

    #[must_use]
    pub fn contains(self, local_minute_of_day: u16) -> bool {
        if local_minute_of_day >= MINUTES_PER_DAY {
            return false;
        }
        if self.start_minute < self.end_minute {
            local_minute_of_day >= self.start_minute && local_minute_of_day < self.end_minute
        } else {
            local_minute_of_day >= self.start_minute || local_minute_of_day < self.end_minute
        }
    }

    #[must_use]
    pub fn retry_at_after(self, delivery_epoch_secs: u64, local_minute_of_day: u16) -> Option<u64> {
        if !self.contains(local_minute_of_day) {
            return None;
        }
        let minutes_until_end = if self.start_minute < self.end_minute {
            self.end_minute.saturating_sub(local_minute_of_day)
        } else if local_minute_of_day >= self.start_minute {
            MINUTES_PER_DAY
                .saturating_sub(local_minute_of_day)
                .saturating_add(self.end_minute)
        } else {
            self.end_minute.saturating_sub(local_minute_of_day)
        };
        Some(delivery_epoch_secs.saturating_add(u64::from(minutes_until_end) * 60))
    }
}

pub(super) fn decode_time_window(value: &Value) -> Result<DeliveryWindowTimeWindow> {
    let entries = value_map(value)?;
    validate_window_keys(entries)?;
    let start = required_u16(entries, KEY_START_MINUTE)?;
    let end = required_u16(entries, KEY_END_MINUTE)?;
    DeliveryWindowTimeWindow::new(start, end)
}

fn validate_window_keys(entries: &[(Value, Value)]) -> Result<()> {
    for (key, _) in entries {
        let key = key
            .as_str()
            .expect("delivery_window value_map validates string keys");
        if ![KEY_START_MINUTE, KEY_END_MINUTE].contains(&key) {
            return Err(invalid_claim("delivery_window window has unsupported key"));
        }
    }
    Ok(())
}
