//! When a job fires, and when it fires next.

use serde::{Deserialize, Serialize};

use crate::{CivilDate, Weekday, ZoneRules};

/// The first retry after a failure, by default.
pub const RETRY_FIRST_SECS: u64 = 60;
/// The longest wait between retries, by default, unless the cadence is shorter.
pub const RETRY_CAP_SECS: u64 = 60 * 60;

const DAY_SECS: u64 = 24 * 60 * 60;

/// When a job fires. Three shapes cover every time trigger the engine has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Trigger {
    /// Once, at this vault-clock second.
    At { at: u64 },
    /// Every `secs` seconds, the first time at `first_at`, or now when it is absent.
    Every {
        secs: u64,
        #[serde(default)]
        first_at: Option<u64>,
    },
    /// At the wall time `hour:minute` in the IANA zone `zone`, on `days` (every day when empty).
    Civil {
        hour: u8,
        minute: u8,
        zone: String,
        #[serde(default)]
        days: Vec<Weekday>,
    },
}

impl Trigger {
    /// Why this trigger can never fire, if it cannot: an interval of zero, a wall time past the
    /// clock's, an unknown zone, or a day named twice.
    #[must_use]
    pub fn refusal(&self, zones: &dyn ZoneRules) -> Option<&'static str> {
        match self {
            Self::At { .. } => None,
            Self::Every { secs: 0, .. } => Some("an interval is at least one second"),
            Self::Every { .. } => None,
            Self::Civil {
                hour,
                minute,
                zone,
                days,
            } => {
                if *hour > 23 || *minute > 59 {
                    Some("a wall time is 00:00 to 23:59")
                } else if !zones.knows(zone) {
                    Some("the zone is no IANA zone the engine knows")
                } else if days
                    .iter()
                    .enumerate()
                    .any(|(index, day)| days[..index].contains(day))
                {
                    Some("a day is named twice")
                } else {
                    None
                }
            }
        }
    }

    /// When a job armed at `now` with this trigger is first due: a deadline at its time (even a
    /// passed one, which then fires late), an interval at `first_at` or now, a wall time at its
    /// first occurrence at or after now.
    #[must_use]
    pub fn first_due(&self, now: u64, zones: &dyn ZoneRules) -> Option<u64> {
        match self {
            Self::At { at } => Some(*at),
            Self::Every { first_at, .. } => Some(first_at.unwrap_or(now)),
            Self::Civil { .. } => self.civil_at_or_after(now, zones),
        }
    }

    /// The catch-up rule: when a job that was due at `due` and ran at `now` is due next. However
    /// many occurrences were missed, it ran once; it is next due at the first occurrence after
    /// now. A deadline is done once it ran: `None`.
    #[must_use]
    pub fn next_due(&self, due: u64, now: u64, zones: &dyn ZoneRules) -> Option<u64> {
        match self {
            Self::At { .. } => None,
            Self::Every { secs, .. } => {
                let secs = (*secs).max(1);
                let missed = now.saturating_sub(due) / secs;
                Some(due.saturating_add(secs.saturating_mul(missed.saturating_add(1))))
            }
            Self::Civil { .. } => self.civil_at_or_after(now.saturating_add(1), zones),
        }
    }

    /// How often it fires, for the retry cap: its interval, a day for a wall time, and none
    /// (the cap alone) for a deadline.
    #[must_use]
    pub fn cadence_secs(&self) -> Option<u64> {
        match self {
            Self::At { .. } => None,
            Self::Every { secs, .. } => Some(*secs),
            Self::Civil { .. } => Some(DAY_SECS),
        }
    }

    /// The first occurrence of a wall-time trigger at or after `at`, within the week ahead.
    fn civil_at_or_after(&self, at: u64, zones: &dyn ZoneRules) -> Option<u64> {
        let Self::Civil {
            hour,
            minute,
            zone,
            days,
        } = self
        else {
            return None;
        };
        let today = zones.date_of(zone, at)?;
        (0..=7)
            .filter_map(|offset| today.plus_days(offset))
            .filter(|date: &CivilDate| days.is_empty() || days.contains(&date.weekday()))
            .filter_map(|date| zones.wall_to_utc(zone, date, *hour, *minute))
            .find(|utc| *utc >= at)
    }
}

/// What one run of a job answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ran {
    /// The run finished its work: a deadline is done, a repeating job is next due at its next
    /// occurrence after now.
    Done,
    /// The run stopped at its budget: due again at once, going on from `cursor`.
    More { cursor: Vec<u8> },
    /// The run failed: due again after the backoff, its cursor kept.
    Failed,
}

/// How long after its `failures`-th failure in a row a job is due again: `first`, doubling with
/// each failure after the first, never past `cap`.
#[must_use]
pub fn retry_after(failures: u32, first: u64, cap: u64) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    first.saturating_mul(1 << doublings).min(cap)
}

#[cfg(test)]
mod tests {
    use super::{RETRY_CAP_SECS, RETRY_FIRST_SECS, Trigger, retry_after};
    use crate::{CivilDate, Weekday, ZoneRules};

    /// A zone at a fixed offset from UTC, as a test's whole time-zone database.
    struct Fixed {
        name: &'static str,
        offset_secs: i64,
    }

    impl ZoneRules for Fixed {
        fn knows(&self, zone: &str) -> bool {
            zone == self.name
        }

        fn wall_to_utc(&self, zone: &str, date: CivilDate, hour: u8, minute: u8) -> Option<u64> {
            if !self.knows(zone) {
                return None;
            }
            let local =
                date.days_since_epoch() * 86_400 + i64::from(hour) * 3_600 + i64::from(minute) * 60;
            u64::try_from(local - self.offset_secs).ok()
        }

        fn date_of(&self, zone: &str, utc: u64) -> Option<CivilDate> {
            if !self.knows(zone) {
                return None;
            }
            let local = i64::try_from(utc).ok()? + self.offset_secs;
            CivilDate::from_days_since_epoch(local.div_euclid(86_400))
        }
    }

    const TOKYO: Fixed = Fixed {
        name: "Asia/Tokyo",
        offset_secs: 9 * 3_600,
    };

    /// 2026-11-15 00:00:00 UTC, a Sunday: 09:00 in Tokyo.
    const SUNDAY_0900_JST: u64 = 1_794_700_800;

    #[test]
    fn a_late_interval_runs_once_then_goes_on_from_now() {
        let every = Trigger::Every {
            secs: 3_600,
            first_at: None,
        };
        assert_eq!(every.first_due(1_000, &TOKYO), Some(1_000));
        assert_eq!(every.next_due(1_000, 1_000, &TOKYO), Some(4_600));
        // five hours late: one run, then the next point of the grid after now
        assert_eq!(
            every.next_due(1_000, 1_000 + 5 * 3_600 + 10, &TOKYO),
            Some(1_000 + 6 * 3_600)
        );
        assert_eq!(Trigger::At { at: 50 }.first_due(1_000, &TOKYO), Some(50));
        assert_eq!(Trigger::At { at: 50 }.next_due(50, 1_000, &TOKYO), None);
    }

    #[test]
    fn a_wall_time_fires_at_its_next_occurrence_on_its_days() {
        let daily = Trigger::Civil {
            hour: 9,
            minute: 0,
            zone: "Asia/Tokyo".to_owned(),
            days: Vec::new(),
        };
        assert_eq!(
            daily.first_due(SUNDAY_0900_JST, &TOKYO),
            Some(SUNDAY_0900_JST)
        );
        assert_eq!(
            daily.first_due(SUNDAY_0900_JST + 1, &TOKYO),
            Some(SUNDAY_0900_JST + 86_400)
        );
        // a week missed: one run, then the next morning
        assert_eq!(
            daily.next_due(SUNDAY_0900_JST, SUNDAY_0900_JST + 7 * 86_400 + 5, &TOKYO),
            Some(SUNDAY_0900_JST + 8 * 86_400)
        );
        let weekdays = Trigger::Civil {
            hour: 9,
            minute: 0,
            zone: "Asia/Tokyo".to_owned(),
            days: vec![Weekday::Monday, Weekday::Friday],
        };
        assert_eq!(
            weekdays.first_due(SUNDAY_0900_JST, &TOKYO),
            Some(SUNDAY_0900_JST + 86_400)
        );
        assert_eq!(
            weekdays.next_due(SUNDAY_0900_JST + 86_400, SUNDAY_0900_JST + 86_400, &TOKYO),
            Some(SUNDAY_0900_JST + 5 * 86_400)
        );
    }

    #[test]
    fn a_trigger_that_can_never_fire_is_refused() {
        assert!(
            Trigger::Every {
                secs: 0,
                first_at: None
            }
            .refusal(&TOKYO)
            .is_some()
        );
        let civil = |hour, zone: &str, days| Trigger::Civil {
            hour,
            minute: 0,
            zone: zone.to_owned(),
            days,
        };
        assert!(
            civil(24, "Asia/Tokyo", Vec::new())
                .refusal(&TOKYO)
                .is_some()
        );
        assert!(
            civil(9, "Mars/Olympus", Vec::new())
                .refusal(&TOKYO)
                .is_some()
        );
        assert!(
            civil(9, "Asia/Tokyo", vec![Weekday::Monday, Weekday::Monday])
                .refusal(&TOKYO)
                .is_some()
        );
        assert!(civil(9, "Asia/Tokyo", Vec::new()).refusal(&TOKYO).is_none());
    }

    #[test]
    fn a_retry_doubles_from_a_minute_to_its_cap() {
        let cap = RETRY_CAP_SECS;
        assert_eq!(retry_after(1, RETRY_FIRST_SECS, cap), 60);
        assert_eq!(retry_after(2, RETRY_FIRST_SECS, cap), 120);
        assert_eq!(retry_after(6, RETRY_FIRST_SECS, cap), 1_920);
        assert_eq!(retry_after(7, RETRY_FIRST_SECS, cap), 3_600);
        assert_eq!(retry_after(40, RETRY_FIRST_SECS, cap), 3_600);
        assert_eq!(retry_after(3, RETRY_FIRST_SECS, 100), 100);
    }
}
