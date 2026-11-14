//! Civil dates and the zone rules a wall-clock trigger reads through.

use serde::{Deserialize, Serialize};

/// A day of the week.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl Weekday {
    /// Monday first.
    pub const ALL: [Self; 7] = [
        Self::Monday,
        Self::Tuesday,
        Self::Wednesday,
        Self::Thursday,
        Self::Friday,
        Self::Saturday,
        Self::Sunday,
    ];
}

/// A date on the proleptic Gregorian calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CivilDate {
    pub year: i32,
    pub month: u8,
    pub day: u8,
}

impl CivilDate {
    /// Days since 1970-01-01 (H. Hinnant's `days_from_civil`).
    #[must_use]
    pub fn days_since_epoch(self) -> i64 {
        let month = i64::from(self.month);
        let year = i64::from(self.year) - i64::from(month <= 2);
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let month_from_march = if month > 2 { month - 3 } else { month + 9 };
        let day_of_year = (153 * month_from_march + 2) / 5 + i64::from(self.day) - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era - 719_468
    }

    /// The date `days` days after 1970-01-01 (H. Hinnant's `civil_from_days`); `None` past the
    /// years an `i32` holds.
    #[must_use]
    pub fn from_days_since_epoch(days: i64) -> Option<Self> {
        let days = days.checked_add(719_468)?;
        let era = days.div_euclid(146_097);
        let day_of_era = days - era * 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let month_from_march = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
        let month = if month_from_march < 10 {
            month_from_march + 3
        } else {
            month_from_march - 9
        };
        let year = year_of_era + era * 400 + i64::from(month <= 2);
        Some(Self {
            year: i32::try_from(year).ok()?,
            month: u8::try_from(month).ok()?,
            day: u8::try_from(day).ok()?,
        })
    }

    /// The date `days` later; `None` out of range.
    #[must_use]
    pub fn plus_days(self, days: i64) -> Option<Self> {
        Self::from_days_since_epoch(self.days_since_epoch().checked_add(days)?)
    }

    /// Its day of the week (1970-01-01 was a Thursday).
    #[must_use]
    pub fn weekday(self) -> Weekday {
        let index = (self.days_since_epoch() + 3).rem_euclid(7);
        Weekday::ALL[usize::try_from(index).unwrap_or_default()]
    }
}

/// The wall-clock arithmetic of IANA zones, which the engine owns. Seconds are vault-clock Unix
/// seconds.
pub trait ZoneRules {
    /// Whether `zone` names a zone these rules know.
    fn knows(&self, zone: &str) -> bool;

    /// The second the wall time `hour:minute` on `date` falls on in `zone`. A wall time a
    /// transition skips takes the first instant after the gap; one a transition repeats takes
    /// the earlier instant. `None` for an unknown zone or a date out of range.
    fn wall_to_utc(&self, zone: &str, date: CivilDate, hour: u8, minute: u8) -> Option<u64>;

    /// The date `utc` falls on in `zone`.
    fn date_of(&self, zone: &str, utc: u64) -> Option<CivilDate>;
}

#[cfg(test)]
mod tests {
    use super::{CivilDate, Weekday};

    #[test]
    fn dates_round_trip_through_their_day_count() {
        let epoch = CivilDate {
            year: 1970,
            month: 1,
            day: 1,
        };
        assert_eq!(epoch.days_since_epoch(), 0);
        assert_eq!(epoch.weekday(), Weekday::Thursday);
        let leap = CivilDate {
            year: 2028,
            month: 2,
            day: 29,
        };
        assert_eq!(
            CivilDate::from_days_since_epoch(leap.days_since_epoch()),
            Some(leap)
        );
        assert_eq!(
            leap.plus_days(1),
            Some(CivilDate {
                year: 2028,
                month: 3,
                day: 1
            })
        );
        for days in [-800_000_i64, -1, 0, 59, 365, 20_000, 2_000_000] {
            let date = CivilDate::from_days_since_epoch(days).expect("in range");
            assert_eq!(date.days_since_epoch(), days);
        }
        assert_eq!(
            CivilDate {
                year: 2026,
                month: 11,
                day: 15
            }
            .weekday(),
            Weekday::Sunday
        );
    }
}
