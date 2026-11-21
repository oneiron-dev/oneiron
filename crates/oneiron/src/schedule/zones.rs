//! The engine's zone rules for wall-clock triggers: its own time-zone database
//! (`calendar::tz`).

use super::{CivilDate, ZoneRules};
use crate::calendar::tz::{ResolvedTimeZone, utc_to_wall};

/// The IANA zones the engine's calendar knows.
#[derive(Debug, Clone, Copy, Default)]
pub struct EngineZones;

impl ZoneRules for EngineZones {
    fn knows(&self, zone: &str) -> bool {
        ResolvedTimeZone::new(zone).is_ok()
    }

    fn wall_to_utc(&self, zone: &str, date: CivilDate, hour: u8, minute: u8) -> Option<u64> {
        let carrier = date
            .days_since_epoch()
            .checked_mul(86_400)?
            .checked_add(i64::from(hour) * 3_600 + i64::from(minute) * 60)?;
        ResolvedTimeZone::new(zone)
            .ok()?
            .carrier_to_utc(u64::try_from(carrier).ok()?)
    }

    fn date_of(&self, zone: &str, utc: u64) -> Option<CivilDate> {
        let wall = utc_to_wall(utc, zone).ok()?;
        Some(CivilDate {
            year: wall.y,
            month: wall.mo,
            day: wall.d,
        })
    }
}
