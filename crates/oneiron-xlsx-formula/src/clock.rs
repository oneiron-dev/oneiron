//! What one recalculation reads from its caller: the instant NOW() and
//! TODAY() observe, the local UTC offset their date and time use, and the
//! seed of RAND, RANDBETWEEN and RANDARRAY.
use chrono::{DateTime, Local, Offset, TimeZone, Utc};
use rand_core::{OsRng, RngCore};

/// The caller context of one recalculation, sampled once. Excel reads its
/// clock once per recalculation, so every NOW() and TODAY() in the workbook
/// observes the same instant, in the local time of the machine that
/// recalculates; RAND draws fresh values on every recalculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecalcClock {
    now: DateTime<Utc>,
    utc_offset_minutes: i16,
    seed: u64,
}

impl RecalcClock {
    /// `now`, read `utc_offset_minutes` east of UTC, with `seed` for the
    /// random functions: the same clock and seed recalculate the same values.
    /// `None` for an offset beyond the ±14 hours of any time zone.
    #[must_use]
    pub fn new(now: DateTime<Utc>, utc_offset_minutes: i16, seed: u64) -> Option<Self> {
        (-840..=840).contains(&utc_offset_minutes).then_some(Self {
            now,
            utc_offset_minutes,
            seed,
        })
    }

    /// The host's clock now, at the host's local offset, with a fresh seed
    /// from the operating system: what Excel recalculating on this machine
    /// at this moment observes, and what the host's own recalc reads.
    #[must_use]
    pub fn system() -> Self {
        let now = Utc::now();
        let offset = Local
            .offset_from_utc_datetime(&now.naive_utc())
            .fix()
            .local_minus_utc()
            / 60;
        Self {
            now,
            // A real offset is within a day, so in i16 minutes.
            utc_offset_minutes: i16::try_from(offset).unwrap_or(0),
            seed: OsRng.next_u64(),
        }
    }

    /// The instant NOW() reads, in UTC.
    #[must_use]
    pub const fn now(&self) -> DateTime<Utc> {
        self.now
    }

    /// Minutes east of UTC of the local date and time NOW() and TODAY() give.
    #[must_use]
    pub const fn utc_offset_minutes(&self) -> i16 {
        self.utc_offset_minutes
    }

    /// The seed of RAND, RANDBETWEEN and RANDARRAY.
    #[must_use]
    pub const fn seed(&self) -> u64 {
        self.seed
    }
}
