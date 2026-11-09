//! The flaky-test quarantine and the three nextest tiers.
//!
//! `.config/test-quarantine.toml` lists each quarantined test with an issue
//! and an expiry at most seven days after it was added. `.config/nextest.toml`
//! carries the `pr`, `nightly` and `quarantine` profiles. [`check`] says
//! where the two disagree: a tier with retries, a quarantine filter missing
//! from a profile, an entry with no issue or too long a stay, and, given
//! today's date (the nightly passes it; a test never reads the wall clock),
//! an expired entry.

use std::fs;
use std::path::Path;

/// The most days an entry may stay in the quarantine.
pub const MAX_QUARANTINE_DAYS: i64 = 7;

/// The tier profiles whose default filter carries the quarantine.
pub const TIER_PROFILES: [&str; 3] = ["pr", "nightly", "quarantine"];

/// Every profile of the test tiers, each of which must run with zero
/// retries: a retry hides a flake.
pub const RETRY_FREE_PROFILES: [&str; 4] = ["pr", "nightly", "quarantine", "pending-door"];

/// A calendar date, `YYYY-MM-DD`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    pub year: i64,
    pub month: u32,
    pub day: u32,
}

impl Date {
    /// Parses `YYYY-MM-DD`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.trim().splitn(3, '-');
        let year = parts.next()?.parse().ok()?;
        let month = parts.next()?.parse().ok()?;
        let day = parts.next()?.parse().ok()?;
        ((1..=12).contains(&month) && (1..=31).contains(&day)).then_some(Self { year, month, day })
    }

    /// Days since 1970-01-01 (proleptic Gregorian).
    #[must_use]
    pub fn days(self) -> i64 {
        // Howard Hinnant's days_from_civil.
        let year = if self.month <= 2 { self.year - 1 } else { self.year };
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let month = i64::from(self.month);
        let shifted = if month > 2 { month - 3 } else { month + 9 };
        let day_of_year = (153 * shifted + 2) / 5 + i64::from(self.day) - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era - 719_468
    }
}

/// One quarantined test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The nextest filterset naming the test.
    pub filter: String,
    pub issue: String,
    pub added: Date,
    pub expires: Date,
}

fn squash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The quarantine entries in `.config/test-quarantine.toml` under `root`.
///
/// # Errors
/// The file cannot be read or parsed, or an entry lacks a field.
pub fn load(root: &Path) -> Result<Vec<Entry>, String> {
    let path = root.join(".config/test-quarantine.toml");
    let text = fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let table: toml::Table = text
        .parse()
        .map_err(|error| format!("{}: {error}", path.display()))?;
    let Some(tests) = table.get("test") else {
        return Ok(Vec::new());
    };
    let tests = tests
        .as_array()
        .ok_or_else(|| format!("{}: `test` must be an array of tables", path.display()))?;
    tests
        .iter()
        .enumerate()
        .map(|(index, test)| {
            let field = |name: &str| {
                test.get(name)
                    .and_then(toml::Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| format!("quarantine entry {}: no `{name}`", index + 1))
            };
            let date = |name: &str| {
                let text = field(name)?;
                Date::parse(&text)
                    .ok_or_else(|| format!("quarantine entry {}: `{name}` is not YYYY-MM-DD", index + 1))
            };
            Ok(Entry {
                filter: field("filter")?,
                issue: field("issue")?,
                added: date("added")?,
                expires: date("expires")?,
            })
        })
        .collect()
}

/// The union of the entries' filters as the profiles must write it:
/// `(<filter>) | (<filter>) ...`, or `none()` when there is none.
#[must_use]
pub fn union(entries: &[Entry]) -> String {
    if entries.is_empty() {
        return "none()".to_owned();
    }
    entries
        .iter()
        .map(|entry| format!("({})", squash(&entry.filter)))
        .collect::<Vec<_>>()
        .join(" | ")
}

/// Every disagreement between the quarantine and the nextest tiers under
/// `root`; empty when they agree. With `today`, an expired entry is one too.
#[must_use]
pub fn check(root: &Path, today: Option<Date>) -> Vec<String> {
    let mut problems = Vec::new();
    let entries = match load(root) {
        Ok(entries) => entries,
        Err(problem) => return vec![problem],
    };
    for entry in &entries {
        if entry.issue.trim().is_empty() {
            problems.push(format!("quarantine {:?}: no issue", entry.filter));
        }
        let stay = entry.expires.days() - entry.added.days();
        if !(0..=MAX_QUARANTINE_DAYS).contains(&stay) {
            problems.push(format!(
                "quarantine {:?}: expires {stay} days after it was added; at most {MAX_QUARANTINE_DAYS}",
                entry.filter
            ));
        }
        if let Some(today) = today {
            if today > entry.expires {
                problems.push(format!(
                    "quarantine {:?} ({}) expired on {:04}-{:02}-{:02}: fix or delete the test",
                    entry.filter, entry.issue, entry.expires.year, entry.expires.month, entry.expires.day
                ));
            }
        }
    }
    let path = root.join(".config/nextest.toml");
    let config: toml::Table = match fs::read_to_string(&path)
        .map_err(|error| error.to_string())
        .and_then(|text| text.parse().map_err(|error: toml::de::Error| error.to_string()))
    {
        Ok(config) => config,
        Err(error) => {
            problems.push(format!("{}: {error}", path.display()));
            return problems;
        }
    };
    let union = union(&entries);
    let exclusion = format!("not ({union})");
    let profile_of = |name: &str| {
        config
            .get("profile")
            .and_then(|profiles| profiles.get(name))
            .and_then(toml::Value::as_table)
    };
    for name in RETRY_FREE_PROFILES {
        match profile_of(name) {
            None => problems.push(format!(".config/nextest.toml: no [profile.{name}]")),
            Some(profile) if profile.get("retries").and_then(toml::Value::as_integer) != Some(0) => {
                problems.push(format!("[profile.{name}]: retries must be 0 (a retry hides a flake)"));
            }
            Some(_) => {}
        }
    }
    for name in TIER_PROFILES {
        let Some(profile) = profile_of(name) else {
            continue;
        };
        let filter = profile
            .get("default-filter")
            .and_then(toml::Value::as_str)
            .map(squash)
            .unwrap_or_default();
        let agrees = if name == "quarantine" {
            filter == union
        } else {
            filter.ends_with(&exclusion)
        };
        if !agrees {
            let wanted = if name == "quarantine" { &union } else { &exclusion };
            problems.push(format!(
                "[profile.{name}]: default-filter must {} {wanted:?} to match .config/test-quarantine.toml; it is {filter:?}",
                if name == "quarantine" { "be" } else { "end with" }
            ));
        }
    }
    problems
}
