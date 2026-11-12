//! The `check_in` policy row (ARCH-0082 #waits and #changing; Engine ruling
//! P22-SHAPE Q5 = A): one versioned, read-only row in the vault's policy
//! manifest that holds `rung_wait` per act class and per scope. Its only
//! writer today is the Owner's manifest install; the change verbs are PR 3.
//!
//! Wire shape, version 1:
//!
//! ```text
//! check_in: { version: 1, rung_wait: [ { row_ref, act_class?, world_ref?, project_ref?, secs } ] }
//! ```
//!
//! A row with neither `world_ref` nor `project_ref` is a vault row. The
//! narrowest matching row decides: the narrower scope first (a project row
//! over a world row over a vault row), then a row that names the act class
//! over one that does not. A malformed row, an unknown version, an unknown
//! field, a wait of zero, a repeated `row_ref` or two rows for the same act
//! class and scope make the whole manifest unreadable, as every other
//! manifest key does.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::act_class::ActClass;

/// The policy-manifest key of the check-in row.
pub(crate) const CHECK_IN_ROW_KEY: &str = "check_in";

/// The only version of the row this build reads.
pub const CHECK_IN_ROW_VERSION: u16 = 1;

/// The wait per person rung when no row names one (ruling R2: 24 hours).
pub const DEFAULT_RUNG_WAIT_SECS: u64 = 24 * 60 * 60;

/// Where an act sits, as the wait rows match it: the vault, a world, a
/// project, or a project inside a world.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CheckInScope {
    pub world_ref: Option<String>,
    pub project_ref: Option<String>,
}

/// One `rung_wait` row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RungWaitRow {
    /// The row's stable ref, which a receipt names.
    pub row_ref: String,
    /// The act class the row governs; `None` for every class.
    pub act: Option<ActClass>,
    pub world_ref: Option<String>,
    pub project_ref: Option<String>,
    /// The wait per person rung, in seconds; never zero.
    pub secs: u64,
}

impl RungWaitRow {
    fn matches(&self, act: ActClass, scope: &CheckInScope) -> bool {
        self.act.is_none_or(|row_act| row_act == act)
            && self
                .world_ref
                .as_ref()
                .is_none_or(|world| scope.world_ref.as_ref() == Some(world))
            && self
                .project_ref
                .as_ref()
                .is_none_or(|project| scope.project_ref.as_ref() == Some(project))
    }

    /// The row's narrowness: the scope first, then a named act class.
    fn narrowness(&self) -> (u8, bool) {
        (
            u8::from(self.project_ref.is_some()) * 2 + u8::from(self.world_ref.is_some()),
            self.act.is_some(),
        )
    }
}

/// The decoded `check_in` row.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CheckInPolicy {
    rung_waits: Vec<RungWaitRow>,
}

/// What the vault's resolved policy says about the check-in row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CheckInPolicyRead<'a> {
    /// No trusted manifest names the row: the shipped defaults decide.
    NoRow,
    Row(&'a CheckInPolicy),
    /// The resolved policy failed closed; the shipped defaults decide and
    /// the receipt says the row was unreadable.
    Unreadable,
}

/// Where a captured wait came from. A receipt names it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitSource {
    /// No row: the shipped 24-hour default.
    ShippedDefault,
    /// The policy failed closed: the shipped default, and the receipt says so.
    Unreadable,
    /// The `rung_wait` row with this ref.
    Row(String),
}

impl WaitSource {
    /// The receipt token: `shipped_default`, `unreadable` or `row:<ref>`.
    #[must_use]
    pub fn receipt_token(&self) -> String {
        match self {
            Self::ShippedDefault => "shipped_default".to_owned(),
            Self::Unreadable => "unreadable".to_owned(),
            Self::Row(row_ref) => format!("row:{row_ref}"),
        }
    }
}

/// An act class's effective wait per person rung: its floor. The asker's
/// longer wait and a holder's extension only lengthen it; only a policy
/// holder's row shortens it (Engine ruling P22-SHAPE Q5).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClassWait {
    pub secs: u64,
    pub source: WaitSource,
}

impl CheckInPolicy {
    /// The rows, in manifest order.
    #[must_use]
    pub fn rung_waits(&self) -> &[RungWaitRow] {
        &self.rung_waits
    }

    /// Decodes the manifest row. `None` for anything but a well-formed
    /// version 1 row (module doc).
    pub(crate) fn decode_row(value: &Value) -> Option<Self> {
        let fields = value.as_map()?;
        if fields.len() != 2 {
            return None;
        }
        let version = u16::try_from(map_field(fields, "version")?.as_u64()?).ok()?;
        if version != CHECK_IN_ROW_VERSION {
            return None;
        }
        let rung_waits = map_field(fields, "rung_wait")?
            .as_array()?
            .iter()
            .map(decode_rung_wait)
            .collect::<Option<Vec<_>>>()?;
        for (at, row) in rung_waits.iter().enumerate() {
            let repeated = rung_waits[..at].iter().any(|earlier| {
                earlier.row_ref == row.row_ref
                    || (earlier.act == row.act
                        && earlier.world_ref == row.world_ref
                        && earlier.project_ref == row.project_ref)
            });
            if repeated {
                return None;
            }
        }
        Some(Self { rung_waits })
    }

    /// The narrowest row that matches `act` in `scope`.
    #[must_use]
    pub fn rung_wait_row(&self, act: ActClass, scope: &CheckInScope) -> Option<&RungWaitRow> {
        self.rung_waits
            .iter()
            .filter(|row| row.matches(act, scope))
            .max_by_key(|row| row.narrowness())
    }
}

/// The wait per person rung for `act` in `scope`, as `read` gives it.
pub(crate) fn class_wait(
    read: CheckInPolicyRead<'_>,
    act: ActClass,
    scope: &CheckInScope,
) -> ClassWait {
    let source = match read {
        CheckInPolicyRead::Unreadable => WaitSource::Unreadable,
        CheckInPolicyRead::NoRow => WaitSource::ShippedDefault,
        CheckInPolicyRead::Row(policy) => match policy.rung_wait_row(act, scope) {
            Some(row) => {
                return ClassWait {
                    secs: row.secs,
                    source: WaitSource::Row(row.row_ref.clone()),
                };
            }
            None => WaitSource::ShippedDefault,
        },
    };
    ClassWait {
        secs: DEFAULT_RUNG_WAIT_SECS,
        source,
    }
}

const ROW_FIELDS: [&str; 5] = ["row_ref", "act_class", "world_ref", "project_ref", "secs"];

fn decode_rung_wait(value: &Value) -> Option<RungWaitRow> {
    let fields = value.as_map()?;
    for (at, (key, _)) in fields.iter().enumerate() {
        let known = key.as_str().is_some_and(|key| ROW_FIELDS.contains(&key));
        if !known || fields[..at].iter().any(|(earlier, _)| earlier == key) {
            return None;
        }
    }
    let text = |name: &str| -> Option<Option<String>> {
        match map_field(fields, name) {
            None => Some(None),
            Some(value) => {
                let text = value.as_str()?;
                (!text.is_empty()).then(|| Some(text.to_owned()))
            }
        }
    };
    let row_ref = text("row_ref")??;
    let act = match text("act_class")? {
        None => None,
        Some(token) => Some(ActClass::from_token(&token)?),
    };
    let secs = map_field(fields, "secs")?.as_u64()?;
    if secs == 0 {
        return None;
    }
    Some(RungWaitRow {
        row_ref,
        act,
        world_ref: text("world_ref")?,
        project_ref: text("project_ref")?,
        secs,
    })
}

/// The value of the one `name` field of a manifest map; `None` when it is
/// absent or repeated.
fn map_field<'a>(fields: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    let mut found = fields.iter().filter(|(key, _)| key.as_str() == Some(name));
    let (_, value) = found.next()?;
    found.next().is_none().then_some(value)
}
