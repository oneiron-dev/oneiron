//! The `check_in` policy row (ARCH-0082 #waits, #modes and #changing; Engine
//! ruling P22-SHAPE Q5 = A; PLAN L3-35 D1): one versioned, read-only row in
//! the vault's policy manifest that holds `rung_wait` and `mode` rows per act
//! class and per scope. Its only writer today is the Owner's manifest install;
//! the change verbs are PR 3.
//!
//! Wire shape, version 1:
//!
//! ```text
//! check_in: { version: 1,
//!             rung_wait?: [ { row_ref, act_class?, world_ref?, project_ref?, secs } ],
//!             mode?: [ { row_ref, act_class, world_ref?, project_ref?, mode, ask_per? } ] }
//! ```
//!
//! At least one of `rung_wait` and `mode` is present. A row with neither
//! `world_ref` nor `project_ref` is a vault row.
//!
//! For `rung_wait`, the narrowest matching row decides: the narrower scope
//! first (a project row over a world row over a vault row), then a row that
//! names the act class over one that does not.
//!
//! A `mode` row sets the check-in mode (`manual`, `auto` or `full-access`) of
//! the one act class it names; a row with no class would pass every act at
//! once. Every matching `mode` row applies, and the strictest wins (#composing
//! 3-5). `ask_per` (`send` or `batch`) says whether a `manual` send asks once
//! per send or once for a reviewed batch (ARCH-0046 #send-grant). It is
//! allowed only on an `outbound_send` row at `manual`; absent, it reads
//! `send`. A `mode` row's ref is at most [`MODE_ROW_REF_MAX_BYTES`] bytes,
//! because a send's Gate decision is indexed by the row's ref.
//!
//! A malformed row, an unknown version, an unknown field, a wait of zero, a
//! `row_ref` used twice (in one list or across both), or two rows of one list
//! for the same act class and scope make the whole manifest unreadable, as
//! every other manifest key does.

use rmpv::Value;

use super::act_class::ActClass;
use super::mode::CheckInMode;

/// The policy-manifest key of the check-in row.
pub(crate) const CHECK_IN_ROW_KEY: &str = "check_in";

/// The only version of the row this build reads.
pub const CHECK_IN_ROW_VERSION: u16 = 1;

/// The wait per person rung when no row names one (ruling R2: 24 hours).
pub const DEFAULT_RUNG_WAIT_SECS: u64 = 24 * 60 * 60;

/// The longest `mode` row ref, in bytes. A send the row decides names the
/// ref in its Gate decision's grant-ref index key, which LMDB bounds.
pub const MODE_ROW_REF_MAX_BYTES: usize = 128;

#[doc(hidden)]
pub use oneiron_records::check_in::policy::{CheckInScope, ClassWait, WaitSource};

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
            && scope_matches(self.world_ref.as_ref(), self.project_ref.as_ref(), scope)
    }

    /// The row's narrowness: the scope first, then a named act class.
    fn narrowness(&self) -> (u8, bool) {
        (
            u8::from(self.project_ref.is_some()) * 2 + u8::from(self.world_ref.is_some()),
            self.act.is_some(),
        )
    }
}

/// How a `manual` send asks (ARCH-0046 #send-grant): once per send, or once
/// for a reviewed batch of exact sends.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum AskPer {
    /// A press per send. Wire token `send`.
    #[default]
    Send,
    /// One press for a reviewed batch. Wire token `batch`.
    Batch,
}

impl AskPer {
    /// The wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Batch => "batch",
        }
    }

    fn from_token(token: &str) -> Option<Self> {
        [Self::Send, Self::Batch]
            .into_iter()
            .find(|ask_per| ask_per.as_str() == token)
    }

    /// The stricter of two: a press per send beats one for a batch.
    #[must_use]
    pub const fn stricter(self, other: Self) -> Self {
        match (self, other) {
            (Self::Batch, Self::Batch) => Self::Batch,
            _ => Self::Send,
        }
    }
}

/// One `mode` row: the check-in mode of one act class in one scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModeRow {
    /// The row's stable ref, which a receipt names.
    pub row_ref: String,
    /// The act class the row governs.
    pub act: ActClass,
    pub world_ref: Option<String>,
    pub project_ref: Option<String>,
    pub mode: CheckInMode,
    /// As the row states it; `Some` only on an `outbound_send` row at
    /// `manual`.
    pub ask_per: Option<AskPer>,
}

impl ModeRow {
    fn matches(&self, act: ActClass, scope: &CheckInScope) -> bool {
        self.act == act && scope_matches(self.world_ref.as_ref(), self.project_ref.as_ref(), scope)
    }
}

/// What the `mode` rows that match one act in one scope give it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitMode {
    /// The strictest matching row's mode.
    pub mode: CheckInMode,
    /// How a `manual` act asks: `batch` only when every matching `manual`
    /// row says so; `send` in every other case.
    pub ask_per: AskPer,
    /// The refs of the rows that set `mode`, in manifest order.
    pub row_refs: Vec<String>,
}

/// The decoded `check_in` row.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CheckInPolicy {
    rung_waits: Vec<RungWaitRow>,
    modes: Vec<ModeRow>,
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

impl CheckInPolicy {
    /// The `rung_wait` rows, in manifest order.
    #[must_use]
    pub fn rung_waits(&self) -> &[RungWaitRow] {
        &self.rung_waits
    }

    /// The `mode` rows, in manifest order.
    #[must_use]
    pub fn modes(&self) -> &[ModeRow] {
        &self.modes
    }

    /// Decodes the manifest row. `None` for anything but a well-formed
    /// version 1 row (module doc).
    pub(crate) fn decode_row(value: &Value) -> Option<Self> {
        let fields = known_fields(value, &POLICY_FIELDS)?;
        let version = u16::try_from(map_field(fields, "version")?.as_u64()?).ok()?;
        if version != CHECK_IN_ROW_VERSION {
            return None;
        }
        let rung_wait = map_field(fields, "rung_wait");
        let mode = map_field(fields, "mode");
        if rung_wait.is_none() && mode.is_none() {
            return None;
        }
        let rung_waits = decode_list(rung_wait, decode_rung_wait)?;
        let modes = decode_list(mode, decode_mode_row)?;
        let wait_scope_repeated = rung_waits.iter().enumerate().any(|(at, row)| {
            rung_waits[..at].iter().any(|earlier| {
                earlier.act == row.act
                    && earlier.world_ref == row.world_ref
                    && earlier.project_ref == row.project_ref
            })
        });
        let mode_scope_repeated = modes.iter().enumerate().any(|(at, row)| {
            modes[..at].iter().any(|earlier| {
                earlier.act == row.act
                    && earlier.world_ref == row.world_ref
                    && earlier.project_ref == row.project_ref
            })
        });
        let refs = rung_waits
            .iter()
            .map(|row| &row.row_ref)
            .chain(modes.iter().map(|row| &row.row_ref))
            .collect::<Vec<_>>();
        let ref_repeated = refs
            .iter()
            .enumerate()
            .any(|(at, row_ref)| refs[..at].contains(row_ref));
        if wait_scope_repeated || mode_scope_repeated || ref_repeated {
            return None;
        }
        Some(Self { rung_waits, modes })
    }

    /// The narrowest row that matches `act` in `scope`.
    #[must_use]
    pub fn rung_wait_row(&self, act: ActClass, scope: &CheckInScope) -> Option<&RungWaitRow> {
        self.rung_waits
            .iter()
            .filter(|row| row.matches(act, scope))
            .max_by_key(|row| row.narrowness())
    }

    /// The mode the `mode` rows that match `act` in `scope` give it: each one
    /// applies, from vault down to thread, and the strictest wins (ARCH-0082
    /// #composing 3-5). `None` when no row matches.
    #[must_use]
    pub fn explicit_mode(&self, act: ActClass, scope: &CheckInScope) -> Option<ExplicitMode> {
        let matched = self
            .modes
            .iter()
            .filter(|row| row.matches(act, scope))
            .collect::<Vec<_>>();
        let mode = matched
            .iter()
            .map(|row| row.mode)
            .reduce(CheckInMode::stricter)?;
        let ask_per = matched
            .iter()
            .filter(|row| row.mode == CheckInMode::AlwaysAsk)
            .map(|row| row.ask_per.unwrap_or_default())
            .reduce(AskPer::stricter)
            .unwrap_or_default();
        Some(ExplicitMode {
            mode,
            ask_per,
            row_refs: matched
                .iter()
                .filter(|row| row.mode == mode)
                .map(|row| row.row_ref.clone())
                .collect(),
        })
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

/// Whether a row naming `world_ref` and `project_ref` covers `scope`: a field
/// the row leaves out covers every value.
fn scope_matches(
    world_ref: Option<&String>,
    project_ref: Option<&String>,
    scope: &CheckInScope,
) -> bool {
    world_ref.is_none_or(|world| scope.world_ref.as_ref() == Some(world))
        && project_ref.is_none_or(|project| scope.project_ref.as_ref() == Some(project))
}

const POLICY_FIELDS: [&str; 3] = ["version", "rung_wait", "mode"];

const ROW_FIELDS: [&str; 5] = ["row_ref", "act_class", "world_ref", "project_ref", "secs"];

const MODE_ROW_FIELDS: [&str; 6] = [
    "row_ref",
    "act_class",
    "world_ref",
    "project_ref",
    "mode",
    "ask_per",
];

/// The rows of one list field; an absent field is no rows.
fn decode_list<T>(value: Option<&Value>, decode: fn(&Value) -> Option<T>) -> Option<Vec<T>> {
    match value {
        None => Some(Vec::new()),
        Some(value) => value.as_array()?.iter().map(decode).collect(),
    }
}

fn decode_rung_wait(value: &Value) -> Option<RungWaitRow> {
    let fields = known_fields(value, &ROW_FIELDS)?;
    let row_ref = text_field(fields, "row_ref")??;
    let act = match text_field(fields, "act_class")? {
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
        world_ref: text_field(fields, "world_ref")?,
        project_ref: text_field(fields, "project_ref")?,
        secs,
    })
}

fn decode_mode_row(value: &Value) -> Option<ModeRow> {
    let fields = known_fields(value, &MODE_ROW_FIELDS)?;
    let row_ref = text_field(fields, "row_ref")??;
    if row_ref.len() > MODE_ROW_REF_MAX_BYTES {
        return None;
    }
    let act = ActClass::from_token(&text_field(fields, "act_class")??)?;
    let mode_token = text_field(fields, "mode")??;
    let mode = CheckInMode::ALL
        .into_iter()
        .find(|mode| mode.as_str() == mode_token)?;
    let ask_per = match text_field(fields, "ask_per")? {
        None => None,
        Some(_) if act != ActClass::OutboundSend || mode != CheckInMode::AlwaysAsk => return None,
        Some(token) => Some(AskPer::from_token(&token)?),
    };
    Some(ModeRow {
        row_ref,
        act,
        world_ref: text_field(fields, "world_ref")?,
        project_ref: text_field(fields, "project_ref")?,
        mode,
        ask_per,
    })
}

/// The entries of `value`, a map whose keys are each one of `names`, once.
fn known_fields<'a>(value: &'a Value, names: &[&str]) -> Option<&'a [(Value, Value)]> {
    let fields = value.as_map()?;
    for (at, (key, _)) in fields.iter().enumerate() {
        let known = key.as_str().is_some_and(|key| names.contains(&key));
        if !known || fields[..at].iter().any(|(earlier, _)| earlier == key) {
            return None;
        }
    }
    Some(fields)
}

/// The `name` text field: `Some(None)` when absent, `None` when it is not a
/// non-empty string.
fn text_field(fields: &[(Value, Value)], name: &str) -> Option<Option<String>> {
    match map_field(fields, name) {
        None => Some(None),
        Some(value) => {
            let text = value.as_str()?;
            (!text.is_empty()).then(|| Some(text.to_owned()))
        }
    }
}

/// The value of the one `name` field of a manifest map; `None` when it is
/// absent or repeated.
fn map_field<'a>(fields: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    let mut found = fields.iter().filter(|(key, _)| key.as_str() == Some(name));
    let (_, value) = found.next()?;
    found.next().is_none().then_some(value)
}
