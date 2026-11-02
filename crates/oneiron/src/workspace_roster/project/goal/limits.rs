//! DEC-0005 goal limits: the thresholds a confirmed goal intake is counted
//! against. None refuses (rule 5): past one, the intake raises its scan
//! check and keeps the whole record. Reading a historical goal never counts
//! it again.
use rmpv::Value;

use crate::EntityId;

/// How the trusted rows combine. Vault-level rows narrow one another field
/// by field, and each row scoped to the intake's project or thread narrows
/// that. Under the holder precedence, the authenticated holder's own scoped
/// rows then replace the narrowed values, never past the vault's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum GoalLimitsPrecedence {
    NestedNarrowing,
    #[default]
    NestedNarrowingHolderCappedAtVault,
}
impl GoalLimitsPrecedence {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NestedNarrowing => "nested_narrowing",
            Self::NestedNarrowingHolderCappedAtVault => "nested_narrowing_holder_capped_at_vault",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "nested_narrowing" => Some(Self::NestedNarrowing),
            "nested_narrowing_holder_capped_at_vault" => {
                Some(Self::NestedNarrowingHolderCappedAtVault)
            }
            _ => None,
        }
    }

    /// The stricter of two: a holder override stands only where every
    /// trusted row allows it.
    fn stricter(self, other: Self) -> Self {
        match (self, other) {
            (
                Self::NestedNarrowingHolderCappedAtVault,
                Self::NestedNarrowingHolderCappedAtVault,
            ) => Self::NestedNarrowingHolderCappedAtVault,
            _ => Self::NestedNarrowing,
        }
    }
}

/// The six thresholds of one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GoalLimitValues {
    pub goal_bytes: u64,
    pub why_bytes: u64,
    pub axis_name_bytes: u64,
    pub axis_detail_bytes: u64,
    pub axes: u64,
    pub preferences: u64,
}

impl GoalLimitValues {
    /// Field by field, the lower of the two.
    pub(crate) fn narrow(self, other: Self) -> Self {
        Self {
            goal_bytes: self.goal_bytes.min(other.goal_bytes),
            why_bytes: self.why_bytes.min(other.why_bytes),
            axis_name_bytes: self.axis_name_bytes.min(other.axis_name_bytes),
            axis_detail_bytes: self.axis_detail_bytes.min(other.axis_detail_bytes),
            axes: self.axes.min(other.axes),
            preferences: self.preferences.min(other.preferences),
        }
    }

    fn fields(self) -> [u64; 6] {
        [
            self.goal_bytes,
            self.why_bytes,
            self.axis_name_bytes,
            self.axis_detail_bytes,
            self.axes,
            self.preferences,
        ]
    }

    fn entries(self) -> impl Iterator<Item = (Value, Value)> {
        [
            ("goal_bytes", self.goal_bytes),
            ("why_bytes", self.why_bytes),
            ("axis_name_bytes", self.axis_name_bytes),
            ("axis_detail_bytes", self.axis_detail_bytes),
            ("axes", self.axes),
            ("preferences", self.preferences),
        ]
        .into_iter()
        .map(|(k, v)| (Value::from(k), Value::from(v)))
    }

    fn decode(entries: &[(Value, Value)]) -> Option<Self> {
        let get = |name: &str| field(entries, name)??.as_u64().filter(|v| *v > 0);
        Some(Self {
            goal_bytes: get("goal_bytes")?,
            why_bytes: get("why_bytes")?,
            axis_name_bytes: get("axis_name_bytes")?,
            axis_detail_bytes: get("axis_detail_bytes")?,
            axes: get("axes")?,
            preferences: get("preferences")?,
        })
    }
}

/// Where a scoped row applies: one project, or one room thread by its root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum GoalLimitScope {
    Project(EntityId),
    Thread(EntityId),
}

/// One row scoped to a project or a thread. With a holder it is that
/// holder's override there; without one it narrows every intake there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GoalLimitRow {
    pub scope: GoalLimitScope,
    pub holder: Option<EntityId>,
    pub values: GoalLimitValues,
}

impl GoalLimitRow {
    fn encode(&self) -> Value {
        let (scope, id) = match self.scope {
            GoalLimitScope::Project(id) => ("project", id),
            GoalLimitScope::Thread(id) => ("thread", id),
        };
        let mut row = vec![
            (Value::from("scope"), Value::from(scope)),
            (Value::from("ref"), Value::from(id.to_hex())),
        ];
        if let Some(holder) = self.holder {
            row.push((Value::from("holder"), Value::from(holder.to_hex())));
        }
        row.extend(self.values.entries());
        Value::Map(row)
    }

    /// Strict: exactly its scope, its ref, an optional holder and the six
    /// limits, every id in canonical hex.
    fn decode(value: &Value) -> Option<Self> {
        let entries = value.as_map()?;
        let holder = match field(entries, "holder")? {
            Some(holder) => Some(canonical_id(holder)?),
            None => None,
        };
        if entries.len() != 8 + usize::from(holder.is_some()) {
            return None;
        }
        let id = canonical_id(field(entries, "ref")??)?;
        let scope = match field(entries, "scope")??.as_str()? {
            "project" => GoalLimitScope::Project(id),
            "thread" => GoalLimitScope::Thread(id),
            _ => return None,
        };
        Some(Self {
            scope,
            holder,
            values: GoalLimitValues::decode(entries)?,
        })
    }

    /// The row's frontier bytes: its scope, its ref, its holder if any and
    /// its six limits, each at a fixed width.
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let (tag, id) = match self.scope {
            GoalLimitScope::Project(id) => (1u8, id),
            GoalLimitScope::Thread(id) => (2, id),
        };
        let mut bytes = vec![tag];
        bytes.extend_from_slice(id.as_bytes());
        match self.holder {
            Some(holder) => {
                bytes.push(1);
                bytes.extend_from_slice(holder.as_bytes());
            }
            None => bytes.push(0),
        }
        for value in self.values.fields() {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GoalLimits {
    pub precedence: GoalLimitsPrecedence,
    pub goal_bytes: u64,
    pub why_bytes: u64,
    pub axis_name_bytes: u64,
    pub axis_detail_bytes: u64,
    pub axes: u64,
    pub preferences: u64,
    /// The rows scoped to a project or a thread, sorted, each once.
    pub scoped: Vec<GoalLimitRow>,
}

impl Default for GoalLimits {
    fn default() -> Self {
        Self {
            precedence: GoalLimitsPrecedence::default(),
            goal_bytes: 4096,
            why_bytes: 4096,
            axis_name_bytes: 128,
            axis_detail_bytes: 1024,
            axes: 32,
            preferences: 64,
            scoped: Vec::new(),
        }
    }
}
impl GoalLimits {
    fn of(
        precedence: GoalLimitsPrecedence,
        values: GoalLimitValues,
        scoped: Vec<GoalLimitRow>,
    ) -> Self {
        Self {
            precedence,
            goal_bytes: values.goal_bytes,
            why_bytes: values.why_bytes,
            axis_name_bytes: values.axis_name_bytes,
            axis_detail_bytes: values.axis_detail_bytes,
            axes: values.axes,
            preferences: values.preferences,
            scoped,
        }
    }

    /// The vault-level thresholds.
    pub(crate) fn values(&self) -> GoalLimitValues {
        GoalLimitValues {
            goal_bytes: self.goal_bytes,
            why_bytes: self.why_bytes,
            axis_name_bytes: self.axis_name_bytes,
            axis_detail_bytes: self.axis_detail_bytes,
            axes: self.axes,
            preferences: self.preferences,
        }
    }

    /// Two trusted bundles as one: the lower vault limits, every scoped row
    /// of both, and the stricter precedence.
    pub(crate) fn restrict(self, other: Self) -> Self {
        let values = self.values().narrow(other.values());
        let precedence = self.precedence.stricter(other.precedence);
        let mut scoped = self.scoped;
        scoped.extend(other.scoped);
        scoped.sort_unstable();
        scoped.dedup();
        Self::of(precedence, values, scoped)
    }

    /// The thresholds one intake on `project`, in `thread` if any, by
    /// `holder` is counted against: the vault limits, narrowed by every
    /// row scoped there that names no holder. Under the holder precedence
    /// the holder's own rows there replace those values, narrowed by one
    /// another and capped at the vault limits.
    pub(crate) fn resolve_for(
        &self,
        project: EntityId,
        thread: Option<EntityId>,
        holder: Option<EntityId>,
    ) -> GoalLimitValues {
        let vault = self.values();
        let applies = |row: &GoalLimitRow| match row.scope {
            GoalLimitScope::Project(id) => id == project,
            GoalLimitScope::Thread(id) => Some(id) == thread,
        };
        let nested = (self.scoped.iter())
            .filter(|&row| applies(row) && row.holder.is_none())
            .fold(vault, |values, row| values.narrow(row.values));
        if self.precedence != GoalLimitsPrecedence::NestedNarrowingHolderCappedAtVault {
            return nested;
        }
        let held = (self.scoped.iter())
            .filter(|&row| applies(row) && row.holder.is_some() && row.holder == holder)
            .map(|row| row.values)
            .reduce(GoalLimitValues::narrow);
        held.map_or(nested, |held| vault.narrow(held))
    }

    pub(crate) fn encode(&self) -> Value {
        let mut row = vec![(
            Value::from("precedence"),
            Value::from(self.precedence.as_str()),
        )];
        row.extend(self.values().entries());
        if !self.scoped.is_empty() {
            row.push((
                Value::from("scoped"),
                Value::Array(self.scoped.iter().map(GoalLimitRow::encode).collect()),
            ));
        }
        Value::Map(row)
    }

    /// Strict: exactly the precedence and six vault limits, then optional
    /// `scoped` rows. Anything else is malformed and fails closed upstream.
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let entries = value.as_map()?;
        let rows = field(entries, "scoped")?;
        if entries.len() != 7 + usize::from(rows.is_some()) {
            return None;
        }
        let precedence = GoalLimitsPrecedence::parse(field(entries, "precedence")??.as_str()?)?;
        let mut scoped = match rows {
            Some(rows) => (rows.as_array()?.iter())
                .map(GoalLimitRow::decode)
                .collect::<Option<Vec<_>>>()?,
            None => Vec::new(),
        };
        scoped.sort_unstable();
        scoped.dedup();
        Some(Self::of(
            precedence,
            GoalLimitValues::decode(entries)?,
            scoped,
        ))
    }

    pub(crate) fn fields(&self) -> [u64; 6] {
        self.values().fields()
    }
}

/// `name`'s one value in `entries`: `Some(None)` when absent, `None` when
/// named twice.
fn field<'v>(entries: &'v [(Value, Value)], name: &str) -> Option<Option<&'v Value>> {
    let mut rows = entries.iter().filter(|(k, _)| k.as_str() == Some(name));
    let first = rows.next().map(|(_, v)| v);
    rows.next().is_none().then_some(first)
}

fn canonical_id(value: &Value) -> Option<EntityId> {
    let hex = value.as_str()?;
    let id = EntityId::from_hex(hex).ok()?;
    (id.to_hex() == hex).then_some(id)
}
