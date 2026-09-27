//! DEC-0005 admission limits. Only the write door applies them; reading a
//! historical goal never retroactively rejects a previously admitted record.
use rmpv::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GoalLimits {
    pub goal_bytes: u64,
    pub why_bytes: u64,
    pub axis_name_bytes: u64,
    pub axis_detail_bytes: u64,
    pub axes: u64,
    pub preferences: u64,
}

impl Default for GoalLimits {
    fn default() -> Self {
        Self {
            goal_bytes: 4096,
            why_bytes: 4096,
            axis_name_bytes: 128,
            axis_detail_bytes: 1024,
            axes: 32,
            preferences: 64,
        }
    }
}
impl GoalLimits {
    pub(crate) fn restrict(self, other: Self) -> Self {
        Self {
            goal_bytes: self.goal_bytes.min(other.goal_bytes),
            why_bytes: self.why_bytes.min(other.why_bytes),
            axis_name_bytes: self.axis_name_bytes.min(other.axis_name_bytes),
            axis_detail_bytes: self.axis_detail_bytes.min(other.axis_detail_bytes),
            axes: self.axes.min(other.axes),
            preferences: self.preferences.min(other.preferences),
        }
    }
    pub(crate) fn encode(self) -> Value {
        Value::Map(
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
            .collect(),
        )
    }
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let entries = value.as_map()?;
        if entries.len() != 6 {
            return None;
        }
        let get = |name: &str| {
            let mut rows = entries.iter().filter(|(k, _)| k.as_str() == Some(name));
            let v = rows.next()?.1.as_u64()?;
            (v > 0 && rows.next().is_none()).then_some(v)
        };
        Some(Self {
            goal_bytes: get("goal_bytes")?,
            why_bytes: get("why_bytes")?,
            axis_name_bytes: get("axis_name_bytes")?,
            axis_detail_bytes: get("axis_detail_bytes")?,
            axes: get("axes")?,
            preferences: get("preferences")?,
        })
    }
    pub(crate) fn fields(self) -> [u64; 6] {
        [
            self.goal_bytes,
            self.why_bytes,
            self.axis_name_bytes,
            self.axis_detail_bytes,
            self.axes,
            self.preferences,
        ]
    }
}
