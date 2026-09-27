//! Manifest-owned room working-set policy with restrictive composition.
use rmpv::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RoomThreadFill {
    Recency,
    NudgeDue,
    Stage,
}
impl RoomThreadFill {
    pub const fn token(self) -> &'static str {
        match self {
            Self::Recency => "recency",
            Self::NudgeDue => "nudge_due",
            Self::Stage => "stage",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RoomThreadSettings {
    pub(crate) fresh_for: u64,
    pub(crate) rows_per_list: usize,
    pub(crate) tokens_per_list: usize,
    pub(crate) fill: RoomThreadFill,
    pub(crate) waits_per_thread: usize,
}
impl Default for RoomThreadSettings {
    fn default() -> Self {
        Self {
            fresh_for: 7 * 86_400,
            rows_per_list: 8,
            tokens_per_list: 512,
            fill: RoomThreadFill::Stage,
            waits_per_thread: 8,
        }
    }
}
impl RoomThreadSettings {
    pub(crate) fn restrict(self, other: Self) -> Self {
        Self {
            fresh_for: self.fresh_for.min(other.fresh_for),
            rows_per_list: self.rows_per_list.min(other.rows_per_list),
            tokens_per_list: self.tokens_per_list.min(other.tokens_per_list),
            fill: self.fill.min(other.fill),
            waits_per_thread: self.waits_per_thread.min(other.waits_per_thread),
        }
    }
    pub(crate) fn decode(value: &Value) -> Option<Self> {
        let entries = value.as_map()?;
        if entries.len() != 5 {
            return None;
        }
        let get = |name: &str| {
            let mut fields = entries.iter().filter(|(key, _)| key.as_str() == Some(name));
            let value = &fields.next()?.1;
            fields.next().is_none().then_some(value)
        };
        let fresh_for = get("fresh_for_secs")?.as_u64()?.min(7 * 86_400);
        let rows_per_list = usize::try_from(get("rows_per_list")?.as_u64()?).ok()?;
        let tokens_per_list = usize::try_from(get("tokens_per_list")?.as_u64()?).ok()?;
        let waits_per_thread = usize::try_from(get("waits_per_thread")?.as_u64()?).ok()?;
        let fill = match get("fill")?.as_str()? {
            "recency" => RoomThreadFill::Recency,
            "nudge_due" => RoomThreadFill::NudgeDue,
            "stage" => RoomThreadFill::Stage,
            _ => return None,
        };
        if rows_per_list == 0
            || rows_per_list > 64
            || !(64..=2048).contains(&tokens_per_list)
            || !(1..=8).contains(&waits_per_thread)
            || entries.iter().any(|(key, _)| {
                !matches!(
                    key.as_str(),
                    Some(
                        "fresh_for_secs"
                            | "rows_per_list"
                            | "tokens_per_list"
                            | "fill"
                            | "waits_per_thread"
                    )
                )
            })
        {
            return None;
        }
        Some(Self {
            fresh_for,
            rows_per_list,
            tokens_per_list,
            fill,
            waits_per_thread,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_decode_is_closed_and_child_settings_narrow() {
        let row = |fresh, rows, tokens, fill| {
            Value::Map(vec![
                (Value::from("fresh_for_secs"), Value::from(fresh)),
                (Value::from("rows_per_list"), Value::from(rows)),
                (Value::from("tokens_per_list"), Value::from(tokens)),
                (Value::from("fill"), Value::from(fill)),
                (Value::from("waits_per_thread"), Value::from(8)),
            ])
        };
        let parent = RoomThreadSettings::decode(&row(100, 8, 512, "stage")).unwrap();
        let child = RoomThreadSettings::decode(&row(20, 2, 128, "recency")).unwrap();
        let folded = parent.restrict(child);
        assert_eq!(folded, child);
        assert_eq!(child.restrict(parent), child);
        let mut duplicate = row(20, 2, 128, "recency");
        if let Value::Map(fields) = &mut duplicate {
            fields.push((Value::from("fill"), Value::from("stage")));
        }
        assert!(RoomThreadSettings::decode(&duplicate).is_none());
        assert!(RoomThreadSettings::decode(&row(20, 0, 128, "stage")).is_none());
        assert!(RoomThreadSettings::decode(&row(20, 2, 128, "unknown")).is_none());
    }
}
