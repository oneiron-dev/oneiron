//! Typed room authority policy rows. Defaults ship in the seeded manifest.
//! Structural identity, replay and in-flight erasure fences stay in code;
//! role permissions and completed-sweep admission are policy decisions.
use super::resolution::PolicyManifestResolution;
use crate::EntityId;
use crate::conversation::RoomRole;
use rmpv::Value;

pub(crate) const KEY: &str = "room_policy_rows";
const MAX_ROWS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RoomAction {
    Delegate,
    AuthorDelete,
    PolicyDelete,
    GdprSelf,
    GdprManage,
    PostErasureAppend,
}
impl RoomAction {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "delegate" => Some(Self::Delegate),
            "author_delete" => Some(Self::AuthorDelete),
            "policy_delete" => Some(Self::PolicyDelete),
            "gdpr_self" => Some(Self::GdprSelf),
            "gdpr_manage" => Some(Self::GdprManage),
            "post_erasure_append" => Some(Self::PostErasureAppend),
            _ => None,
        }
    }
    const fn as_str(self) -> &'static str {
        match self {
            Self::Delegate => "delegate",
            Self::AuthorDelete => "author_delete",
            Self::PolicyDelete => "policy_delete",
            Self::GdprSelf => "gdpr_self",
            Self::GdprManage => "gdpr_manage",
            Self::PostErasureAppend => "post_erasure_append",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Precedence {
    NestedNarrowing,
    HolderOverride,
}
impl Precedence {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "nested_narrowing" => Some(Self::NestedNarrowing),
            "holder_override" => Some(Self::HolderOverride),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RoomPolicyRow {
    action: RoomAction,
    room: Option<EntityId>,
    roles: Vec<RoomRole>,
    allow: bool,
    precedence: Precedence,
}
impl RoomPolicyRow {
    fn admits(&self, role: RoomRole) -> bool {
        self.allow && (self.action == RoomAction::PostErasureAppend || self.roles.contains(&role))
    }
}

/// Strict map grammar: duplicates, unknown keys, malformed ids/roles and
/// missing axes reject the entire manifest rather than silently widening.
pub(in crate::gate) fn parse_rows(value: &Value) -> Option<Vec<RoomPolicyRow>> {
    let Value::Array(rows) = value else {
        return None;
    };
    if rows.len() > MAX_ROWS {
        return None;
    }
    rows.iter()
        .map(|row| {
            let Value::Map(fields) = row else {
                return None;
            };
            let mut action = None;
            let mut room = None;
            let mut roles = None;
            let mut allow = None;
            let mut precedence = None;
            let mut seen = std::collections::BTreeSet::new();
            for (key, value) in fields {
                let key = key.as_str()?;
                if !seen.insert(key) {
                    return None;
                }
                match key {
                    "action" => action = Some(RoomAction::parse(value.as_str()?)?),
                    "room_ref" => {
                        let text = value.as_str()?;
                        let id = EntityId::from_hex(text).ok()?;
                        if id.to_hex() != text {
                            return None;
                        }
                        room = Some(id);
                    }
                    "roles" => {
                        let Value::Array(values) = value else {
                            return None;
                        };
                        if values.len() > 3 {
                            return None;
                        }
                        let mut parsed = Vec::new();
                        for value in values {
                            let role = match value.as_str()? {
                                "owner" => RoomRole::Owner,
                                "admin" => RoomRole::Admin,
                                "member" => RoomRole::Member,
                                _ => return None,
                            };
                            if parsed.contains(&role) {
                                return None;
                            }
                            parsed.push(role);
                        }
                        roles = Some(parsed);
                    }
                    "allow" => allow = Some(value.as_bool()?),
                    "precedence" => precedence = Some(Precedence::parse(value.as_str()?)?),
                    _ => return None,
                }
            }
            let action = action?;
            let roles = roles?;
            if action != RoomAction::PostErasureAppend && roles.is_empty() {
                return None;
            }
            Some(RoomPolicyRow {
                action,
                room,
                roles,
                allow: allow?,
                precedence: precedence?,
            })
        })
        .collect()
}

/// Every trusted vault row narrows the shipped default. Room rows narrow in
/// the default mode. A holder override can replace another holder's scoped
/// row but is always capped by the vault-wide intersection.
pub(crate) fn allows(
    policy: &PolicyManifestResolution,
    room: EntityId,
    action: RoomAction,
    role: RoomRole,
) -> bool {
    if policy.is_fail_closed() {
        return false;
    }
    let mut vault_seen = false;
    let mut vault_allowed = true;
    let mut nested_allowed = true;
    let mut holder = None;
    for row in &policy.room_policy_rows {
        if row.action != action {
            continue;
        }
        if row.room.is_none() {
            vault_seen = true;
            vault_allowed &= row.admits(role);
        } else if row.room == Some(room) {
            match row.precedence {
                Precedence::NestedNarrowing => nested_allowed &= row.admits(role),
                Precedence::HolderOverride => holder = Some(row.admits(role)),
            }
        }
    }
    if !vault_seen {
        // No trusted manifest names this action: a seeded manifest that
        // predates room rows is never reseeded, and a vault may hold none.
        // The shipped default row decides, as absent policy does elsewhere.
        vault_allowed = parse_rows(&default_rows()).is_some_and(|rows| {
            let mut shipped = rows
                .iter()
                .filter(|row| row.action == action && row.room.is_none())
                .peekable();
            shipped.peek().is_some() && shipped.all(|row| row.admits(role))
        });
    }
    vault_allowed && nested_allowed && holder.unwrap_or(true)
}

/// Shipped room behavior lives in the default POLICY_MANIFEST rather than a
/// hardcoded role allow-list in a room/deletion write door.
pub(crate) fn default_rows() -> Value {
    let row = |action: RoomAction, roles: &[&str], allow| {
        Value::Map(vec![
            (Value::from("action"), Value::from(action.as_str())),
            (
                Value::from("roles"),
                Value::Array(roles.iter().map(|r| Value::from(*r)).collect()),
            ),
            (Value::from("allow"), Value::Boolean(allow)),
            (Value::from("precedence"), Value::from("nested_narrowing")),
        ])
    };
    Value::Array(vec![
        row(RoomAction::Delegate, &["owner"], true),
        row(
            RoomAction::AuthorDelete,
            &["owner", "admin", "member"],
            true,
        ),
        row(RoomAction::PolicyDelete, &["owner", "admin"], true),
        row(RoomAction::GdprSelf, &["owner", "admin", "member"], true),
        row(RoomAction::GdprManage, &["owner", "admin"], true),
        row(RoomAction::PostErasureAppend, &[], true),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_rows_are_typed_complete_and_fail_closed_on_ambiguous_fields() {
        let Value::Array(defaults) = default_rows() else {
            unreachable!()
        };
        assert_eq!(
            parse_rows(&Value::Array(defaults.clone())).unwrap().len(),
            6
        );
        for (key, value) in [
            ("action", Value::from("delegate")),
            ("precedence", Value::from("widen_everywhere")),
            ("unrecognized_role_axis", Value::Boolean(true)),
        ] {
            let mut invalid = defaults.clone();
            let Value::Map(fields) = &mut invalid[0] else {
                unreachable!()
            };
            fields.push((key.into(), value));
            assert!(parse_rows(&Value::Array(invalid)).is_none());
        }
    }
}
