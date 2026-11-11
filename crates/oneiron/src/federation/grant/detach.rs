//! The `detach_on_member_leave` key of the FEDERATION_GRANT body (FIX 12555):
//! the member's local release setting on an Owner-authorized Connect grant. When the named
//! person genuinely leaves the named shared vault, this vault withdraws the
//! grant here; the binding only selects which grants that leave releases. It
//! proves no peer-vault kind, no remote identity and no new authority: the
//! mint writer revalidates the original Owner and the consenting person's
//! membership in the same transaction. Only a Connect guest grant carries the
//! key; every other body encodes exactly as before.

use rmpv::Value;

use super::{FederationGrant, FederationGrantRole, FederationGrantScope};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::codec::{
    decode_canonical_entity_ref, invalid_grant, optional_value, required_value,
};

/// The one body key of the detach setting: a standalone literal, not an index
/// into [`super::FEDERATION_GRANT_BODY_KEYS`], so a second optional key family
/// landing beside it keeps its own constant and allowlist arm.
pub(super) const KEY_DETACH_ON_MEMBER_LEAVE: &str = "detach_on_member_leave";

const DETACH_VALUE_KEYS: [&str; 2] = ["shared_vault_id", "person_ref"];

/// The member's local release setting on an Owner-authorized Connect grant:
/// the shared logical vault whose genuine member leave releases this grant,
/// and the actual person the mint writer revalidated. A selector, never proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectMemberLeaveBinding {
    /// The shared logical vault id, nonzero.
    pub shared_vault_id: u64,
    /// The actual consenting person, canonical EntityId.
    pub person_ref: EntityId,
}

/// The body entry of `grant`'s detach setting, when it carries one.
pub(super) fn body_entry(grant: &FederationGrant) -> Option<(Value, Value)> {
    grant.detach_on_member_leave.as_ref().map(|binding| {
        (
            Value::from(KEY_DETACH_ON_MEMBER_LEAVE),
            Value::Map(vec![
                (
                    Value::from(DETACH_VALUE_KEYS[0]),
                    Value::from(binding.shared_vault_id),
                ),
                (
                    Value::from(DETACH_VALUE_KEYS[1]),
                    Value::from(binding.person_ref.to_hex()),
                ),
            ]),
        )
    })
}

/// The detach setting a body carries; a malformed value refuses the body.
pub(super) fn decode_body_entry(
    entries: &[(Value, Value)],
) -> Result<Option<ConnectMemberLeaveBinding>> {
    let Some(value) = optional_value(entries, KEY_DETACH_ON_MEMBER_LEAVE) else {
        return Ok(None);
    };
    let Value::Map(binding) = value else {
        return Err(invalid_grant());
    };
    super::validate_scope_keys(binding, &DETACH_VALUE_KEYS)?;
    let shared_vault_id = required_value(binding, DETACH_VALUE_KEYS[0])?
        .as_u64()
        .ok_or_else(invalid_grant)?;
    if shared_vault_id == 0 {
        return Err(invalid_grant());
    }
    let person_ref = decode_canonical_entity_ref(required_value(binding, DETACH_VALUE_KEYS[1])?)?;
    Ok(Some(ConnectMemberLeaveBinding {
        shared_vault_id,
        person_ref,
    }))
}

/// The setting rides a Connect guest grant only, with no ask payload.
pub(super) fn validate(grant: &FederationGrant) -> Result<()> {
    match &grant.detach_on_member_leave {
        None => Ok(()),
        Some(binding) if binding.shared_vault_id == 0 => Err(invalid_grant()),
        Some(_) => {
            if grant.role != FederationGrantRole::Guest
                || !matches!(grant.scope, FederationGrantScope::Connect { .. })
                || grant.guest.is_some()
            {
                return Err(invalid_grant());
            }
            Ok(())
        }
    }
}
