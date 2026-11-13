//! Door for `tests/graduated_scope_demotion_authors.rs` (census L7-33): the
//! owner-authored grant rows that let a role carry the `policy.change` verb
//! class. The shipped rows give it to no role, so no Admin is a policy holder
//! until its owner says so.

use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::federation::FederationGrantRole;
use crate::federation::ScopeAxis;
use crate::federation::grant_policy::{GrantPolicyRow, ROWS_KEY, encode_row, parse_rows};
use crate::vault::Vault;

/// Installs, through the owner's manifest door, grant rows that give each of
/// `roles` the `policy.change` verb in the member grants minted from now on
/// (the lib test `owner_rows::tests::admit_policy_verb`, on this door).
///
/// # Errors
///
/// A missing or unreadable stored manifest (`InvalidConfig`), and the owner
/// install door's refusals.
pub fn admit_policy_verb(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    roles: &[FederationGrantRole],
) -> Result<()> {
    let unreadable = || Error::InvalidConfig("the stored policy manifest does not read".to_owned());
    let id = crate::gate::default_policy_manifest_id()?;
    let raw = vault.get_raw(&id)?.ok_or_else(unreadable)?;
    let body = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .ok_or_else(unreadable)?;
    let rmpv::Value::Map(mut entries) =
        rmpv::decode::read_value(&mut &body[..]).map_err(|_| unreadable())?
    else {
        return Err(unreadable());
    };
    let (_, value) = entries
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some(ROWS_KEY))
        .ok_or_else(unreadable)?;
    let mut rows = parse_rows(value).ok_or_else(unreadable)?;
    for row in &mut rows {
        if let GrantPolicyRow::RoleDefault { role, scope } = row
            && roles.contains(role)
            && let ScopeAxis::Some(verbs) = &mut scope.verbs
        {
            verbs.insert("policy.change".to_owned());
        }
    }
    *value = rmpv::Value::Array(rows.iter().map(encode_row).collect::<Result<_>>()?);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(entries)).map_err(|_| unreadable())?;
    vault.install_owner_policy_manifest(owner, id, bytes, 1)
}
