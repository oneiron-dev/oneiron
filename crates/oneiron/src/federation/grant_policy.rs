//! Vault-resident default capability rows for member-grant minting.
//! Roles and no-widen ceilings stay substrate; choices live in trusted manifests.
use super::{FederationGrantRole as Role, Scope};
use crate::EntityId;
use crate::error::{Error, Result};
use rmpv::Value;
use std::collections::BTreeMap;

pub(crate) const ROWS_KEY: &str = "federation_grant_rows";
const MAX_ROWS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GrantPolicyRow {
    PrecedenceNestedNarrowing,
    RoleDefault {
        role: Role,
        scope: Scope,
    },
    VaultOverride {
        role: Role,
        vault_id: u64,
        scope: Scope,
    },
    HolderOverride {
        role: Role,
        vault_id: u64,
        holder: EntityId,
        scope: Scope,
    },
}

fn row(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}
pub(crate) fn encode_row(value: &GrantPolicyRow) -> Result<Value> {
    Ok(match value {
        GrantPolicyRow::PrecedenceNestedNarrowing => row(vec![
            ("kind", "precedence".into()),
            ("strategy", "nested_narrowing".into()),
        ]),
        GrantPolicyRow::RoleDefault { role, scope } => row(vec![
            ("kind", "role_default".into()),
            ("role", role.as_str().into()),
            ("scope", super::scope_codec::encode_scope_value(scope)?),
        ]),
        GrantPolicyRow::VaultOverride {
            role,
            vault_id,
            scope,
        } => row(vec![
            ("kind", "vault_override".into()),
            ("role", role.as_str().into()),
            ("vault_id", (*vault_id).into()),
            ("scope", super::scope_codec::encode_scope_value(scope)?),
        ]),
        GrantPolicyRow::HolderOverride {
            role,
            vault_id,
            holder,
            scope,
        } => row(vec![
            ("kind", "holder_override".into()),
            ("role", role.as_str().into()),
            ("vault_id", (*vault_id).into()),
            ("holder_ref", holder.to_hex().into()),
            ("scope", super::scope_codec::encode_scope_value(scope)?),
        ]),
    })
}

fn parse_map(value: &Value) -> Option<BTreeMap<&str, &Value>> {
    let Value::Map(entries) = value else {
        return None;
    };
    let mut out = BTreeMap::new();
    for (key, value) in entries {
        if out.insert(key.as_str()?, value).is_some() {
            return None;
        }
    }
    Some(out)
}
fn role(value: &Value) -> Option<Role> {
    let raw = value.as_str()?;
    let role = Role::parse(raw)?;
    (role.as_str() == raw && !matches!(role, Role::Guest | Role::Auditor)).then_some(role)
}
fn scope(value: &Value) -> Option<Scope> {
    super::scope_codec::decode_scope_value(value).ok()
}

/// Strict shape: no duplicate/unknown keys, one precedence row FIRST, and
/// all scopes explicit six-axis values. Malformed rows drop the whole manifest.
pub(crate) fn parse_rows(value: &Value) -> Option<Vec<GrantPolicyRow>> {
    let Value::Array(values) = value else {
        return None;
    };
    if values.len() > MAX_ROWS {
        return None;
    }
    if values.is_empty() {
        return Some(Vec::new());
    }
    let mut rows = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let fields = parse_map(value)?;
        let kind = fields.get("kind")?.as_str()?;
        let parsed = match kind {
            "precedence"
                if index == 0
                    && fields.len() == 2
                    && fields.get("strategy")?.as_str()? == "nested_narrowing" =>
            {
                GrantPolicyRow::PrecedenceNestedNarrowing
            }
            "role_default" if fields.len() == 3 => GrantPolicyRow::RoleDefault {
                role: role(fields.get("role")?)?,
                scope: scope(fields.get("scope")?)?,
            },
            "vault_override" if fields.len() == 4 => GrantPolicyRow::VaultOverride {
                role: role(fields.get("role")?)?,
                vault_id: fields.get("vault_id")?.as_u64().filter(|id| *id > 0)?,
                scope: scope(fields.get("scope")?)?,
            },
            "holder_override" if fields.len() == 5 => {
                let holder_ref = fields.get("holder_ref")?.as_str()?;
                let holder = EntityId::from_hex(holder_ref).ok()?;
                if holder.to_hex() != holder_ref {
                    return None;
                }
                GrantPolicyRow::HolderOverride {
                    role: role(fields.get("role")?)?,
                    vault_id: fields.get("vault_id")?.as_u64().filter(|id| *id > 0)?,
                    holder,
                    scope: scope(fields.get("scope")?)?,
                }
            }
            _ => return None,
        };
        // The map size check plus exact known keys rejects aliases/unknowns.
        let expected: &[&str] = match &parsed {
            GrantPolicyRow::PrecedenceNestedNarrowing => &["kind", "strategy"],
            GrantPolicyRow::RoleDefault { .. } => &["kind", "role", "scope"],
            GrantPolicyRow::VaultOverride { .. } => &["kind", "role", "scope", "vault_id"],
            GrantPolicyRow::HolderOverride { .. } => {
                &["kind", "role", "scope", "vault_id", "holder_ref"]
            }
        };
        if fields.keys().copied().collect::<Vec<_>>() != {
            let mut names = expected.to_vec();
            names.sort_unstable();
            names
        } {
            return None;
        }
        rows.push(parsed);
    }
    Some(rows)
}

/// The precedence row binds all contributions. Role default -> vault cap ->
/// holder cap -> structural role ceiling; every later layer is a meet. An
/// absent role row is bottom, never the constructor's broad ceiling.
pub(crate) fn resolved_scope(
    rows: &[GrantPolicyRow],
    role: Role,
    vault_id: u64,
    holder: EntityId,
) -> Result<Scope> {
    if !rows
        .iter()
        .any(|row| matches!(row, GrantPolicyRow::PrecedenceNestedNarrowing))
    {
        return Err(Error::InvalidConfig(
            "grant policy precedence row missing".into(),
        ));
    }
    let defaults = rows
        .iter()
        .filter_map(|row| match row {
            GrantPolicyRow::RoleDefault {
                role: selected,
                scope,
            } if *selected == role => Some(scope.clone()),
            _ => None,
        })
        .reduce(|left, right| left.meet(&right));
    let Some(defaults) = defaults else {
        return Err(Error::InvalidConfig(
            "grant role default row missing".into(),
        ));
    };
    // The vault's trusted manifest supplies the default; code provides only
    // the structural role ceiling (or the parent ceiling for a Delegate).
    let mut effective = defaults;
    for row in rows {
        if let GrantPolicyRow::VaultOverride {
            role: selected,
            vault_id: selected_vault,
            scope,
        } = row
            && *selected == role
            && *selected_vault == vault_id
        {
            effective = effective.meet(scope);
        }
    }
    for row in rows {
        if let GrantPolicyRow::HolderOverride {
            role: selected,
            vault_id: selected_vault,
            holder: selected_holder,
            scope,
        } = row
            && *selected == role
            && *selected_vault == vault_id
            && *selected_holder == holder
        {
            effective = effective.meet(scope);
        }
    }
    Ok(if role == Role::Delegate {
        // Parent authority is the hard ceiling at the vault mint door. A
        // Delegate's manifest row may select an explicit narrow write class.
        effective
    } else {
        effective.meet(&super::grant_scope::membership_preset(role))
    })
}

impl crate::Vault {
    /// Resolve default authority in the SAME writer that materializes a new
    /// membership row. Missing/malformed manifests and role rows never fall
    /// back to a broad constructor ceiling.
    pub(crate) fn grant_default_scope_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        role: Role,
        vault_id: u64,
        holder: EntityId,
    ) -> Result<Scope> {
        let policy = crate::gate::resolve_policy_manifest(&self.store, txn)?;
        if policy.is_fail_closed() {
            return Err(Error::InvalidConfig(
                "grant default policy is fail-closed".into(),
            ));
        }
        resolved_scope(&policy.federation_grant_rows, role, vault_id, holder)
    }
}

impl crate::Vault {
    /// Authenticated one-hop Delegate mint. Resolve policy in the SAME writer
    /// that persists the record, then meet its default with the live parent's
    /// authority. The bare grant constructor does not choose a capability.
    pub fn create_federation_delegate(
        &self,
        holder: &crate::consent::AuthenticatedOwner,
        parent_grant_id: EntityId,
        member_ref: EntityId,
        now: u64,
        expires_at: u64,
    ) -> Result<EntityId> {
        self.with_write_txn(|txn| {
            self.create_federation_delegate_in_txn(
                txn,
                holder,
                parent_grant_id,
                member_ref,
                now,
                expires_at,
            )
        })
    }

    pub(crate) fn create_federation_delegate_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        holder: &crate::consent::AuthenticatedOwner,
        parent_grant_id: EntityId,
        member_ref: EntityId,
        now: u64,
        expires_at: u64,
    ) -> Result<EntityId> {
        holder.revalidate_in_txn(self, txn)?;
        let raw = self
            .get_raw_in(txn, &parent_grant_id)?
            .ok_or(Error::EntityNotFound)?;
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("parent federation grant header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_FEDERATION_GRANT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        // A deleted parent grant delegates nothing, even while its body is stored.
        if !crate::vault::live_entity_row_in_txn(&self.store, txn, &parent_grant_id)?.is_live() {
            return Err(Error::InvalidConfig(
                "delegate parent or member is not active".into(),
            ));
        }
        let parent =
            super::decode_federation_grant_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
        // An ask-scoped guest grant is never a delegate parent.
        let super::FederationGrantScope::Vault { vault_id } = parent.scope else {
            return Err(Error::InvalidConfig(
                "delegate parent or member is not active".into(),
            ));
        };
        if parent.member_ref != holder.actor()
            || !parent.is_admin()
            || parent.expires_at.is_some_and(|expires| now >= expires)
            || self
                .shared_vault_creation_in_txn(txn)?
                .is_none_or(|row| row.vault_id != vault_id)
            || self
                .store
                .entities
                .get(txn, member_ref.as_bytes())?
                .is_none()
        {
            return Err(Error::InvalidConfig(
                "delegate parent or member is not active".into(),
            ));
        }
        let fold = self.authority_fold_readonly_in_txn(txn)?;
        if matches!(
            crate::authority::federation_grant_activation(&fold, &parent_grant_id),
            crate::authority::FederationGrantActivation::Inactive(_),
        ) {
            return Err(Error::InvalidConfig(
                "delegate parent pact is inactive".into(),
            ));
        }
        let mut grant =
            super::FederationGrant::attenuated_delegate(&parent, member_ref, now, expires_at)?;
        grant.authority_scope = parent
            .authority_scope
            .meet(&self.grant_default_scope_in_txn(txn, Role::Delegate, vault_id, member_ref)?);
        let id = EntityId::now();
        crate::batch::apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            vec![crate::batch::BatchOp::Put {
                id,
                entity_type: crate::registry::ENTITY_TYPE_FEDERATION_GRANT,
                occurred: crate::TimeRange {
                    start: now,
                    end: now,
                },
                learned_at: now,
                data: super::encode_federation_grant_body(&grant)?,
                allow_maintenance: true,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )?;
        Ok(id)
    }
}

#[cfg(test)]
#[path = "grant_policy/tests.rs"]
mod tests;
