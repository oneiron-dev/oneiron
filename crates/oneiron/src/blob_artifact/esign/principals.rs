//! Owner-editable principal set and the legal-reality-gated D6 action dial.
use super::model::{invalid, reference};
use crate::consent::AuthenticatedOwner;
use crate::side_table::{self, HexId, LegacyJson, Raw, SideTable};
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Signing principal. Key: hex32.
const PRINCIPALS: SideTable<HexId, SigningPrincipal, LegacyJson> =
    SideTable::new(&side_table::ESIGN_PRINCIPAL);
/// Signing principal set owner stamp. Key: ().
const OWNER_STAMP: SideTable<(), [u8; 16], Raw> =
    SideTable::new(&side_table::ESIGN_PRINCIPAL_OWNER_STAMP);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningAutonomy {
    ScopedRead,
    Draft,
    SendWithApproval,
    AutonomousInEnvelope,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningPrincipal {
    pub principal_ref: String,
    pub autonomy: SigningAutonomy,
    /// Defaults closed. This is a legal-reality dial, not a fixed safety ban.
    pub automated_sign_action: bool,
}
pub(super) fn verify_owner(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    owner: &AuthenticatedOwner,
) -> Result<()> {
    crate::memory::verify_deletion_authority_in_txn(
        vault,
        txn,
        owner.actor(),
        crate::edge::EdgeActorClass::Human,
    )
    .map_err(|_| invalid("live owner authority required"))
}
impl Vault {
    pub fn set_signing_principals(
        &self,
        owner: &AuthenticatedOwner,
        principals: &[SigningPrincipal],
    ) -> Result<()> {
        if principals.len() > 256 {
            return Err(invalid("too many signing principals"));
        }
        self.with_write_txn(|txn| {
            verify_owner(self, txn, owner)?;
            let mut seen = BTreeSet::new();
            for row in principals {
                reference(&row.principal_ref)?;
                let id = EntityId::from_hex(&row.principal_ref)?;
                if !seen.insert(id)
                    || !matches!(
                        self.get_entity_type_in_txn(txn, &id)?,
                        Some(
                            crate::registry::ENTITY_TYPE_PERSON | crate::registry::ENTITY_TYPE_ORG
                        )
                    )
                {
                    return Err(invalid("principal must be a PERSON or ORG"));
                }
            }
            let old = PRINCIPALS.scan_keys(&self.store, txn, &[])?;
            for key in old {
                PRINCIPALS.delete(&self.store, txn, &key)?;
            }
            for row in principals {
                let key = HexId(EntityId::from_hex(&row.principal_ref)?);
                PRINCIPALS.put(&self.store, txn, &key, row)?;
            }
            OWNER_STAMP.put(&self.store, txn, &(), &owner.decision_id().as_bytes())?;
            Ok(())
        })
    }
    pub fn signing_principals(&self) -> Result<Vec<SigningPrincipal>> {
        let txn = self.store.env.read_txn()?;
        Ok(PRINCIPALS
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, principal)| principal)
            .collect())
    }
}
pub(super) fn automated_signing_allowed(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: Option<&str>,
) -> Result<bool> {
    let Some(principal) = principal else {
        return Ok(false);
    };
    let heads = vault.resolve_entity_in_txn(txn, &EntityId::from_hex(principal)?)?;
    let [canonical] = heads.as_slice() else {
        return Ok(false);
    };
    let mut matches = Vec::new();
    for row in PRINCIPALS.iter_from(&vault.store, txn, &[])? {
        let (_, policy) = row?;
        if vault.resolve_entity_in_txn(txn, &EntityId::from_hex(&policy.principal_ref)?)?
            == vec![*canonical]
        {
            matches.push(policy);
        }
    }
    // Ambiguous merged grants do not accidentally widen the action dial.
    Ok(!matches.is_empty()
        && matches.iter().all(|p| {
            p.automated_sign_action && p.autonomy == SigningAutonomy::AutonomousInEnvelope
        }))
}

/// The send-with-approval rung requires the authenticated Human to dispatch
/// the reviewed command on the normal rail. It is not autonomous agent send.
pub(super) fn automated_outbound_allowed(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: Option<&str>,
) -> Result<bool> {
    let Some(principal) = principal else {
        return Ok(false);
    };
    let heads = vault.resolve_entity_in_txn(txn, &EntityId::from_hex(principal)?)?;
    let [canonical] = heads.as_slice() else {
        return Ok(false);
    };
    let mut found = false;
    for row in PRINCIPALS.iter_from(&vault.store, txn, &[])? {
        let (_, policy) = row?;
        if vault.resolve_entity_in_txn(txn, &EntityId::from_hex(&policy.principal_ref)?)?
            == vec![*canonical]
        {
            found = true;
            if policy.autonomy != SigningAutonomy::AutonomousInEnvelope {
                return Ok(false);
            }
        }
    }
    Ok(found)
}
