//! Opens an existing job's native copy before any provider or live-home read.
//! Only data and original obligations cross into the canonical writer.

use std::path::PathBuf;

use heed::RoTxn;

use super::ReceivedHomeClaimVector;
use super::actor_copy::RetainedHomeClaimActors;
use super::retained::RetainedResponseSource;
use super::retained_copy::RetainedHomeClaimCopy;
use crate::store::key_custody::{CustodyBinding, binding_in_txn, retirement_in_txn};
use crate::store::{
    ResponseDb, body_key_in, instance_id, response_carrier, response_instance_owner_in_txn,
};
use crate::{EntityId, Result, Vault};

enum Requirements {
    Response(RetainedResponseSource),
    OriginActors(RetainedHomeClaimActors),
}

/// Not a lease, receipt or grant. No key or read guard is retained here.
pub(super) struct OpenedRetainedHomeClaim {
    path: PathBuf,
    binding: CustodyBinding,
    bytes: Vec<u8>,
    requirements: Requirements,
    pub(super) received: ReceivedHomeClaimVector,
}

fn response_current_in_txn(
    vault: &Vault,
    txn: &RoTxn<'_>,
    binding: &CustodyBinding,
    id: &EntityId,
    response: &RetainedResponseSource,
) -> Result<bool> {
    let instance = instance_id(binding, &response.instance)?;
    if retirement_in_txn(&vault.store, txn, instance.subject())?
        .is_some_and(|intent| intent.through >= instance.generation())
    {
        return Ok(false);
    }
    let carrier = response_carrier(ResponseDb::Entities, id.as_bytes());
    for owner in &response.owners {
        if !response_instance_owner_in_txn(&vault.store, txn, *owner, response.instance, &carrier)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

impl OpenedRetainedHomeClaim {
    pub(super) fn open(vault: &Vault, id: &EntityId, bytes: Vec<u8>) -> Result<Option<Self>> {
        let copy = RetainedHomeClaimCopy::decode(id, &bytes)?;
        let binding = {
            let txn = vault.store.env.read_txn()?;
            let Some(binding) = binding_in_txn(&vault.store, &txn)? else {
                return Ok(None);
            };
            binding
        };
        let (received, requirements) = match copy {
            RetainedHomeClaimCopy::Response(copy) => {
                copy.validate(&vault.store, id)?;
                {
                    let _guard = vault.store.core.key_custody.read_guard()?;
                    let txn = vault.store.env.read_txn()?;
                    if binding_in_txn(&vault.store, &txn)?.as_ref() != Some(&binding)
                        || !response_current_in_txn(vault, &txn, &binding, id, &copy.response)?
                    {
                        return Ok(None);
                    }
                    // The ORIGINAL instance, never the current source's binding.
                    // Drop this key and guard before opening the canonical writer.
                    let _key = body_key_in(&binding, &copy.response.instance)?;
                }
                (
                    ReceivedHomeClaimVector {
                        peer: copy.sender.peer(),
                        vector: copy.vector,
                    },
                    Requirements::Response(copy.response),
                )
            }
            RetainedHomeClaimCopy::OriginActors(copy) => {
                let Some(vector) = copy.open_in_vault(vault)? else {
                    return Ok(None);
                };
                (
                    ReceivedHomeClaimVector {
                        peer: copy.sender_peer(),
                        vector,
                    },
                    Requirements::OriginActors(copy),
                )
            }
        };
        Ok(Some(Self {
            path: vault.store.env.path().to_path_buf(),
            binding,
            bytes,
            requirements,
            received,
        }))
    }

    /// Checks original custody and exact job bytes in the actual filling writer.
    /// The caller also rejudges the original sender, full source and model tuple.
    pub(super) fn current_in_txn(&self, vault: &Vault, txn: &RoTxn<'_>) -> Result<bool> {
        let id = self.received.vector.entity_id;
        if self.path != vault.store.env.path()
            || binding_in_txn(&vault.store, txn)?.as_ref() != Some(&self.binding)
            || crate::sync::queue::embed_job_home_claim_copy_in_txn(&vault.store, txn, &id)?
                .as_deref()
                != Some(self.bytes.as_slice())
        {
            return Ok(false);
        }
        match &self.requirements {
            Requirements::Response(response) => {
                response_current_in_txn(vault, txn, &self.binding, &id, response)
            }
            Requirements::OriginActors(copy) => {
                copy.requirements_current_in_txn(vault, txn, &self.binding)
            }
        }
    }

    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Clears only the selected copy if no later receive replaced it. The original
/// priority/time and native zero-length job survive every derived-copy miss.
pub(super) fn discard_current_copy(vault: &Vault, id: &EntityId, expected: &[u8]) -> Result<()> {
    vault.with_write_txn_grouped(|txn| discard_current_copy_in_txn(vault, txn, id, expected))
}

pub(super) fn discard_current_copy_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    expected: &[u8],
) -> Result<()> {
    if crate::sync::queue::embed_job_home_claim_copy_in_txn(&vault.store, txn, id)?.as_deref()
        == Some(expected)
    {
        crate::sync::queue::clear_embed_job_home_claim_copy_in_txn(&vault.store, txn, id)?;
    }
    Ok(())
}
