//! The run TASK's writer proof (FIX AGENT-RUN-HANDOVER-TRUSTS-REPLICATED-PAYLOAD):
//! which machine wrote an agent run's frozen fields, signed with that
//! machine's install key, so that another machine re-creates a run from its
//! frozen payload only when a machine it counts wrote it.
//!
//! A run TASK rides the shared base window to every machine
//! (`super::run_task`), and its bytes name no signer: on a shared vault
//! every member's admitted machine can write it, and a federation peer's
//! TASK is admitted on its role alone. The handover re-creates the run's try
//! from the TASK's frozen payload (`super::run_handover`), so with no proof
//! every field of the dispatch input it runs (target, definition, requester,
//! scope, depth, budget, launch, parent link) is whatever the row's last
//! writer put there.
//!
//! The machine that writes the frozen fields signs them: a dispatch's mint,
//! a promotion's mint, and every later write that changes them over a stored
//! proof that counts (`super::run_task`). The proof is that machine's id and
//! its Ed25519 signature, under its install machine key, over this module's
//! domain, the vault's genesis-bound id, the machine, the run TASK's id and
//! the digest of the frozen fields: the MESSAGE writer proof's pattern
//! (`crate::sync::ingest::message_writer`). The lease, the outcome and the
//! effect marks are not frozen fields, so a renewal, a take that keeps the
//! live try, or an effect mark signs nothing.
//!
//! A proof counts when it verifies under the key of a machine mine under
//! this install's pin (`AuthorityFold::trusted_machine`), or, for this
//! install's own machine, under its own loaded key. A hosted node, a rented
//! machine, an execution node and another member's machine count for nothing
//! here (Engine ASK AGENT-RUN-HANDOVER-SIGNER).

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{EntityId, Vault};

/// The domain a run TASK writer proof's signature is bound to.
const DOMAIN: &[u8] = b"oneiron/agent-run-task-writer/v1";

/// A proof's bytes: the writer machine's id, then the signature.
const PROOF_LEN: usize = 16 + 64;

/// One machine's proof that it wrote a run TASK's frozen fields, stored as
/// one MessagePack bin of [`PROOF_LEN`] bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AgentRunWriterProof {
    machine: EntityId,
    signature: [u8; 64],
}

impl AgentRunWriterProof {
    /// The machine whose signature this is.
    #[cfg(oneiron_test_support)]
    pub(super) const fn machine(&self) -> EntityId {
        self.machine
    }

    /// The proof `key`, the install key of `machine`, makes over the frozen
    /// fields of digest `frozen` of the run TASK `task_ref` in the vault of
    /// genesis-bound id `vault`.
    pub(super) fn signed(
        vault: &[u8; 32],
        machine: EntityId,
        key: &SigningKey,
        task_ref: EntityId,
        frozen: &[u8; 32],
    ) -> Self {
        Self {
            machine,
            signature: key
                .sign(&transcript(vault, machine, task_ref, frozen))
                .to_bytes(),
        }
    }

    fn encode(&self) -> [u8; PROOF_LEN] {
        let mut raw = [0_u8; PROOF_LEN];
        raw[..16].copy_from_slice(self.machine.as_bytes());
        raw[16..].copy_from_slice(&self.signature);
        raw
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != PROOF_LEN {
            return None;
        }
        Some(Self {
            machine: EntityId::from_bytes(raw[..16].try_into().ok()?).ok()?,
            signature: raw[16..].try_into().ok()?,
        })
    }
}

impl Serialize for AgentRunWriterProof {
    fn serialize<S: Serializer>(&self, out: S) -> std::result::Result<S::Ok, S::Error> {
        out.serialize_bytes(&self.encode())
    }
}

impl<'de> Deserialize<'de> for AgentRunWriterProof {
    fn deserialize<D: Deserializer<'de>>(input: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = AgentRunWriterProof;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an agent run TASK writer proof's bytes")
            }
            fn visit_bytes<E: serde::de::Error>(
                self,
                raw: &[u8],
            ) -> std::result::Result<Self::Value, E> {
                AgentRunWriterProof::decode(raw).ok_or_else(|| E::invalid_length(raw.len(), &self))
            }
        }
        input.deserialize_bytes(Visitor)
    }
}

/// The bytes a writer signs for the frozen fields of digest `frozen` of the
/// run TASK `task_ref`.
fn transcript(
    vault: &[u8; 32],
    machine: EntityId,
    task_ref: EntityId,
    frozen: &[u8; 32],
) -> Vec<u8> {
    let mut signed = Vec::with_capacity(DOMAIN.len() + 32 + 16 + 16 + 32);
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(vault);
    signed.extend_from_slice(machine.as_bytes());
    signed.extend_from_slice(task_ref.as_bytes());
    signed.extend_from_slice(frozen);
    signed
}

/// This install's proof that it wrote the frozen fields of digest `frozen`
/// of the run TASK `task_ref`, read in `txn`; `None` when it holds no loaded
/// signer or the vault has no genesis-bound id yet. The TASK then goes
/// unsigned, and no other machine takes the run from it.
pub(super) fn sign_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
    frozen: &[u8; 32],
) -> Option<AgentRunWriterProof> {
    let genesis = match vault.authority_view_readonly_in_txn(txn) {
        Ok(view) => view.vault_id?,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "an agent run TASK goes unsigned: the authority view did not read"
            );
            return None;
        }
    };
    let (machine, key) = match crate::store::install_identity::machine_signer_in_txn(vault, txn) {
        Ok(signer) => signer,
        Err(error) => {
            tracing::debug!(
                kind = ?error.kind(),
                "an agent run TASK goes unsigned: no signer here"
            );
            return None;
        }
    };
    Some(AgentRunWriterProof::signed(
        &genesis, machine, &key, task_ref, frozen,
    ))
}

/// Whether `proof` is a proof that counts for the frozen fields of digest
/// `frozen` of the run TASK `task_ref`, read in `txn`: it verifies, over
/// this vault's genesis-bound id, under the key of a machine mine under this
/// install's pin, or under this install's own loaded key when it names this
/// install's machine. `false` with no proof, for any other machine, and for
/// an authority view that does not read.
pub(super) fn counts_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    task_ref: EntityId,
    frozen: &[u8; 32],
    proof: Option<&AgentRunWriterProof>,
) -> bool {
    let Some(proof) = proof else {
        return false;
    };
    let view = match vault.authority_view_readonly_in_txn(txn) {
        Ok(view) => view,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "an agent run TASK's writer proof was not judged: the authority view did not read"
            );
            return false;
        }
    };
    let Some(genesis) = view.vault_id else {
        return false;
    };
    let machine_key = match view.trusted_machine(proof.machine) {
        Some(trusted) => trusted.profile.machine_key,
        None => match own_machine_key_in(vault, txn, proof.machine) {
            Some(key) => key,
            None => return false,
        },
    };
    let Ok(key) = VerifyingKey::from_bytes(&machine_key) else {
        return false;
    };
    key.verify_strict(
        &transcript(&genesis, proof.machine, task_ref, frozen),
        &Signature::from_bytes(&proof.signature),
    )
    .is_ok()
}

/// The public half of this install's loaded machine key, read in `txn`, when
/// `machine` is this install's machine; `None` otherwise.
fn own_machine_key_in(vault: &Vault, txn: &heed::RoTxn<'_>, machine: EntityId) -> Option<[u8; 32]> {
    let (own, key) = crate::store::install_identity::machine_signer_in_txn(vault, txn).ok()?;
    (own == machine).then(|| key.verifying_key().to_bytes())
}
