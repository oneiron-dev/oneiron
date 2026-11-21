//! What proves a TASK authority fact (Fable pass 28 R5, DESIGN 3.2 and 3.3).
//!
//! A fact is an act of use (SR-4 = A): its proof is its carrier's signature at the sign-in
//! rung, for persons and agents alike. The carrier is the machine whose door made the fact,
//! and it signs the fact's row with its install key ([`CarrierSignature`]). Another machine
//! counts the fact only when that signature verifies over the fact's own bytes and its fold
//! admitted the carrier.
//!
//! Which actors a carrier may speak for is the judge's answer, and the judge is SPLIT-6's
//! (`owner_proof.rs`, its off-log family row). Until that row lands, [`carrier_admitted`] is
//! the one seam it replaces: any machine the fold admitted carries any actor's act of use, as
//! a hosted node carries the facts of the persons and agents signed in to it (DESIGN 7.3).

use ed25519_dalek::Signer as _;

use crate::Vault;
use crate::authority::{
    AuthorityFold, AuthorityKey, AuthorityVaultId, AuthorityView, CarrierSignature,
    authority_view_readonly_for_store_in_txn, carrier_signature_verifies, carrier_transcript,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;
use oneiron_contracts::fingerprint::ContentHash;

/// The domain of a TASK fact's carrier transcript. It names the body schema: version 2 is the
/// first that carries a carrier.
pub(crate) const TASK_FACT_CARRIER_DOMAIN: &[u8] = b"oneiron/task-fact/v2";

/// The facts this install's own doors wrote, each by the content hash of the exact body it
/// wrote. The door is the first reader (pass 26): it checked the act before it wrote the fact,
/// so this install counts its own facts without asking their carrier again, in an unrooted
/// vault, before its root and with no signer loaded alike. No peer writes here, and a row
/// replaced under a fact's id no longer matches its hash.
const WRITTEN_HERE: SideTable<HexId, [u8; 32], Raw> =
    SideTable::new(&side_table::TASK_FACT_WRITTEN_HERE);

/// Records that this install's door wrote `body` as the fact row `fact_ref`, in the
/// transaction that writes it.
pub(super) fn record_written_fact_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    fact_ref: &EntityId,
    body: &[u8],
) -> Result<()> {
    WRITTEN_HERE.put(
        store,
        wtxn,
        &HexId(*fact_ref),
        &ContentHash::of(body).into_bytes(),
    )
}

/// Every fact row this install's doors wrote, with the content hash of the body each wrote.
pub(super) fn facts_written_here_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<(EntityId, [u8; 32])>> {
    Ok(WRITTEN_HERE
        .scan(store, txn)?
        .into_iter()
        .map(|(HexId(fact_ref), hash)| (fact_ref, hash))
        .collect())
}

/// Forgets that this install wrote the fact row `fact_ref`: the row then counts here only as
/// it proves itself, as on any other install.
pub(super) fn forget_written_fact_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    fact_ref: &EntityId,
) -> Result<()> {
    WRITTEN_HERE
        .delete(store, wtxn, &HexId(*fact_ref))
        .map(drop)
}

/// Whether a fact this install writes in `txn` gets a carrier signature: the vault is rooted
/// and the host loaded this install's signer.
pub(super) fn signs_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<bool> {
    Ok(vault
        .authority_view_readonly_in_txn(txn)?
        .vault_id
        .is_some()
        && signer_in_txn(vault, txn)?.is_some())
}

/// The signer the host loaded for the machine id `txn` holds. A signer loaded for an id
/// since dropped would sign as a machine this install no longer is, so it is none.
fn signer_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<std::sync::Arc<crate::identity::InstallSigner>>> {
    let machine = crate::identity::read_machine_id_in_txn(vault, txn)?;
    Ok(vault
        .loaded_install_signer()
        .filter(|signer| Some(signer.machine) == machine))
}

/// Whether this install's door wrote exactly `body` as the fact row `fact_ref`.
pub(super) fn written_here_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fact_ref: &EntityId,
    body: &[u8],
) -> Result<bool> {
    Ok(
        WRITTEN_HERE.get(store, txn, &HexId(*fact_ref))?
            == Some(ContentHash::of(body).into_bytes()),
    )
}

/// The carrier signature this install puts on the fact row `fact_ref`, whose canonical body
/// without a carrier is `unsigned`: its install key's signature, once the vault is rooted
/// and the host loaded that key. `None` in an unrooted vault, which has no vault id to sign
/// under, and on an install with no signer loaded; such a fact is proved to no other machine.
pub(super) fn carrier_signature_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fact_ref: &EntityId,
    unsigned: &[u8],
) -> Result<Option<CarrierSignature>> {
    let Some(vault_id) = vault.authority_view_readonly_in_txn(txn)?.vault_id else {
        return Ok(None);
    };
    let Some(signer) = signer_in_txn(vault, txn)? else {
        tracing::warn!(
            "no install signer loaded: this task fact is written unsigned and counts on this install only"
        );
        return Ok(None);
    };
    let transcript = carrier_transcript(
        TASK_FACT_CARRIER_DOMAIN,
        &vault_id,
        fact_ref,
        &signer.machine,
        unsigned,
    );
    Ok(Some(CarrierSignature {
        machine: signer.machine,
        key: signer.machine_key.verifying_key().to_bytes(),
        signature: signer.machine_key.sign(&transcript).to_bytes(),
    }))
}

/// How one read proves the facts it folds: the fold its transaction holds, read once, at the
/// first fact that needs it.
pub(super) struct FactProof {
    rooted: Option<(AuthorityVaultId, AuthorityView)>,
}

impl FactProof {
    pub(super) fn in_txn(store: &Store, txn: &heed::RoTxn<'_>) -> Result<Self> {
        let view = authority_view_readonly_for_store_in_txn(store, store.privacy_posture, txn)?;
        Ok(Self {
            rooted: view.vault_id.map(|vault| (vault, view)),
        })
    }

    /// Whether `carrier` proves the fact row `fact_ref` whose canonical body without its
    /// carrier is `unsigned`: the signature verifies under this vault's id and the fold
    /// admitted its machine under its key. Nothing proves a fact in a vault with no settled
    /// root, an unrooted one or one whose root conflicted.
    pub(super) fn proves(
        &self,
        fact_ref: &EntityId,
        unsigned: &[u8],
        carrier: &CarrierSignature,
    ) -> bool {
        self.rooted.as_ref().is_some_and(|(vault, fold)| {
            carrier_signature_verifies(carrier, TASK_FACT_CARRIER_DOMAIN, vault, fact_ref, unsigned)
                && carrier_admitted(fold, carrier)
        })
    }
}

/// Whether `fold` admitted `carrier`'s machine under its key: a profile chain of that machine
/// names the key and is live, or was removed. A removal does not unmake the facts the machine
/// carried before it (SR-2 = A). A conflicted chain admits nothing, and an install key is
/// never a roster key, as the carrier rule of the owner's acts has it (`owner_act.rs`).
fn carrier_admitted(fold: &AuthorityFold, carrier: &CarrierSignature) -> bool {
    !fold
        .roster
        .contains_key(&AuthorityKey::Ed25519(carrier.key))
        && fold.machines.get(&carrier.machine).is_some_and(|machine| {
            machine.chains().any(|(_, chain)| {
                chain.profile.machine_key == carrier.key
                    && !chain.conflicted
                    && (chain.is_live() || chain.removed)
            })
        })
}
