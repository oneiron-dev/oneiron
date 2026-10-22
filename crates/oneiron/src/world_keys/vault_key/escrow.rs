//! Vault-key escrow result shapes and outbound capsule access.
//! The entry point is `reseal_escrow_capsule`.
//! `super` owns escrow tables and forwards these public definitions.

use super::*;

/// What an escrow add warns of (FIX 2857). The wrap is sealed either way;
/// a warning names labels only, never a key or a value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "warning")]
pub enum EscrowAddWarning {
    /// The recipient's key is one an escrow label was released to and then
    /// retired under: a released recipient is not meant to be sealed to
    /// again. Seal to a new key, and remove this wrap.
    RetiredRecipient { retired_label: String },
}

/// One escrow wrap added, and what the add warns of.
#[derive(Debug, Clone, Serialize)]
pub struct EscrowAdded {
    pub wrap: VaultKeyWrapInfo,
    /// Empty when nothing warns.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<EscrowAddWarning>,
}

/// One escrow recipient retired after its secret was released, and the
/// owner's receipt for it ([`Vault::retire_vault_key_escrow_as`]). Ids and
/// times only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowRetirement {
    pub receipt_id: String,
    pub label: String,
    /// The vault still carried the wrap `escrow:<label>`, and the retirement
    /// removed it.
    pub removed_wrap: bool,
    /// The vault clock, in seconds, when it was retired.
    pub retired_at: u64,
}

/// An escrow capsule resealed to a fresh recipient ([`reseal_escrow_capsule`]).
/// None of it is secret.
#[derive(Debug, Clone)]
pub struct ResealedEscrowCapsule {
    pub wrap_id: String,
    pub label: String,
    /// The vault the capsule is bound to.
    pub vault_id: [u8; 32],
    /// The commitment an opened key must match.
    pub commitment: [u8; 32],
    /// The E0 `VaultDek` envelope sealed to the fresh recipient.
    pub capsule: Vec<u8>,
}

/// Reseals an escrow capsule to a fresh recipient without the vault: the
/// one-pass re-escrow of a released recipient (CROSS-ARCH-0022
/// #ov-custody-backend). `capsule`, escrow wrap `label` of vault `vault_id`
/// whose data key `commitment` names, opens with its recipient's released
/// `secret`; the key it holds is sealed at once as escrow wrap `new_label` to
/// `recipient`, and only that new capsule leaves. The key never leaves as
/// bytes and is wiped before this returns. Refused when the capsule opens to
/// no key the commitment names, and when `new_label` is `label`: a released
/// recipient is never reused.
pub fn reseal_escrow_capsule(
    vault_id: &[u8; 32],
    commitment: &[u8; 32],
    label: &str,
    capsule: &[u8],
    secret: &HybridSecretKey,
    new_label: &str,
    recipient: &HybridPublicKey,
) -> Result<ResealedEscrowCapsule> {
    check_name(new_label)?;
    if new_label == label {
        return Err(refused(
            "a released escrow recipient is never sealed to again: name a fresh one",
        ));
    }
    let presented = presented_escrow(label, capsule)?;
    let key = open_wrap(
        vault_id,
        commitment,
        &presented,
        &UnlockSecret::Hybrid(secret),
    )?;
    let kind = VaultKeyWrapKind::Escrow {
        label: new_label.to_owned(),
    };
    let capsule = seal_wrap(
        vault_id,
        commitment,
        &kind,
        &WrapSecret::Hybrid(recipient),
        &key,
    )?;
    Ok(ResealedEscrowCapsule {
        wrap_id: kind.id(),
        label: new_label.to_owned(),
        vault_id: *vault_id,
        commitment: *commitment,
        capsule,
    })
}

/// One escrow wrap as a registry keeps it (CROSS-ARCH-0022 #ov-custody):
/// the capsule and what opens and checks it. None of it is secret.
#[derive(Debug, Clone)]
pub struct VaultKeyEscrowCapsule {
    pub wrap_id: String,
    pub label: String,
    /// The vault the capsule is bound to.
    pub vault_id: [u8; 32],
    /// The commitment an opened key must match.
    pub commitment: [u8; 32],
    /// The E0 `VaultDek` envelope: a hybrid capsule of the data key.
    pub capsule: Vec<u8>,
    /// The vault clock, in seconds, when the wrap was added.
    pub created_at: u64,
    /// This capsule is on the host's outbound spool already.
    pub spooled: bool,
}

impl Vault {
    /// The vault key's escrow capsules, each with whether the host's
    /// outbound spool holds it yet.
    pub fn vault_key_escrow_capsules(&self) -> Result<Vec<VaultKeyEscrowCapsule>> {
        let txn = self.store.env.read_txn()?;
        let Some(state) = STATE.get(&self.store, &txn, &())? else {
            return Ok(Vec::new());
        };
        let vault_id = *self.vault_id().as_bytes();
        let mut capsules = Vec::new();
        for (id, stored) in WRAPS.scan(&self.store, &txn)? {
            let VaultKeyWrapKind::Escrow { label } = stored.info.kind else {
                continue;
            };
            let spooled = ESCROW_SPOOLED
                .get(&self.store, &txn, &id)?
                .is_some_and(|hash| hash == *blake3::hash(&stored.envelope).as_bytes());
            capsules.push(VaultKeyEscrowCapsule {
                wrap_id: id,
                label,
                vault_id,
                commitment: state.commitment,
                capsule: stored.envelope,
                created_at: stored.info.created_at,
                spooled,
            });
        }
        Ok(capsules)
    }

    /// Records that the host's outbound spool durably holds `capsule`, the
    /// escrow wrap `wrap_id`'s envelope, so the vault hands each capsule over
    /// once. A wrap sealed again since holds another capsule and is refused.
    pub fn mark_vault_key_escrow_spooled(&self, wrap_id: &str, capsule: &[u8]) -> Result<()> {
        let hash = *blake3::hash(capsule).as_bytes();
        self.with_write_txn(|txn| {
            let id = wrap_id.to_owned();
            let held = WRAPS
                .get(&self.store, txn, &id)?
                .is_some_and(|stored| *blake3::hash(&stored.envelope).as_bytes() == hash);
            if !held {
                return Err(refused("the vault key holds no such escrow capsule"));
            }
            ESCROW_SPOOLED.put(&self.store, txn, &id, &hash)?;
            Ok(())
        })
    }
}
