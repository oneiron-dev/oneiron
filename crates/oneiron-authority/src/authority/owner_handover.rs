//! An Owner handover in a shared vault as a signed AUTHORITY_LOG Owner action
//! (ARCH-0043, "Last-Owner successor rule"). An Owner who leaves names a
//! successor or signs their own removal; an organization root with no Owner
//! left gets one on proof of control, the host writing the handover. The
//! entry is the signed record of the change the shared-act execution applies
//! (its receipt names it back); the fold admits it as any roster-signed Owner
//! action and keeps no state of its own for it.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_OWNER_HANDOVER: &str = "owner_handover";
/// Longest act id, receipt id or role name an entry carries.
pub const OWNER_HANDOVER_REF_MAX: usize = 128;
const REQUIRED_KEYS: [&str; 5] = [OP_KEY_KIND, "shared_vault", "cause", "from", "receipt"];
const OPTIONAL_KEYS: [&str; 4] = ["to", "from_keeps", "act", "proof"];
/// A proof digest is a BLAKE3 hash, lowercase hex.
const PROOF_HEX_LEN: usize = 64;

/// Why the Owner role moved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OwnerHandoverCause {
    /// An Owner handed the role to a successor (`transfer_ownership`).
    Transfer,
    /// An Owner was removed, or signed their own removal, with or without a
    /// successor (`remove_owner`).
    Removal,
    /// No Owner was left: the claimant proved control of the organization
    /// and the host wrote the handover.
    ProofOfControl,
}

impl OwnerHandoverCause {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Transfer => "transfer",
            Self::Removal => "removal",
            Self::ProofOfControl => "proof_of_control",
        }
    }

    pub fn parse(wire: &str) -> Option<Self> {
        match wire {
            "transfer" => Some(Self::Transfer),
            "removal" => Some(Self::Removal),
            "proof_of_control" => Some(Self::ProofOfControl),
            _ => None,
        }
    }
}

/// One Owner handover.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OwnerHandover {
    /// The shared vault's federation id.
    pub shared_vault: u64,
    pub cause: OwnerHandoverCause,
    /// The member who stops being an Owner.
    pub from: EntityId,
    /// The member who becomes Owner. A transfer and a proof-of-control
    /// handover always name one; a removal may leave the other Owners.
    pub to: Option<EntityId>,
    /// The role `from` keeps, by its wire name; `None` when they leave.
    pub from_keeps: Option<String>,
    /// The shared act the handover executes, when one did.
    pub act: Option<String>,
    /// A proof-of-control handover's BLAKE3 (lowercase hex) of the proof of
    /// organization control the host judged; never the proof itself.
    pub proof: Option<String>,
    /// The execution receipt's id.
    pub receipt: String,
}

impl OwnerHandover {
    pub fn validate(&self) -> Result<()> {
        let names_successor = self.to.is_some();
        let needs_successor = matches!(
            self.cause,
            OwnerHandoverCause::Transfer | OwnerHandoverCause::ProofOfControl
        );
        let refs_ok = [Some(&self.receipt), self.act.as_ref()]
            .into_iter()
            .flatten()
            .all(|value| !value.is_empty() && value.len() <= OWNER_HANDOVER_REF_MAX);
        // A role kept is a lesser one, by a lowercase wire name.
        let role_ok = self.from_keeps.as_deref().is_none_or(|role| {
            !role.is_empty()
                && role.len() <= OWNER_HANDOVER_REF_MAX
                && role != "owner"
                && role
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        });
        // Only the host's proof-of-control judgement carries a proof digest.
        let proof_ok = self.proof.as_deref().is_none_or(|proof| {
            self.cause == OwnerHandoverCause::ProofOfControl
                && proof.len() == PROOF_HEX_LEN
                && proof
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        if (needs_successor && !names_successor)
            || self.to == Some(self.from)
            || !proof_ok
            || !refs_ok
            || !role_ok
        {
            return Err(invalid_authority());
        }
        Ok(())
    }
}

/// Canonical field order: kind, shared_vault, cause, from, then `to`,
/// `from_keeps`, `act` and `proof` when present, then receipt.
pub(super) fn owner_handover_value(handover: &OwnerHandover) -> Value {
    let mut entries = vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_OWNER_HANDOVER),
        ),
        (
            Value::from("shared_vault"),
            Value::from(handover.shared_vault),
        ),
        (Value::from("cause"), Value::from(handover.cause.wire())),
        (Value::from("from"), Value::from(handover.from.to_hex())),
    ];
    if let Some(to) = handover.to {
        entries.push((Value::from("to"), Value::from(to.to_hex())));
    }
    if let Some(role) = &handover.from_keeps {
        entries.push((Value::from("from_keeps"), Value::from(role.as_str())));
    }
    if let Some(act) = &handover.act {
        entries.push((Value::from("act"), Value::from(act.as_str())));
    }
    if let Some(proof) = &handover.proof {
        entries.push((Value::from("proof"), Value::from(proof.as_str())));
    }
    entries.push((
        Value::from("receipt"),
        Value::from(handover.receipt.as_str()),
    ));
    Value::Map(entries)
}

pub(super) fn decode_owner_handover(entries: &[(Value, Value)]) -> Result<AuthorityOp> {
    let present = |name: &str| entries.iter().any(|(key, _)| key.as_str() == Some(name));
    let mut keys = REQUIRED_KEYS.to_vec();
    keys.extend(OPTIONAL_KEYS.iter().filter(|name| present(**name)));
    validate_keys(entries, &keys)?;
    // Canonical only: the encoder's order, so one handover has one encoding.
    let order = [
        OP_KEY_KIND,
        "shared_vault",
        "cause",
        "from",
        "to",
        "from_keeps",
        "act",
        "proof",
        "receipt",
    ];
    let positions: Vec<_> = entries
        .iter()
        .filter_map(|(key, _)| order.iter().position(|name| key.as_str() == Some(name)))
        .collect();
    if positions.len() != entries.len() || positions.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(invalid_authority());
    }
    let text = |name: &str| -> Result<String> {
        required(entries, name)?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(invalid_authority)
    };
    let id = |name: &str| super::machine_profile::decode_canonical_id(required(entries, name)?);
    let handover = OwnerHandover {
        shared_vault: required(entries, "shared_vault")?
            .as_u64()
            .ok_or_else(invalid_authority)?,
        cause: required(entries, "cause")?
            .as_str()
            .and_then(OwnerHandoverCause::parse)
            .ok_or_else(invalid_authority)?,
        from: id("from")?,
        to: present("to").then(|| id("to")).transpose()?,
        from_keeps: present("from_keeps")
            .then(|| text("from_keeps"))
            .transpose()?,
        act: present("act").then(|| text("act")).transpose()?,
        proof: present("proof").then(|| text("proof")).transpose()?,
        receipt: text("receipt")?,
    };
    handover.validate()?;
    Ok(AuthorityOp::OwnerHandover(handover))
}
