//! The owner's cancel of one pending root request, and its wire codec (FIX
//! 4739, CALLS ROOT_WORK_CANCEL).
//!
//! An install that carries the owner's act records an [`OwnerWorkCancel`]
//! signed with its install key, the carrier, naming the request's signed
//! entry. Ids only: the carrier, the act and the request, never a seed,
//! piece, passphrase or code. It is main-log metadata, so every linked
//! machine folds it, the target included whenever it comes back, however
//! long it was offline.
//!
//! A cancel signs no result and stands for none. A request it reaches before
//! its executor answers it never runs, and reads as cancelled, derived from
//! the fold. A result the executor signed before it folded the cancel is the
//! request's one terminal state and stands: the cancel came too late, and
//! nothing is undone.
//!
//! Its act is a root act on the request's target ([`OwnerActKind::RootRequest`]),
//! owner-only like every root act until a Grant line names it, and its
//! `seen` is the request it cancels under [`ROOT_WORK_CANCEL_CONTEXT`]: the
//! request the deciding surface showed. Only a root request takes a cancel;
//! another work kind needs a ruling of its own.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_OWNER_WORK_CANCEL: &str = "owner_work_cancel";
const CANCEL_KEYS: [&str; 4] = [OP_KEY_KIND, "carrier", OP_KEY_ACT, "request"];

/// The context a cancel's `seen` is hashed under ([`act_revision`]): the
/// request it cancels, so one cancel never stands for another request.
pub const ROOT_WORK_CANCEL_CONTEXT: &[u8] = b"oneiron/root-work-cancel/v1";

/// The owner's cancel of one root request, signed by the install key of
/// `carrier`: a live machine of the vault, in any role, that carried his
/// act. It need not be the request's carrier or its target.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct OwnerWorkCancel {
    pub carrier: EntityId,
    /// The owner's act: a root act whose target is the request's target, on
    /// the revision [`OwnerWorkCancel::seen_for`] the request.
    pub act: OwnerAct,
    /// The cancelled request's signed entry, in this entry's causal past (the
    /// fold of its parents), which judges it there.
    pub request: AuthorityEntryHash,
}

impl OwnerWorkCancel {
    /// The `seen` the act of a cancel of the request signed as entry
    /// `request` states.
    #[must_use]
    pub fn seen_for(request: AuthorityEntryHash) -> [u8; 32] {
        act_revision(ROOT_WORK_CANCEL_CONTEXT, [request])
    }

    /// The owner's own root act, on the revision of the request it names.
    /// Whether that request is a root request of the act's target is the
    /// fold's to judge: only the parents' fold holds it.
    pub fn validate(&self) -> Result<()> {
        self.act
            .validate_carried(OwnerActKind::RootRequest, self.act.target)?;
        if self.act.by != ActBy::Owner
            || self.request == [0; 32]
            || self.act.seen != Self::seen_for(self.request)
        {
            return Err(invalid_authority());
        }
        Ok(())
    }

    /// Signed alone by an Ed25519 install key, the carrier's.
    pub(in crate::authority) fn validate_entry(&self, entry: &AuthorityLogEntry) -> Result<()> {
        signed_alone_by_install_key(entry)
    }
}

/// Canonical field order: kind, carrier, act, then request.
pub(in crate::authority) fn owner_work_cancel_value(cancel: &OwnerWorkCancel) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_OWNER_WORK_CANCEL),
        ),
        (Value::from("carrier"), Value::from(cancel.carrier.to_hex())),
        (
            Value::from(OP_KEY_ACT),
            crate::authority::owner_act::owner_act_value(&cancel.act),
        ),
        (Value::from("request"), binary_value(cancel.request)),
    ])
}

pub(in crate::authority) fn decode_owner_work_cancel(
    entries: &[(Value, Value)],
) -> Result<AuthorityOp> {
    validate_keys(entries, &CANCEL_KEYS)?;
    let cancel = OwnerWorkCancel {
        carrier: decode_canonical_id(required(entries, "carrier")?)?,
        act: crate::authority::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
        request: decode_hash(required(entries, "request")?)?,
    };
    cancel.validate()?;
    Ok(AuthorityOp::OwnerWorkCancel(cancel))
}
