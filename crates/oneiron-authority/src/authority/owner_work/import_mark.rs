//! The owner's mark that he imported one export secret supplement, and its
//! wire codec (FIX 12062).
//!
//! The install where the owner's import of the supplement committed records
//! an [`ExportSupplementImported`] signed with its install key, the carrier,
//! naming the export secret request's signed entry. Ids only: the carrier,
//! the act and the request, never a byte of the sealed copy or its value. It
//! is main-log metadata, so every linked machine folds it, and none relays
//! the request's sealed copy on the window plane once it does.
//!
//! Its act is the export's own kind ([`OwnerActKind::Export`]) on the
//! reserved export target, owner-only like every export act, and its `seen`
//! is the request it marks under [`EXPORT_SUPPLEMENT_IMPORTED_CONTEXT`]: one
//! mark never stands for another request. Only an export secret request
//! takes a mark; the fold judges that, as only the parents' fold holds it.

use rmpv::Value;

use crate::entity_id::EntityId;
use crate::error::Result;

use super::*;

pub const OP_KIND_EXPORT_SUPPLEMENT_IMPORTED: &str = "export_supplement_imported";
const IMPORTED_KEYS: [&str; 4] = [OP_KEY_KIND, "carrier", OP_KEY_ACT, "request"];

/// The context a mark's `seen` is hashed under ([`act_revision`]): the
/// request it marks, so one mark never stands for another request.
pub const EXPORT_SUPPLEMENT_IMPORTED_CONTEXT: &[u8] = b"oneiron/export-supplement-imported/v1";

/// The owner's mark that he imported the supplement of one export secret
/// request, signed by the install key of `carrier`: the live machine of the
/// vault his import committed on.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ExportSupplementImported {
    pub carrier: EntityId,
    /// The owner's act: kind `export`, on the reserved export target, on
    /// the revision [`ExportSupplementImported::seen_for`] the request.
    pub act: OwnerAct,
    /// The export secret request's signed entry, in this entry's causal past
    /// (the fold of its parents), which judges it there.
    pub request: AuthorityEntryHash,
}

impl ExportSupplementImported {
    /// The `seen` the act of a mark of the request signed as entry
    /// `request` states.
    #[must_use]
    pub fn seen_for(request: AuthorityEntryHash) -> [u8; 32] {
        act_revision(EXPORT_SUPPLEMENT_IMPORTED_CONTEXT, [request])
    }

    /// The owner's own export act, on the revision of the request it names.
    /// Whether that request is an export secret request of his is the
    /// fold's to judge: only the parents' fold holds it.
    pub fn validate(&self) -> Result<()> {
        self.act.validate_carried(
            OwnerActKind::Export,
            owner_act_target(EXPORT_ACT_TARGET_NAME)?,
        )?;
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
pub(in crate::authority) fn export_supplement_imported_value(
    mark: &ExportSupplementImported,
) -> Value {
    Value::Map(vec![
        (
            Value::from(OP_KEY_KIND),
            Value::from(OP_KIND_EXPORT_SUPPLEMENT_IMPORTED),
        ),
        (Value::from("carrier"), Value::from(mark.carrier.to_hex())),
        (
            Value::from(OP_KEY_ACT),
            crate::authority::owner_act::owner_act_value(&mark.act),
        ),
        (Value::from("request"), binary_value(mark.request)),
    ])
}

pub(in crate::authority) fn decode_export_supplement_imported(
    entries: &[(Value, Value)],
) -> Result<AuthorityOp> {
    validate_keys(entries, &IMPORTED_KEYS)?;
    let mark = ExportSupplementImported {
        carrier: decode_canonical_id(required(entries, "carrier")?)?,
        act: crate::authority::owner_act::decode_owner_act(required(entries, OP_KEY_ACT)?)?,
        request: decode_hash(required(entries, "request")?)?,
    };
    mark.validate()?;
    Ok(AuthorityOp::ExportSupplementImported(mark))
}
