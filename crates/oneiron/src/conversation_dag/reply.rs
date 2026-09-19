//! Revision-bound reply strips. Missing or edited targets never expose a
//! replacement body as though it were the historical quotation.

use super::graph::{conversation_of, edge_ids, invalid, require_type};
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_TURN;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};
use rmpv::Value;

/// Renderer-neutral reply strip over an exact content revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyStrip {
    /// Target of the historical reply pointer.
    pub record: EntityId,
    /// BLAKE3 content hash captured at the merge move.
    pub revision: String,
    /// Target's txt field, only when it is still live at the pinned revision.
    pub text: Option<String>,
    /// Target is missing, deleted or no longer at the pinned revision.
    pub stale: bool,
}

impl Vault {
    /// Projects a revision-bound reply strip. Never reconstructs or invents text.
    pub fn reply_strip(&self, record: &EntityId) -> Result<Option<ReplyStrip>> {
        let txn = self.store.env.read_txn()?;
        let bytes = require_type(&self.store, &txn, record, ENTITY_TYPE_TURN)?;
        let mut input = bytes.as_slice();
        let value =
            rmpv::decode::read_value(&mut input).map_err(|_| invalid("invalid record body"))?;
        let Value::Map(fields) = value else {
            return Err(invalid("invalid record body"));
        };
        if !input.is_empty() {
            return Err(invalid("trailing record bytes"));
        }
        let pointers: Vec<_> = fields
            .iter()
            .filter(|(key, _)| key.as_str() == Some("reply_to"))
            .collect();
        if pointers.is_empty() {
            return Ok(None);
        }
        if pointers.len() != 1 {
            return Err(invalid("duplicate reply pointer"));
        }
        let Value::Map(pointer) = &pointers[0].1 else {
            return Err(invalid("invalid reply pointer"));
        };
        let get = |name| -> Result<&Value> {
            let mut values = pointer.iter().filter(|(key, _)| key.as_str() == Some(name));
            let (_, value) = values
                .next()
                .ok_or_else(|| invalid("incomplete reply pointer"))?;
            if values.next().is_some() {
                return Err(invalid("duplicate reply pointer field"));
            }
            Ok(value)
        };
        let target = EntityId::from_hex(
            get("record")?
                .as_str()
                .ok_or_else(|| invalid("invalid reply target"))?,
        )?;
        let revision = get("revision")?
            .as_str()
            .ok_or_else(|| invalid("invalid reply revision"))?
            .to_owned();
        if revision.len() != 64 || !revision.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid("invalid reply hash"));
        }
        if edge_ids(&self.store, &txn, record, EdgeKind::RepliesTo, false, 2)? != [target] {
            return Err(Error::CorruptedIndex("reply pointer index"));
        }
        let (text, stale) = match live_entity_row_in_txn(&self.store, &txn, &target)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_TURN,
                body,
            } => {
                if conversation_of(&self.store, &txn, &target)?
                    != conversation_of(&self.store, &txn, record)?
                {
                    return Err(invalid("reply target is outside conversation"));
                }
                if blake3::hash(&body).to_hex().as_str() != revision {
                    (None, true)
                } else {
                    let value = rmpv::decode::read_value(&mut body.as_slice())
                        .map_err(|_| invalid("invalid reply target body"))?;
                    let text = value
                        .as_map()
                        .and_then(|fields| {
                            fields.iter().find(|(key, _)| key.as_str() == Some("txt"))
                        })
                        .and_then(|(_, value)| value.as_str())
                        .map(str::to_owned);
                    (text, false)
                }
            }
            _ => (None, true),
        };
        Ok(Some(ReplyStrip {
            record: target,
            revision,
            text,
            stale,
        }))
    }
}
