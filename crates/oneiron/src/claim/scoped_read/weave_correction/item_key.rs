//! Current-format wrong-item keys keep entity and gate-decision families apart.

use crate::EntityId;
use crate::side_table::{FixedSideKey, SideKey};
use crate::store::GateDecisionId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WeaveItemKey {
    Entity(EntityId),
    LoopDecision(GateDecisionId),
}

impl WeaveItemKey {
    pub(super) fn bytes(self) -> [u8; 17] {
        let mut key = [0; 17];
        match self {
            Self::Entity(id) => key[1..].copy_from_slice(id.as_bytes()),
            Self::LoopDecision(id) => {
                key[0] = 1;
                key[1..].copy_from_slice(&id.as_bytes());
            }
        }
        key
    }

    pub(in crate::claim::scoped_read) fn to_hex(self) -> String {
        crate::entity_id::bytes_to_hex_lower(&self.bytes())
    }

    pub(in crate::claim::scoped_read) fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != Self::WIDTH * 2 || !hex.is_ascii() {
            return None;
        }
        let mut bytes = [0; Self::WIDTH];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
        }
        Self::decode_key(&bytes)
    }
}

impl SideKey for WeaveItemKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes());
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::WIDTH {
            return None;
        }
        match bytes[0] {
            0 => EntityId::decode_key(&bytes[1..]).map(Self::Entity),
            1 => GateDecisionId::decode_key(&bytes[1..]).map(Self::LoopDecision),
            _ => None,
        }
    }
}

impl FixedSideKey for WeaveItemKey {
    const WIDTH: usize = 17;
}
