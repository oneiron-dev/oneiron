//! Moved from `crates/oneiron/src/workspace_roster/rooms/audience_events.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::workspace_roster::rooms::audience_events::ThreadAudienceHistory;
use serde::Deserialize;
use serde::Serialize;

/// The domain of an erased person's stand-in in a root's audience edits
/// (FIX 5640).
pub const AUDIENCE_PERSON_ERASED_DOMAIN: &str = "oneiron.rooms.thread-audience.person-erased.v1";

/// What a stand-in reads and writes as, before its digest's hex.
pub const ERASED_PERSON_PREFIX: &str = "erased:";

/// Whom an audience edit adds or removes (FIX 5640): a live id, or no one,
/// the stand-in the edit's root keeps for a person once they were erased.
/// It reads and writes as the id's hex, or as `erased:` and the digest's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AudiencePerson {
    Live(EntityId),
    Erased([u8; 16]),
}

impl AudiencePerson {
    /// The stand-in the root `root` keeps for `person` once they were
    /// erased: one per root and person, so an add and a remove of them still
    /// meet, and two people never share one.
    pub fn erased(root: EntityId, person: EntityId) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(AUDIENCE_PERSON_ERASED_DOMAIN.as_bytes());
        hasher.update(&[0]);
        hasher.update(root.as_bytes());
        hasher.update(person.as_bytes());
        let mut digest = [0; 16];
        digest.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Self::Erased(digest)
    }

    /// The person, while not erased.
    pub const fn live(&self) -> Option<EntityId> {
        match self {
            Self::Live(id) => Some(*id),
            Self::Erased(_) => None,
        }
    }

    /// This, or the stand-in the root `root` keeps for it once erased.
    pub fn stand_in(self, root: EntityId) -> Self {
        self.live().map_or(self, |live| Self::erased(root, live))
    }
}

impl Serialize for AudiencePerson {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Live(id) => serializer.serialize_str(&id.to_hex()),
            Self::Erased(digest) => serializer.serialize_str(&format!(
                "{ERASED_PERSON_PREFIX}{}",
                oneiron_contracts::entity_id::bytes_to_hex_lower(digest)
            )),
        }
    }
}

impl<'de> Deserialize<'de> for AudiencePerson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let Some(hex) = value.strip_prefix(ERASED_PERSON_PREFIX) else {
            return EntityId::from_hex(&value)
                .map(Self::Live)
                .map_err(serde::de::Error::custom);
        };
        let invalid = || <D::Error as serde::de::Error>::custom("invalid erased person");
        // One spelling: thirty-two lowercase hex digits.
        if hex.len() != 32
            || !hex
                .bytes()
                .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(invalid());
        }
        let mut digest = [0; 16];
        for (at, byte) in digest.iter_mut().enumerate() {
            let pair = hex.get(at * 2..at * 2 + 2).ok_or_else(invalid)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Ok(Self::Erased(digest))
    }
}

/// How a request to join settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinSettlement {
    /// An add, a walk-in or an opened history of its person.
    Approved,
    /// A denial of it.
    Denied,
}
