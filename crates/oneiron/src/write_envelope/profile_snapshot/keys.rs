//! Stable Person x Facet x World addressing and entity-id derivation.

use crate::entity_id::EntityId;

/// Address of one profile snapshot in the Person x Facet x World space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PsychProfileKey {
    pub person: EntityId,
    pub facet: Option<EntityId>,
    pub world: Option<EntityId>,
}

const PSYCH_PROFILE_ENTITY_ID_DOMAIN: &[u8] = b"oneiron:psych_profile:v1";

fn hash_optional_profile_entity(hasher: &mut blake3::Hasher, value: Option<EntityId>) {
    match value {
        Some(id) => {
            hasher.update(&[1]);
            hasher.update(id.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

/// Derives the stable entity id for a Person x Facet x World profile.
#[must_use]
pub fn psych_profile_entity_id(key: &PsychProfileKey) -> EntityId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PSYCH_PROFILE_ENTITY_ID_DOMAIN);
    hasher.update(key.person.as_bytes());
    hash_optional_profile_entity(&mut hasher, key.facet);
    hash_optional_profile_entity(&mut hasher, key.world);
    let mut digest = hasher.finalize();
    loop {
        let bytes: [u8; 16] = digest.as_bytes()[..16]
            .try_into()
            .expect("blake3 digest has at least 16 bytes");
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return id;
        }
        // A reserved sentinel is astronomically unlikely, but derived ids
        // must never expose one; deterministically advance the digest instead.
        digest = blake3::hash(digest.as_bytes());
    }
}
