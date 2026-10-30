//! The WORLD row a guest's base copy lands with (FIX 3831; Engine ruling
//! 09:39 A).
//! The entry point is `DerivedBaseWorld::plan`.
//! Owned by `super`.
//!
//! A guest's base CLAIMs land in the foreign WORLD its source vault and its
//! reserved base id derive (FIX 3497). The sender's base reality has no WORLD
//! row to send, so that foreign world had no row here and no name on the
//! board. Admission now lands one beside them when this vault stores none and
//! the update carries none: a WORLD row marked derived, built here from the
//! pact's source, never signed or attested by anyone. No leaf in it is
//! authority: a world's privacy and owner come only from a signed
//! `AuthorityOp::WorldPrivacy`. Its visibility is the narrowest of the CLAIMs
//! it lands with, never wider: the sensitivity of the birth scope it carries
//! (FIX 3656). It lands in the update's own window, part 0, a base window,
//! since WORLD is no window's world carrier.

use loro::LoroDoc;

use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::validate_claim_body_and_decode;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::SensitivityCeiling;
use crate::registry::ENTITY_TYPE_WORLD;
use crate::sync::loro_support::{map_get_bytes, map_insert_bytes};
use crate::sync::window::birth_scope::BIRTH_SCOPES_MAP;

use super::routing::Routes;

/// The derived WORLD row of a guest's base copy, as admission lands it.
#[cfg(feature = "sync")]
pub(super) struct DerivedBaseWorld {
    /// The foreign WORLD the guest's base CLAIMs move to.
    id: EntityId,
    /// The pact's source vault.
    source: [u8; 32],
    /// The earliest the moved CLAIMs were learned.
    learned_at: u64,
    /// The narrowest sensitivity among the moved CLAIMs.
    sensitivity: SensitivityCeiling,
}

#[cfg(feature = "sync")]
impl DerivedBaseWorld {
    /// The row to derive for `routes`, a guest's update read from `remote`;
    /// `None` when no base CLAIM moves, when the update carries a WORLD row
    /// that lands at the base copy, or when this vault already stores one.
    pub(super) fn plan(vault: &Vault, remote: &LoroDoc, routes: &Routes<'_>) -> Result<Option<Self>> {
        let (Some(guest), Some((id, moved))) = (routes.guest_copy(), routes.base_copy()) else {
            return Ok(None);
        };
        if guest.worlds.values().any(|here| *here == id) || vault.get_raw_unsealed(&id)?.is_some() {
            return Ok(None);
        }
        let entities = remote.get_map("entities");
        let mut learned_at = None::<u64>;
        let mut sensitivity = SensitivityCeiling::Bottom;
        for claim in moved {
            let Some(blob) = map_get_bytes(&entities, &claim.to_hex()) else {
                continue;
            };
            let (Some(header), Ok(body)) = (
                EntityMetadataHeader::parse(&blob),
                validate_claim_body_and_decode(
                    blob.get(ENTITY_METADATA_HEADER_LEN..).unwrap_or_default(),
                    true,
                ),
            ) else {
                continue;
            };
            learned_at = Some(learned_at.map_or(header.learned_at, |at| at.min(header.learned_at)));
            sensitivity = narrower(sensitivity, body.record_scope("read").sensitivity);
        }
        Ok(learned_at.map(|learned_at| Self {
            id,
            source: *guest.source,
            learned_at,
            sensitivity,
        }))
    }

    /// Lands the row in `admitted`, part 0's doc, with its birth scope.
    pub(super) fn land(&self, admitted: &LoroDoc) -> Result<()> {
        let key = self.id.to_hex();
        map_insert_bytes(&admitted.get_map("entities"), &key, &self.row()?)?;
        let scope =
            crate::federation::record_scope::derived_world_birth_scope(self.id, self.sensitivity)?;
        map_insert_bytes(&admitted.get_map(BIRTH_SCOPES_MAP), &key, &scope)
    }

    /// The row's bytes: its metadata header, then a body that names the
    /// sender's base reality and says it is derived.
    fn row(&self) -> Result<Vec<u8>> {
        let source = crate::entity_id::bytes_to_hex_lower(&self.source);
        let body = rmpv::Value::Map(vec![
            (
                rmpv::Value::from("label"),
                rmpv::Value::from(format!("base reality of vault {}", &source[..8])),
            ),
            (rmpv::Value::from("kind"), rmpv::Value::from("base")),
            (rmpv::Value::from("derived"), rmpv::Value::from(true)),
            (rmpv::Value::from("source_vault"), rmpv::Value::from(source)),
        ]);
        let mut row = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + 128);
        row.push(ENTITY_TYPE_WORLD);
        for stamp in [self.learned_at, self.learned_at, self.learned_at] {
            row.extend_from_slice(&stamp.to_be_bytes());
        }
        rmpv::encode::write_value(&mut row, &body)
            .map_err(|_| Error::InvariantViolation("derived WORLD body does not encode"))?;
        Ok(row)
    }
}

/// The narrower of two record sensitivities: the stricter band, so a row at
/// it reads where both do. A record with no band (`Bottom`) holds no reader
/// back.
#[cfg(feature = "sync")]
fn narrower(a: SensitivityCeiling, b: SensitivityCeiling) -> SensitivityCeiling {
    match (a, b) {
        (SensitivityCeiling::AtMost(a), SensitivityCeiling::AtMost(b)) => {
            SensitivityCeiling::AtMost(a.max(b))
        }
        (SensitivityCeiling::Bottom, other) | (other, SensitivityCeiling::Bottom) => other,
    }
}
