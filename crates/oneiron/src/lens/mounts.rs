//! Pack-aware lens mounts and regeneration from vault-owned intent records.
use super::{
    GeneratedUiCard, GeneratedUiRender, LensEvaluatedRevision, LensRegenFailure,
    LensRegenFailurePhase, LensRegenOutcome, LensRegenRequest, LensRegenerator, LensRenderId,
    LensVersionStamp, regenerate_lens,
};
use crate::{EntityId, Error, Result, Vault};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LensMountId {
    Vault,
    Admin,
    Pack(String),
}

struct Mount {
    pack: Option<EntityId>,
    intent: EntityId,
    card_id: LensRenderId,
    active: LensEvaluatedRevision,
    pending: Option<LensEvaluatedRevision>,
}

/// Host-generation seam. The prompt is read by the engine, not supplied anew
/// by a shell upgrade. The ordinary behavior-diff gate remains the adopter.
pub trait LensIntentRegenerator {
    fn regenerate(
        &self,
        stored_intent: &str,
        request: &LensRegenRequest,
    ) -> std::result::Result<LensEvaluatedRevision, LensRegenFailure>;
}

/// Built-in mounts are always present. Pack mounts re-read the SKILL lifecycle
/// every render; a cached card is never evidence that a pack is still installed.
pub struct LensMountRegistry {
    mounts: BTreeMap<LensMountId, Mount>,
}
impl LensMountRegistry {
    pub fn new(
        vault: (EntityId, LensRenderId, LensEvaluatedRevision),
        admin: (EntityId, LensRenderId, LensEvaluatedRevision),
    ) -> Self {
        let mount = |(intent, card_id, active)| Mount {
            pack: None,
            intent,
            card_id,
            active,
            pending: None,
        };
        Self {
            mounts: BTreeMap::from([
                (LensMountId::Vault, mount(vault)),
                (LensMountId::Admin, mount(admin)),
            ]),
        }
    }
    pub fn register_pack(
        &mut self,
        name: String,
        skill: EntityId,
        intent: EntityId,
        card_id: LensRenderId,
        revision: LensEvaluatedRevision,
    ) -> Result<()> {
        if name.trim().is_empty() || name.len() > 256 || self.mounts.len() >= 256 {
            return Err(Error::InvalidConfig(
                "Invalid lens mount name or collection bound".into(),
            ));
        }
        self.mounts.insert(
            LensMountId::Pack(name),
            Mount {
                pack: Some(skill),
                intent,
                card_id,
                active: revision,
                pending: None,
            },
        );
        Ok(())
    }
    pub fn remove_pack(&mut self, name: &str) -> bool {
        self.mounts
            .remove(&LensMountId::Pack(name.into()))
            .is_some()
    }
    fn is_live(vault: &Vault, mount: &Mount) -> Result<bool> {
        match mount.pack {
            None => Ok(true),
            Some(id) => Ok(vault
                .get_skill_record(&id)?
                .is_some_and(|skill| skill.lifecycle_status.loads_as_canon())),
        }
    }
    pub fn render(&self, vault: &Vault, id: &LensMountId) -> Result<Option<GeneratedUiRender>> {
        let Some(mount) = self.mounts.get(id) else {
            return Ok(None);
        };
        if !Self::is_live(vault, mount)? {
            return Ok(None);
        }
        GeneratedUiCard::new(mount.card_id.clone(), mount.active.lens().clone())?
            .render()
            .map(Some)
    }
    pub fn pending_candidate(&self, id: &LensMountId) -> Option<&LensEvaluatedRevision> {
        self.mounts.get(id).and_then(|mount| mount.pending.as_ref())
    }
    pub fn regenerate_on_upgrade<R: LensIntentRegenerator>(
        &mut self,
        vault: &Vault,
        id: &LensMountId,
        regenerator: &R,
    ) -> Result<Option<LensRegenOutcome>> {
        let Some(mount) = self.mounts.get_mut(id) else {
            return Ok(None);
        };
        if !Self::is_live(vault, mount)?
            || mount.active.lens().version_stamp() == LensVersionStamp::current()
        {
            return Ok(None);
        }
        let prompt = match vault.lens_intent(mount.intent) {
            Ok(Some(prompt)) => prompt,
            result => {
                let failure = LensRegenFailure::new(
                    LensRegenFailurePhase::SummaryPromptRerun,
                    match result {
                        Ok(None) => "Lens intent missing".into(),
                        Err(error) => error.to_string(),
                        _ => unreachable!(),
                    },
                );
                return Ok(Some(LensRegenOutcome::RolledBack {
                    last_good: mount.active.clone(),
                    failure,
                }));
            }
        };
        struct Bound<'a, R> {
            prompt: &'a str,
            inner: &'a R,
        }
        impl<R: LensIntentRegenerator> LensRegenerator for Bound<'_, R> {
            fn regenerate(
                &self,
                request: &LensRegenRequest,
            ) -> std::result::Result<LensEvaluatedRevision, LensRegenFailure> {
                self.inner.regenerate(self.prompt, request)
            }
        }
        let outcome = regenerate_lens(
            &Bound {
                prompt: &prompt,
                inner: regenerator,
            },
            &LensRegenRequest::new(LensVersionStamp::current()),
            mount.active.clone(),
        );
        mount.active = outcome.active_revision().clone();
        mount.pending = outcome.pending_candidate().cloned();
        Ok(Some(outcome))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentRecord {
    lens_intent_version: u8,
    prompt: String,
}
impl Vault {
    /// Stores primary prompt data as a normal replicated DOCUMENT, not a local sidecar.
    pub fn put_lens_intent(
        &self,
        id: EntityId,
        prompt: &str,
        occurred: crate::TimeRange,
        learned_at: u64,
    ) -> Result<()> {
        if prompt.trim().is_empty() || prompt.len() > 64 * 1024 {
            return Err(Error::InvalidConfig(
                "Lens intent must contain 1..=65536 bytes".into(),
            ));
        }
        let bytes = serde_json::to_vec(&IntentRecord {
            lens_intent_version: 1,
            prompt: prompt.into(),
        })
        .map_err(|_| Error::InvalidConfig("Lens intent could not encode".into()))?;
        self.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_ASSET_TEXT,
            occurred,
            learned_at,
            &bytes,
        )
    }
    pub fn lens_intent(&self, id: EntityId) -> Result<Option<String>> {
        let txn = self.store.env.read_txn()?;
        let Some(raw) = self.get_raw_in(&txn, &id)? else {
            return Ok(None);
        };
        let header = crate::batch::EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("lens intent header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_ASSET_TEXT {
            return Err(Error::InvalidEntityType(header.entity_type));
        }
        let record: IntentRecord =
            serde_json::from_slice(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                .map_err(|_| Error::InvalidConfig("Invalid lens intent record".into()))?;
        if record.lens_intent_version != 1
            || record.prompt.trim().is_empty()
            || record.prompt.len() > 64 * 1024
        {
            return Err(Error::InvalidConfig("Invalid lens intent record".into()));
        }
        Ok(Some(record.prompt))
    }
}
