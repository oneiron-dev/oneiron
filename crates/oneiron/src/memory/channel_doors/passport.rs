use serde::{Deserialize, Serialize};

use super::*;
use crate::thread_passport::{
    StickyMaskDecision, ThreadMask, ThreadPassport, canonical_message_id,
};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadPassportRequest {
    pub identity_ref: EntityId,
    pub message_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadPassportsRequest {
    pub thread_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadMaskView {
    pub identity_ref: EntityId,
    pub actor_ref: EntityId,
    pub facet_ref: Option<EntityId>,
}

impl From<ThreadMask> for ThreadMaskView {
    fn from(mask: ThreadMask) -> Self {
        Self {
            identity_ref: mask.identity_ref,
            actor_ref: mask.actor_ref,
            facet_ref: mask.facet_ref,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadPassportView {
    pub identity_ref: EntityId,
    pub message_id: String,
    pub thread_ref: String,
    pub mask: ThreadMaskView,
    pub observed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadPassportLookup {
    pub passport: Option<ThreadPassportView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadPassportsView {
    pub canonical_thread_ref: String,
    pub passports: Vec<ThreadPassportView>,
    pub pinned_mask: Option<ThreadMaskView>,
}

impl Memory<'_> {
    pub(super) fn channel_mask_readable(&self, mask: ThreadMask) -> MemoryResult<()> {
        self.channel_readable(mask.identity_ref)?;
        self.channel_readable(mask.actor_ref)?;
        if let Some(facet) = mask.facet_ref {
            self.channel_readable(facet)?;
        }
        Ok(())
    }

    fn channel_passport_view(&self, passport: ThreadPassport) -> MemoryResult<ThreadPassportView> {
        self.channel_mask_readable(passport.mask)?;
        Ok(ThreadPassportView {
            identity_ref: passport.identity_ref,
            message_id: passport.message_id.into_string(),
            thread_ref: self.vault.canonical_thread_ref(&passport.thread_ref)?,
            mask: passport.mask.into(),
            observed_at: passport.observed_at,
        })
    }

    pub(super) fn channel_thread_mask(&self, thread_ref: &str) -> MemoryResult<Option<ThreadMask>> {
        let mask = match self.vault.sticky_thread_mask(thread_ref, None)? {
            StickyMaskDecision::Unset => return Ok(None),
            StickyMaskDecision::Keep(mask) | StickyMaskDecision::Conflict { pinned: mask, .. } => {
                mask
            }
        };
        self.channel_mask_readable(mask)?;
        Ok(Some(mask))
    }

    pub fn channel_thread_passport(
        &self,
        input: ThreadPassportRequest,
    ) -> MemoryResult<ThreadPassportLookup> {
        self.channel_readable(input.identity_ref)?;
        let passport = self
            .vault
            .thread_passport(
                &input.identity_ref,
                &canonical_message_id(&input.message_id)?,
            )?
            .map(|passport| self.channel_passport_view(passport))
            .transpose()?;
        Ok(ThreadPassportLookup { passport })
    }

    pub fn channel_thread_passports(
        &self,
        input: ThreadPassportsRequest,
    ) -> MemoryResult<ThreadPassportsView> {
        let canonical_thread_ref = self.vault.canonical_thread_ref(&input.thread_ref)?;
        let passports = self
            .vault
            .thread_passports(&canonical_thread_ref)?
            .into_iter()
            .map(|passport| self.channel_passport_view(passport))
            .collect::<MemoryResult<Vec<_>>>()?;
        let pinned_mask = self
            .channel_thread_mask(&canonical_thread_ref)?
            .map(ThreadMaskView::from);
        Ok(ThreadPassportsView {
            canonical_thread_ref,
            passports,
            pinned_mask,
        })
    }
}
