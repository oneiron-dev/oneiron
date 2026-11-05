use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::error::{Error, Result};
use crate::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange, Vault,
};

use super::{ClipboardWorld, clipboard_world_id};

pub const PREDICATE_CLIPBOARD_CAPTURED: &str = "clipboard.captured";
const KEY_TEXT: &str = "text";
pub(super) const KEY_COPIED_AT: &str = "copied_at";

/// One ordinary clip, read back after the batch door's secret masking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClipboardEntry {
    pub clip: EntityId,
    pub copied_at: u64,
    pub text: String,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ClipMetadata {
    pub clip: EntityId,
    pub copied_at: u64,
    pub text_bytes: u64,
}

impl Vault {
    /// Records one new ordinary text copy. Hosts must finish private-type
    /// classification first; marked/private bytes must never call this door.
    /// Duplicate copies remain distinct clips. No raw text entity is written:
    /// the CLAIM and its subject edge pass through the normal mask-on-write.
    pub fn capture_clipboard_text_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        surface: crate::authority::ActSurface,
        text: &str,
        copied_at: u64,
    ) -> Result<EntityId> {
        let ClipboardWorld { world } = self.open_clipboard_world(owner, surface)?;
        let clip = EntityId::now();
        let mut body = ClaimBody::new(
            PREDICATE_CLIPBOARD_CAPTURED,
            ClaimSubject::Entity(world),
            Value::Map(vec![
                (Value::from(KEY_TEXT), Value::from(text)),
                (Value::from(KEY_COPIED_AT), Value::from(copied_at)),
            ]),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )?;
        body.world = Some(world);
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_as_vault_owner_in_txn(self, txn)?;
            if !self.clipboard_world_exists_in_txn(txn, world)? {
                return Err(Error::EntityNotFound);
            }
            self.put_claim_in_txn(
                txn,
                &clip,
                &body,
                TimeRange {
                    start: copied_at,
                    end: copied_at,
                },
                copied_at,
            )
        })?;
        Ok(clip)
    }

    /// Lists active ordinary clips newest first under one owner-checked snapshot.
    /// `before` is an exclusive (copied_at, clip) position. Every positive
    /// requested limit is served; zero requests no rows. Private copies are
    /// not joined. Only the selected page's text is retained in the result.
    pub fn clipboard_entries_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        before: Option<(u64, EntityId)>,
        limit: usize,
    ) -> Result<Vec<ClipboardEntry>> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_as_vault_owner_in_txn(self, &txn)?;
        let mut rows = self.clipboard_metadata_in_txn(&txn, true)?;
        rows.sort_by(|a, b| (b.copied_at, b.clip).cmp(&(a.copied_at, a.clip)));
        let mut entries = Vec::new();
        for row in rows
            .into_iter()
            .filter(|row| before.is_none_or(|before| (row.copied_at, row.clip) < before))
            .take(limit)
        {
            if let Some(entry) = self.clipboard_entry_in_txn(&txn, row.clip)? {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    pub(super) fn clipboard_metadata_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        active_only: bool,
    ) -> Result<Vec<ClipMetadata>> {
        let world = clipboard_world_id()?;
        let mut rows = Vec::new();
        if !self.clipboard_world_exists_in_txn(txn, world)? {
            return Ok(rows);
        }
        for clip in self.claims_for_subject_in_txn(txn, &world)? {
            let entry = self.clipboard_claim_in_txn(txn, clip).and_then(|body| {
                body.filter(|body| !active_only || body.lifecycle == ClaimLifecycleStatus::Active)
                    .map(|body| clipboard_entry(clip, &body))
                    .transpose()
            });
            match entry {
                Ok(Some(entry)) => rows.push(ClipMetadata {
                    clip,
                    copied_at: entry.copied_at,
                    text_bytes: u64::try_from(entry.text.len()).unwrap_or(u64::MAX),
                }),
                Ok(None) => {}
                Err(Error::InvalidClaimBody(_)) => {
                    tracing::warn!(clip = %clip.to_hex(), reason = "malformed_clipboard_value", "skipping malformed Clipboard value");
                }
                Err(error) => return Err(error),
            }
        }
        Ok(rows)
    }

    pub(super) fn clipboard_claim_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        clip: EntityId,
    ) -> Result<Option<ClaimBody>> {
        let world = clipboard_world_id()?;
        let Some(body) = self.get_claim_in_txn(txn, &clip)? else {
            return Ok(None);
        };
        Ok((body.predicate == PREDICATE_CLIPBOARD_CAPTURED
            && body.world == Some(world)
            && body.subject == ClaimSubject::Entity(world))
        .then_some(body))
    }

    pub(super) fn clipboard_entry_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        clip: EntityId,
    ) -> Result<Option<ClipboardEntry>> {
        let Some(body) = self.clipboard_claim_in_txn(txn, clip)? else {
            return Ok(None);
        };
        clipboard_entry(clip, &body).map(Some)
    }
}

fn clipboard_entry(clip: EntityId, body: &ClaimBody) -> Result<ClipboardEntry> {
    let fields = body
        .value
        .as_map()
        .ok_or(Error::InvalidClaimBody("Clipboard value is not a map"))?;
    let text = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some(KEY_TEXT))
        .and_then(|(_, value)| value.as_str())
        .ok_or(Error::InvalidClaimBody("Clipboard value has no text"))?;
    let copied_at = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some(KEY_COPIED_AT))
        .and_then(|(_, value)| value.as_u64())
        .ok_or(Error::InvalidClaimBody("Clipboard value has no copied_at"))?;
    Ok(ClipboardEntry {
        clip,
        copied_at,
        text: text.to_owned(),
    })
}
