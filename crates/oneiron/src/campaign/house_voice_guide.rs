//! The vault's house voice guide (ARCH-0059 #copy-review; lead ruling
//! COPY-REVIEW-JUDGE-BY-DEFAULT = B, 21 Nov 13:2x): one NOTE per vault that a
//! campaign's copy review checks each body against when the campaign names no
//! voice guide of its own, so the judge reviews every campaign's copy. The
//! owner edits it as any NOTE.
//!
//! A vault gets its guide with its first campaign: the campaign create door
//! seeds it once the campaign is stored. A vault from before this build that
//! already holds a campaign gets it at its next seeded writable open. A vault
//! that never runs a campaign gets none, so the guide's text never reaches
//! its reads and context. Its row in `CAMPAIGN_HOUSE_VOICE_GUIDE` names the
//! NOTE and is the seed's marker: written in the NOTE's birth commit, it makes
//! the seed run once. Each replica seeds its own, as the root project is
//! seeded. A guide the owner deletes is not seeded again: a campaign with no
//! voice guide of its own then holds its sends, as one whose guide was
//! deleted does, until the owner names a guide or skips its copy review
//! (`campaign.copy_review.skip`). A failed seed (no owner PERSON yet, an
//! erased owner) leaves the same hold, and the next create or seeded open
//! tries again; a vault that has left a share runs no seed at open.

use crate::edge::EdgeActorClass;
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault, WriteActor};

/// The kind the guide is born as: a vault-readable NOTE, so a campaign's
/// owner, the vault's owner or an agent that reads the vault, reads it
/// through the scoped NOTE read the copy review uses.
pub const HOUSE_VOICE_GUIDE_NOTE_KIND: &str = "research";

/// The guide's first text, for the owner to rewrite in their own voice.
pub const HOUSE_VOICE_GUIDE_MARKDOWN: &str = "# House voice guide

Copy review checks each campaign's mail against this guide when the campaign names no voice guide of its own. Edit it to sound like you.

- Write plainly and warmly, as one person writes to another.
- Make no claim, number or promise you cannot back up.
- Keep it short: why you are writing, what you offer, and one next step.
- No pressure, false urgency or guilt.
- Say who you are, and make it easy to say no.
";

/// () → the house voice guide NOTE.
const GUIDE: SideTable<(), EntityId, Raw> = SideTable::new(&side_table::CAMPAIGN_HOUSE_VOICE_GUIDE);

/// The house voice guide NOTE as `store` holds it in `txn`; `None` before it
/// is seeded. The NOTE itself may since have been deleted.
///
/// # Errors
///
/// Storage and decode errors.
pub(crate) fn house_voice_guide_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<Option<EntityId>> {
    GUIDE.get(store, txn, &())
}

/// The open's seed: a vault that holds a campaign and has no house voice
/// guide yet (one from before this build) gets one. A vault with no campaign,
/// or with the marker, writes nothing.
///
/// # Errors
///
/// Storage errors, and a NOTE write the owner's binding refuses.
pub(crate) fn seed_house_voice_guide_at_open(vault: &Vault) -> Result<()> {
    if vault.house_voice_guide()?.is_some() {
        return Ok(());
    }
    let Ok(kind) = crate::campaign::surface::campaign_type_byte(vault) else {
        return Ok(());
    };
    if vault.entities_by_type_page(kind, None, 1)?.is_empty() {
        return Ok(());
    }
    vault.ensure_house_voice_guide().map(|_| ())
}

impl Vault {
    /// The vault's house voice guide NOTE, once seeded; the NOTE may since
    /// have been deleted.
    ///
    /// # Errors
    ///
    /// Storage and decode errors.
    pub fn house_voice_guide(&self) -> Result<Option<EntityId>> {
        let txn = self.store.env.read_txn()?;
        house_voice_guide_in_txn(&self.store, &txn)
    }

    /// Seeds the house voice guide once: a NOTE of
    /// [`HOUSE_VOICE_GUIDE_NOTE_KIND`] with [`HOUSE_VOICE_GUIDE_MARKDOWN`],
    /// written by the vault's owner, and its marker row, in one commit. A
    /// vault that already has its marker keeps it, whatever became of the
    /// NOTE. The campaign create door runs it, and a seeded open for a vault
    /// that holds a campaign. Returns the guide, or `None` when the owner is
    /// erased: no one is left to author it.
    ///
    /// # Errors
    ///
    /// Storage errors, and a NOTE write the owner's binding refuses (no owner
    /// PERSON yet).
    pub fn ensure_house_voice_guide(&self) -> Result<Option<EntityId>> {
        if let Some(guide) = self.house_voice_guide()? {
            return Ok(Some(guide));
        }
        let owner = crate::vault::embedded_owner_actor_id()?;
        self.try_with_write_txn_grouped(|txn| -> Result<Option<EntityId>> {
            if let Some(guide) = GUIDE.get(&self.store, txn, &())? {
                return Ok(Some(guide));
            }
            if self.local_hard_delete_marker_exists_in_txn(txn, &owner)? {
                return Ok(None);
            }
            let guide = EntityId::now();
            self.create_note_in_txn(
                txn,
                guide,
                HOUSE_VOICE_GUIDE_NOTE_KIND,
                HOUSE_VOICE_GUIDE_MARKDOWN,
                WriteActor::new(owner, EdgeActorClass::Human),
            )
            .map_err(|error| {
                Error::InvalidConfig(format!("the house voice guide NOTE: {error}"))
            })?;
            GUIDE.put(&self.store, txn, &(), &guide)?;
            Ok(Some(guide))
        })
    }
}
