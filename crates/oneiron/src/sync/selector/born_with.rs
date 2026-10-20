//! Born-with text on a copy to another vault (OF-491). Such a copy's births
//! go masked (owner Q26 = B) and carry no text. The text its owner lets
//! travel goes beside them in the window's `row_born_with` map, one entry per
//! row the copy carries: the fields the grant's travel choice names, prose
//! only, never a ref. The choice is the owner's, a signed authority action
//! every machine of the owner's folds (`federation::grant_travel`, FIX 2998),
//! never taken from a selector, so a selector names its grant but cannot
//! widen what text it gets. A grant with no choice sends none.
//!
//! On the receiving vault, admission reads the entries for the rows it
//! admitted and keeps them out of the admitted bytes; the import then keeps
//! each beside its landed row, where [`Vault::born_with_text`] reads it.

use std::collections::BTreeMap;

use loro::LoroDoc;

use super::codec::SyncSelector;
use super::document_admission::{DocumentGrant, admit_selected_in_txn, authorize_at_in_txn};
use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError, SyncProtocolValidation};
use crate::federation::FederationGrantScope;
use crate::provenance::birth::row_birth_in_txn;
use crate::provenance::made_by::{MadeBy, MadeByInputRole};
use crate::share_travel::{BornWith, BornWithField, GrantTravel, TravelChoice};
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;
use crate::sync::loro_support::{map_for_each_value_bytes, map_get_bytes, map_insert_bytes};
use crate::sync::window::Withhold;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The window map that carries born-with text beside the row births.
const ROW_BORN_WITH_MAP: &str = "row_born_with";

/// What a row's carried prompt does with a prompt source the export's grant
/// does not read, or one no longer live here (FIX 5937; CALLS: FIX 5937
/// denied prompt source).
enum DeniedPromptAction {
    /// That source's text stays home; the row, its other readable prompt
    /// sources and its other born-with fields still travel.
    OmitSourceText,
}

const DENIED_PROMPT_ACTION: DeniedPromptAction = DeniedPromptAction::OmitSourceText;

/// What a carried prompt says, at its end, when a source's text stayed home:
/// nothing, so the copy does not tell that one did (CALLS: FIX 5937 denied
/// prompt source).
const WITHHELD_TEXT_MARKER: Option<&str> = None;

/// The text a copy from another vault carried, by row.
const CARRIED: SideTable<EntityId, BornWith, Named> =
    SideTable::new(&side_table::SYNC_BORN_WITH_CARRIED);

/// One row's carried text, with the kind the row came as.
pub(crate) type CarriedText = (EntityId, u8, BornWith);

fn encode(text: &BornWith) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(text)
        .map_err(|_| Error::InvalidConfig("born-with text does not encode".into()))
}

/// The carried text, when `bytes` is its canonical encoding.
fn decode(bytes: &[u8]) -> Option<BornWith> {
    let text: BornWith = rmp_serde::from_slice(bytes).ok()?;
    (encode(&text).ok()? == bytes).then_some(text)
}

/// Every row `doc` carries as an entity, by its canonical hex key.
fn carried_rows(doc: &LoroDoc) -> Vec<(EntityId, u8)> {
    let mut rows = Vec::new();
    map_for_each_value_bytes(&doc.get_map("entities"), |key, blob| {
        let Some(header) = blob.and_then(EntityMetadataHeader::parse) else {
            return;
        };
        if let Some(id) = EntityId::from_hex(key).ok().filter(|id| id.to_hex() == key) {
            rows.push((id, header.entity_type));
        }
    });
    rows
}

/// Writes into `doc`, beside its births, the born-with text the owner lets
/// `selector`'s grant's windows carry, for each row `doc` carries: the bound
/// choice's fields of [`Vault::born_with_text`], none from a row a world
/// `withhold` keeps off the destination holds, and a prompt only from a
/// source that grant reads in `scope` at the export's `now_secs`
/// ([`readable_births`], FIX 5937). Nothing here writes a birth, so its
/// masked refs stay masked.
pub(super) fn carry_born_with(
    vault: &Vault,
    doc: &LoroDoc,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    now_secs: u64,
    withhold: Withhold<'_>,
) -> Result<()> {
    let Some(bound) = vault.federation_grant_travel(&selector.grant_id)? else {
        return Ok(());
    };
    let kept = withhold.worlds(vault)?;
    let rows = carried_rows(doc);
    // A choice without the prompt sends no prompt text, so no source is read.
    let births = if bound.travel.born_with.contains(&BornWithField::Prompt) {
        readable_births(vault, scope, selector, now_secs, &rows)?
    } else {
        rows.iter().map(|_| None).collect()
    };
    let map = doc.get_map(ROW_BORN_WITH_MAP);
    for ((id, _), birth) in rows.into_iter().zip(births) {
        let made_by = birth.as_ref().map(|birth| &birth.made_by);
        let mut text = bound
            .travel
            .project(vault.born_with_text_kept_off(&id, made_by, &kept)?);
        if birth.as_ref().is_some_and(|birth| birth.omitted)
            && let Some(marker) = WITHHELD_TEXT_MARKER
        {
            let prompt = text.entry(BornWithField::Prompt).or_default();
            if !prompt.is_empty() {
                prompt.push_str("\n\n");
            }
            prompt.push_str(marker);
        }
        if !text.is_empty() {
            map_insert_bytes(&map, &id.to_hex(), &encode(&text)?)?;
        }
    }
    doc.commit();
    Ok(())
}

/// A carried row's birth as the export reads it, and whether a prompt
/// source's text stayed home.
struct ReadableBirth {
    made_by: MadeBy,
    omitted: bool,
}

/// Each of `rows`' births, read in one snapshot, with only the prompt
/// sources `selector`'s grant reads in `scope`: live here and in the
/// subgraph the grant selects, judged on the stored rows as a document read
/// is ([`admit_selected_in_txn`]), not by whether `doc` carries them. Every
/// other source goes as [`DENIED_PROMPT_ACTION`] says; every other input
/// stays as stamped, in its order. `None` for a row with no birth. The grant
/// resolves once, at the export's `now_secs`, and only when a birth names a
/// prompt. The export's own check already admitted that grant: should this
/// one deny it, every prompt source here is denied, and the export still
/// goes.
fn readable_births(
    vault: &Vault,
    scope: FederationGrantScope,
    selector: &SyncSelector,
    now_secs: u64,
    rows: &[(EntityId, u8)],
) -> Result<Vec<Option<ReadableBirth>>> {
    let txn = vault.store.env.read_txn()?;
    let mut births = Vec::with_capacity(rows.len());
    for (id, _) in rows {
        births.push(row_birth_in_txn(&vault.store, &txn, id)?);
    }
    let prompted = births
        .iter()
        .flatten()
        .flat_map(|birth| &birth.made_by.inputs)
        .any(|input| input.role == MadeByInputRole::Prompt);
    let admission = if prompted {
        match authorize_at_in_txn(vault, &txn, scope, selector, None, now_secs) {
            Ok(admission) => Some(admission),
            Err(Error::Sync(SyncError::SyncProtocolError {
                context: SyncProtocolValidation::Selector { .. },
            })) => None,
            Err(Error::Sync(SyncError::SyncProtocolError {
                context: SyncProtocolValidation::DocumentAdmissionDenied,
            })) => None,
            Err(error) => return Err(error),
        }
    } else {
        None
    };
    let admission = admission.as_ref();
    let mut readable = Vec::with_capacity(births.len());
    for birth in births {
        let Some(birth) = birth else {
            readable.push(None);
            continue;
        };
        let mut made_by = birth.made_by;
        let mut omitted = false;
        if prompted {
            for input in std::mem::take(&mut made_by.inputs) {
                if input.role != MadeByInputRole::Prompt
                    || prompt_source_readable(vault, &txn, input.row, selector, admission)?
                {
                    made_by.inputs.push(input);
                    continue;
                }
                match DENIED_PROMPT_ACTION {
                    DeniedPromptAction::OmitSourceText => omitted = true,
                }
            }
        }
        readable.push(Some(ReadableBirth { made_by, omitted }));
    }
    Ok(readable)
}

/// Whether the export `admission` resolved reads prompt source `source`. No
/// admission (its grant denied here), a source not live here, or the
/// admission's denial answers no; any other error is the export's.
fn prompt_source_readable(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    source: EntityId,
    selector: &SyncSelector,
    admission: Option<&DocumentGrant>,
) -> Result<bool> {
    let Some(admission) = admission else {
        return Ok(false);
    };
    if !live_entity_row_in_txn(&vault.store, txn, &source)?.is_live() {
        return Ok(false);
    }
    match admit_selected_in_txn(vault, txn, source, selector, admission) {
        Ok(()) => Ok(true),
        Err(Error::Sync(SyncError::SyncProtocolError {
            context: SyncProtocolValidation::DocumentAdmissionDenied,
        })) => Ok(false),
        Err(error) => Err(error),
    }
}

/// The text `remote` carries for each row `admitted` holds. A row
/// admission lands under another id than the sender's, by the id it lands
/// under in `renamed` (a guest's WORLD, FIX 3657), takes the text the sender
/// keyed by its own id, kept under the id here (FIX 3889). An entry that does
/// not decode, holds nothing, or names a row admission dropped stays behind.
pub(super) fn admitted_born_with(
    remote: &LoroDoc,
    admitted: &LoroDoc,
    renamed: &BTreeMap<EntityId, EntityId>,
) -> Vec<CarriedText> {
    let map = remote.get_map(ROW_BORN_WITH_MAP);
    carried_rows(admitted)
        .into_iter()
        .filter_map(|(id, kind)| {
            let sent = renamed.get(&id).unwrap_or(&id);
            let text = map_get_bytes(&map, &sent.to_hex()).and_then(|bytes| decode(&bytes))?;
            (!text.is_empty()).then_some((id, kind, text))
        })
        .collect()
}

/// Keeps each carried text beside its row once that row is live here as the
/// kind it came as. A later copy's text replaces an earlier one's; no other
/// door writes it.
pub(super) fn keep_carried(vault: &Vault, carried: &[CarriedText]) -> Result<()> {
    if carried.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        for (id, kind, text) in carried {
            if matches!(
                live_entity_row_in_txn(&vault.store, txn, id)?,
                LiveEntityRow::Live { entity_type, .. } if entity_type == *kind
            ) {
                CARRIED.put(&vault.store, txn, id, text)?;
            }
        }
        Ok(())
    })
}

/// The text a copy from another vault carried for `id`; empty for any other
/// row.
pub(crate) fn carried_born_with(vault: &Vault, id: &EntityId) -> Result<BornWith> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(CARRIED
        .get_lenient(&vault.store, &rtxn, id)?
        .unwrap_or_default())
}

/// [`carried_born_with`] in the caller's `txn`. The caller admits `id`
/// first: the import-time check admitted the row for this vault, not for
/// whoever shares it on.
pub(crate) fn carried_born_with_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<BornWith> {
    Ok(CARRIED
        .get_lenient(&vault.store, txn, id)?
        .unwrap_or_default())
}

/// Drops the text a copy carried for `id` when its row is erased; a no-op
/// for any other row.
pub(crate) fn erase_carried_born_with_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    CARRIED.delete(store, wtxn, id).map(|_| ())
}

impl Vault {
    /// The born-with text `grant`'s windows carry to another vault: the
    /// effective choice this vault's authority fold reads across the
    /// owner's machines. `None` sends none.
    pub fn federation_grant_travel(&self, grant: &EntityId) -> Result<Option<GrantTravel>> {
        let rtxn = self.store.env.read_txn()?;
        self.federation_grant_travel_in_txn(&rtxn, grant)
    }

    /// Sets `travel` on the live federation grant `grant`, or with `None`
    /// clears it, for every machine of the owner's that serves the grant,
    /// and answers the effective choice after: concurrent choices meet.
    /// Windows exported from now on carry the text it names; text a guest
    /// already holds stays its copy. The owner says so from any surface
    /// where he is authenticated (`surface`, audit only); `seen` is the
    /// grant's revision that surface showed him
    /// ([`Vault::grant_travel_revision`]), `None` the current one.
    pub fn set_federation_grant_travel_as(
        &self,
        owner: &AuthenticatedOwner,
        surface: crate::authority::ActSurface,
        grant: &EntityId,
        travel: Option<TravelChoice>,
        seen: Option<[u8; 32]>,
        now: u64,
    ) -> Result<Option<GrantTravel>> {
        self.with_write_txn_grouped(|txn| {
            self.set_federation_grant_travel_in_txn(txn, owner, surface, grant, travel, seen, now)
        })
    }
}
