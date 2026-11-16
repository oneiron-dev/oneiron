//! The owner's list of every secret in custody, value-free (FIX
//! [SECRETS-OWNER-LIST-READ], [SECRETS-HOLDER-LIST-READ]).
//!
//! One custody snapshot reads every local custody record (its metadata,
//! never its value) and every secret the fold proves another machine holds
//! that has no record here, named by the transition this vault keeps of it
//! when it keeps one. A record that is revoked, ended by an admitted revoke,
//! erase-fenced or bound to one run (`browser-run/`, `desktop-run/`) is left
//! out.
//!
//! Duplicates (RULING SECRETS-LIST-DUP-GROUPING = A, Engine 16 Nov 01:32):
//! two records become one item only when this install holds both and the
//! known-value index's entries for their current generations match (length
//! and keyed fingerprint of the whole value). Nothing else merges them. An
//! item whose origin (source record, scan kind and place) matches exactly
//! one other item, the two not proven different, carries that item as a
//! "maybe the same" hint, and stays its own item: an act on an item never
//! spans a hinted pair.

use std::cmp::Reverse;

use heed::RoTxn;

use super::handle_labels::{
    live_owner_in_txn, payment_suggested_in_txn, secret_handle_label_in_txn,
    suggested_secret_handle_label_in_txn,
};
use super::types::{CustodyClass, SecretCustodyRecord, SecretCustodyStatus};
use crate::Vault;
use crate::authority::{AuthorityFold, MachineDeviceClass, MachineRole};
use crate::consent::AuthenticatedOwner;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EntityStoreRead, ShortIdStoreRead};
use crate::registry::ENTITY_TYPE_SECRET_CUSTODY;
use crate::store::KnownEntry;

/// The display name of a cloud registration slot that has no label.
const CLOUD_REGISTRATION_NAME: &str = "Cloud registration";

/// Every secret in custody as the owner's list shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretCustodyList {
    /// One item per secret value, newest first.
    pub items: Vec<SecretCustodyListItem>,
}

/// One secret value: its records (one, or several this install proves hold
/// the same value) and every machine that holds one of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretCustodyListItem {
    /// The record the item's acts name: of its records, the one held on the
    /// most machines, then the earliest registered. First in `records`.
    pub primary: EntityId,
    /// What the item is called.
    pub display_name: String,
    /// Where `display_name` comes from.
    pub display_name_source: SecretDisplayNameSource,
    /// The item's records, `primary` first.
    pub records: Vec<SecretCustodyListRecord>,
    /// Every machine that holds one of the records: the primary's first.
    pub holders: Vec<SecretCustodyHolder>,
    /// The primary record of the one other item whose origin matches this
    /// one's, while the two are not proven different values: a hint, never
    /// a merge.
    pub maybe_same_as: Option<EntityId>,
}

/// Where an item's display name comes from, in the order it is chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretDisplayNameSource {
    /// The owner's label on one of its records.
    Label,
    /// The service a binding of its primary opens (`connector:<service>`).
    Service,
    /// The kind a scan found it as (`OpenAI key`), or a cloud registration
    /// slot.
    Kind,
    /// The primary's custody name.
    Name,
}

impl SecretDisplayNameSource {
    /// The wire string: `label`, `service`, `kind` or `name`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Label => "label",
            Self::Service => "service",
            Self::Kind => "kind",
            Self::Name => "name",
        }
    }
}

/// One custody record of an item, value-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretCustodyListRecord {
    pub id: EntityId,
    /// Its handle, such as `sc12`, while it has one here.
    pub handle: Option<String>,
    /// Its custody name; `None` for a secret another machine holds that this
    /// vault keeps no transition of.
    pub name: Option<String>,
    pub class: Option<CustodyClass>,
    /// The generation its holders hold.
    pub generation: u32,
    /// This install holds the record.
    pub held_here: bool,
    /// Unix seconds; `None` where `name` is.
    pub registered_at: Option<u64>,
    pub rotated_at: Option<u64>,
    /// The owner's label.
    pub label: Option<String>,
    /// The kind label a scan suggests.
    pub suggested_label: Option<String>,
    /// What it is for, in the owner's words.
    pub purpose: Option<String>,
    /// Its bindings' effectors (`connector:gmail`, `door:receive-pack`).
    pub uses: Vec<String>,
    /// The owner's payment mark; `None` while unanswered.
    pub payment_marked: Option<bool>,
    /// What its label hint says: a key a scan found as a Stripe key pays.
    pub payment_suggested: bool,
    /// Where a mask on write found it, when one did here.
    pub origin: Option<SecretCustodyOrigin>,
    /// The machines that hold its value: those the fold proves hold its
    /// generation (live heads first), then this machine when it holds the
    /// record and the fold does not name it.
    pub holders: Vec<EntityId>,
    /// For a record of an item with several, held on exactly one machine
    /// and not the primary: that machine, which holds its own copy.
    pub own_copy: Option<EntityId>,
}

/// Where a mask on write found a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretCustodyOrigin {
    /// The record whose text or field held the value.
    pub source: EntityId,
    /// The scan's kind code, `gate.secret_scan.` stripped (`openai_key`).
    pub kind: String,
    /// Where in the record: `body`, `claim`, `text:<field>`, `file`, ...
    pub place: String,
}

/// One machine that holds a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretCustodyHolder {
    pub machine: EntityId,
    /// Its class and role as its roster revision states them; `None` for a
    /// machine the fold names no revision of.
    pub class: Option<MachineDeviceClass>,
    pub role: Option<MachineRole>,
    /// This install.
    pub this_install: bool,
}

/// One record as the list reads it, before grouping.
struct Read {
    record: SecretCustodyListRecord,
    /// The current generation's known-value entry, for a record this
    /// install holds that the index keys.
    print: Option<KnownEntry>,
    newest: u64,
}

impl Vault {
    /// Every secret in custody, value-free, one item per value (FIX
    /// [SECRETS-OWNER-LIST-READ]). An owner's read: the proof is revalidated
    /// as a live vault owner's in the snapshot.
    ///
    /// # Errors
    /// [`crate::error::GateError::ConsentOwnerNotAuthenticated`] when the
    /// proof is no longer the live owner's; custody lost or damaged under a
    /// known-value reference; storage errors.
    pub fn secret_custody_list(&self, owner: &AuthenticatedOwner) -> Result<SecretCustodyList> {
        let snapshot = self.store.custody_snapshot()?;
        let txn: &RoTxn<'_> = &snapshot;
        live_owner_in_txn(self, owner, txn, "only the vault owner lists secrets")?;
        let fold = self.authority_view_readonly_in_txn(txn)?;
        let this = crate::identity::read_machine_id_in_txn(self, txn)?;
        let mut reads = Vec::new();
        for entry in self
            .store
            .port_entity_ids_by_type(txn, ENTITY_TYPE_SECRET_CUSTODY, None)?
        {
            let id = entry?;
            let Some(record) = super::read_secret_custody_meta_in_txn(&self.store, txn, &id)?
            else {
                continue;
            };
            if record.status == SecretCustodyStatus::Revoked
                || !self.listed_in_txn(txn, &fold, &id, &record.name)
            {
                continue;
            }
            let generation = record.rotation_generation;
            // A print that does not read groups nothing: the record stands
            // as its own item, the safe side of the ruling (a missed group
            // costs one row; a wrong one would span a different secret).
            let print = match self.store.known_entries_for_in_snapshot(txn, &id) {
                Ok(entries) => entries.and_then(|entries| {
                    entries
                        .into_iter()
                        .find(|(at, _)| *at == generation)
                        .map(|(_, entry)| entry)
                }),
                Err(error) => {
                    tracing::warn!(
                        kind = ?error.kind(),
                        "a secret's known-value entry did not read; the list does not group it"
                    );
                    None
                }
            };
            reads.push(self.read_record_in_txn(
                txn,
                &fold,
                this,
                id,
                Some(&record),
                generation,
                true,
                print,
            )?);
        }
        for (id, generation) in fold.custody_held_generations() {
            if crate::ports::EntityStoreRead::port_entity_present(&self.store, txn, &id)? {
                continue;
            }
            let record = super::transition::transition_record_in_txn(self, txn, &id)?;
            let name = record.as_ref().map_or("", |record| record.name.as_str());
            if !self.listed_in_txn(txn, &fold, &id, name) {
                continue;
            }
            reads.push(self.read_record_in_txn(
                txn,
                &fold,
                this,
                id,
                record.as_ref(),
                generation,
                false,
                None,
            )?);
        }
        Ok(SecretCustodyList {
            items: group(reads, &fold, this),
        })
    }

    /// Whether the list names secret `id` (custody name `name`): not ended
    /// by an admitted revoke, not erase-fenced, not bound to one run.
    fn listed_in_txn(
        &self,
        txn: &RoTxn<'_>,
        fold: &AuthorityFold,
        id: &EntityId,
        name: &str,
    ) -> bool {
        !fold.custody_revoked(id)
            && !self.store.credential_fenced_in_txn(txn, id)
            && !super::run_bound::is_run_bound_name(name)
    }

    /// One record's row of the list, read in `txn`: `record` is its
    /// metadata (the local record's, or the kept transition's), `None` for a
    /// secret this vault knows only from the fold.
    #[allow(clippy::too_many_arguments)]
    fn read_record_in_txn(
        &self,
        txn: &RoTxn<'_>,
        fold: &AuthorityFold,
        this: Option<EntityId>,
        id: EntityId,
        record: Option<&SecretCustodyRecord>,
        generation: u32,
        held_here: bool,
        print: Option<KnownEntry>,
    ) -> Result<Read> {
        let store = &self.store;
        let mut holders = fold.custody_value_holders(id, generation);
        if held_here
            && let Some(this) = this
            && !holders.contains(&this)
        {
            holders.push(this);
        }
        let origin =
            crate::batch::secret_scan::mask_origin_in_txn(store, txn, &id)?.map(|origin| {
                SecretCustodyOrigin {
                    source: origin.record,
                    kind: origin
                        .reason
                        .strip_prefix("gate.secret_scan.")
                        .unwrap_or(&origin.reason)
                        .to_owned(),
                    place: origin.place,
                }
            });
        let registered_at = record.map(|record| record.registered_at);
        let rotated_at = record.and_then(|record| record.rotated_at);
        Ok(Read {
            newest: rotated_at.or(registered_at).unwrap_or(0),
            print,
            record: SecretCustodyListRecord {
                id,
                handle: store
                    .port_short_id_reference(txn, &id)?
                    .map(|(short, _)| short),
                name: record.map(|record| record.name.clone()),
                class: record.map(|record| record.class),
                generation,
                held_here,
                registered_at,
                rotated_at,
                label: secret_handle_label_in_txn(store, txn, &id)?.map(|label| label.label),
                suggested_label: suggested_secret_handle_label_in_txn(store, txn, &id)?,
                purpose: crate::store::secret_handle_purpose::PURPOSE
                    .get(store, txn, &id)?
                    .map(|row| row.purpose),
                uses: record.map_or_else(Vec::new, |record| {
                    record
                        .bindings
                        .iter()
                        .map(|binding| binding.effector.clone())
                        .collect()
                }),
                payment_marked: crate::store::secret_payment_marks::PAYMENT_MARK
                    .get(store, txn, &id)?
                    .map(|mark| mark.payment),
                payment_suggested: payment_suggested_in_txn(store, txn, &id)?,
                origin,
                holders,
                own_copy: None,
            },
        })
    }
}

/// Whether two known-value entries name one value: same length, same keyed
/// fingerprint under this install's one index key.
fn same_value(a: &KnownEntry, b: &KnownEntry) -> bool {
    a.len == b.len && a.fingerprint == b.fingerprint
}

/// The list's items from its records: grouped on proven equality alone,
/// each item's primary chosen, its holders joined, hints set, newest first.
fn group(
    reads: Vec<Read>,
    fold: &AuthorityFold,
    this: Option<EntityId>,
) -> Vec<SecretCustodyListItem> {
    let mut groups: Vec<Vec<Read>> = Vec::new();
    for read in reads {
        let joined = read.print.as_ref().and_then(|print| {
            groups.iter().position(|group| {
                group[0]
                    .print
                    .as_ref()
                    .is_some_and(|first| same_value(first, print))
            })
        });
        match joined {
            Some(at) => groups[at].push(read),
            None => groups.push(vec![read]),
        }
    }
    let mut built: Vec<(u64, bool, SecretCustodyListItem)> = groups
        .into_iter()
        .map(|group| item(group, fold, this))
        .collect();
    hint(&mut built);
    built.sort_by_key(|(newest, _, item)| (Reverse(*newest), item.primary));
    built.into_iter().map(|(_, _, item)| item).collect()
}

/// One item from one group: its primary first, every holder once, its
/// own copies marked. Answers the item's newest time and whether its value
/// has a known-value print.
fn item(
    mut group: Vec<Read>,
    fold: &AuthorityFold,
    this: Option<EntityId>,
) -> (u64, bool, SecretCustodyListItem) {
    group.sort_by_key(|read| {
        (
            Reverse(read.record.holders.len()),
            read.record.registered_at.unwrap_or(u64::MAX),
            read.record.id,
        )
    });
    let newest = group.iter().map(|read| read.newest).max().unwrap_or(0);
    let printed = group.iter().any(|read| read.print.is_some());
    let several = group.len() > 1;
    let mut records: Vec<SecretCustodyListRecord> =
        group.into_iter().map(|read| read.record).collect();
    if several {
        for record in records.iter_mut().skip(1) {
            if let [machine] = record.holders.as_slice() {
                record.own_copy = Some(*machine);
            }
        }
    }
    let mut machines: Vec<EntityId> = Vec::new();
    for record in &records {
        for machine in &record.holders {
            if !machines.contains(machine) {
                machines.push(*machine);
            }
        }
    }
    let holders = machines
        .into_iter()
        .map(|machine| {
            let profile = fold
                .machines
                .get(&machine)
                .and_then(|folded| folded.roster.as_ref())
                .map(|roster| &roster.profile);
            SecretCustodyHolder {
                machine,
                class: profile.map(|profile| profile.device_class),
                role: profile.map(|profile| profile.role),
                this_install: this == Some(machine),
            }
        })
        .collect();
    let (display_name, display_name_source) = display_name(&records);
    (
        newest,
        printed,
        SecretCustodyListItem {
            primary: records[0].id,
            display_name,
            display_name_source,
            records,
            holders,
            maybe_same_as: None,
        },
    )
}

/// An item's name: a label on one of its records (the primary's first),
/// else the service its primary's binding opens, else the kind a scan
/// found it as (or a cloud registration slot), else its custody name.
fn display_name(records: &[SecretCustodyListRecord]) -> (String, SecretDisplayNameSource) {
    if let Some(label) = records.iter().find_map(|record| record.label.clone()) {
        return (label, SecretDisplayNameSource::Label);
    }
    let primary = &records[0];
    if let Some(service) = primary
        .uses
        .iter()
        .find_map(|effector| effector.strip_prefix("connector:"))
        .filter(|service| !service.is_empty())
    {
        return (service.to_owned(), SecretDisplayNameSource::Service);
    }
    if let Some(kind) = &primary.suggested_label {
        return (kind.clone(), SecretDisplayNameSource::Kind);
    }
    match &primary.name {
        Some(name) if crate::secret_record::is_cloud_registration_slot(name) => (
            CLOUD_REGISTRATION_NAME.to_owned(),
            SecretDisplayNameSource::Kind,
        ),
        Some(name) => (name.clone(), SecretDisplayNameSource::Name),
        None => (primary.id.to_hex(), SecretDisplayNameSource::Name),
    }
}

/// Sets each item's hint: the one other item whose primary's origin
/// (source record, kind and place) is the same, unless both values have a
/// known-value print, which proves them different (equal prints would
/// have grouped them).
fn hint(built: &mut [(u64, bool, SecretCustodyListItem)]) {
    let origin_of = |item: &SecretCustodyListItem| {
        item.records[0]
            .origin
            .as_ref()
            .map(|origin| (origin.source, origin.kind.clone(), origin.place.clone()))
    };
    let origins: Vec<_> = built.iter().map(|(_, _, item)| origin_of(item)).collect();
    for at in 0..built.len() {
        let Some(origin) = &origins[at] else {
            continue;
        };
        let mut matches = (0..built.len())
            .filter(|other| *other != at && origins[*other].as_ref() == Some(origin));
        let (Some(other), None) = (matches.next(), matches.next()) else {
            continue;
        };
        if built[at].1 && built[other].1 {
            continue;
        }
        built[at].2.maybe_same_as = Some(built[other].2.primary);
    }
}
