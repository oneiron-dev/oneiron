//! The families' answers to one window capture (KS7-3b): which holders
//! each value and withheld key the vendored capture meets has, as its
//! family's codec places it, and what each atom's copies hold. A first pass
//! notes every manifest, and every parted room turn row, of the capture's
//! history, so a part goes with every holder a manifest names it for, and a
//! parted turn is carried joined (FIX 12153).

use loro::LoroValue;
use loro::checkpoint::{Classify, Field, OwnerId, SlotKind};

use super::joined_turns::{TurnInventory, TurnSource};
use super::owners::{
    WithheldKey, key_refusal, root_entry, withheld_client_key, withheld_key, withheld_part_key,
};
use super::parts::PartHolders;
use super::{
    AtomHome, DerivedRole, DerivedSlot, Holder, Placement, SyncPayloadOwners, SyncUnclassified,
    ValueSplit,
};
use crate::store::checkpoint_payload::rows::{OtherClient, OwnerRef};
use crate::sync::room_turns::ROOM_TURNS_MAP;

/// A change's commit message.
const MESSAGE: &str = "a window change's message, which no window family writes";

/// The owner found, when one was, and why a window stays whole.
pub(super) type Refusal = (Option<OwnerRef>, SyncUnclassified);

/// What one copy of a value goes to. Its index among a capture's homes is
/// the owner handle the vendored capture records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Home {
    Holder(Holder),
    Structure(Vec<OwnerRef>),
    Client(OtherClient),
}

impl Home {
    pub(super) fn target(&self) -> (AtomHome, Vec<OwnerRef>) {
        match self {
            Self::Holder(holder) => (AtomHome::Owner(holder.owner), holder.dependencies.clone()),
            Self::Structure(dependencies) => (AtomHome::Structure, dependencies.clone()),
            Self::Client(client) => (AtomHome::Client(*client), Vec::new()),
        }
    }
}

/// One value or withheld key the capture met, in the order it made its
/// atoms: its root map and key, its kind, what each of its copies holds,
/// and its actors; or, for a slot derived from the joined turn, what it
/// holds of that turn (FIX 12153).
pub(super) struct Plan {
    pub(super) root: String,
    pub(super) key: String,
    pub(super) kind: SlotKind,
    pub(super) value: Vec<u8>,
    pub(super) split: Option<ValueSplit>,
    pub(super) derived: Option<DerivedSlot>,
}

/// The families' answers to one capture.
pub(super) struct Classifier<'o> {
    owners: &'o dyn SyncPayloadOwners,
    /// Every part's holders, once a first pass noted the manifests.
    parts: Option<PartHolders>,
    /// The first pass's notes, while it runs.
    pub(super) noting: Option<PartHolders>,
    pub(super) homes: Vec<Home>,
    pub(super) plans: Vec<Plan>,
    pub(super) refusal: Option<Refusal>,
    /// A part was met before the manifests were noted.
    pub(super) needs_parts: bool,
    /// The room turn map's parted rows the first pass met (FIX 12153).
    pub(super) turns: TurnInventory,
    /// The parted turn this capture carries joined, once the first pass
    /// proved one.
    pub(super) turn: Option<TurnSource>,
}

impl<'o> Classifier<'o> {
    pub(super) fn new(
        owners: &'o dyn SyncPayloadOwners,
        parts: Option<PartHolders>,
        turn: Option<TurnSource>,
    ) -> Self {
        Self {
            owners,
            parts,
            noting: None,
            homes: Vec::new(),
            plans: Vec::new(),
            refusal: None,
            needs_parts: false,
            turns: TurnInventory::default(),
            turn,
        }
    }

    /// A slot derived from the joined turn (FIX 12153): no copy of its own,
    /// held by the turn's holder.
    fn derived(
        &mut self,
        root: &str,
        key: &str,
        kind: SlotKind,
        role: DerivedRole,
    ) -> Option<Vec<OwnerId>> {
        let holder = self.turn.as_ref()?.holder.clone();
        let handle = self.handle(Home::Holder(holder));
        self.plans.push(Plan {
            root: root.to_owned(),
            key: key.to_owned(),
            kind,
            value: Vec::new(),
            split: None,
            derived: Some(DerivedSlot { source: 0, role }),
        });
        Some(vec![handle])
    }

    /// Notes the first reason the window stays whole.
    fn refuse(
        &mut self,
        owner: Option<OwnerRef>,
        reason: SyncUnclassified,
    ) -> Option<Vec<OwnerId>> {
        if self.refusal.is_none() {
            self.refusal = Some((owner, reason));
        }
        None
    }

    /// A part's withheld digest key (FIX 10278): one copy under each holder
    /// a manifest names the part for, the same holders its value goes to,
    /// whole. Met before the manifests were noted, the capture runs again
    /// once they are.
    fn part_key_holders(&mut self, root: &str, key: &str) -> Option<Vec<OwnerId>> {
        if let Some(role) = self.turn.as_ref().and_then(|turn| turn.key_role(root, key)) {
            return self.derived(root, key, SlotKind::Key, role);
        }
        let placed = match &self.parts {
            Some(parts) => parts.place(root, key),
            None => {
                self.needs_parts = true;
                return None;
            }
        };
        let holders = match placed {
            Placement::Owned(holders) => holders,
            Placement::Unclassified { owner, reason } => return self.refuse(owner, reason),
            _ => return self.refuse(None, SyncUnclassified::OrphanPart),
        };
        if holders.is_empty() {
            return self.refuse(None, SyncUnclassified::NoOwner);
        }
        let handles: Vec<OwnerId> = holders
            .into_iter()
            .map(|holder| self.handle(Home::Holder(holder)))
            .collect();
        self.plans.push(Plan {
            root: root.to_owned(),
            key: key.to_owned(),
            kind: SlotKind::Key,
            value: key.as_bytes().to_vec(),
            split: None,
            derived: None,
        });
        Some(handles)
    }

    /// The capture-local handle of `home`: equal homes share one, and two
    /// holders of one owner with other dependencies do not.
    fn handle(&mut self, home: Home) -> OwnerId {
        let index = match self.homes.iter().position(|known| *known == home) {
            Some(index) => index,
            None => {
                self.homes.push(home);
                self.homes.len() - 1
            }
        };
        OwnerId::try_from(index).unwrap_or(OwnerId::MAX)
    }
}

impl Classify for Classifier<'_> {
    fn plain_key(&mut self, root: &str, key: &str) -> bool {
        if self.noting.is_some() {
            return true;
        }
        match key_refusal(root, key) {
            None => true,
            // A key its family withholds is asked for its holders next.
            Some(_)
                if withheld_key(root, key).is_some()
                    || withheld_part_key(root, key)
                    || withheld_client_key(root, key).is_some() =>
            {
                false
            }
            Some(reason) => {
                self.refuse(None, reason);
                false
            }
        }
    }

    /// A key withheld in an atom of its own (FIX 10279): its holders' copies
    /// hold it, the actor it names split out, made before any value under it.
    fn key_holders(&mut self, root: &str, key: &str) -> Option<Vec<OwnerId>> {
        if withheld_part_key(root, key) {
            return self.part_key_holders(root, key);
        }
        // A custody digest key goes whole with the client's copy of its
        // value (FIX 10278).
        if let Some(client) = withheld_client_key(root, key) {
            let handle = self.handle(Home::Client(client));
            self.plans.push(Plan {
                root: root.to_owned(),
                key: key.to_owned(),
                kind: SlotKind::Key,
                value: key.as_bytes().to_vec(),
                split: None,
                derived: None,
            });
            return Some(vec![handle]);
        }
        let Some(WithheldKey { holders, split }) = withheld_key(root, key) else {
            let reason = key_refusal(root, key).unwrap_or(SyncUnclassified::NoOwner);
            return self.refuse(None, reason);
        };
        if holders.is_empty() {
            return self.refuse(None, SyncUnclassified::NoOwner);
        }
        let handles: Vec<OwnerId> = holders
            .into_iter()
            .map(|holder| self.handle(Home::Holder(holder)))
            .collect();
        let value = match &split {
            Some(split) => split.no_one.clone(),
            None => key.as_bytes().to_vec(),
        };
        self.plans.push(Plan {
            root: root.to_owned(),
            key: key.to_owned(),
            kind: SlotKind::Key,
            value,
            split,
            derived: None,
        });
        Some(handles)
    }

    fn holders(&mut self, field: Field<'_>) -> Option<Vec<OwnerId>> {
        let Field::Value {
            root, key, value, ..
        } = field
        else {
            return self.refuse(None, SyncUnclassified::ActorSplit(MESSAGE));
        };
        let LoroValue::Binary(bytes) = value else {
            return self.refuse(None, SyncUnclassified::Undecodable);
        };
        if let Some(role) = self
            .turn
            .as_ref()
            .and_then(|turn| turn.value_role(root, key, bytes.as_slice()))
        {
            return self.derived(root, key, SlotKind::Value, role);
        }
        let placed = root_entry(root, key, bytes.as_slice(), self.owners);
        if let Some(noting) = self.noting.as_mut() {
            noting.note(root, &placed);
            self.turns.note(root, key, bytes.as_slice());
            return Some(vec![0]);
        }
        // A turn row's manifest met before its parts: the history is noted
        // first, so the turn can be carried joined (FIX 12153).
        if self.parts.is_none()
            && root == ROOM_TURNS_MAP
            && matches!(
                placed,
                Placement::Manifest {
                    joined: Some(_),
                    ..
                }
            )
        {
            self.needs_parts = true;
            return None;
        }
        let placed = match placed {
            Placement::Part => match &self.parts {
                Some(parts) => parts.place(root, key),
                None => {
                    self.needs_parts = true;
                    return None;
                }
            },
            placed => placed,
        };
        let held =
            |holders: Vec<Holder>| -> Vec<Home> { holders.into_iter().map(Home::Holder).collect() };
        let (homes, split): (Vec<Home>, Option<ValueSplit>) = match placed {
            Placement::Owned(owned) => (held(owned), None),
            Placement::Split {
                holders: owned,
                split,
            } => (held(owned), Some(split)),
            Placement::Structure { dependencies } => (vec![Home::Structure(dependencies)], None),
            Placement::Dispatched(client) => (vec![Home::Client(client)], None),
            Placement::Manifest {
                holders: owned,
                joined: None,
                ..
            } => (held(owned), None),
            Placement::Manifest {
                holders: owned,
                joined: Some(reason),
                ..
            } => return self.refuse(owned.first().map(|holder| holder.owner), reason),
            Placement::Unclassified { owner, reason } => return self.refuse(owner, reason),
            Placement::Part => return self.refuse(None, SyncUnclassified::OrphanPart),
        };
        if homes.is_empty() {
            return self.refuse(None, SyncUnclassified::NoOwner);
        }
        let handles: Vec<OwnerId> = homes.into_iter().map(|home| self.handle(home)).collect();
        let value = match &split {
            Some(split) => split.no_one.clone(),
            None => bytes.to_vec(),
        };
        self.plans.push(Plan {
            root: root.to_owned(),
            key: key.to_owned(),
            kind: SlotKind::Value,
            value,
            split,
            derived: None,
        });
        Some(handles)
    }
}

/// A final capture with native source slots still distinct from ordinary
/// family plans. The paired source owner consumes it before any emission.
pub(super) struct RecordDocumentClassification<'o> {
    pub(super) parts: loro::checkpoint::Parts,
    pub(super) ordinary: Classifier<'o>,
    pub(super) native_slots: std::collections::BTreeSet<loro::checkpoint::AtomId>,
}

/// Captures the actual closed document with native digest keys withheld.
/// This does not change the ordinary emitted WINDOW_ROOTS registry.
pub(super) fn capture_record_documents<'o>(
    doc: &loro::LoroDoc,
    roots: &[&str],
    owners: &'o dyn SyncPayloadOwners,
    records: &super::record_documents::PreparedRecordDocuments,
) -> std::result::Result<RecordDocumentClassification<'o>, Refusal> {
    use loro::checkpoint::Capture;

    let mut roots = roots.to_vec();
    if !roots.contains(&crate::sync::skill_docs::SKILL_DOCS_MAP) {
        roots.push(crate::sync::skill_docs::SKILL_DOCS_MAP);
    }
    let mut classifier =
        RecordDocumentClassifier::new(Classifier::new(owners, None, None), records);
    let mut captured = doc.export_root_map_checkpoint(&roots, &mut classifier);
    if classifier.ordinary.needs_parts {
        let mut noting =
            RecordDocumentClassifier::new(Classifier::new(owners, None, None), records);
        noting.ordinary.noting = Some(PartHolders::default());
        doc.export_root_map_checkpoint(&roots, &mut noting);
        let turn = TurnSource::of(&noting.ordinary.turns);
        classifier = RecordDocumentClassifier::new(
            Classifier::new(owners, noting.ordinary.noting, turn),
            records,
        );
        captured = doc.export_root_map_checkpoint(&roots, &mut classifier);
    }
    let parts = match captured {
        Capture::Classified(parts) => parts,
        Capture::Unclassified(_) => {
            return Err(classifier
                .ordinary
                .refusal
                .unwrap_or((None, SyncUnclassified::Undecodable)));
        }
    };
    if classifier.ordinary.plans.len() != parts.atoms.len() {
        return Err((None, SyncUnclassified::Undecodable));
    }
    classifier.ordinary.turn = classifier.ordinary.turn.take().filter(|_| {
        classifier.ordinary.plans.iter().any(|plan| {
            plan.derived
                .is_some_and(|slot| slot.role == DerivedRole::Manifest)
        })
    });
    Ok(RecordDocumentClassification {
        parts,
        ordinary: classifier.ordinary,
        native_slots: classifier.native_slots,
    })
}

/// Classifies native writes by their actual Site, not callback ordinals.
/// All other families still use the original Classifier and its homes.
struct RecordDocumentClassifier<'o, 'r> {
    ordinary: Classifier<'o>,
    records: &'r super::record_documents::PreparedRecordDocuments,
    native_slots: std::collections::BTreeSet<loro::checkpoint::AtomId>,
}

impl<'o, 'r> RecordDocumentClassifier<'o, 'r> {
    fn new(
        ordinary: Classifier<'o>,
        records: &'r super::record_documents::PreparedRecordDocuments,
    ) -> Self {
        Self {
            ordinary,
            records,
            native_slots: Default::default(),
        }
    }

    fn native(
        &mut self,
        root: &str,
        key: &str,
        kind: SlotKind,
        holders: Vec<Holder>,
    ) -> Option<Vec<OwnerId>> {
        if holders.is_empty() {
            return self.ordinary.refuse(None, SyncUnclassified::NoOwner);
        }
        let id = loro::checkpoint::AtomId::try_from(self.ordinary.plans.len()).ok()?;
        let handles = holders
            .into_iter()
            .map(|holder| self.ordinary.handle(Home::Holder(holder)))
            .collect();
        self.ordinary.plans.push(Plan {
            root: root.to_owned(),
            key: key.to_owned(),
            kind,
            // The original head/row/part/key is NOT an ordinary sealed copy.
            // Its complete native source is emitted by the paired owner.
            value: Vec::new(),
            split: None,
            derived: None,
        });
        self.native_slots.insert(id);
        Some(handles)
    }
}

impl Classify for RecordDocumentClassifier<'_, '_> {
    fn plain_key(&mut self, root: &str, key: &str) -> bool {
        if root != crate::sync::skill_docs::SKILL_DOCS_MAP {
            return self.ordinary.plain_key(root, key);
        }
        // Only a canonical opaque entity id may outlive its native content.
        crate::EntityId::from_hex(key).is_ok_and(|entity| entity.to_hex() == key)
    }

    fn key_holders(&mut self, root: &str, key: &str) -> Option<Vec<OwnerId>> {
        if root != crate::sync::skill_docs::SKILL_DOCS_MAP {
            return self.ordinary.key_holders(root, key);
        }
        let Some(holders) = self.records.key_holders(key) else {
            return self.ordinary.refuse(None, SyncUnclassified::OrphanPart);
        };
        self.native(root, key, SlotKind::Key, holders)
    }

    fn holders(&mut self, field: Field<'_>) -> Option<Vec<OwnerId>> {
        let Field::Value {
            root,
            key,
            value,
            site,
        } = field
        else {
            return self.ordinary.holders(field);
        };
        if root != crate::sync::skill_docs::SKILL_DOCS_MAP && root != "entities" {
            return self.ordinary.holders(field);
        }
        match self.records.value_holders(root, key, value, site) {
            Ok(Some(holders)) => self.native(root, key, SlotKind::Value, holders),
            Ok(None) if root == "entities" => self.ordinary.holders(field),
            Ok(None) => self.ordinary.refuse(None, SyncUnclassified::OrphanPart),
            Err(_) => self.ordinary.refuse(None, SyncUnclassified::Undecodable),
        }
    }
}
