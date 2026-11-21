//! Which values of a window the discarded rows own, and the projection of
//! one window document from its classified atoms.

use super::*;

/// A parted row filed under another row's key: its manifest and parts are
/// placed by the key's holder, so only the joined row shows whose they are
/// (UC-10 PR 1).
const UNBOUND_PARTED_ROW: &str = "a parted row whose parts join to a row its key does not name";

/// A whole row whose own key differs from the key that files it: the key
/// and the row name two rows, and the projection cannot tell which one the
/// value goes with (FIX SYNC-DISCARD-KEEPS-UNBOUND-WHOLE-ROW).
const UNBOUND_WHOLE_ROW: &str = "a whole row filed under a key it does not name";

/// A room turn in parts whose joined row does not fit the memory free now:
/// only the joined row shows whose it is, so the window waits for a pass
/// that can join it, never narrowing to the turn alone.
const UNJOINED_PARTED_TURN: &str = "a parted room turn too large to join in the memory free now";

/// A part: its root map and its digest key. A manifest lists parts of its
/// own map only, as the checkpoint capture's part holders read it.
type MapPart = (String, String);

/// The holder of a value that stays.
const KEEP: OwnerId = 0;
/// The holder of a value a discarded row owns.
const ERASE: OwnerId = 1;
/// A part's holder: this plus its place in [`DiscardClassifier::parts`].
const PART: OwnerId = 1 << 32;
/// A rewritten value's holder: this plus its place in
/// [`DiscardClassifier::rewrites`].
const REWRITE: OwnerId = 1 << 40;
/// A room turn manifest's holder, decided once the capture has met every
/// part: this plus its place in [`DiscardClassifier::turn_manifests`].
const TURN_MANIFEST: OwnerId = 1 << 48;

/// Every entity kind its own row's: the projection asks only who owns a
/// value, never where a checkpoint would seal it.
struct EveryKindOwned;

impl SyncPayloadOwners for EveryKindOwned {
    fn entity_kind(&self, _: u8) -> KindPlacement {
        KindPlacement::Owner
    }
}

/// Which of a window's values the discarded rows own.
struct DiscardClassifier<'a> {
    discarded: &'a BTreeSet<EntityId>,
    owners: BTreeSet<OwnerRef>,
    /// Each part the capture met, by its place.
    parts: Vec<MapPart>,
    part_places: BTreeMap<MapPart, usize>,
    /// Parts a manifest that goes names, and ones a manifest that stays
    /// names, across the window's whole history: a manifest of one map
    /// keeps no part of another (UC-10 PR 1).
    parts_going: BTreeSet<MapPart>,
    parts_staying: BTreeSet<MapPart>,
    rewrites: Vec<Vec<u8>>,
    /// Why the window cannot be projected, once a value names an owner the
    /// projection cannot read.
    unknown: Option<&'static str>,
    /// Every parted map value the capture met, to bind each manifest to
    /// its key (UC-10 PR 1).
    parted: PartedRows<Vec<u8>>,
    /// Each room turn manifest the capture met, by its place.
    turn_manifests: Vec<TurnManifest>,
}

/// A room turn's manifest the capture met: its key, the parts it lists, its
/// own holder (the turn alone), and whether it goes, once decided
/// ([`DiscardClassifier::decide_turn_manifests`]).
struct TurnManifest {
    key: String,
    parts: Parts,
    holders: Vec<Holder>,
    going: bool,
}

impl<'a> DiscardClassifier<'a> {
    fn new(discarded: &'a BTreeSet<EntityId>) -> Self {
        Self {
            discarded,
            owners: discarded.iter().map(OwnerRef::entity).collect(),
            parts: Vec::new(),
            part_places: BTreeMap::new(),
            parts_going: BTreeSet::new(),
            parts_staying: BTreeSet::new(),
            rewrites: Vec::new(),
            unknown: None,
            parted: PartedRows::default(),
            turn_manifests: Vec::new(),
        }
    }

    fn names_discarded(&self, key: &str) -> bool {
        EntityId::from_hex(key).is_ok_and(|id| id.to_hex() == key && self.discarded.contains(&id))
    }

    /// Whether no holder of a value keeps it: each is a discarded row, or
    /// holds it only while a discarded row stands.
    fn gone(&self, holders: &[Holder]) -> bool {
        !holders.is_empty()
            && holders.iter().all(|holder| {
                self.owners.contains(&holder.owner)
                    || holder
                        .dependencies
                        .iter()
                        .any(|on| self.owners.contains(on))
            })
    }

    fn decide(&mut self, root: &str, key: &str, value: &[u8]) -> OwnerId {
        match root {
            // A deletion's id-only truth stays (call 3).
            "tombstones" => KEEP,
            // A row and every edge it ends are its own, whatever kind
            // carries them (an ASSET row is no sealing owner's).
            "entities" | ASSET_BODY_REFS_MAP => erase(self.names_discarded(key)),
            "edges" => erase(parse_edge_key(key).is_some_and(|(source, _, target)| {
                self.discarded.contains(&source) || self.discarded.contains(&target)
            })),
            map if is_note_carrier_map(map) => self.note_atom(map, key, value),
            _ => self.placed(root_entry(root, key, value, &EveryKindOwned), root, key),
        }
    }

    /// Decides each room turn manifest the capture met as the same turn
    /// stored whole goes: by its joined row's holders, held while its room,
    /// its messages and each turn it quotes are, its parts joined from every
    /// version the window holds. A manifest whose parts the window does not
    /// all hold, or that join to no turn row, proves nothing and goes by its
    /// own holder, the turn alone. Each part it lists goes or stays with it.
    /// Why the window waits instead: a joined row that does not fit the
    /// memory free now, or that is another turn.
    fn decide_turn_manifests(&mut self) -> std::result::Result<(), &'static str> {
        let mut manifests = std::mem::take(&mut self.turn_manifests);
        for manifest in &mut manifests {
            if !assembly_fits(manifest.parts.len) {
                return Err(UNJOINED_PARTED_TURN);
            }
            let joined =
                join_parts_from(&manifest.parts, |key| self.parted.part(ROOM_TURNS_MAP, key))
                    .map(|joined| entry_joined(&manifest.key, &joined));
            manifest.going = match joined {
                Some(Placement::Owned(holders) | Placement::Split { holders, .. }) => {
                    self.gone(&holders)
                }
                Some(Placement::Unclassified {
                    reason: SyncUnclassified::KeyMismatch,
                    ..
                }) => return Err(UNBOUND_PARTED_ROW),
                _ => self.gone(&manifest.holders),
            };
            let named = manifest
                .parts
                .parts
                .iter()
                .map(|digest| (ROOM_TURNS_MAP.to_owned(), part_key(digest)));
            if manifest.going {
                self.parts_going.extend(named);
            } else {
                self.parts_staying.extend(named);
            }
        }
        self.turn_manifests = manifests;
        Ok(())
    }

    /// A room turn manifest's holder as [`Self::decide_turn_manifests`]
    /// decided it; any other holder, and one naming no manifest the capture
    /// met, as it is.
    fn settled(&self, holder: OwnerId) -> OwnerId {
        holder
            .checked_sub(TURN_MANIFEST)
            .and_then(|place| usize::try_from(place).ok())
            .and_then(|place| self.turn_manifests.get(place))
            .map_or(holder, |manifest| erase(manifest.going))
    }

    /// A NOTE carrier's atom, as its codec projects it.
    fn note_atom(&mut self, map: &str, key: &str, value: &[u8]) -> OwnerId {
        match project_atom(map, key, value, self.discarded) {
            Ok(NoteAtom::Keep) => KEEP,
            Ok(NoteAtom::Drop) => ERASE,
            Ok(NoteAtom::Rewrite(bytes)) => {
                self.rewrites.push(bytes);
                REWRITE + place_of(self.rewrites.len() - 1)
            }
            Err(_) => {
                self.unknown = Some("a NOTE carrier whose owner does not read");
                KEEP
            }
        }
    }

    /// Any other family's value under `key` of the root map `root`, as its
    /// codec places it.
    fn placed(&mut self, placement: Placement, root: &str, key: &str) -> OwnerId {
        match placement {
            Placement::Owned(holders) | Placement::Split { holders, .. } => {
                erase(self.gone(&holders))
            }
            // A room turn's manifest goes as its joined row does, which
            // only every part the window holds shows.
            Placement::Manifest { holders, parts, .. } if root == ROOM_TURNS_MAP => {
                self.turn_manifests.push(TurnManifest {
                    key: key.to_owned(),
                    parts,
                    holders,
                    going: false,
                });
                TURN_MANIFEST + place_of(self.turn_manifests.len() - 1)
            }
            Placement::Manifest { holders, parts, .. } => {
                let going = self.gone(&holders);
                let named = parts
                    .parts
                    .iter()
                    .map(|digest| (root.to_owned(), part_key(digest)));
                if going {
                    self.parts_going.extend(named);
                } else {
                    self.parts_staying.extend(named);
                }
                erase(going)
            }
            Placement::Part => {
                let part = (root.to_owned(), key.to_owned());
                let place = match self.part_places.get(&part) {
                    Some(place) => *place,
                    None => {
                        self.parts.push(part.clone());
                        self.part_places.insert(part, self.parts.len() - 1);
                        self.parts.len() - 1
                    }
                };
                PART + place_of(place)
            }
            Placement::Structure { dependencies } => {
                erase(dependencies.iter().any(|on| self.owners.contains(on)))
            }
            Placement::Unclassified {
                reason: SyncUnclassified::KeyMismatch,
                ..
            } => {
                self.unknown = Some(UNBOUND_WHOLE_ROW);
                KEEP
            }
            Placement::Unclassified { owner, .. } => {
                erase(owner.is_some_and(|owner| self.owners.contains(&owner)))
            }
            Placement::Dispatched(_) => KEEP,
        }
    }
}

/// The holder of a value that goes when `going`, else of one that stays.
fn erase(going: bool) -> OwnerId {
    if going { ERASE } else { KEEP }
}

/// `place` as an owner handle offset: a capture holds far fewer values than
/// a handle's range.
fn place_of(place: usize) -> OwnerId {
    OwnerId::try_from(place).unwrap_or(OwnerId::MAX >> 1)
}

impl Classify for DiscardClassifier<'_> {
    /// The skeleton never leaves this process, so every key may stand in it.
    fn plain_key(&mut self, _: &str, _: &str) -> bool {
        true
    }

    fn holders(&mut self, field: Field<'_>) -> Option<Vec<OwnerId>> {
        let Field::Value {
            root, key, value, ..
        } = field
        else {
            return Some(vec![KEEP]);
        };
        let LoroValue::Binary(bytes) = value else {
            return Some(vec![KEEP]);
        };
        self.parted.note(root, key, || bytes.to_vec());
        Some(vec![self.decide(root, key, bytes.as_slice())])
    }
}

/// What projecting one window's document came to.
pub(crate) enum Projected {
    /// The document holds nothing the discarded rows own.
    Unchanged,
    /// The projected document's native snapshot bytes, how many values went
    /// and were rewritten, and how many the rows own stay whole for now: each
    /// written by an operation the home does not hold.
    Joined {
        bytes: Vec<u8>,
        erased: usize,
        rewritten: usize,
        waiting: usize,
    },
    /// The document cannot be projected now, and why.
    Deferred(&'static str),
}

/// `doc`, a quiescent window document, with every value the rows in
/// `discarded` own erased at its own operation and every NOTE bundle that
/// keeps other members redacted. No operation is authored. With `held`, the
/// operations the home holds, a value written by any other operation stays
/// whole and counts as waiting (E2 = A): only the home's operations are
/// rewritten.
///
/// # Errors
///
/// A NOTE carrier of the current state that does not decode.
pub(crate) fn project_window_doc(
    doc: &LoroDoc,
    discarded: &BTreeSet<EntityId>,
    held: Option<&VersionVector>,
) -> Result<Projected> {
    if discarded.is_empty() {
        return Ok(Projected::Unchanged);
    }
    let mut classifier = DiscardClassifier::new(discarded);
    let Capture::Classified(parts) = doc.export_root_map_checkpoint(&WINDOW_ROOTS, &mut classifier)
    else {
        return Ok(Projected::Deferred(
            "a window document that is not plain root-map writes of its maps",
        ));
    };
    if let Some(why) = classifier.unknown {
        return Ok(Projected::Deferred(why));
    }
    if classifier.parted.mismatch().is_some() {
        return Ok(Projected::Deferred(UNBOUND_PARTED_ROW));
    }
    if let Err(why) = classifier.decide_turn_manifests() {
        return Ok(Projected::Deferred(why));
    }
    let unheld = held
        .map(|held| unheld_atoms(&parts.skeleton, held))
        .unwrap_or_default();
    let mut sorted = match classifier.sort(parts.atoms, unheld) {
        Ok(sorted) => sorted,
        Err(why) => return Ok(Projected::Deferred(why)),
    };
    // The current rows of the NOTE maps beyond what each atom's own
    // projection took: a retained NOTE's attachments a departed member
    // alone bound go too, so the window still validates.
    if let Err(why) = sorted.apply_current(&parts.skeleton, project_current(doc, discarded)?) {
        return Ok(Projected::Deferred(why));
    }
    if sorted.erased.is_empty() && sorted.rewritten == 0 {
        return Ok(if sorted.waiting == 0 {
            Projected::Unchanged
        } else {
            Projected::Deferred("values the rows own whose operations the home lacks")
        });
    }
    Ok(sorted.join(&parts.skeleton))
}

/// The atoms `skeleton`'s retained operations write past `held`, and, when
/// `held` does not hold the shallow root itself, each root winner no retained
/// operation writes: a local cut is no proof the home holds what is under it.
fn unheld_atoms(skeleton: &Skeleton, held: &VersionVector) -> BTreeSet<AtomId> {
    let mut unheld = BTreeSet::new();
    let mut retained = BTreeSet::new();
    for change in &skeleton.changes {
        let from = held.get(&change.peer).copied().unwrap_or(0);
        for (index, op) in change.ops.iter().enumerate() {
            let Some(atom) = op.value else {
                continue;
            };
            retained.insert(atom);
            let counter = i32::try_from(index)
                .ok()
                .and_then(|index| change.counter.checked_add(index));
            if counter.is_none_or(|counter| counter >= from) {
                unheld.insert(atom);
            }
        }
    }
    if let Some(shallow) = &skeleton.shallow
        && !shallow
            .vv
            .iter()
            .all(|(peer, end)| held.get(peer).copied().unwrap_or(0) >= *end)
    {
        unheld.extend(
            shallow
                .winners
                .iter()
                .filter_map(|winner| winner.value)
                .filter(|atom| !retained.contains(atom)),
        );
    }
    unheld
}

/// A capture's atoms, sorted: the ones that go, and the ones that stay,
/// some with rewritten values.
struct Sorted {
    erased: BTreeSet<AtomId>,
    available: BTreeMap<AtomId, Atom>,
    rewritten: usize,
    /// Atoms written by operations the home does not hold: they stay whole.
    unheld: BTreeSet<AtomId>,
    /// How many of those the projection would have changed.
    waiting: usize,
}

impl DiscardClassifier<'_> {
    /// Sorts the atoms of this classifier's capture by their holders: a part
    /// goes only when a manifest that goes names it and none that stays does;
    /// an atom in `unheld` stays as it is.
    fn sort(
        &self,
        atoms: Vec<Atom>,
        unheld: BTreeSet<AtomId>,
    ) -> std::result::Result<Sorted, &'static str> {
        let mut sorted = Sorted {
            erased: BTreeSet::new(),
            available: BTreeMap::new(),
            rewritten: 0,
            unheld,
            waiting: 0,
        };
        for mut atom in atoms {
            let holder = match atom.holders.as_slice() {
                [holder] => self.settled(*holder),
                _ => KEEP,
            };
            let changes = holder == ERASE
                || holder >= REWRITE
                || (holder >= PART && self.part_goes(holder - PART));
            if changes && sorted.unheld.contains(&atom.id) {
                sorted.waiting += 1;
                sorted.available.insert(atom.id, atom);
            } else if holder == ERASE {
                sorted.erased.insert(atom.id);
            } else if holder >= REWRITE {
                let bytes = usize::try_from(holder - REWRITE)
                    .ok()
                    .and_then(|place| self.rewrites.get(place))
                    .ok_or("a rewritten value the projection lost")?;
                atom.payload = Payload::Value(LoroValue::Binary(bytes.clone().into()));
                sorted.rewritten += 1;
                sorted.available.insert(atom.id, atom);
            } else if holder >= PART && self.part_goes(holder - PART) {
                sorted.erased.insert(atom.id);
            } else {
                sorted.available.insert(atom.id, atom);
            }
        }
        Ok(sorted)
    }

    fn part_goes(&self, place: OwnerId) -> bool {
        usize::try_from(place)
            .ok()
            .and_then(|place| self.parts.get(place))
            .is_some_and(|part| {
                self.parts_going.contains(part) && !self.parts_staying.contains(part)
            })
    }
}

impl Sorted {
    /// Applies `changes`, the current NOTE rows to rewrite or erase, to each
    /// row's latest winner in `skeleton`.
    fn apply_current(
        &mut self,
        skeleton: &Skeleton,
        changes: BTreeMap<(&'static str, String), Option<Vec<u8>>>,
    ) -> std::result::Result<(), &'static str> {
        for ((map, key), after) in changes {
            let winner = skeleton.latest.iter().find(|winner| {
                winner.key == key
                    && usize::try_from(winner.root)
                        .ok()
                        .and_then(|root| skeleton.roots.get(root))
                        .is_some_and(|root| root == map)
            });
            let Some(atom) = winner.and_then(|winner| winner.value) else {
                if after.is_some() {
                    return Err("a NOTE row the projection cannot rewrite");
                }
                continue;
            };
            if self.unheld.contains(&atom) {
                self.waiting += 1;
                continue;
            }
            match after {
                Some(bytes) => {
                    let found = self
                        .available
                        .get_mut(&atom)
                        .ok_or("a NOTE row the projection erased")?;
                    found.payload = Payload::Value(LoroValue::Binary(bytes.into()));
                    self.rewritten += 1;
                }
                None => {
                    self.available.remove(&atom);
                    self.erased.insert(atom);
                }
            }
        }
        Ok(())
    }

    /// The native document `skeleton` holds with these atoms, proved.
    fn join(self, skeleton: &Skeleton) -> Projected {
        let available: Vec<Atom> = self.available.into_values().collect();
        let erased: Vec<AtomId> = self.erased.into_iter().collect();
        match LoroDoc::join_root_map_checkpoint(skeleton, &available, &erased) {
            Ok(joined) if joined.report.equivalent => Projected::Joined {
                bytes: joined.bytes,
                erased: erased.len(),
                rewritten: self.rewritten,
                waiting: self.waiting,
            },
            Ok(_) => Projected::Deferred("a projection its join did not prove"),
            Err(error) => {
                tracing::warn!(%error, "a window's discard projection did not join");
                Projected::Deferred("a projection that did not join")
            }
        }
    }
}
