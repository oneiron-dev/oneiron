//! Golden-corpus behavior fingerprint and structured behavior diff.

use super::{GeneratedLens, GeneratedUiPrimitive};
use crate::lens::atom::{GeneratedUiResultSetSelectAll, LensAtom, LensNode};
use crate::lens::validate::validate_lens_token;
use crate::lens::wire_ids::{LensHandleName, LensHandleRole};
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};

// ── Regen-on-update: behavior fingerprint, structured diff, adoption decision ──
//
// Everything below is a pure decision path over *rendered* lens bodies. It performs no
// store write, gate call, approval mutation, queue write, mount mutation, or model
// routing, and it never accepts prompt text, generated source, source bytes, or any
// hash of them. Only validated golden renders cross into the comparison.

/// The rendered behavior of one golden corpus, keyed by fixture id.
///
/// Fixture boundaries are part of the comparison domain: the corpus is never flattened
/// into one set, so a handle or atom moving between cases stays visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensBehaviorFingerprint {
    cases: BTreeMap<String, LensFixtureBehavior>,
}

/// The four semantic dimensions compared per fixture.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LensFixtureBehavior {
    atom_tree: Vec<LensAtomTreeEntry>,
    bound_handles: BTreeSet<LensHandleBinding>,
    /// The subset of declared reach a result-set atom actually *points at*: every row
    /// `target_handle` and every select-all `predicate_handle`, resolved to the
    /// `(name, role)` pair its own node declared. This is not a second declared set —
    /// each pair here is by construction already in `bound_handles` — it is which of
    /// those declarations the host is really told to read.
    referenced_handles: BTreeSet<LensHandleBinding>,
    atom_inventory: BTreeMap<GeneratedUiPrimitive, u32>,
}

/// One ordered pre-order tree position. Primitive plus position plus child count encodes
/// the atom-kind shape without node ids or any text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct LensAtomTreeEntry {
    primitive: GeneratedUiPrimitive,
    child_count: usize,
}

/// The bound-read identity: the full `(name, role)` pair. Name equality alone is not
/// authority, and duplicate occurrences of an identical pair deduplicate in the set.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LensHandleBinding {
    name: LensHandleName,
    role: LensHandleRole,
}

impl LensBehaviorFingerprint {
    /// Build behavior from already-rendered, validated golden-corpus outputs.
    ///
    /// The diff path accepts [`GeneratedLens`] values, not source text:
    ///
    /// ```compile_fail
    /// use oneiron::lens::LensBehaviorFingerprint;
    /// let _ = LensBehaviorFingerprint::from_golden_renders([
    ///     ("fixture", "generated lens source text"),
    /// ]);
    /// ```
    ///
    /// ```
    /// use oneiron::lens::{GeneratedLens, LensBehaviorFingerprint};
    ///
    /// fn fingerprint(rendered: &GeneratedLens) {
    ///     let _ = LensBehaviorFingerprint::from_golden_renders([
    ///         ("fixture", rendered),
    ///     ]);
    /// }
    ///
    /// let _ = fingerprint as fn(&GeneratedLens);
    /// ```
    pub fn from_golden_renders<'a>(
        renders: impl IntoIterator<Item = (&'a str, &'a GeneratedLens)>,
    ) -> Result<Self> {
        let mut cases = BTreeMap::new();
        for (fixture_id, rendered) in renders {
            validate_lens_token("lens golden fixture id", fixture_id)?;
            let behavior = fingerprint_render(rendered)?;
            if cases.insert(fixture_id.to_owned(), behavior).is_some() {
                return Err(Error::InvalidConfig(format!(
                    "lens golden corpus contains duplicate fixture id {fixture_id}"
                )));
            }
        }
        if cases.is_empty() {
            return Err(Error::InvalidConfig(
                "lens golden corpus must contain at least one fixture".to_string(),
            ));
        }
        Ok(Self { cases })
    }

    #[must_use]
    pub fn fixture_ids(&self) -> impl ExactSizeIterator<Item = &str> {
        self.cases.keys().map(String::as_str)
    }

    #[must_use]
    pub fn fixture_count(&self) -> usize {
        self.cases.len()
    }
}

/// Reduce one validated render to its four behavior dimensions.
///
/// Node ids, fallback text, literal/interpolated text values, labels, layout payloads,
/// and any source or prompt material are deliberately not inputs.
fn fingerprint_render(rendered: &GeneratedLens) -> Result<LensFixtureBehavior> {
    let mut atom_tree = Vec::new();
    let mut bound_handles = BTreeSet::new();
    let mut referenced_handles = BTreeSet::new();
    let mut atom_inventory: BTreeMap<GeneratedUiPrimitive, u32> = BTreeMap::new();
    let mut stack = vec![rendered.root()];

    while let Some(node) = stack.pop() {
        // The closed atom vocabulary is read through `LensAtom::primitive()`, never a
        // mirrored kind list, so any future atom participates automatically.
        let primitive = node.atom.primitive();
        atom_tree.push(LensAtomTreeEntry {
            primitive,
            child_count: node.children.len(),
        });
        let count = atom_inventory.entry(primitive).or_insert(0_u32);
        *count = count
            .checked_add(1)
            .ok_or_else(|| Error::InvalidConfig("lens atom inventory overflowed".to_string()))?;

        // `node.bindings` and `AnswerSheetAtom::citations` are the only
        // `(LensHandleName, LensHandleRole)` surfaces in a generated lens tree.
        // `node.state_bindings` (the `$bind` descriptors) are excluded on purpose: a
        // `$bind` names one `$state` key and one control property and carries no
        // `LensHandleRole`, so it belongs to the same role-less class as interpolation
        // keys, graph node/edge ids, backing refs, `SelfUiValue::Handle`, and media
        // handles. Promoting any of them here would contradict the fixed
        // `(name, role)` bound-read boundary.
        for binding in &node.bindings {
            bound_handles.insert(LensHandleBinding {
                name: binding.name.clone(),
                role: binding.role,
            });
        }
        if let LensAtom::AnswerSheet(answer) = &node.atom {
            for binding in &answer.citations {
                bound_handles.insert(LensHandleBinding {
                    name: binding.name.clone(),
                    role: binding.role,
                });
            }
        }

        // A result set's row `target_handle` and its select-all `predicate_handle` are
        // *references*, not declarations: each one has to name reach this same node
        // already advertised, and `super::mediation::select_atom` copies the host
        // backing row for exactly that handle. So swapping a row from one declared
        // handle to another leaves the declared set above byte-identical while moving
        // which host rows the selection actually reads — a data-read change the
        // `bound_handles` dimension alone cannot see.
        if let LensAtom::ResultSet(result_set) = &node.atom {
            for row in &result_set.rows {
                referenced_handles.insert(referenced_binding(node, &row.target_handle)?);
            }
            if let GeneratedUiResultSetSelectAll::WithinFilter { predicate_handle } =
                &result_set.select_all
            {
                referenced_handles.insert(referenced_binding(node, predicate_handle)?);
            }
        }

        // Reversed push keeps the pop order equal to the source child order.
        stack.extend(node.children.iter().rev());
    }

    Ok(LensFixtureBehavior {
        atom_tree,
        bound_handles,
        referenced_handles,
        atom_inventory,
    })
}

/// Resolve one result-set handle reference against the declaring node's own bindings.
///
/// The tree validator already proved every such reference names a handle this node
/// declares exactly once, so a missing or duplicated declaration is a broken invariant.
/// It fails the fingerprint rather than resolving to nothing: a reference silently
/// dropped here would read as "no reference changed" and could auto-adopt.
fn referenced_binding(node: &LensNode, handle: &LensHandleName) -> Result<LensHandleBinding> {
    let mut declared = node
        .bindings
        .iter()
        .filter(|binding| &binding.name == handle);
    let binding = declared.next().ok_or_else(|| {
        Error::InvalidConfig(
            "lens result set handle must be declared by the node that references it".to_string(),
        )
    })?;
    if declared.next().is_some() {
        return Err(Error::InvalidConfig(
            "lens result set handle must be declared exactly once by its own node".to_string(),
        ));
    }
    Ok(LensHandleBinding {
        name: binding.name.clone(),
        role: binding.role,
    })
}

/// One `(fixture, name, role)` data read that was added or removed — either a
/// declared binding or the reach a result-set reference resolves to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LensBehaviorHandle {
    fixture_id: String,
    name: LensHandleName,
    role: LensHandleRole,
}

impl LensBehaviorHandle {
    #[must_use]
    pub fn fixture_id(&self) -> &str {
        &self.fixture_id
    }

    #[must_use]
    pub const fn name(&self) -> &LensHandleName {
        &self.name
    }

    #[must_use]
    pub const fn role(&self) -> LensHandleRole {
        self.role
    }
}

/// A handle name whose role set changed. The old and new pairs are also present in
/// `removed_handles`/`added_handles`; this is the direct before/after evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensHandleRoleChange {
    fixture_id: String,
    name: LensHandleName,
    before: BTreeSet<LensHandleRole>,
    after: BTreeSet<LensHandleRole>,
}

impl LensHandleRoleChange {
    #[must_use]
    pub fn fixture_id(&self) -> &str {
        &self.fixture_id
    }

    #[must_use]
    pub const fn name(&self) -> &LensHandleName {
        &self.name
    }

    #[must_use]
    pub const fn before(&self) -> &BTreeSet<LensHandleRole> {
        &self.before
    }

    #[must_use]
    pub const fn after(&self) -> &BTreeSet<LensHandleRole> {
        &self.after
    }
}

/// An atom-kind count that changed in one fixture. Equal counts never produce an entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LensAtomInventoryChange {
    fixture_id: String,
    primitive: GeneratedUiPrimitive,
    before: u32,
    after: u32,
}

impl LensAtomInventoryChange {
    #[must_use]
    pub fn fixture_id(&self) -> &str {
        &self.fixture_id
    }

    #[must_use]
    pub const fn primitive(&self) -> GeneratedUiPrimitive {
        self.primitive
    }

    #[must_use]
    pub const fn before(&self) -> u32 {
        self.before
    }

    #[must_use]
    pub const fn after(&self) -> u32 {
        self.after
    }
}

/// The full behavior delta between two corpus fingerprints.
///
/// All four dimensions are reported, but only handle changes — declared *or*
/// referenced — drive the adoption lane: structure and inventory are evidence, not
/// approval authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensBehaviorDiff {
    structural_cases: BTreeSet<String>,
    added_handles: BTreeSet<LensBehaviorHandle>,
    removed_handles: BTreeSet<LensBehaviorHandle>,
    added_referenced_handles: BTreeSet<LensBehaviorHandle>,
    removed_referenced_handles: BTreeSet<LensBehaviorHandle>,
    role_changes: Vec<LensHandleRoleChange>,
    inventory_changes: BTreeSet<LensAtomInventoryChange>,
}

impl LensBehaviorDiff {
    /// Compare two corpus fingerprints.
    ///
    /// The fixture-id sets must be equal; a missing render is never treated as empty
    /// behavior and the two sides are never intersected or position-matched.
    pub fn between(
        before: &LensBehaviorFingerprint,
        after: &LensBehaviorFingerprint,
    ) -> Result<Self> {
        if !before.cases.keys().eq(after.cases.keys()) {
            return Err(Error::InvalidConfig(
                "lens behavior fingerprints cover different golden fixtures".to_string(),
            ));
        }

        let mut diff = Self {
            structural_cases: BTreeSet::new(),
            added_handles: BTreeSet::new(),
            removed_handles: BTreeSet::new(),
            added_referenced_handles: BTreeSet::new(),
            removed_referenced_handles: BTreeSet::new(),
            role_changes: Vec::new(),
            inventory_changes: BTreeSet::new(),
        };
        // The key sets are proven equal above, so the two ordered maps walk in lockstep.
        for ((fixture_id, before_case), (_, after_case)) in
            before.cases.iter().zip(after.cases.iter())
        {
            diff.push_fixture(fixture_id, before_case, after_case);
        }
        diff.role_changes.sort_by(|left, right| {
            left.fixture_id
                .cmp(&right.fixture_id)
                .then_with(|| left.name.as_str().cmp(right.name.as_str()))
        });
        Ok(diff)
    }

    fn push_fixture(
        &mut self,
        fixture_id: &str,
        before: &LensFixtureBehavior,
        after: &LensFixtureBehavior,
    ) {
        if before.atom_tree != after.atom_tree {
            self.structural_cases.insert(fixture_id.to_owned());
        }
        self.push_inventory_changes(fixture_id, before, after);
        self.push_handle_changes(fixture_id, before, after);
        self.push_referenced_handle_changes(fixture_id, before, after);
        self.push_role_changes(fixture_id, before, after);
    }

    fn push_inventory_changes(
        &mut self,
        fixture_id: &str,
        before: &LensFixtureBehavior,
        after: &LensFixtureBehavior,
    ) {
        let primitives = before
            .atom_inventory
            .keys()
            .chain(after.atom_inventory.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        for &primitive in &primitives {
            // An absent side counts as zero; an unchanged count emits nothing at all.
            let before_count = before.atom_inventory.get(&primitive).copied().unwrap_or(0);
            let after_count = after.atom_inventory.get(&primitive).copied().unwrap_or(0);
            if before_count != after_count {
                self.inventory_changes.insert(LensAtomInventoryChange {
                    fixture_id: fixture_id.to_owned(),
                    primitive,
                    before: before_count,
                    after: after_count,
                });
            }
        }
    }

    fn push_handle_changes(
        &mut self,
        fixture_id: &str,
        before: &LensFixtureBehavior,
        after: &LensFixtureBehavior,
    ) {
        for binding in after.bound_handles.difference(&before.bound_handles) {
            self.added_handles
                .insert(behavior_handle(fixture_id, binding));
        }
        for binding in before.bound_handles.difference(&after.bound_handles) {
            self.removed_handles
                .insert(behavior_handle(fixture_id, binding));
        }
    }

    /// The same set difference over the *referenced* dimension. A pair can appear here
    /// while `added_handles`/`removed_handles` stay empty: that is exactly a result set
    /// retargeted between two handles the node declares either way.
    fn push_referenced_handle_changes(
        &mut self,
        fixture_id: &str,
        before: &LensFixtureBehavior,
        after: &LensFixtureBehavior,
    ) {
        let before_referenced = &before.referenced_handles;
        let after_referenced = &after.referenced_handles;
        for binding in after_referenced.difference(before_referenced) {
            self.added_referenced_handles
                .insert(behavior_handle(fixture_id, binding));
        }
        for binding in before_referenced.difference(after_referenced) {
            self.removed_referenced_handles
                .insert(behavior_handle(fixture_id, binding));
        }
    }

    fn push_role_changes(
        &mut self,
        fixture_id: &str,
        before: &LensFixtureBehavior,
        after: &LensFixtureBehavior,
    ) {
        let before_roles = roles_by_handle_name(&before.bound_handles);
        let after_roles = roles_by_handle_name(&after.bound_handles);
        for (name, before_set) in &before_roles {
            // Only a name present on both sides can have *changed* role; a name that
            // appears on one side alone is already an added/removed pair.
            let Some(after_set) = after_roles.get(name) else {
                continue;
            };
            if before_set == after_set {
                continue;
            }
            self.role_changes.push(LensHandleRoleChange {
                fixture_id: fixture_id.to_owned(),
                name: (*name).clone(),
                before: before_set.clone(),
                after: after_set.clone(),
            });
        }
    }

    /// True when all seven collections are empty.
    #[must_use]
    pub fn is_identical(&self) -> bool {
        self.structural_cases.is_empty()
            && self.added_handles.is_empty()
            && self.removed_handles.is_empty()
            && self.added_referenced_handles.is_empty()
            && self.removed_referenced_handles.is_empty()
            && self.role_changes.is_empty()
            && self.inventory_changes.is_empty()
    }

    /// The single adoption predicate: which reach is declared, *and* which of it a
    /// result set points at. Structural and inventory churn never forces a human stamp
    /// on its own, and `role_changes` stays evidence — every role move is already a
    /// removed/added pair here.
    #[must_use]
    pub fn has_data_read_change(&self) -> bool {
        !self.added_handles.is_empty()
            || !self.removed_handles.is_empty()
            || !self.added_referenced_handles.is_empty()
            || !self.removed_referenced_handles.is_empty()
    }

    #[must_use]
    pub const fn structural_cases(&self) -> &BTreeSet<String> {
        &self.structural_cases
    }

    #[must_use]
    pub const fn added_handles(&self) -> &BTreeSet<LensBehaviorHandle> {
        &self.added_handles
    }

    #[must_use]
    pub const fn removed_handles(&self) -> &BTreeSet<LensBehaviorHandle> {
        &self.removed_handles
    }

    /// Reach a result-set row or select-all predicate newly points at.
    #[must_use]
    pub const fn added_referenced_handles(&self) -> &BTreeSet<LensBehaviorHandle> {
        &self.added_referenced_handles
    }

    /// Reach a result-set row or select-all predicate no longer points at.
    #[must_use]
    pub const fn removed_referenced_handles(&self) -> &BTreeSet<LensBehaviorHandle> {
        &self.removed_referenced_handles
    }

    #[must_use]
    pub fn role_changes(&self) -> &[LensHandleRoleChange] {
        &self.role_changes
    }

    #[must_use]
    pub const fn inventory_changes(&self) -> &BTreeSet<LensAtomInventoryChange> {
        &self.inventory_changes
    }
}

fn behavior_handle(fixture_id: &str, binding: &LensHandleBinding) -> LensBehaviorHandle {
    LensBehaviorHandle {
        fixture_id: fixture_id.to_owned(),
        name: binding.name.clone(),
        role: binding.role,
    }
}

fn roles_by_handle_name(
    handles: &BTreeSet<LensHandleBinding>,
) -> BTreeMap<&LensHandleName, BTreeSet<LensHandleRole>> {
    let mut grouped: BTreeMap<&LensHandleName, BTreeSet<LensHandleRole>> = BTreeMap::new();
    for binding in handles {
        grouped
            .entry(&binding.name)
            .or_default()
            .insert(binding.role);
    }
    grouped
}
