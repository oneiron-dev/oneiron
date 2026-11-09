//! Port of facade_types.py:1010-1051 (the `census` section of `Inventory`): how the rows' inputs and results
//! read, fully typed, typed to an opaque leaf, or with an unread shape.

use indexmap::{IndexMap, IndexSet};

use super::super::{Ir, Key};
use super::{Inventory, row_field};
use crate::error::GenerateError;
use crate::py::value::Dict;

impl Inventory {
    /// Port of facade_types.py:1012-1029 (`Inventory.reach`): the fallback and opaque counts reachable from an IR
    /// value, each declaration counted once per `seen`.
    pub(crate) fn reach(
        &self,
        value: &Ir,
        seen: &mut IndexSet<Key>,
    ) -> Result<(usize, usize), GenerateError> {
        let (mut unknown, mut opaque) = (0, 0);
        let mut stack = vec![value];
        while let Some(node) = stack.pop() {
            match node {
                Ir::Unknown(_) => unknown += 1,
                Ir::Opaque => opaque += 1,
                Ir::Array(inner) | Ir::Option(inner) | Ir::Map(inner) | Ir::Partial(inner) => {
                    stack.push(inner);
                }
                Ir::Tuple(items) | Ir::Union(items) | Ir::And(items) => stack.extend(items.iter()),
                Ir::Object(fields, _) => stack.extend(fields.iter().map(|field| &field.value)),
                Ir::Ref(key, arguments) => {
                    stack.extend(arguments.iter());
                    if seen.insert(key.clone()) {
                        stack.push(self.decl(key)?.ir()?);
                    }
                }
                _ => {}
            }
        }
        Ok((unknown, opaque))
    }

    /// Port of facade_types.py:1031-1033 (`Inventory.root_state`): `unknown`, `opaque` or `typed`.
    pub(crate) fn root_state(
        &mut self,
        text: &crate::py::value::Value,
    ) -> Result<&'static str, GenerateError> {
        let value = self.root_ir_value(text)?;
        let (unknown, opaque) = self.reach(&value, &mut IndexSet::new())?;
        Ok(if unknown > 0 {
            "unknown"
        } else if opaque > 0 {
            "opaque"
        } else {
            "typed"
        })
    }

    /// Port of facade_types.py:1035-1051 (`Inventory.census`): the four census lines over the rows.
    pub(crate) fn census(&mut self, rows: &[&Dict]) -> Result<Vec<String>, GenerateError> {
        let mut states: IndexMap<&str, IndexMap<&str, usize>> =
            [("input", IndexMap::new()), ("output", IndexMap::new())]
                .into_iter()
                .collect();
        for row in rows {
            for side in ["input", "output"] {
                let state = self.root_state(row_field(row, side)?)?;
                if let Some(counts) = states.get_mut(side) {
                    *counts.entry(state).or_insert(0) += 1;
                }
            }
        }
        let count = |side: &str, state: &str| {
            states
                .get(side)
                .and_then(|counts| counts.get(state))
                .copied()
                .unwrap_or(0)
        };
        let total = rows.len();
        let side = |name: &str, label: &str| {
            format!(
                "{label}: {} of {total} fully typed, {} typed down to an opaque serde_json::Value leaf, {} with a shape the generator could not read",
                count(name, "typed"),
                count(name, "opaque"),
                count(name, "unknown")
            )
        };
        Ok(vec![
            format!(
                "Census: {total} facade rows, {} declarations.",
                self.decls.len()
            ),
            side("input", "Inputs"),
            side("output", "Results"),
            format!(
                "Opaque serde_json::Value leaves: {}; unread shapes: {}.",
                self.opaques.len(),
                self.fallbacks.len()
            ),
        ])
    }
}
