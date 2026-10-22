//! The owned, framed inputs a thing's agent is lent (FIX 7508): each of the
//! branch's clean extraction slices (FIX 9017), its neighbourhood rendered
//! in, cut into pieces no larger than one share of the agent's window and
//! every piece lent; the `src` manifest naming them; the pack the decide
//! port takes; and the newest checkpoint an earlier transport run of the
//! attempt left.
//!
//! A slice keeps its labels and its source offsets: each piece's header
//! names its slice, its place among the slice's pieces and the byte range
//! of the slice's text it holds. Nothing is cut short (Rule 5): an oversized
//! slice is split into as many pieces as it takes.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use super::{THING_DECIDE_PORT, THING_EXTRACT_PORT};
use crate::code_run::HostInput;
use crate::dreamer_consolidation::resources::ExtractionSlice;
use crate::entity_id::EntityId;
use crate::llm::Scope;

/// The manifest a scoped child reads first, by the name every reader child
/// reads its primary input by.
const SOURCE_INPUT: &str = "src";

/// The one pack the decide port takes: the branch's correction pack.
pub(super) const CORRECTIONS_PACK: &str = "pack-corrections";

/// The checkpoint an earlier transport run of the attempt left.
const CHECKPOINT_INPUT: &str = "checkpoint";

/// Where the inputs sit in the host parent run.
const INPUT_ROOT: &str = "thing/input/";

/// Which slice each lent piece is of, and each slice's input name (its
/// first piece's), in slice order.
pub(super) struct ThingPlan {
    pieces: BTreeMap<String, usize>,
    slices: Vec<String>,
}

impl ThingPlan {
    /// The slice the lent piece `input` is of.
    pub(super) fn slice_of(&self, input: &str) -> Option<usize> {
        self.pieces.get(input).copied()
    }

    /// Slice `slice`'s input name.
    pub(super) fn slice_name(&self, slice: usize) -> &str {
        self.slices.get(slice).map_or("", String::as_str)
    }

    /// How many slices the branch has.
    pub(super) fn slice_count(&self) -> usize {
        self.slices.len()
    }
}

/// The inputs `slices` are lent as, each piece at most `grain_tokens`
/// tokens of its slice's text, with the manifest, the pack and, when an
/// earlier run left one, the `checkpoint`; and the plan that maps them back.
pub(super) fn frame_inputs(
    slices: &[&ExtractionSlice],
    grain_tokens: u64,
    checkpoint: Option<Vec<u8>>,
) -> (Vec<HostInput>, ThingPlan) {
    let grain = usize::try_from(grain_tokens).unwrap_or(usize::MAX).max(1);
    let mut inputs = Vec::new();
    let mut plan = ThingPlan {
        pieces: BTreeMap::new(),
        slices: Vec::with_capacity(slices.len()),
    };
    let mut listed = Vec::with_capacity(slices.len());
    for (index, slice) in slices.iter().enumerate() {
        let cuts = pieces(&slice.transcript, grain);
        let total = cuts.len();
        let mut names = Vec::with_capacity(total);
        for (at, (start, end)) in cuts.into_iter().enumerate() {
            let name = piece_name(index, at);
            let header = json!({
                "slice": index,
                "piece": at + 1,
                "pieces": total,
                "bytes": [start, end],
                "turns": slice.turns.len(),
            });
            let mut body = header.to_string().into_bytes();
            body.push(b'\n');
            body.extend_from_slice(&slice.transcript.as_bytes()[start..end]);
            inputs.push(HostInput {
                path: format!("{INPUT_ROOT}{name}"),
                name: name.clone(),
                body,
                rows: Some(slice.turns.clone()),
            });
            plan.pieces.insert(name.clone(), index);
            names.push(name);
        }
        plan.slices.push(names.first().cloned().unwrap_or_default());
        listed.push(json!({
            "slice": index,
            "input": plan.slice_name(index),
            "pieces": names,
            "turns": slice.turns.len(),
        }));
    }
    let lends_checkpoint = checkpoint.is_some();
    if let Some(body) = checkpoint {
        inputs.push(host_input(CHECKPOINT_INPUT, body, Vec::new()));
    }
    inputs.push(host_input(
        CORRECTIONS_PACK,
        json!({"pack": "corrections", "slices": plan.slices})
            .to_string()
            .into_bytes(),
        Vec::new(),
    ));
    let manifest = json!({
        "thing": {
            "slices": listed,
            "pack": CORRECTIONS_PACK,
            "checkpoint": lends_checkpoint.then_some(CHECKPOINT_INPUT),
            "ports": {"extract": THING_EXTRACT_PORT, "decide": THING_DECIDE_PORT},
            "report": {
                "proposals": "every proposal ref the extract answers gave",
                "coverage": "the input name of every slice you extracted",
                "checkpoint": "the checkpoint input you were lent, or null",
            },
        },
    });
    inputs.push(host_input(
        SOURCE_INPUT,
        manifest.to_string().into_bytes(),
        Vec::new(),
    ));
    (inputs, plan)
}

/// The scope a thing's loan lends: its branch's axes, every lent slice's
/// readable resources and no writable one. A slice held back is not read
/// into it, so the loan never widens past what it lends.
pub(super) fn lent_scope(request: &Scope, slices: &[&ExtractionSlice]) -> Scope {
    Scope {
        world: request.world,
        facet: request.facet,
        relationship: request.relationship,
        project: request.project,
        readable: slices
            .iter()
            .flat_map(|slice| slice.scope.readable.iter().cloned())
            .collect(),
        writable: BTreeSet::new(),
    }
}

/// A non-slice input at its own name.
fn host_input(name: &str, body: Vec<u8>, rows: Vec<EntityId>) -> HostInput {
    HostInput {
        name: name.to_owned(),
        path: format!("{INPUT_ROOT}{name}"),
        body,
        rows: Some(rows),
    }
}

/// The name piece `at` of slice `slice` is lent by: the slice's own name
/// for its first piece, that name and the piece's number after.
fn piece_name(slice: usize, at: usize) -> String {
    if at == 0 {
        format!("slice-{slice:04}")
    } else {
        format!("slice-{slice:04}.{}", at + 1)
    }
}

/// `text` cut into byte ranges of at most `grain` tokens each, at line ends
/// where a line fits; a line past the grain on its own is cut every `grain`
/// characters. Every byte is in exactly one range; an empty text is one
/// empty range.
fn pieces(text: &str, grain: usize) -> Vec<(usize, usize)> {
    let mut cuts = Vec::new();
    let mut start = 0;
    let mut tokens = 0;
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        let line_tokens = crate::count_context_pack_tokens(line);
        if tokens > 0 && tokens + line_tokens > grain {
            cuts.push((start, at));
            start = at;
            tokens = 0;
        }
        if line_tokens > grain {
            let mut from = at;
            for (count, (offset, _)) in line.char_indices().enumerate() {
                if count > 0 && count.is_multiple_of(grain) {
                    cuts.push((from, at + offset));
                    from = at + offset;
                }
            }
            start = from;
            tokens = crate::count_context_pack_tokens(&text[from..at + line.len()]);
        } else {
            tokens += line_tokens;
        }
        at += line.len();
    }
    if start < at || cuts.is_empty() {
        cuts.push((start, at));
    }
    cuts
}
