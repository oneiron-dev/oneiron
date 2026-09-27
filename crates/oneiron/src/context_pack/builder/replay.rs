//! Opt-in pack-assembly and terminal-projection settings for offline replay.

use serde_json::{Value, json};

use super::ContextPackBuilder;
use crate::serialize::SerializeConfig;

impl ContextPackBuilder<'_> {
    pub(super) fn pack_replay_config(&self) -> Value {
        json!({
            "assembly": {
                "hydrate": self.hydrate,
                "read_mode": self.read_mode,
                "include_edges": self.include_edges,
                "edge_hop": self.edge_hop,
                "selected_edge_budget": self.selected_edge_budget,
                "include_vectors": self.include_vectors,
                "criticality": self.criticality,
                "source_ranking": self.source_ranking,
                "world_scope": format!("{:?}", self.world_scope),
                "non_base_world_fraction": self.non_base_world_fraction,
                "l2_summary_subjects": self.l2_summary_subjects.iter().map(crate::EntityId::to_hex).collect::<Vec<_>>(),
                "l2_summary_reader_present": self.l2_summary_reader.is_some(),
                "signals_used": self.signals_used,
            },
            "projection": projection_config(&SerializeConfig {
                format: self.format,
                profile: self.field_profile,
                budget: self.token_budget,
                allocation: self.token_allocation,
                include_stats: self.include_stats,
                merge_neighbors: self.merge_neighbors,
                max_field_chars: self.max_field_chars,
                max_item_tokens: self.max_item_tokens,
            }),
        })
    }
}

pub(super) fn projection_config(config: &SerializeConfig) -> Value {
    json!({
        "format": format!("{:?}", config.format),
        "profile": format!("{:?}", config.profile),
        "token_budget": config.budget,
        "allocation": {
            "claims": config.allocation.claims,
            "turns": config.allocation.turns,
            "summaries": config.allocation.summaries,
            "other": config.allocation.other,
        },
        "include_stats": config.include_stats,
        "merge_neighbors": config.merge_neighbors,
        "max_field_chars": config.max_field_chars,
        "max_item_tokens": config.max_item_tokens,
    })
}
