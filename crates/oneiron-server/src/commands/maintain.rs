//! `maintain`: the owner's "run housekeeping now" on a stopped vault.
//!
//! It runs every sweep of the engine's housekeeping pass now, due or not, and
//! then the repairs the owner names, which only make sense on demand: a
//! vector-graph rebuild, a short-id recompute, the gate claim-index backfill,
//! the conversation DAG migration and a text-index rebuild. `--lift-secrets`
//! queues a historical secret lift run first, which the pass works to its
//! end. A running `serve` runs the same pass on its own tick and answers
//! `POST /v1/owner/maintain`. The report is JSON on stdout; a sweep that
//! failed makes the exit nonzero.

use oneiron::housekeeping::{HousekeepingBudget, HousekeepingReport};
use oneiron::policy_model::SecretLiftStatus;
use serde::Serialize;

use super::owner::{emit, open_stopped_vault_with, vault_config};
use crate::cli::MaintainArgs;
use crate::config::resolve_serve_config;

#[derive(Debug, Serialize)]
struct MaintainReport {
    housekeeping: HousekeepingReport,
    #[serde(skip_serializing_if = "Repairs::is_empty")]
    repairs: Repairs,
    /// The lift sweep's state after the pass, when the owner queued a run.
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_lift: Option<SecretLiftStatus>,
}

/// What each repair the owner named did; a repair not named is absent.
#[derive(Debug, Default, Serialize)]
struct Repairs {
    #[serde(skip_serializing_if = "Option::is_none")]
    vector_graph: Option<VectorGraphRepair>,
    #[serde(skip_serializing_if = "Option::is_none")]
    short_ids: Option<ShortIdRepair>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gate_claim_index: Option<GateClaimIndexRepair>,
    #[serde(skip_serializing_if = "Option::is_none")]
    conversation_dags: Option<ConversationDagRepair>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text_index: Option<TextIndexRepair>,
}

impl Repairs {
    fn is_empty(&self) -> bool {
        self.vector_graph.is_none()
            && self.short_ids.is_none()
            && self.gate_claim_index.is_none()
            && self.conversation_dags.is_none()
            && self.text_index.is_none()
    }
}

#[derive(Debug, Serialize)]
struct VectorGraphRepair {
    live_nodes: u64,
    dead_nodes_removed: u64,
    invalid_vectors_skipped: u64,
}

#[derive(Debug, Serialize)]
struct ShortIdRepair {
    hashes_updated: u64,
    orphans_deleted: u64,
}

#[derive(Debug, Serialize)]
struct GateClaimIndexRepair {
    rows_backfilled: u64,
    already_complete: bool,
}

#[derive(Debug, Serialize)]
struct ConversationDagRepair {
    migrated: u64,
    skipped_invalid: usize,
}

#[derive(Debug, Serialize)]
struct TextIndexRepair {
    postings_removed: u64,
    documents_reindexed: u64,
}

pub fn maintain(args: MaintainArgs) -> anyhow::Result<()> {
    let config = resolve_serve_config(&args.serve)?;
    let mut vault_config = vault_config(&config);
    // A vault whose text index no longer matches its analyzer is refused at
    // open; the rebuild is the repair, so it opens for it.
    vault_config.skip_text_index_manifest_check = args.reindex_text;
    let vault = open_stopped_vault_with(
        &config,
        vault_config,
        "or ask it: `oneiron api raw POST /v1/owner/maintain`",
    )?;
    let repairs = repair(&vault, &args)?;
    if args.lift_secrets {
        let owner = crate::owner::local_owner(&vault)?;
        vault.start_secret_lift(&owner, vault.now_recorded_at())?;
    }
    let housekeeping = vault.housekeeping_all(HousekeepingBudget::unbounded())?;
    let failed = housekeeping.failed();
    let secret_lift = args
        .lift_secrets
        .then(|| vault.secret_lift_status())
        .transpose()?;
    emit(&MaintainReport {
        housekeeping,
        repairs,
        secret_lift,
    })?;
    anyhow::ensure!(
        failed == 0,
        "{failed} housekeeping sweep(s) failed; the report names them, and the next pass retries them"
    );
    Ok(())
}

fn repair(vault: &oneiron::Vault, args: &MaintainArgs) -> anyhow::Result<Repairs> {
    let mut builder = vault.maintain();
    let mut named = false;
    if args.rebuild_vector_graph {
        builder = if args.heal_invalid_vectors {
            builder.rebuild_hnsw_heal_invalid_vectors()
        } else {
            builder.rebuild_hnsw()
        };
        named = true;
    }
    if args.recompute_short_ids {
        builder = builder.recompute_short_id_hashes();
        named = true;
    }
    if args.backfill_gate_claim_index {
        builder = builder.backfill_gate_decision_claim_index();
        named = true;
    }
    if args.migrate_conversation_dags {
        builder = builder.migrate_conversation_dags();
        named = true;
    }
    if args.reindex_text {
        builder = builder.rebuild_text_index();
        named = true;
    }
    if !named {
        return Ok(Repairs::default());
    }
    let report = builder.run()?;
    Ok(Repairs {
        vector_graph: args.rebuild_vector_graph.then_some(VectorGraphRepair {
            live_nodes: report.hnsw_live_nodes,
            dead_nodes_removed: report.hnsw_dead_nodes_removed,
            invalid_vectors_skipped: report.hnsw_invalid_vectors_skipped,
        }),
        short_ids: args.recompute_short_ids.then_some(ShortIdRepair {
            hashes_updated: report.short_id_hashes_updated,
            orphans_deleted: report.orphan_short_ids_deleted,
        }),
        gate_claim_index: args
            .backfill_gate_claim_index
            .then_some(GateClaimIndexRepair {
                rows_backfilled: report.gate_claim_index_rows_backfilled,
                already_complete: report.gate_claim_index_backfill_already_complete,
            }),
        conversation_dags: args
            .migrate_conversation_dags
            .then_some(ConversationDagRepair {
                migrated: report.conversation_dags_migrated,
                skipped_invalid: report.conversation_dags_skipped_invalid.len(),
            }),
        text_index: args.reindex_text.then_some(TextIndexRepair {
            postings_removed: report.text_postings_removed,
            documents_reindexed: report.text_documents_reindexed,
        }),
    })
}
