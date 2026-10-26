//! Snapshot classification. Index pages and process coordination never enter the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageTier {
    Canonical,
    Derived,
    Runtime,
}
use StorageTier::*;
/// Host orders and the host-only log (OF-470 C2): a restore carries them from
/// the live vault, never from an image (`host_holds`).
pub(super) const HOST_HOLD_PREFIX: &[u8] = b"legal_hold:host:";
pub fn storage_tier(database: &str, key: &[u8]) -> StorageTier {
    match database {
        "entities" | "edges_out" | "edges_in" | "short_ids" | "short_ids_reverse"
        | "job_records" => Canonical,
        "vault_meta" => {
            if [
                b"dreamer:budget:".as_slice(),
                b"dreamer:budget_reservation:",
                // The host's last home-node candidates are this node's own
                // topology input, never an image's (DOOR-101 PR2a).
                b"dreamer:home_candidates:v1",
                b"dreamer:parked:",
                b"dreamer:peer_wait",
                b"dreamer:trap_binding:",
                // A pass's own observation of its clock, calls and leases
                // (DOOR-144): no image restores a live lease.
                b"dreamer:wake:observation:v1:",
                // A parked code run's trap binding, node-local as the
                // step's own.
                b"code_run:wait_trap:",
                b"retr_run",
                b"retr_out",
                b"retr_trace",
                // The key over stored fork hashes stays with the node, like
                // the telemetry it keys.
                b"retrieval_trace_key:",
                b"tasks.create.rate.",
                b"own_rate.",
                b"vault_cleanup.scan",
                b"self_heal:signed:",
                b"booking:anti_abuse:v1:rate\0",
                b"booking:anti_abuse:v1:cache\0",
                b"gate_pending:critical_confirm_expiry_cursor:v1",
                b"gate_pending:critical_confirm_list_cursor:v1",
                b"outbound:authorized_recovery_lease:v1",
                b"vault_archived:v1",
                // A store's backup incarnation is its own: a restored store
                // mints a fresh one (the backup watermark), and counts every
                // commit until a classed write stamps one (FIX 6730).
                b"backup:change:v1",
                b"backup:incarnation:v1",
                // A repair's staged authority rows are this device's own
                // progress, never an image's (OF-469).
                b"authority.history.stage.v1:",
                // So is the checkpoint upkeep's own accounting: its totals,
                // the head it kept and the adopted rows it awaits (OF-469).
                b"authority.checkpoint.local.",
                // A mirror's kept LFS census is this host's own walk; a
                // restore walks the whole history again (FIX 6331).
                b"origin:mirror_lfs_census:v1:",
                // Host orders and the host-only log never enter an owner's
                // image (OF-470 C2).
                HOST_HOLD_PREFIX,
                // An owner's confirm stands only where he gave it: an image's
                // receipt is never an election (FIX-LIST 10671).
                b"secret_custody:restore_election:v1:",
            ]
            .iter()
            .any(|p| key.starts_with(p))
            {
                Runtime
            } else if [
                b"provider_confidence/".as_slice(),
                // Who computed each vector: derived with the vectors it
                // describes, which a restore embeds again.
                b"embedding/device/",
                b"ppr_community_cache:",
                // The thread projection is a cache over the reply chain; a
                // restore folds it again from the restored edges (OF-296).
                b"conversation_dag:thread_meta:v1:",
                b"conversation_dag:thread_meta_dirty:v1:",
                b"skill_hub/content_hash_index/v1\0",
                b"skill_hub/content_hash_index_schema_version",
                b"skill_convert/source_index/v1\0",
                b"dreamer.milestone_index.v1.",
                b"dreamer:step_index:v1:",
                b"edit_distance/routing_aggregate/v1\0",
                b"edit_distance/routing_member/v1\0",
                b"edit_distance/routing_rung/v1\0",
                b"edit_distance/routing_serving_model/v1",
                b"ramp_stats:v1:",
                b"human_task.followup.v1\0",
                b"edit_distance/reservoir_candidate/v1\0",
                b"commitment_due_rev:v1:",
                b"commitment_series_project:v1:",
                b"outbound_grant/principal/v1\0",
                b"counterparty_contact.index.v1:",
                b"counterparty.contact.party_channel.v1:",
                b"connector_key/connector/v1\0",
                b"gate_pending:run_index:v1:",
                b"gate_pending:group_index:v1:",
                b"gate_pending:hash_index:v1:",
                b"gate_pending:sequence_index:v1:",
                b"gate_pending:critical_confirm_by_id:v1:",
                // Project revision indexes: a restore rebuilds them from the
                // revision companions it keeps.
                b"project.revisions.v1/",
                b"project.revision_awaiting_mint.v1/",
                b"project.revision_backfill.v1",
            ]
            .iter()
            .any(|p| key.starts_with(p))
            {
                Derived
            } else {
                // Prefilter receipts/membership and tuned blend weights are
                // historical decisions, not reconstructable projections.
                Canonical
            }
        }
        "hnsw_meta" => {
            if [
                b"model_id".as_slice(),
                b"embedding_transform",
                b"hnsw_config",
                b"embedding_model_epoch",
                b"vector_version",
                b"graph_version",
                b"temporal_long_intervals_schema_version",
            ]
            .contains(&key)
            {
                Canonical
            } else {
                Derived
            }
        }
        "sync_state" => {
            if [
                b"pelease:".as_slice(),
                b"bulk:",
                b"m:last_sync",
                b"m:maintenance_ingest_quota",
                b"budget:",
                // A provider's offer cooldowns belong to this deployment.
                b"models:offer-cooldown:",
                // So do the Responses chains its providers keep (OF-602).
                b"models:responses-chain:",
                // The home's kit door nonces and its unfinished bundle
                // uploads: a restore drops the uploads, and their machines
                // start over (FIX 922).
                b"rb:n:",
                b"rb:s:",
                b"rb:u:",
            ]
            .iter()
            .any(|p| key.starts_with(p))
            {
                Runtime
            } else if [
                b"sv:".as_slice(),
                b"svf:",
                b"sv_base:",
                b"ssv:",
                b"pe:",
                b"usage:rollup:",
            ]
            .iter()
            .any(|p| key.starts_with(p))
            {
                Derived
            } else {
                Canonical
            }
        }
        "sync_queue" => {
            if key.starts_with(b"m:maintenance_ingest_quota:v1:") {
                Runtime
            } else if key.starts_with(b"e:") {
                Derived
            } else {
                Canonical
            }
        }
        _ => Derived,
    }
}
