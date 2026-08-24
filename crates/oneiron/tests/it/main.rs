//! Consolidated integration-test binary (default-features lane).
//!
//! Each module below was a standalone `tests/*.rs` Cargo target; compiling
//! them as one binary replaces ~40 independent link steps with one. The
//! `sync`-feature cluster lives in `tests/it_sync/main.rs` (a Cargo target
//! gated on `required-features = ["sync"]`), and the trybuild compile-fail
//! harness stays standalone in `tests/relay_attestation_compilefail.rs`.
//!
//! `common` is the shared fixture-helper module; it stays at
//! `tests/common/mod.rs` because both this binary and `it_sync` include it.
//! Static fixture data stays under `tests/fixtures/`.

#[path = "../common/mod.rs"]
mod common;

mod analyzer_asset_policy;
mod booking_lifecycle;
mod booking_solver;
mod byte_space_v3_conformance;
mod calendar_connector_smoke;
mod calendar_ics_ingest_adapter;
mod calendar_outcome;
mod calendar_prep;
mod calendar_surface_oracle;
mod calendar_transcript;
mod campaign_claim_gate_oracle;
mod campaign_compliance_oracle;
mod campaign_enrollment_oracle;
mod campaign_send_hygiene_oracle;
mod campaign_stage_ladder_oracle;
mod cb_oracle_agents;
mod cb_oracle_frame;
mod cb_oracle_plugin;
mod cb_oracle_stream;
mod cb_oracle_tasks;
mod channel_identity_email_adapter_smoke;
mod channel_identity_slack_adapter_smoke;
mod code_consent;
mod counterparty_opt_out_shipping_paths_oracle;
mod effect_spine_oracle;
mod gate_regression;
mod image_station_injection;
mod linkedin_connector_adapter;
mod merge_split_oracle;
mod microvm_contract;
mod of060_fitness;
mod of360_extraction_eval;
mod ops_docs;
mod outbound_intent_ledger;
mod prompt_blocks;
mod receipt_answerability;
mod receipt_context;
mod saved_query_oracle;
mod session_overlay_spec;
mod skills_epic_oracle;
