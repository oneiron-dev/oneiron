//! Store-layer modules of core `git_wire`; core re-exports each one at its old path.

pub mod argv;
pub mod bridge;
pub mod bundle_tree;
pub mod config;
pub mod execution_context;
pub mod execution_scope;
pub mod failure;
pub mod hub_read;
pub mod ids;
pub mod import_fetch;
pub mod mirror_push;
pub mod mutation_commands;
pub mod objects;
pub mod operation;
pub mod origin_relay;
pub mod path_text;
pub mod plan;
pub mod process;
pub mod projected_object;
pub mod record;
pub mod repo;
pub mod repository_profile;
pub mod retained_object;
