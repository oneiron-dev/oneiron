## crate
crates/oneiron

## allowed
crates/oneiron/src/anchored_annotation.rs
crates/oneiron/src/anchored_annotation/tests.rs
crates/oneiron/src/artifact_hosting.rs
crates/oneiron/src/artifact_hosting/tests.rs
crates/oneiron/src/batch.rs
crates/oneiron/src/batch/tests.rs
crates/oneiron/src/blob_artifact.rs
crates/oneiron/src/blob_artifact/tests.rs
crates/oneiron/src/bm25.rs
crates/oneiron/src/bm25/tests.rs
crates/oneiron/src/channel_identity_lifecycle.rs
crates/oneiron/src/channel_identity_lifecycle/tests.rs
crates/oneiron/src/channel_identity_provider.rs
crates/oneiron/src/channel_identity_provider/tests.rs
crates/oneiron/src/code_revision.rs
crates/oneiron/src/code_revision/tests.rs
crates/oneiron/src/code_run.rs
crates/oneiron/src/code_run/tests.rs
crates/oneiron/src/code_sandbox.rs
crates/oneiron/src/code_sandbox/tests.rs
crates/oneiron/src/code_symbol.rs
crates/oneiron/src/code_symbol/tests.rs
crates/oneiron/src/codebase.rs
crates/oneiron/src/codebase/tests.rs
crates/oneiron/src/context_pack.rs
crates/oneiron/src/context_pack/tests.rs
crates/oneiron/src/critic.rs
crates/oneiron/src/critic/tests.rs
crates/oneiron/src/deletion.rs
crates/oneiron/src/deletion/tests.rs
crates/oneiron/src/delivery_window.rs
crates/oneiron/src/delivery_window/tests.rs
crates/oneiron/src/dreamer_runner.rs
crates/oneiron/src/dreamer_runner/tests.rs
crates/oneiron/src/dreamer_tournament.rs
crates/oneiron/src/dreamer_tournament/tests.rs
crates/oneiron/src/embed.rs
crates/oneiron/src/embed/tests.rs
crates/oneiron/src/engine_executor.rs
crates/oneiron/src/engine_executor/tests.rs
crates/oneiron/src/extraction_eval.rs
crates/oneiron/src/extraction_eval/tests.rs
crates/oneiron/src/fusion.rs
crates/oneiron/src/fusion/tests.rs
crates/oneiron/src/gate.rs
crates/oneiron/src/gate/tests.rs
crates/oneiron/src/genui.rs
crates/oneiron/src/genui/tests.rs
crates/oneiron/src/graph_fs.rs
crates/oneiron/src/graph_fs/tests.rs
crates/oneiron/src/hnsw.rs
crates/oneiron/src/hnsw/tests.rs
crates/oneiron/src/identity_reputation.rs
crates/oneiron/src/identity_reputation/tests.rs
crates/oneiron/src/inbox.rs
crates/oneiron/src/inbox/tests.rs
crates/oneiron/src/ingest.rs
crates/oneiron/src/ingest/tests.rs
crates/oneiron/src/job_queue.rs
crates/oneiron/src/job_queue/tests.rs
crates/oneiron/src/lens.rs
crates/oneiron/src/lens/tests.rs
crates/oneiron/src/llm.rs
crates/oneiron/src/llm/tests.rs
crates/oneiron/src/maintain.rs
crates/oneiron/src/maintain/tests.rs
crates/oneiron/src/off_record.rs
crates/oneiron/src/off_record/tests.rs
crates/oneiron/src/outbound.rs
crates/oneiron/src/outbound/tests.rs
crates/oneiron/src/pipeline.rs
crates/oneiron/src/pipeline/tests.rs
crates/oneiron/src/policy_model.rs
crates/oneiron/src/policy_model/tests.rs
crates/oneiron/src/ppr.rs
crates/oneiron/src/ppr/tests.rs
crates/oneiron/src/provenance.rs
crates/oneiron/src/provenance/tests.rs
crates/oneiron/src/receipt.rs
crates/oneiron/src/receipt/tests.rs
crates/oneiron/src/recovery.rs
crates/oneiron/src/recovery/tests.rs
crates/oneiron/src/repo_mutation.rs
crates/oneiron/src/repo_mutation/tests.rs
crates/oneiron/src/run_tree.rs
crates/oneiron/src/run_tree/tests.rs
crates/oneiron/src/serialize.rs
crates/oneiron/src/serialize/tests.rs
crates/oneiron/src/settings.rs
crates/oneiron/src/settings/tests.rs
crates/oneiron/src/skill.rs
crates/oneiron/src/skill/tests.rs
crates/oneiron/src/store.rs
crates/oneiron/src/store/tests.rs
crates/oneiron/src/surface_event.rs
crates/oneiron/src/surface_event/tests.rs
crates/oneiron/src/sweep.rs
crates/oneiron/src/sweep/tests.rs
crates/oneiron/src/thread_lens.rs
crates/oneiron/src/thread_lens/tests.rs
crates/oneiron/src/vault.rs
crates/oneiron/src/vault/tests.rs

## forbid

## anchors

## uniqueness

## error-literal

## decl

## impl-delta
- crates/oneiron/src/codebase.rs	impl HostedMediaHashMatchProvider for KnownMatchProvider
- crates/oneiron/src/codebase.rs	impl HostedMediaHashMatchProvider for RecordingHashMatchProvider
- crates/oneiron/src/embed.rs	impl Embedder for RecordingEmbedder
- crates/oneiron/src/embed.rs	impl RecordingEmbedder
- crates/oneiron/src/engine_executor.rs	impl ErrorAfterCallsRuntime
- crates/oneiron/src/engine_executor.rs	impl FixtureBackend
- crates/oneiron/src/engine_executor.rs	impl FixtureRuntime
- crates/oneiron/src/engine_executor.rs	impl JsCodeModeRuntime for ErrorAfterCallsRuntime
- crates/oneiron/src/engine_executor.rs	impl JsCodeModeRuntime for FixtureRuntime
- crates/oneiron/src/engine_executor.rs	impl LlmBackend for FixtureBackend
- crates/oneiron/src/job_queue.rs	impl tracing :: Subscriber for TelemetryCapture
- crates/oneiron/src/job_queue.rs	impl tracing :: field :: Visit for TelemetryVisitor < ' _ >
- crates/oneiron/src/llm.rs	impl LlmBackend for Backend
- crates/oneiron/src/llm.rs	impl LlmBackend for DenyingBackend
- crates/oneiron/src/llm.rs	impl ReadyLlmStream
- crates/oneiron/src/llm.rs	impl Stream for EmptyLlmStream
- crates/oneiron/src/llm.rs	impl Stream for ReadyLlmStream
- crates/oneiron/src/off_record.rs	impl OutboundExecutionSink for PanicSink
- crates/oneiron/src/outbound.rs	impl Default for RecordingExecutor
- crates/oneiron/src/outbound.rs	impl LinkedInMcpSendTransport for ScriptedLinkedInTransport
- crates/oneiron/src/outbound.rs	impl LinkedInSandboxHostHarness for RecordingLinkedInSandboxHarness
- crates/oneiron/src/outbound.rs	impl OutboundExecutionSink for RecordingExecutor
- crates/oneiron/src/outbound.rs	impl ScriptedLinkedInTransport
- crates/oneiron/src/policy_model.rs	impl LlmBackend for FailingPolicyBackend
- crates/oneiron/src/policy_model.rs	impl LlmBackend for RecordingPolicyBackend
- crates/oneiron/src/policy_model.rs	impl LlmBackend for StaticPolicyBackend
+ crates/oneiron/src/codebase/tests.rs	impl HostedMediaHashMatchProvider for KnownMatchProvider
+ crates/oneiron/src/codebase/tests.rs	impl HostedMediaHashMatchProvider for RecordingHashMatchProvider
+ crates/oneiron/src/embed/tests.rs	impl Embedder for RecordingEmbedder
+ crates/oneiron/src/embed/tests.rs	impl RecordingEmbedder
+ crates/oneiron/src/engine_executor/tests.rs	impl ErrorAfterCallsRuntime
+ crates/oneiron/src/engine_executor/tests.rs	impl FixtureBackend
+ crates/oneiron/src/engine_executor/tests.rs	impl FixtureRuntime
+ crates/oneiron/src/engine_executor/tests.rs	impl JsCodeModeRuntime for ErrorAfterCallsRuntime
+ crates/oneiron/src/engine_executor/tests.rs	impl JsCodeModeRuntime for FixtureRuntime
+ crates/oneiron/src/engine_executor/tests.rs	impl LlmBackend for FixtureBackend
+ crates/oneiron/src/job_queue/tests.rs	impl tracing :: Subscriber for TelemetryCapture
+ crates/oneiron/src/job_queue/tests.rs	impl tracing :: field :: Visit for TelemetryVisitor < ' _ >
+ crates/oneiron/src/llm/tests.rs	impl LlmBackend for Backend
+ crates/oneiron/src/llm/tests.rs	impl LlmBackend for DenyingBackend
+ crates/oneiron/src/llm/tests.rs	impl ReadyLlmStream
+ crates/oneiron/src/llm/tests.rs	impl Stream for EmptyLlmStream
+ crates/oneiron/src/llm/tests.rs	impl Stream for ReadyLlmStream
+ crates/oneiron/src/off_record/tests.rs	impl OutboundExecutionSink for PanicSink
+ crates/oneiron/src/outbound/tests.rs	impl Default for RecordingExecutor
+ crates/oneiron/src/outbound/tests.rs	impl LinkedInMcpSendTransport for ScriptedLinkedInTransport
+ crates/oneiron/src/outbound/tests.rs	impl LinkedInSandboxHostHarness for RecordingLinkedInSandboxHarness
+ crates/oneiron/src/outbound/tests.rs	impl OutboundExecutionSink for RecordingExecutor
+ crates/oneiron/src/outbound/tests.rs	impl ScriptedLinkedInTransport
+ crates/oneiron/src/policy_model/tests.rs	impl LlmBackend for FailingPolicyBackend
+ crates/oneiron/src/policy_model/tests.rs	impl LlmBackend for RecordingPolicyBackend
+ crates/oneiron/src/policy_model/tests.rs	impl LlmBackend for StaticPolicyBackend
## frag-edit
crates/oneiron/src/ingest.rs	include_str!("../tests/fixtures/ingest/minimal_transcript.jsonl");	include_str!("../../tests/fixtures/ingest/minimal_transcript.jsonl");
crates/oneiron/src/ingest.rs	include_str!("../tests/fixtures/ingest/null_optional_metadata.jsonl");	include_str!("../../tests/fixtures/ingest/null_optional_metadata.jsonl");
crates/oneiron/src/pipeline.rs	let source = include_str!("pipeline.rs");	let source = include_str!("../pipeline.rs");
