// Generated from Rust facade DTOs by scripts/sdk/generate.py.
export type TaskCanAskRequest = {
  ask: unknown
}
export type TaskAskShort = {
  who?: unknown | null
  what: unknown
  until?: number | null
  default?: unknown
}
export type TaskWaitRequest = {
  handle: unknown
  step_key: string
}
export type TaskAnswerRequest = {
  handle: unknown
  word: unknown
}
export type EmptyRequest = {
}
export type RoomRequest = {
  room_ref: string
  after?: string | null
  limit?: number | null
}
export type RoomRefRequest = {
  room_ref: string
}
export type RoomTurnRequest = {
  room_ref: string
  turn_ref: string
}
export type RoomClaimRequest = {
  room_ref: string
  turn_ref: string
}
export type ProjectRefRequest = {
  project_ref: string
}
export type ProjectGoalDismissRequest = {
  project_ref: string
  expected_goal_ref: string
  question_digest: string
}
export type ProjectGoalDismissReceipt = {
  dismissed: boolean
}
export type ProjectTradeoffRouteRequest = {
  task_ref: string
  proposal_ref: string
}
export type RoomHostRequest = {
  room_ref: string
  session_ref?: string | null
}
export type CompanionSharingRequest = {
  companion_ref: string
  contact_ref: string
}
export type CompanionSharingSetRequest = {
  companion_ref: string
  contact_ref: string
  proposal_ref: string
  expected_delta: string
}
export type WorkspaceRefRequest = {
  workspace_ref: string
}
export type WorkCompanionSetRequest = {
  workspace_ref: string
  policy: unknown
}
export type TaskRequest = {
  task_ref: string
}
export type ProjectConversationRequest = {
  conversation_ref: string
}
export type ProjectCardRequest = {
  card_id: string
}
export type ProjectCardDismissal = {
  card_id: string
  dismissed: boolean
}
export type DescribeRequest = {
  task_ref?: string | null
  self?: boolean
  session_id?: string | null
  key?: string | null
  frame_epoch?: number | null
  fold?: string | null
}
export type TaskCreateRequest = {
  spec: unknown
  label?: string | null
  assignee?: unknown | null
}
export type BoardRefreshRequest = {
  frame_epoch?: number | null
}
export type BoardSubscriptionRequest = {
  scopes: unknown
}
export type RoomEntry = {
  id: string
  room: unknown
}
export type RecallRequest = {
  query: string
  effort?: unknown | null
  scope?: unknown | null
  limit?: number | null
  format?: string | null
  as_of?: number | null
  deadline_ms?: number | null
}
export type ReceiptsRequest = {
  limit?: number | null
}
export type VaultReceiptsRequest = {
  limit?: number | null
  kinds?: (string)[]
}
export type InboxListRequest = {
  after?: string | null
  limit?: number | null
}
export type InboxMarkRequest = {
  notification_ref: string
  mark: unknown
}
export type CommitRequest = {
  claims: (ClaimInput)[]
}
export type ClaimRefRequest = {
  claim_ref: string
}
export type ForgetPredicateRequest = {
  subject_ref: string
  predicate: string
}
export type SafeDeleteRequest = {
  entity_ref: string
  reason: SafeDeleteReason
}
export type HydrateRequest = {
  refs: (string)[]
}
export type EntityRequest = {
  entity_ref: string
}
export type QueryBm25Request = {
  query: string
  limit: number
}
export type NeighborsRequest = {
  entity_ref: string
  opts: NeighborOpts
}
export type AppendBlobVersionRequest = {
  artifact_ref: string
  content_base64: string
  run_ref?: string | null
  occurred_at: number
  learned_at?: number | null
}
export type ReadBlobVersionRequest = {
  artifact_ref: string
  version: number
}
export type CreateNoteRequest = {
  kind: string
  markdown: string
}
export type CreateNoteFromEntityRequest = {
  source_ref: string
  kind: string
}
export type EditNoteRequest = {
  note_ref: string
  edit: unknown
}
export type BlobContent = {
  content_base64: string
}
export type ClaimInput = {
  id?: string | null
  predicate: string
  subject_ref: string
  value: unknown
  confidence: number
  source: string
  world_ref?: string | null
  relationship_ref?: string | null
  scope?: unknown | null
  valid_from?: number | null
  valid_to?: number | null
  occurred_at?: number | null
  learned_at?: number | null
  salience?: number | null
}
export type CommitReceipt = {
  claim_short_id: string
  approval: string
  superseded_short_id?: string | null
  receipt_ref: string
  claim?: unknown | null
  superseded?: unknown | null
}
export type DeleteReceipt = {
  existed: boolean
  reason: string
  receipt_ref?: string | null
}
export type PendingWrite = {
  claim_ref: string
  decision_ref: string
  created_at: number
  reason_codes: (string)[]
  dreamer_run_id?: string | null
}
export type MemoryReceipt = {
  receipt_ref: string
  kind: string
  outcome: string
  created_at: number
  reason_codes: (string)[]
  actor_class: string
  actor_ref?: string | null
  content_kind: string
  claim_ref?: string | null
  claim?: unknown | null
  fields?: unknown
}
export type EntityView = {
  id_hex: string
  short_ref?: string | null
  kind: string
  occurred_start: number
  occurred_end: number
  learned_at: number
  body?: unknown | null
}
export type TextIndexField = {
  field: string
  value: string
}
export type StructuralEdgeSpec = {
  edge_kind: string
  target_ref: string
  weight?: number | null
}
export type StructuralPutInput = {
  id?: string | null
  kind: string
  body: unknown
  text_fields?: (TextIndexField)[] | null
  edges?: (StructuralEdgeSpec)[] | null
  occurred_at: number
  learned_at?: number | null
}
export type EntityRefReceipt = {
  entity_ref: string
  id_hex: string
  receipt_ref: string
  record?: unknown | null
}
export type HabitCheckinInput = {
  habit_ref: string
  id?: string | null
  data?: unknown | null
  occurred_at: number
  learned_at?: number | null
}
export type AdmitImportedClaimInput = {
  source_id: string
  source_record_id: string
  id?: string | null
  subject_ref: string
  predicate: string
  value: unknown
  occurred_at: number
  learned_at?: number | null
}
export type BlobArtifactInput = {
  id?: string | null
  name: string
  media_type: string
  occurred_at: number
  learned_at?: number | null
}
export type BlobVersionView = {
  artifact_ref: string
  version: number
  content_hash_hex: string
  claim_ref: string
  created_at: number
  artifact?: unknown | null
  claim?: unknown | null
}
export type ClaimView = {
  claim_ref: string
  short_ref?: string | null
  predicate: string
  subject_ref: string
  value: unknown
  confidence: number
  approval: string
  lifecycle: string
  source?: string | null
  world_ref?: string | null
  scope?: unknown | null
  valid_from?: number | null
  valid_to?: number | null
  salience?: number | null
  stale: boolean
  claim?: unknown | null
}
export type ClaimListFilter = {
  subject_ref?: string | null
  predicate?: string | null
  lifecycle?: string | null
  limit: number
}
export type LexicalHit = {
  short_id: string
  kind: string
  score: number
  snippet?: string | null
  record?: unknown | null
}
export type NeighborOpts = {
  edge_kind?: string | null
  min_weight?: number | null
  limit: number
}
export type NeighborHit = {
  short_id: string
  kind: string
  edge_kind: string
  weight: number
  direction: string
  record?: unknown | null
}
export type ExportOptions = {
  format?: string | null
  include_secrets?: boolean | null
}
export type ExportReceipt = {
  at: number
  format: string
  bytes: number
  digest: string
  by: string
  diary_reads: (unknown)[]
}
export type MemoryExport = {
  format: string
  archive: string
  digest: string
}
export type WitnessMessage = {
  id?: string | null
  author: WitnessAuthor
  message_type: string
  content: string
  metadata?: unknown | null
  is_visible: boolean
  order: number
}
export type WitnessTurn = {
  conversation_ref: string
  turn_ref?: string | null
  quote?: unknown | null
  messages: (WitnessMessage)[]
  occurred_at: number
}
export type WitnessReceipt = {
  turn_short_id: string
  message_short_ids: (string)[]
  receipt_ref: string
  turn?: unknown | null
  messages?: (unknown)[]
}
export type ForgetRequest = ClaimRefRequest | ForgetPredicateRequest
export type SafeDeleteReason = "user_delete" | "user_hard_delete" | "gdpr_delete" | "policy_delete"
export type WitnessAuthor = "user" | "companion" | "system"
