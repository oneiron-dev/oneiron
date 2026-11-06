# Frozen pattern revision witnesses

A planned team's frozen pattern pack keeps the admitted files and their body
hash, the skill entity, `skill_id`, and version. Its optional retained-revision
witness records the actual revision observed at first freeze. The witness is
metadata, not the identity of the frozen launch or permission to read a skill.

## Hard erase

A permanent local hard-delete marker for that exact skill removes only the
revision witness from retained planned-intent packs. The pack bytes, start,
entity, version, hash, phase, exposures, IDs, and recorded times stay unchanged.
The existing asker and target erase paths still remove the full intent text
when their own rules apply.

The keeper runs in the erase's existing writer. It covers the marked hard-actor
sweep, the headerless and replay paths after they write the hard marker, and
checkpoint restore's per-ID sweep. Restore's live scrub IDs alone do not prove
hard erase: the keeper checks each actual hard-delete marker again. It matches
both the frozen pack entity and the witness entity to the erased target.

Every ordinary durable intent write uses the same writer's marker check before
storage. A stale copy cannot restore a witnessed revision after that skill's
hard erase. If the late-write marker read fails, the fence logs a content-free
warning, retains the witness, and continues the original write behavior. Errors
in an erase or restore still follow those paths' existing error handling.

## Launch and attribution

Launch comparison still requires the same custody fence, placement, plan,
frozen start, and full frozen pack body. Only the optional revision witness is
ignored. A witness scrub between preflight and launch therefore does not create
a new launch refusal. A missing pack is still different from a present pack.

The child uses the witness the frozen pack carries, or no retained pin after it
has been erased. It does not infer a revision from today's skill version text.
Existing attribution fallback and first-freeze behavior are unchanged.

Implementation: `team/spawn_intent.rs`,
`agent_dispatch/planner_live/intent.rs` and `intent/erase.rs`, plus the native
`deletion/actor_fields.rs`, `deletion/delete/headerless.rs`, and
`deletion/erase/replay.rs` hooks. This is a revision-witness repair, not a claim
that all retained skill bytes or every erase carrier have been removed.
