# Scope-summary sources in a composed session view

A scoped read validates scope-summary source content through the same composed
session view and read transaction as the row it is reading. This applies to a
scope-summary body, a TURN that copies one, and a `merge.summary` claim that
names one. Message revisions, conversation edges, branch placement and retained
session membership all use that content view. A base row is not accepted first
and retried through the view only when it fails.

An overlay-only source can therefore resolve. An erased source or changed
MESSAGE revision in that view does not validate against an older base copy.
The caller retains its existing unresolved-summary and private-thread error
behavior. A composed read also checks the base private-thread walk independently,
so invalid composed content cannot remove a base privacy restriction. A root
present on base keeps its base resolution, including a deleted shell. Only a
root genuinely absent on base resolves through the composed view, so a new
public or private overlay thread still meets its native audience check. The
epoch-summary and registered dependency paths still retain both base and
composed-view source obligations.

This does not make a content view an authority source. Archive controls, task
bindings, audience edits and membership, policy, grants and the Dreamer's
NOTE-source admission remain on their existing native base readers. Resolving a
new thread's root and conversation through the view does not move those
authority checks into the view. The NOTE-source admission and
stale-note behavior are unchanged; this change does not establish complete
NOTE-overlay support. Ordinary writer, landing and metadata calls still use
the base store through the same validation bodies.

No storage format, setting, default, generated client or deployment artifact
changes. A normal engine/server rebuild carries the reader fix.
