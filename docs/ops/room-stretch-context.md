# Room stretch context

The typed `RoomSection.stretches` list reports every open stretch in the room
for a current room member. Each `RoomStretch` carries:

- `session_ref`: the registry handle used by the off-record verbs;
- `instance_ref`: this entry's existing overlay-shell identity;
- `mode`: `off_record`, `on_record`, or `anonymous`.

The `ROOM` section renders one `stretch:` row per entry on every page. The
instance identity changes when a closed handle is entered again, even if the
handle and mode are reused. It does not grant access or replace the handle.

The projection checks current room membership before reading published RAM
records. It takes no registry or session-state mutex. Entry, mode changes and
close publish the native record; the next room render reads that state again.
Ordinary chat context and MCP board reads render fresh. MCP's existing board
state hash includes the rendered stretch rows. This is a current-state
projection, not a lifecycle event log or a mid-stream notification service.

The room's scope, posture, roster, rules, offers and paging are unchanged.
Unsaved scratch remains isolated in the stretch and is discarded on ordinary close.
