# NOTE summary requester lanes

A credential-bound `Memory::create_summary` NOTE request queues the portable
scope of its actual read lane. The NOTE planner rebuilds that lane in the same
transaction as source admission. It repeats this check when the queued
composition is reused or landed.

A non-principal declaration keeps `requester_lane` plus two private Boolean
fields: `requester_owner_exemption` and `requester_relationship_grants`. The
producer captures both from the actual live key inside the enqueue transaction.
They are required on a non-principal NOTE declaration; missing or malformed
values are not treated as an owner exemption. These fields contain no proof,
secret, key, or serialized read capability.

The planner restores the native access-grant or relationship-grant basis and
then applies the frozen scope. An owner exemption requires both the captured
eligibility and the current owner binding. A transferred owner credential has
no captured exemption, even though its holder id still names the owner. Moving
a NOTE to a facet outside that credential's saved scope therefore does not
restore the exemption during later planning. A narrowed declaration never
gets the unrestricted vault-owner floor.

Principal/default declarations and the internal NOTE topic trigger retain their
original principal path. Conversation targets are unchanged. The current
room-turn and unsupported narrowed-guest paths still use the existing plain
queue; this change does not provide portable frozen forms for them.

This covers the actual queued declaration, not every future derivation. The
projection and explicit re-derivation paths still normalize a fresh declaration
without its saved requester lane and basis. That is a separate open follow-up.
A full transferred credential can also freeze as principal before the new
metadata is captured; that separate existing case remains open. No old-format
reader or migration is supplied.

The request's existing named-map version remains 2; only its private declaration
metadata changes. Matching engine/server deployment needs no SDK, worker,
configuration, or guest-image change.
