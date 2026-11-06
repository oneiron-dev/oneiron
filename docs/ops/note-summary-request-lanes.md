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

A NOTE projection preserves these same private fields when it registers the
saved declaration and observes its sources. Automatic and explicit
re-derivation carry that original narrowing and grant basis into the new queue
input. Explicit re-derivation still records its actual requester, but does not
widen the saved source-reading bound. The native planner checks the current
requester, frozen credential and source permissions again. Projection identity,
principal declarations and other summary targets are unchanged.

A full non-guest credential whose native key lacks the owner's full floor
keeps its credential id even when its read scope is top and it names no records.
It therefore reaches the same native basis capture and live-credential checks,
rather than becoming its holder's principal lane. This includes a transferred
owner credential. Native owner keys, bare-identity keys and the existing full
guest principal path are unchanged. No old-format reader or migration is supplied.

The request's existing named-map version remains 2; only its private declaration
metadata changes. Matching engine/server deployment needs no SDK, worker,
configuration, or guest-image change.
