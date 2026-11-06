# Coach grant-environment repair proposals

A custom `CoachHealAuthor` can implement `draft_environment` for a failure-ladder
CASE routed to `environment`. The engine supplies the case, its recorded cause,
and typed `EnvironmentGrantTarget` values. Each target names a real native
ACCESS_GRANT whose `principal_ref` is the failing agent. This association does
not prove that the grant caused the failure.

The target list includes active, expired and revoked grants. Deleted entity
shells and erased grant history are not targets. An author returns
`CoachEnvironmentDraft` with one supplied `grant_ref`, an object-valued `change`,
and a rationale. The engine does not trim or execute that data. An unknown target,
decline, failed author or unusable draft leaves a route-only heal with a skipped
reason. The default author method returns `None`; the default served host does
not gain an Environment drafting model from this port.

Before landing, the existing heal writer revalidates the authentic case and its
actual Failed attempt, dispatched agent and TASK binding. It rereads the target's
principal and canonical grant-terms digest. The digest excludes read-witness
history; a history-only update does not invalidate unchanged terms. A moved case
or target leaves the original heal proposal and settlement path intact. Storage
and malformed-record errors propagate and roll back rather than claiming a
successful repair.

A usable draft lands as an ordinary Proposed CLAIM with predicate
`coach.environment_repair` in the same transaction as its heal. Its value records
the case, failed attempt, agent, diagnosis, real grant id, canonical terms digest,
change and rationale. Its evidence includes the selected grant. The heal carries
`HealerRepairRoute::Environment`, with `environment_ref` naming that grant and
`repair_ref` naming the actual artifact.

Both the artifact and route are DATA for review. They do not edit or grant access,
revive a terminal grant, mint credentials, execute a tool, or prove a repair
worked. Existing native grant-renewal rules still require a new grant id for
revoked or expired access. No checkpoint prerequisite is added to Environment.

This is a CASE/custom-author AccessGrant port only. SkillEdit, Issues and Person
routes are unchanged. The separate prompt artifact port, default served author,
application, tool and connector targets, and full FIX1551/FIX2498 closure remain
separate work. No configuration, migration, new storage family or SDK change is
required; hosts that use the port build against matching engine types.
