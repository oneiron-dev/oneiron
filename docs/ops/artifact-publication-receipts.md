# Artifact publication receipts on the sync socket

A publication part is admitted only on the owner lane under the vault owner's bound Read+Write session. Each storage writer still rechecks credential liveness. This gate does not grant the sender any new authority.

A known owner-lane, scope, actor or owner-binding denial produces the existing `ARTIFACT_RECEIPT` with `Refused`. The receipt contains only the digest supplied in the part and the refusal outcome. It is queued only on the socket that sent that part. The rejection path reads or changes no publication spool, pointer, artifact body or transfer settlement.

An unreadable part produces no receipt, as on the admitted import path. Missing or unproven credential liveness, an unavailable owner check and storage failures keep the existing socket-error behavior. They do not become terminal refusals that could clear a device's durable outbox after a temporary failure.

The direct document filter and final destination filter allow the structurally valid refusal control reply. Other artifact receipts keep their existing owner and destination checks. The stopping transport's credential revocation checks remain in force.

Admitted publication parts keep their current behavior: they are held until complete, hashed and applied or staged. `Applied` and `Refused` settle only the exact current digest on the sending device; a newer pointer change remains owed. A failed owner gate never settles or deletes an already admitted server-side transfer.

This changes no wire kind, digest, part limit, protocol version, retry interval or configuration default. It does not address generic document REQUEST/UPDATE errors or decide whether an artifact row can arrive later. No migration, deployment change or external service is needed.
