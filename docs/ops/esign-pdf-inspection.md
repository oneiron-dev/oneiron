# E-sign PDF inspection

The geometry upload and ceremony preview routes share the same PDF inspection
selector. On Unix, a registered seal organ that advertises `seal.inspect` receives
the inspection in its isolated worker. A host without that verb, and non-Unix
hosts, keep the existing native inspection path. Installing an inspection
worker is not a new prerequisite for these requests.

Ceremony preview keeps its original capability check, pinned PDF read, memory
lease, decode budget and deadline. The blocking task captures the same server
that supplied that read; it does not reopen the PDF through another reader.
The isolated adapter admits the additional lent input region on that same
lease before copying. The lease stays live through the child call, including
its existing cancellation and grace, then drops before response encoding.

Geometry retains its existing anonymous permit or admitted editor slot.
Preview remains a signing-capability request; it does not acquire an editor
slot or add an editor admission queue. Layout and response construction are unchanged.

The selector keeps its existing memory-floor, deadline, unavailable-worker and
invalid-inspection responses. A configured worker failure does not silently
retry native parsing. No-worker inspection remains native, so this is not
whole-parse process isolation for that configuration or for every e-sign caller.
