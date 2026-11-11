# E-sign preview input memory

The preview reader measures the selected original or sealed PDF before it leases
input memory. It remeasures that same selection in the read transaction before
copying the body. If the current output needs more than the admitted bytes, the
caller grows its existing lease under the existing deadline, then retries. The
version, compaction, readability, original/sealed pin and content-hash checks stay
on the native read path.

The length supplier uses the actual FILE manifest for a file-backed ASSET and the
borrowed row body for an inline ASSET. For an entity-document head, it loads the
same document and counts the resolved output without making a body `String` or
resolved-output `Vec`.

For UTF-8 bodies, the count is Loro's native UTF-8 byte length, not its Unicode or
UTF-16 length. MessagePack map bodies share the materializer's field projection,
metadata validation, body-field placement and native encoding. Only the text sink
differs: it either writes the text or counts its native string framing and UTF-8
bytes. Loro's chunk iterator snapshots owned strings, so the count path does not
use that iterator.

This covers the resolved output copy only. Loading Loro snapshots and updates,
decoding the pointer row and validating metadata still allocate before input
admission. It does not establish full parser or document-graph heap accounting.
No stored-size cache, format change, additional limit or admission wait is added.
