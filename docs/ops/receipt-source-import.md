# Receipt-source archive import

Whole-vault import restores the cited receipt sources of an inert imported
claim through `restore_claim_receipt_sources_in_txn`. The holder must remain a
CLAIM with an imported, proposed or rejected body. The source must name a
canonical attempt receipt and pass the existing credential-nulling and receipt
identity checks. Native receipt authority is never imported.

Before this function admits any new source ASSET, it validates every source,
resolves duplicates, binds each archive to the holder body, computes its
canonical archive id, and checks any existing row under that id. Canonical
encoding is written once into one shared native temporary body, rather than
retaining all encoded archives in memory until the puts begin. Each source
keeps only its pending id, range and digest in the preparation vector. After
all sources are encoded and the shared body is frozen and verified, identities
are computed from its actual bytes in source order, followed by existing-row
comparisons. No length-counting encoding or salted re-encoding is needed.
This puts source validation before the identity/existing-row phase: if both
phases would fail, the source-validation error now wins. Both phases still
finish before the first admitted put. One descriptor serves every source,
so the number of sources does not require more open files.

The temporary body is never published. On a sealed vault, it uses an
in-memory ephemeral key, not a persistent body instance. The temporary name is
unlinked as soon as its read descriptor is open. The descriptor and key stay
alive until the sources are written or the import returns an error. Failed
preparation removes its temporary name too. The existing writer-open debris
sweep handles a process crash during construction.

The archive id uses the same domain, salt, length framing and canonical bytes
as the slice-based id. Bounded seekable ranges read the same open body file,
including for an existing row's canonical comparison; they do not reopen an
archive input or mint a new body instance. The frozen shared bytes are checked against their
encoded digest before any put. Each final staged body's length and digest are checked
again before its put. Puts keep their original order and use the ordinary ASSET
batch admission path. An error still requires the caller's write transaction
to abort; this function does not commit it.

The importer reserves native body instances before its writer opens, alongside
the ordinary File ASSET reserve. It counts preserved receipt sources as an
upper bound because their canonical bytes depend on the mapped holder inside
the writer. Duplicates, already-stored rows, small archives and sources the
stager keeps inline leave unused instances as ordinary debris. Unavailable
sources have a canonical attempt id and a unit omission reason, so stay small.
No instance is minted inside the writer.

The shared ASSET stager recognizes the native receipt archive magic as the
`ReceiptArchive` file kind (code 3). It retains the existing inline threshold,
secret-scan verdicts, known-value marking and sealed-key binding. A long source
that can live on the file plane streams from its frozen range into that native
file. Small sources and sources the existing scan keeps inline retain their
ordinary row path. Each staged body's pin and instance lease remain in the
importer's holds until its writer commits or aborts, including when a put
returns an error. The outer all-body pin spans the same writer.

Source values and receipt decoding can still be held whole. Inline fallback
and ordinary batch staging have their own copies. This does not claim bounded
total import memory or a fully tree-free receipt import.

## Canonical reader seam

Canonical decoding and archive identity now accept a frozen seekable reader.
The existing slice entry points use that same reader path. Decoding reads the
native MessagePack value, rewinds the same source, and compares its canonical
encoding byte for byte through the existing I/O block size. Any trailing byte
or canonical mismatch remains invalid. Identity hashes the same domain, salt,
length and bytes; preparation shares that framing function. Reader I/O errors
propagate rather than becoming absence. The caller must keep the source frozen
and open across the decode, comparison and identity reads.

`ExportReceiptSource::record` returns the record already decoded by its
validation. It no longer serializes and decodes that same admitted body a
second time. Credential nulling, attempt identity and body validation still run.

The restore path uses these readers on its frozen temporary file for identity
and existing-row comparison. A manifest's bytes and an unminted temporary body
do not supply file-admission facts or receipt authority.

## Native file custody source seam

The original put's `options.storage.asset_file` now reaches receipt admission
and custody projection. A staged file is opened only from those original facts,
matched against its manifest, and checked through the native ASSET reader before
canonical decoding. Positional decoding and identity use that same open file,
not a reopened path or a re-encoded body. Stored-row comparisons, source reads
and retirement resolve the SAME-snapshot native ASSET descriptor first. A
manifest-shaped inline body remains inline.

The existing holder, canonical id, dedupe slot, source retirement and claim-body
checks still apply to the logical archive. Native file checks do not mint an
instance or confer receipt authority. Callers must keep the staging pin, or
pin the stored files before opening the snapshot, until their read or write
ends. Whole-vault export already pins all bodies before opening its snapshot.
Its owning adapter reads the logical source through the same descriptor and
canonical reader, then folds the semantic receipt source into its holder's
archive section. The serializer still excludes native receipt archives from
raw `ExportBody::File` attachments. A file kind or manifest never grants
receipt authority.

## Sync representation

The native unsealed mirror readers pin bodies before their original snapshot.
A local `ReceiptArchive` file is resolved under that same snapshot, checked
against its descriptor, canonical bytes and source id, then returned with its
original metadata header. The outbound mirror keeps those canonical bytes in
Loro as an inline source and removes a prior file reference. Ordinary ASSET
file carriers keep their by-reference path. Thus these outgoing readers need
no historical-file reopen after a receipt's native key is retired. They still
materialize the one logical source, as the original inline sync path did.

A by-reference receipt body lands through the same native ingest ladder as
other bodies, at the original lane tier. The landing uses its original bound
carrier and the complete staged canonical bytes, not a later current-row read.
A detached candidate is prepared before the writer opens: Loro's live `fork`
can commit pending local edits, so it must not run inside that writer. Only
that isolated candidate is edited and exported there. The same landing writer
journals its ordinary window update and queue entry beside the native row.
An abort publishes neither. The live document takes the update only after the
commit and the socket's original local-land position handling. A failed or
pending live import leaves the durable journal and queue for native replay;
it does not change a committed body's Receipt to false.

Optional origin positions keep their original incoming values and connection
proofs. An inline receipt can match its original file representation only when
the canonical id, whole logical header/body digest and measured body facts
match, and reconstructing the original header plus manifest satisfies the
original reference's full carrier hash. The immutable scope, birth, facet,
complete source set, registry identity, residence and own-device proof checks
remain. This preserves later position arrival and optional retry errors without
turning a file reference or current id into authority. Ordinary rows retain
their exact representation checks. A manifest, missing payload or file pin is
not an immutable historical source. These source changes still do not claim
bounded total memory or runtime proof; the logical receipt body remains whole
at the sync carrier boundary.
