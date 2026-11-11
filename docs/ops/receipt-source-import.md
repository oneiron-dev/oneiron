# Receipt-source archive import

Whole-vault import restores the cited receipt sources of an inert imported
claim through `restore_claim_receipt_sources_in_txn`. The holder must remain a
CLAIM with an imported, proposed or rejected body. The source must name a
canonical attempt receipt and pass the existing credential-nulling and receipt
identity checks. Native receipt authority is never imported.

Before this function admits any new source ASSET, it validates every source,
resolves duplicates, binds each archive to the holder body, computes its
canonical archive id, and checks any existing row under that id. Canonical
encoding is written into one shared native temporary body, rather than
retaining all encoded archives in memory until the puts begin. Each source
keeps only its id, range and digest in the preparation vector. The canonical
serializer first counts the same owned data tree for its id's length frame;
it does not reopen archive-file inputs. One descriptor serves every source,
so the number of sources does not require more open files.

The temporary body is never published. On a sealed vault, it uses an
in-memory ephemeral key, not a persistent body instance. The temporary name is
unlinked as soon as its read descriptor is open. The descriptor and key stay
alive until the sources are written or the import returns an error. Failed
preparation removes its temporary name too. The existing writer-open debris
sweep handles a process crash during construction.

The archive id uses the same domain, salt, length framing and canonical bytes
as the slice-based id. The frozen shared bytes are checked against their
encoded digest before any put. Each final staged body's length and digest are checked
again before its put. Puts keep their original order and use the ordinary ASSET
batch admission path. An error still requires the caller's write transaction
to abort; this function does not commit it.

Receipt archives remain inline owning-adapter rows. The native ASSET stager
reads one prepared archive back for its put. This does not publish a file
manifest or mint a persistent body instance. Custody, raw archive readback,
holder binding, retirement and the canonical format are unchanged.

This is only the encoded preparation slice of FIX 11180. Source values and
receipt decoding can still be held whole. A single archive is still
materialized for its inline put, and ordinary batch staging has its own copies.
File-backed receipt custody/readback and pre-writer instance preparation remain
separate work. This change does not claim bounded total import memory or a
fully streaming receipt import.
