# Local weight facts in Coach stock briefs

The Coach's stock-option brief includes `verified_local_weights` when this
server can verify the files for an exact captured managed model. Otherwise
that field is `null`. All stock options stay in the brief.

The supplier captures the matching worker row, provider and worker handle
when the model runtime is built. Later runtime configuration does not retarget
that handle. Only managed llama.cpp and EXL3 workers this process supervises
are included. External endpoints and mesh discovery do not prove local files.
If more than one configured worker row names the same engine model, its file
facts stay unknown; no arbitrary row wins and the model remains usable.

At brief time the supplier resolves the configured artifact manifest and uses
the worker host's shared artifact store to verify every declared file in the
operator's offline directory or the manifest's install directory. Verification
checks pinned size and SHA-256. The store reuses its existing hash result only
while the file's stamp and expected digest remain unchanged. This read never
installs, downloads, copies, repairs, starts a worker or makes a model call.
Unreadable manifests, missing files and verification errors yield `null`.

The positive value contains the full engine model id, worker id, artifact
manifest, manifest SHA-256 and declared total bytes. It does not expose local
directory paths or credentials. These facts have no vault entity source row,
so a brief that reads them records its source set as unknown rather than
claiming complete entity provenance.

This is a local-file observation, not evidence that a registry backend is
loaded, healthy or serving that artifact. The registry's `serving_revision`
remains a serving-configuration identity; it is not replaced by an artifact
digest. The facts are supplied to the Coach's model while it drafts options;
they are not a persisted download card or an automatic approval credential.

The owner still answers each offer through the existing approval door.
Persisted off-by-default auto-approval and download-card-once state remain
separate work under FIX4663. No setting, default, numeric limit or approval
behavior changes here. Existing checks of an approved offer's promise remain.
