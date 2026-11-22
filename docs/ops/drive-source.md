# Google Drive source

The owner attaches their Google Drive as a standing source of notes with
`vault.files.drive.attach` (ARCH-0027 #mail-drive; DRIVE-ACCESS = B). It is the
owner's act: the facade takes the vault owner's proof, an embedded handle its
embedded owner, and no agent reaches it until the owner grants one.

```json
{
  "custody_ref": "google-drive-owen",
  "account": "owen@example.com",
  "access": {"kind": "whole"}
}
```

- `access` is `{"kind": "picked", "files": ["<Drive file id>", ...]}` for the
  files the owner picked through the Google Picker, or `{"kind": "whole"}` for
  every file of the Drive.
- `custody_ref` names the custody record that holds the owner's Google grant for
  Drive. The grant holds the scope the access asks for: `drive.file` for picked
  files, `drive.readonly` for a whole Drive. The answer names it
  (`oauth_scope`). On self-host the owner's own OAuth client asks for either at
  once; Cloud's verification of the restricted scope is a later Cloud task.
- `kind` is the note kind a file lands as, `observation` when absent.
- One account is one source, attached as `drive://<account>`. Attaching it again
  is refused; `oneiron import folder detach drive://<account>` detaches it, and
  the notes it landed stay.

The attach makes no Google call. On a served vault it wakes the host's rescan
worker, which steps the source at once: the first step takes the change feed's
start token, then each picked file's metadata or the whole Drive's listing
(newest first, ten pages of 1,000 files a step), and holds each file by its name
until its text is read. Later steps read the owed texts, newest first, and drain
`changes.list`.

## The pace

A step names when the host steps the source again (`next_step_at` on its
report), as a Gmail copy is paced (L3-16-COPY-PACE = A):

- after a step that read on to its budget's end (listing pages, change pages,
  or texts with more owed), at once;
- after a step that ran out of quota, when its window opens (Drive gives one
  user 325,000 units a minute; the copy spends at most 75% of it, so the change
  feed still reads);
- never once the source owes nothing, after a step whose every text read failed
  (a file larger than one download fails each time), or from a wire that
  declares no quota. The host's 300 s pass steps those.

So a whole Drive copies at its share of the provider's quota, not one step per
pass.
