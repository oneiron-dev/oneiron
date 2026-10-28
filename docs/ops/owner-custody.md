# Owner custody commands: unlock, wraps, bindings and pending credentials

This page adds to [owner-actions.md](owner-actions.md). It covers the custody commands that take
an unlock of their own, the wrap a restore can add, secret bindings, the kit push from a running
server, credentials a restore left pending, and the courtesy asks a stopped-vault guest revoke
sends. As on that page, a CLI command needs the server stopped, and a running server answers the
same action at a route under `/v1/owner`.

## Secrets typed at a terminal

A command that reads a secret from stdin asks for it on stderr when stdin is a terminal, and
turns the terminal's echo off until the read ends. The secret does not show on the screen or in
the scrollback. A password, a PRF output, a seed or a kit passphrase ends at the line break you
type. A secret value (`secrets register`, `secrets rotate`) and a recovery kit
(`secrets anchor-sign`) end at Ctrl-D, and a value is kept exactly as typed. A pipe or a file is
read as before.

## Unlock the vault key for any vault-key command

Every `oneiron vault-key` command that opens the vault, and `oneiron recovery-kit confirm`, takes
the same unlock. This install's keystore is the default, as before. Any other way unlocks a sealed
vault's pages before it opens, and a plain vault's key after:

| Flag | What it reads |
|---|---|
| `--unlock device\|password\|passkey\|escrow\|kit` | how the key unlocks |
| `--unlock-credential NAME` | the passkey's credential name |
| `--unlock-label NAME` | the escrow wrap's label |
| `--unlock-capsule REPORT` | a registry's escrow capsule report for this vault |
| `--unlock-piece FILE`, `--unlock-vault-id HEX` | a kit's pieces and the vault id it is bound to |
| `--unlock-secret-file FILE` | the unlock's secret, instead of stdin |
| `--unlock-box-dir DIR`, `--unlock-box-command PROGRAM` | the recovery box that releases an escrow seed |

```sh
# a host restored with a password and `[keystore] backend = "off"`
oneiron vault-key set-password --unlock password --unlock-secret-file old.txt --secret-file new.txt
oneiron vault-key add-escrow usb --box-dir /Volumes/KEY/oneiron-box --unlock password < old.txt
oneiron vault-key status --unlock passkey --unlock-credential my-yubikey --unlock-secret-file prf.bin
oneiron recovery-kit confirm --piece p1.txt --piece p2.txt --unlock password < old.txt
```

The `--unlock-*` names are kept apart from the secret the command enrolls (`--secret-file`,
`--box-dir`) and from a kit's `--piece`. One command reads at most one secret from stdin. When
both the unlock and the new secret would come from stdin, the command asks you to put one of them
in a file. `vault-key prf-input` opens no key and reads no `--unlock`.

`vault-key add-device` keeps its own flags (`--unlock`, `--credential`, `--label`, `--piece`,
`--vault-id`, `--secret-file`, `--box-dir`, `--box-command`). It also takes `--capsule REPORT`
with `--unlock escrow`: a registry's escrow capsule opens the key in place of a wrap. The report
must name this vault. The engine opens it only to the key the vault's commitment names, and a
sealed vault opens only while it holds that capsule's wrap. The command then names the released
recipient on stderr. Retire it with `oneiron vault-key retire-escrow LABEL`.

## Retired escrow labels in the status

`oneiron vault-key status` and `GET /v1/owner/vault-key` list every escrow label retired here in
`retired`, each with its `label`, `receipt_id`, `removed_wrap` and `retired` time. No wrap is
sealed to a retired label again.

## Add a durable wrap at a restore where no vault is yet

On a host whose keystore is off, a restore adds no device wrap. A vault restored with a registry
capsule then keeps only the backup's wraps, and the capsule's recipient is released. Name a wrap
this host can open later with `--wrap-to`. The restore adds it before the vault is kept:

```sh
oneiron restore BACKUP --unlock escrow --capsule report.json --box-dir /Volumes/KEY/box \
  --trust signer.json --wrap-to password --wrap-secret-file new-password.txt
```

| Flag | What it reads |
|---|---|
| `--wrap-to password\|passkey\|escrow` | the new wrap |
| `--wrap-credential NAME` | with `passkey`: the credential name |
| `--wrap-label NAME` | with `escrow`: the new label |
| `--wrap-secret-file FILE` | the password or PRF output, instead of stdin |
| `--wrap-box-dir DIR`, `--wrap-box-command PROGRAM` | with `escrow`: the box that keeps the new seed |

The reply's `added_wrap` names the new wrap. When the keystore is off and no `--wrap-to` was
named, `custody_note` says which wraps the vault keeps. The restore never turns the keystore on.
`--wrap-to` works only where no vault is yet. A vault that is there keeps its own wraps; add one
with `oneiron vault-key set-password --unlock ...`.

## Bind and unbind a secret

```sh
oneiron secrets bind --handle sc12 --effector connector:slack            # rung 0, scope read
oneiron secrets bind --name deploy-token --effector deploy --rung 1 --scope read --scope write
oneiron secrets unbind --handle sc12 --effector connector:slack
oneiron api raw POST /v1/owner/secrets/unbind --data '{"handle": "sc12", "effector": "connector:slack"}'
```

Unbind withdraws one binding. Every other binding, the value and its generation stay. The reply
is the same as a bind's: the bindings the record still holds, the Gate record
(`gate.secret.owner_unbind`), and the custody rewrap that carries the new bindings to your other
machines, or why they stayed on this install.

## Push with your recovery kit from a running server

`oneiron secrets anchor-sign` reads the kit on a stopped vault. A running server takes the same
push in one call, with the kit in its body:

```sh
oneiron api raw POST /v1/owner/secrets/anchor-sign --data @push.json
# push.json: {"target": "<this install, 32 hex>", "name": "NAME",
#             "recipients": ["<machine>"], "pieces": ["<code>", "<code>"]}
```

Add `"passphrase"` when one piece and the kit passphrase open the kit. The kit is the proof for
this call alone. It is not stored, logged or put in a receipt. The rules of the CLI form hold: the
engine takes the push only from an install with no live machine profile, against the root this
vault pins. A hosted or managed install takes no kit (`kit_requires_owner_device`). A `target`
that is not this install's machine id is refused as `kit_target_elsewhere`.

## Credentials a restore left pending

When a restore cannot read its source's erase evidence, it saves those credentials pending, one
batch per restore. The custody passes recheck each one on their own: on upkeep, on the served tick
and when the vault opens. A credential lands once its source reads clear and its value opens. It
waits while the source does not read, and stays withheld when the source names an erase. If the
source is gone for good, you can keep the batch as the backup carried it:

```sh
oneiron secrets pending                                                   # batches, cards, receipts
oneiron secrets pending --keep <batch> --confirm keep_without_source
```

A running server answers `GET /v1/owner/secrets/custody/pending` and takes
`POST /v1/owner/secrets/custody/pending` with `{"batch", "confirm": "keep_without_source"}`. Each
batch carries a generic `card` (`kind`, `headline`, `body`, `action`) that a surface can show in
its own words. Keeping a batch is your election, not a check of the source. A credential whose
value never opens is still re-entered or reissued. The restore report's pending note points here.

## Guest revoke with a courtesy ask on a stopped vault

```sh
oneiron guests revoke <grant> --peer https://former-peer.example
```

Once the revoke commits, the command queues the same courtesy-delete asks as
`POST /v1/owner/guests/revoke`. Each ask goes to the peer, once for each pact the revoke ended,
and is signed with this host's key. A verb hook that rewrites `peer` is followed. A peer that
fails the origin check skips the asks only, and the answer and your inbox say why. An ask that
does not queue never undoes the revoke.
