import { Oneiron } from "oneiron"

const link = process.env.ONEIRON_LINK
if (!link) throw new Error("Set ONEIRON_LINK to the one-line link your server's owner created")
const { credential } = Oneiron.pair(link)

// Store this as ONEIRON_KEY. The link is now spent; the credential is not.
// The result's `pin` is the checkpoint pin the link named (null when the vault
// has no attested checkpoint): a machine that will run a local replica keeps
// it beside the server origin and the credential.
console.log(credential)
