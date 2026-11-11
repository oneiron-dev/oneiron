import { Oneiron } from "oneiron"

const link = process.env.ONEIRON_LINK
if (!link) throw new Error("Set ONEIRON_LINK to the one-line link your server's owner created")
const { credential } = Oneiron.pair(link)

// The link is now spent; the credential is not. Store these privately.
const [slip, seed] = credential.slice("v2.cred.".length).split(".")
console.log(JSON.stringify({ ONEIRON_SECRET: `v2.slip.${slip}`, ONEIRON_BINDING_KEY: seed }))
// The result's `pin` is the checkpoint pin the link named (null when the vault
// has no attested checkpoint): a machine that will run a local replica keeps
// it beside the server origin and the credential.
