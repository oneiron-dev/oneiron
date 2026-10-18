import os

from oneiron import Oneiron

paired = Oneiron.pair(os.environ["ONEIRON_LINK"])

# Store this as ONEIRON_KEY. The link is now spent; the credential is not.
# paired["pin"] is the checkpoint pin the link named (None when the vault has
# no attested checkpoint): a machine that will run a local replica keeps it
# beside the server origin and the credential.
print(paired["credential"])
