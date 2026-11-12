import os

from oneiron import Oneiron

paired = Oneiron.pair(os.environ["ONEIRON_LINK"])

# The link is now spent; the credential is not. Store these privately.
slip, seed = paired["credential"].removeprefix("v2.cred.").rsplit(".", 1)
print({"ONEIRON_SECRET": "v2.slip." + slip, "ONEIRON_BINDING_KEY": seed})
# paired["pin"] is the checkpoint pin the link named (None when the vault has
# no attested checkpoint): a machine that will run a local replica keeps it
# beside the server origin and the credential.
