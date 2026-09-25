import os

from oneiron import Oneiron

memory, credential = Oneiron.pair(os.environ["ONEIRON_LINK"])

# Store this as ONEIRON_KEY. The link is now spent; the credential is not.
print(credential)
