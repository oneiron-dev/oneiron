"""Canaries: each does one job of the fleet tool through Oneiron alone, from the box it runs on.

Every call goes through rack.oneiron_api (`oneiron api ... call <verb>`), to
the issuer the configuration names for this host, with that host's Grant.
"""
