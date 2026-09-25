#!/bin/sh
# Only this checked-in inode is executed. The per-test body is read as data,
# so an inherited writer cannot make exec fail with ETXTBSY.
. "$0.sh"
