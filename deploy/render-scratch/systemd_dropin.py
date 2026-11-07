#!/usr/bin/env python3
"""Emit an opt-in systemd drop-in for the renderer's capped scratch mount."""

import argparse
import sys


def nonnegative(value):
    try:
        number = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected an integer") from error
    if number < 0:
        raise argparse.ArgumentTypeError("expected a nonnegative integer")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bytes", type=nonnegative, required=True,
                        help="operator-chosen total tmpfs capacity in bytes")
    parser.add_argument("--uid", type=nonnegative, required=True,
                        help="numeric uid of the engine service")
    parser.add_argument("--gid", type=nonnegative, required=True,
                        help="numeric gid of the engine service")
    args = parser.parse_args()
    if args.bytes == 0:
        parser.error("--bytes must be positive")
    # The private namespace and tmpfs are created by systemd at service start.
    # No installation or mount command is performed by this generator.
    sys.stdout.write(
        "[Service]\n"
        "Environment=ONEIRON_RENDER_SCRATCH=/run/oneiron-render\n"
        "TemporaryFileSystem=/run/oneiron-render:rw,nosuid,nodev,noexec,noswap,"
        f"size={args.bytes},mode=0700,uid={args.uid},gid={args.gid}\n"
    )


if __name__ == "__main__":
    main()
