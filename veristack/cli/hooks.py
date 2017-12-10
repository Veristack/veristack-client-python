"""Hooks, audit record webhook server."""

from __future__ import absolute_import

from docopt import docopt
from schema import Schema, Use, And, Or, SchemaError


def main(argv):
    """Genny.

    Generates audit data for Veristack. The data is injected into the receiver.
    Receiver adds data to the Hot model, and from there it is ingested into
    Audit model and friends.

    Genny attempts to create coherent random timelines of file activity.
    Events are produced in a manner that yields good timeline data for testing
    the veristack application.

    Usage:
        veristack hooks [--api-key=KEY] [-p PORT] [-H HOST] [-c COUNT]
                        [-s SLEEP] [-S COUNT]

    Options:
        -H --host HOST      Host to connect to [default: localhost]
        -p --port PORT      TCP port to connect to on HOST [default: 41666]
        -c --count COUNT    Number of messages to generate/send [default: 0]
        -s --sleep SLEEP    Seconds to sleep between messages [default: 0]
        -S --word-count COUNT   The average size of the hypothetical file being
                                fingerprinted [default: 100000]
    """
    opts = docopt(main.__doc__, argv=argv)

    try:
        opts = Schema({
            '--api-key': And(str, error='--api-key is required'),
            '--host': str,
            '--port': Use(int),
            '--count': Use(int),
            '--sleep': Use(float),
            '--word-count': Use(int),

            object: object,
        }).validate(opts)

    except SchemaError as e:
        exit(e.args[0])


